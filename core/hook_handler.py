"""
Claude Code hook handler for preflight-check-skill.

Hook protocol (Claude Code):
    Input  (stdin):  JSON with hook_event_name + event-specific fields
    Output (stdout): JSON with hookSpecificOutput structure
    Exit code:       0 = allow (parse stdout), 2 = block (stderr is feedback)

UserPromptSubmit: can warn (additionalContext) or block — CANNOT modify prompt
PreToolUse: can redact via updatedInput, deny, or warn
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from core.redactor import Redactor, redact_nested

_CONFIG_PATH = Path.home() / ".claude" / "preflight.yaml"
_DEFAULT_LOG_PATH = Path.home() / ".claude" / "preflight.log"


def _load_config() -> dict:
    if _CONFIG_PATH.exists():
        try:
            return yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}
    return {}


def _get_mode(config: dict) -> str:
    env_mode = os.environ.get("PREFLIGHT_MODE")
    if env_mode:
        return env_mode
    return config.get("mode", "default")


def _get_log_path(config: dict) -> Path:
    raw = config.get("log_path", str(_DEFAULT_LOG_PATH))
    return Path(os.path.expanduser(raw))


def _log_findings(findings: list, log_path: Path, event: str) -> None:
    if not findings:
        return
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = []
        for f in findings:
            lines.append(
                f"  {f.pattern_id} ({f.severity}) at offset {f.start}:{f.end} "
                f"[{f.end - f.start} chars]"
            )
        entry = (
            f"[{ts}] [{event}] {len(findings)} finding(s):\n"
            + "\n".join(lines)
            + "\n\n"
        )
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(entry)
    except Exception:
        pass


def _findings_summary(findings: list) -> str:
    categories = {}
    for f in findings:
        categories[f.pattern_id] = categories.get(f.pattern_id, 0) + 1
    parts = [f"{cat}={n}" for cat, n in categories.items()]
    return ", ".join(parts)


def _handle_user_prompt_submit(
    payload: dict, redactor: Redactor, mode: str, log_path: Path
) -> int:
    prompt = payload.get("prompt", "")
    if not isinstance(prompt, str) or not prompt:
        sys.stdout.write("{}")
        return 0

    result = redactor.redact(prompt)
    _log_findings(result.findings, log_path, "UserPromptSubmit")

    if not result.findings:
        sys.stdout.write("{}")
        return 0

    has_critical = any(f.severity == "critical" for f in result.findings)
    summary = _findings_summary(result.findings)

    if mode == "strict" and has_critical:
        sys.stderr.write(
            f"[preflight-hook] BLOCKED: {len(result.findings)} finding(s) "
            f"({summary}). See {log_path}\n"
        )
        return 2

    context = (
        f"[preflight-check] WARNING: detected {len(result.findings)} "
        f"secret(s)/PII in the prompt ({summary}). "
        f"Consider removing sensitive data before sending."
    )
    output = {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    }
    sys.stdout.write(json.dumps(output))
    return 0


def _handle_pre_tool_use(
    payload: dict, redactor: Redactor, mode: str, log_path: Path
) -> int:
    tool_input = payload.get("tool_input", {})
    tool_name = payload.get("tool_name", "unknown")

    if not tool_input:
        sys.stdout.write("{}")
        return 0

    all_findings: list = []
    updated_input = redact_nested(tool_input, redactor, all_findings)

    _log_findings(all_findings, log_path, f"PreToolUse:{tool_name}")

    if not all_findings:
        sys.stdout.write("{}")
        return 0

    has_critical = any(f.severity == "critical" for f in all_findings)
    summary = _findings_summary(all_findings)

    if mode == "strict" and has_critical:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"[preflight-hook] BLOCKED: {len(all_findings)} "
                    f"finding(s) ({summary}). See {log_path}"
                ),
            }
        }
        sys.stdout.write(json.dumps(output))
        return 0

    if mode == "warn-only":
        context = (
            f"[preflight-check] WARNING: detected {len(all_findings)} "
            f"secret(s)/PII in {tool_name} input ({summary})."
        )
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": context,
            }
        }
        sys.stdout.write(json.dumps(output))
        return 0

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
        }
    }
    sys.stdout.write(json.dumps(output))
    return 0


def main() -> int:
    config = _load_config()
    mode = _get_mode(config)
    log_path = _get_log_path(config)

    raw = sys.stdin.read()

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        if mode == "strict":
            sys.stderr.write(
                "[preflight-hook] invalid JSON input — blocking (strict)\n"
            )
            return 2
        sys.stderr.write("[preflight-hook] invalid JSON input — passing through\n")
        return 0

    try:
        redactor = Redactor.from_default_catalog()
        event = payload.get("hook_event_name", "")

        if event == "UserPromptSubmit":
            return _handle_user_prompt_submit(payload, redactor, mode, log_path)
        elif event == "PreToolUse":
            return _handle_pre_tool_use(payload, redactor, mode, log_path)
        else:
            if "prompt" in payload:
                return _handle_user_prompt_submit(payload, redactor, mode, log_path)
            elif "tool_input" in payload:
                return _handle_pre_tool_use(payload, redactor, mode, log_path)
            sys.stdout.write("{}")
            return 0

    except Exception as exc:
        if mode == "strict":
            sys.stderr.write(
                f"[preflight-hook] error — blocking (strict): {exc}\n"
            )
            return 2
        sys.stderr.write(f"[preflight-hook] error — passing through: {exc}\n")
        return 0
