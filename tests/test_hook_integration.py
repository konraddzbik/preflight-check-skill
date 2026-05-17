"""
Integration tests for the hook layer.

Tests Claude Code hook protocol compliance: exit codes, hookSpecificOutput,
event-specific behavior (UserPromptSubmit vs PreToolUse).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HOOK_SCRIPT = str(Path(__file__).parent.parent / "hook" / "claude_redact_hook.py")


def _run_hook(
    payload: dict | str, mode: str = "default", env_extra: dict | None = None
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PREFLIGHT_MODE"] = mode
    if env_extra:
        env.update(env_extra)

    input_str = json.dumps(payload) if isinstance(payload, dict) else payload

    result = subprocess.run(
        [sys.executable, HOOK_SCRIPT],
        input=input_str,
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    return result.returncode, result.stdout, result.stderr


# --- UserPromptSubmit ---


class TestUserPromptSubmitDefault:
    def test_warns_on_secret(self) -> None:
        code, out, err = _run_hook(
            {"hook_event_name": "UserPromptSubmit", "prompt": "key AKIAIOSFODNN7EXAMPLE"},
            mode="default",
        )
        assert code == 0
        output = json.loads(out)
        hso = output["hookSpecificOutput"]
        assert hso["hookEventName"] == "UserPromptSubmit"
        assert "WARNING" in hso["additionalContext"]
        assert "AWS_ACCESS_KEY" in hso["additionalContext"]

    def test_no_findings_passthrough(self) -> None:
        code, out, err = _run_hook(
            {"hook_event_name": "UserPromptSubmit", "prompt": "hello world"},
            mode="default",
        )
        assert code == 0
        assert json.loads(out) == {}


class TestUserPromptSubmitStrict:
    def test_blocks_critical(self) -> None:
        code, out, err = _run_hook(
            {"hook_event_name": "UserPromptSubmit", "prompt": "key AKIAIOSFODNN7EXAMPLE"},
            mode="strict",
        )
        assert code == 2
        assert "BLOCKED" in err

    def test_allows_non_critical(self) -> None:
        code, out, err = _run_hook(
            {"hook_event_name": "UserPromptSubmit", "prompt": "email test@example.com"},
            mode="strict",
        )
        assert code == 0


class TestUserPromptSubmitWarnOnly:
    def test_warns_but_does_not_block(self) -> None:
        code, out, err = _run_hook(
            {"hook_event_name": "UserPromptSubmit", "prompt": "key AKIAIOSFODNN7EXAMPLE"},
            mode="warn-only",
        )
        assert code == 0
        output = json.loads(out)
        assert "WARNING" in output["hookSpecificOutput"]["additionalContext"]


# --- PreToolUse ---


class TestPreToolUseDefault:
    def test_redacts_via_updated_input(self) -> None:
        code, out, err = _run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"},
            },
            mode="default",
        )
        assert code == 0
        output = json.loads(out)
        hso = output["hookSpecificOutput"]
        assert hso["hookEventName"] == "PreToolUse"
        assert hso["permissionDecision"] == "allow"
        assert "AKIAIOSFODNN7EXAMPLE" not in hso["updatedInput"]["command"]
        assert "[REDACTED_AWS_ACCESS_KEY_" in hso["updatedInput"]["command"]

    def test_no_findings_passthrough(self) -> None:
        code, out, err = _run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
            },
            mode="default",
        )
        assert code == 0
        assert json.loads(out) == {}

    def test_preserves_non_secret_fields(self) -> None:
        code, out, err = _run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": "/tmp/safe.txt",
                    "content": "key AKIAIOSFODNN7EXAMPLE",
                },
            },
            mode="default",
        )
        assert code == 0
        hso = json.loads(out)["hookSpecificOutput"]
        assert hso["updatedInput"]["file_path"] == "/tmp/safe.txt"
        assert "AKIAIOSFODNN7EXAMPLE" not in hso["updatedInput"]["content"]


class TestPreToolUseStrict:
    def test_denies_critical(self) -> None:
        code, out, err = _run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"},
            },
            mode="strict",
        )
        assert code == 0
        hso = json.loads(out)["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert "BLOCKED" in hso["permissionDecisionReason"]


class TestPreToolUseWarnOnly:
    def test_warns_without_modifying(self) -> None:
        code, out, err = _run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"},
            },
            mode="warn-only",
        )
        assert code == 0
        hso = json.loads(out)["hookSpecificOutput"]
        assert "WARNING" in hso.get("additionalContext", "")
        assert "updatedInput" not in hso


# --- Error handling ---


class TestErrorHandling:
    def test_invalid_json_default_mode(self) -> None:
        code, out, err = _run_hook("{{not json}}", mode="default")
        assert code == 0

    def test_invalid_json_strict_mode(self) -> None:
        code, out, err = _run_hook("not json at all", mode="strict")
        assert code == 2
        assert "invalid JSON" in err

    def test_fallback_field_detection(self) -> None:
        """Without hook_event_name, falls back to field-based detection."""
        code, out, err = _run_hook(
            {"prompt": "key AKIAIOSFODNN7EXAMPLE"},
            mode="default",
        )
        assert code == 0
        output = json.loads(out)
        assert "hookSpecificOutput" in output
