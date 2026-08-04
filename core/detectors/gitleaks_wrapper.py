"""
Gitleaks subprocess wrapper.

Runs gitleaks against text input to detect cloud secrets and API keys.
Falls back gracefully if gitleaks is not installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

_RULES_PATH = Path(__file__).parent.parent / "gitleaks.toml"
_TIMEOUT_SECONDS = 5


def check_gitleaks_available() -> bool:
    return shutil.which("gitleaks") is not None


def get_install_instructions() -> str:
    return (
        "gitleaks is not installed. Install it for enhanced secret detection:\n"
        "  macOS:   brew install gitleaks\n"
        "  Go:      go install github.com/gitleaks/gitleaks/v8@latest\n"
        "  Binary:  https://github.com/gitleaks/gitleaks/releases"
    )


def run_gitleaks(
    text: str,
    rules_path: Path | None = None,
) -> list[dict]:
    """Run gitleaks against text, return raw findings as dicts.

    Each dict has keys: rule_id, description, match, start_line, start_column,
    end_line, end_column.  The caller (Redactor) converts these to Finding objects
    with correct character offsets.

    Returns an empty list if gitleaks is unavailable or times out.
    """
    if not check_gitleaks_available():
        return []

    rules = rules_path or _RULES_PATH
    tmpdir = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="preflight_")
        tmpfile = os.path.join(tmpdir, "input.txt")
        with open(tmpfile, "w", encoding="utf-8") as f:
            f.write(text)

        cmd = [
            "gitleaks",
            "detect",
            "--source", tmpdir,
            "--no-git",
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--config", str(rules),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )

        if not result.stdout or not result.stdout.strip():
            return []

        try:
            findings = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        if not isinstance(findings, list):
            return []

        return findings

    except subprocess.TimeoutExpired:
        return []
    except OSError:
        return []
    finally:
        if tmpdir:
            try:
                import shutil as _shutil
                _shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass


def _normalize_rule_id(rule_id: str) -> str:
    """gitleaks rule ids use hyphens (aws-access-key); placeholders use
    underscores to match the regex-catalog ids (AWS_ACCESS_KEY)."""
    return rule_id.upper().replace("-", "_")


def gitleaks_findings_to_candidates(
    text: str,
    raw_findings: list[dict],
    get_placeholder: Callable[[str, str], str],
) -> list:
    """Convert raw gitleaks findings to Finding objects.

    Redacts **every** occurrence of each flagged secret, not just the first.
    gitleaks reports the secret value but not a reliable character offset into
    our input, and ``str.find`` on the first occurrence could redact a benign
    earlier copy while leaving the real secret in place. Over-redacting an
    identical benign string is the safe failure mode for a secrets tool;
    under-redacting (leaking) is not.

    Prefers the ``Secret`` field (the captured secret) over ``Match`` (which may
    include surrounding rule context), so only the secret itself is replaced.
    """
    from core.redactor import Finding

    # Deduplicate by secret literal (a secret flagged by two rules, or reported
    # twice, should be handled once); keep the first rule id seen for each.
    secrets: dict[str, str] = {}
    for item in raw_findings:
        secret = item.get("Secret") or item.get("Match") or item.get("match", "")
        rule_id = item.get("RuleID", item.get("ruleID", "GITLEAKS"))
        if secret:
            secrets.setdefault(secret, rule_id)

    candidates = []
    seen_spans: set[tuple[int, int]] = set()
    for secret, rule_id in secrets.items():
        norm_id = _normalize_rule_id(rule_id)
        placeholder = get_placeholder(norm_id, secret)
        start = 0
        while True:
            idx = text.find(secret, start)
            if idx == -1:
                break
            span = (idx, idx + len(secret))
            if span not in seen_spans:
                seen_spans.add(span)
                candidates.append(
                    Finding(
                        pattern_id=norm_id,
                        category_group="cloud_keys",
                        severity="critical",
                        start=idx,
                        end=idx + len(secret),
                        value=secret,
                        placeholder=placeholder,
                    )
                )
            start = idx + len(secret)

    return candidates
