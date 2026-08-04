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


def gitleaks_findings_to_candidates(
    text: str,
    raw_findings: list[dict],
    get_placeholder: Callable[[str, str], str],
) -> list:
    """Convert raw gitleaks findings to Finding-compatible tuples.

    Returns a list of dicts with keys matching Finding fields, ready for
    the Redactor to create Finding objects.
    """
    from core.redactor import Finding

    candidates = []
    search_start = 0
    for item in raw_findings:
        match_text = item.get("Match", item.get("match", ""))
        rule_id = item.get("RuleID", item.get("ruleID", "GITLEAKS"))

        if not match_text:
            continue

        start = text.find(match_text, search_start)
        if start == -1:
            start = text.find(match_text)
            if start == -1:
                continue

        placeholder = get_placeholder(rule_id.upper(), match_text)
        candidates.append(
            Finding(
                pattern_id=rule_id.upper(),
                category_group="cloud_keys",
                severity="critical",
                start=start,
                end=start + len(match_text),
                value=match_text,
                placeholder=placeholder,
            )
        )
        search_start = start + len(match_text)

    return candidates
