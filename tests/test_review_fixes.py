"""Regression tests for the 2026-08 full code+architecture review.

Each test pins a specific bug fixed in that pass; see docs/CODE_REVIEW.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.detectors.gitleaks_wrapper import gitleaks_findings_to_candidates
from core.detectors.validators import validate_pesel, validate_regon
from core.redactor import Redactor, redact_nested

_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def redactor() -> Redactor:
    return Redactor.from_default_catalog()


# ── EMAIL ReDoS (blocker) ───────────────────────────────────────────────


class TestEmailReDoS:
    def test_pathological_input_is_linear(self, redactor: Redactor) -> None:
        """A long dotted run used to be O(n^2) and hung the hook. Must be fast."""
        pathological = "a@" + "a." * 20000  # ~39 KB, no valid TLD tail
        start = time.perf_counter()
        result = redactor.redact(pathological)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"EMAIL regex took {elapsed:.2f}s — ReDoS regression"
        assert not result.findings

    @pytest.mark.parametrize(
        "email",
        ["user@corp.com", "a.b+x@mail.corp.co.uk", "x@sub.domain.io", "name@a.io"],
    )
    def test_valid_emails_still_matched(self, redactor: Redactor, email: str) -> None:
        result = redactor.redact(f"contact {email} please")
        assert email not in result.text
        assert "[REDACTED_EMAIL_" in result.text


# ── New secret-format coverage (should-fix) ─────────────────────────────


class TestExpandedCoverage:
    @pytest.mark.parametrize(
        "secret",
        [
            "ASIAY34FZKBOKMUTVV7A",  # AWS STS temporary credential
            "github_pat_11ABCDEFG0abcdefghijkl_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789A",
            "xapp-1-A012345678-1234567890-abcdefabcdef",  # Slack app-level
            "sk-svcacct-" + "a" * 45,  # OpenAI service-account key
        ],
    )
    def test_newly_covered_cloud_keys(self, redactor: Redactor, secret: str) -> None:
        result = redactor.redact(f"key {secret} end")
        assert secret not in result.text

    def test_lowercase_iban_matched(self, redactor: Redactor) -> None:
        # validator already upper-cases, so lowercase IBANs should validate + redact
        iban = "pl27114020040000300201355387"
        result = redactor.redact(f"iban {iban}")
        assert iban not in result.text


# ── gitleaks occurrence-mismatch leak (blocker) ─────────────────────────


class TestGitleaksLeakFix:
    def test_all_occurrences_redacted(self) -> None:
        """A secret gitleaks flags must be redacted at EVERY occurrence, even if
        an identical benign-looking copy appears earlier."""
        secret = "AKIAEXAMPLEKEY0000000"
        text = f"sample {secret} in docs; real key: {secret}"
        raw = [{"RuleID": "aws-access-key", "Match": secret}]
        findings = gitleaks_findings_to_candidates(text, raw, lambda c, v: "[X]")
        expected = {text.index(secret), text.index(secret, len(secret) + 8)}
        assert len(findings) == 2
        assert {f.start for f in findings} == expected

    def test_prefers_secret_field_over_match(self) -> None:
        """When gitleaks reports Match with surrounding context, only the Secret
        substring should be redacted."""
        text = 'aws_key = "AKIAEXAMPLEKEY0000000"'
        raw = [
            {
                "RuleID": "aws-access-key",
                "Match": 'aws_key = "AKIAEXAMPLEKEY0000000"',
                "Secret": "AKIAEXAMPLEKEY0000000",
            }
        ]
        findings = gitleaks_findings_to_candidates(text, raw, lambda c, v: "[X]")
        assert len(findings) == 1
        assert findings[0].value == "AKIAEXAMPLEKEY0000000"

    def test_rule_id_normalized_to_underscores(self) -> None:
        raw = [{"RuleID": "aws-access-key", "Match": "AKIAEXAMPLEKEY0000000"}]
        findings = gitleaks_findings_to_candidates(
            "x AKIAEXAMPLEKEY0000000", raw, lambda c, v: "[X]"
        )
        assert findings[0].pattern_id == "AWS_ACCESS_KEY"


# ── validator false-positive cleanups (nice-to-have) ────────────────────


class TestValidatorHardening:
    def test_regon_all_zeros_rejected(self) -> None:
        assert validate_regon("000000000") is False
        assert validate_regon("00000000000000") is False

    def test_unicode_digits_rejected(self) -> None:
        # Arabic-Indic digits that int() would accept must not pass as a PESEL
        assert validate_pesel("٩٩١٢٣١٧٥٣١٣") is False


# ── nested redaction (shared helper) ────────────────────────────────────


class TestRedactNested:
    def test_dict_and_list_redacted(self, redactor: Redactor) -> None:
        findings: list = []
        payload = {
            "command": "deploy",
            "env": {"K": "AKIAIOSFODNN7EXAMPLE"},
            "args": ["ok", "99123175313"],
        }
        out = redact_nested(payload, redactor, findings)
        assert "AKIAIOSFODNN7EXAMPLE" not in str(out)
        assert "99123175313" not in str(out)
        assert len(findings) >= 2

    def test_depth_cap_returns_value(self, redactor: Redactor) -> None:
        # Beyond the cap the value is returned unchanged rather than recursing.
        deep: dict = {"v": "AKIAIOSFODNN7EXAMPLE"}
        for _ in range(60):
            deep = {"n": deep}
        findings: list = []
        out = redact_nested(deep, redactor, findings)  # must not raise RecursionError
        assert isinstance(out, dict)


# ── CLI scan --json redacts nested tool_input (should-fix) ──────────────


class TestScanJsonNested:
    def test_dict_tool_input_redacted(self) -> None:
        """`scan --json` used to only touch top-level strings, so a dict
        tool_input (the real hook shape) passed through un-redacted."""
        payload = {
            "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE; PESEL 99123175313"}
        }
        proc = subprocess.run(
            [sys.executable, "-m", "core", "scan", "--json"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            cwd=_ROOT,
        )
        assert proc.returncode == 0
        assert "AKIAIOSFODNN7EXAMPLE" not in proc.stdout
        assert "99123175313" not in proc.stdout
        assert "REDACTED" in proc.stdout
