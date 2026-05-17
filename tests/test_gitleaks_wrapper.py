"""
Tests for the gitleaks wrapper.

Uses mocks to test without requiring gitleaks binary.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from core.detectors.gitleaks_wrapper import (
    check_gitleaks_available,
    get_install_instructions,
    gitleaks_findings_to_candidates,
    run_gitleaks,
)


class TestAvailabilityCheck:
    @patch("core.detectors.gitleaks_wrapper.shutil.which", return_value="/usr/local/bin/gitleaks")
    def test_available(self, mock_which: MagicMock) -> None:
        assert check_gitleaks_available() is True

    @patch("core.detectors.gitleaks_wrapper.shutil.which", return_value=None)
    def test_unavailable(self, mock_which: MagicMock) -> None:
        assert check_gitleaks_available() is False


class TestInstallInstructions:
    def test_contains_brew(self) -> None:
        instructions = get_install_instructions()
        assert "brew install gitleaks" in instructions

    def test_contains_go_install(self) -> None:
        instructions = get_install_instructions()
        assert "go install" in instructions


class TestRunGitleaks:
    @patch("core.detectors.gitleaks_wrapper.check_gitleaks_available", return_value=False)
    def test_returns_empty_when_unavailable(self, mock_avail: MagicMock) -> None:
        assert run_gitleaks("some text") == []

    @patch("core.detectors.gitleaks_wrapper.check_gitleaks_available", return_value=True)
    @patch("core.detectors.gitleaks_wrapper.subprocess.run")
    def test_parses_json_output(self, mock_run: MagicMock, mock_avail: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            stdout=json.dumps([
                {"RuleID": "aws-access-key", "Match": "AKIAIOSFODNN7EXAMPLE", "Description": "AWS"}
            ]),
            stderr="",
            returncode=1,
        )
        results = run_gitleaks("key AKIAIOSFODNN7EXAMPLE")
        assert len(results) == 1
        assert results[0]["RuleID"] == "aws-access-key"

    @patch("core.detectors.gitleaks_wrapper.check_gitleaks_available", return_value=True)
    @patch("core.detectors.gitleaks_wrapper.subprocess.run")
    def test_empty_output(self, mock_run: MagicMock, mock_avail: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        assert run_gitleaks("clean text") == []

    @patch("core.detectors.gitleaks_wrapper.check_gitleaks_available", return_value=True)
    @patch("core.detectors.gitleaks_wrapper.subprocess.run")
    def test_timeout_returns_empty(self, mock_run: MagicMock, mock_avail: MagicMock) -> None:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="gitleaks", timeout=5)
        assert run_gitleaks("text") == []

    @patch("core.detectors.gitleaks_wrapper.check_gitleaks_available", return_value=True)
    @patch("core.detectors.gitleaks_wrapper.subprocess.run")
    def test_invalid_json_returns_empty(self, mock_run: MagicMock, mock_avail: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="not json", stderr="", returncode=1)
        assert run_gitleaks("text") == []


class TestFindingsConversion:
    def test_converts_to_finding_objects(self) -> None:
        text = "my key AKIAIOSFODNN7EXAMPLE here"
        raw = [{"RuleID": "aws-access-key", "Match": "AKIAIOSFODNN7EXAMPLE", "Description": "AWS"}]

        counter = {"n": 0}
        def mock_placeholder(cat: str, val: str) -> str:
            counter["n"] += 1
            return f"[REDACTED_{cat}_{counter['n']:03d}]"

        findings = gitleaks_findings_to_candidates(text, raw, mock_placeholder)
        assert len(findings) == 1
        assert findings[0].pattern_id == "AWS-ACCESS-KEY"
        assert findings[0].start == 7
        assert findings[0].end == 27

    def test_match_not_found_in_text_skipped(self) -> None:
        raw = [{"RuleID": "test", "Match": "NOT_IN_TEXT"}]
        findings = gitleaks_findings_to_candidates("other text", raw, lambda c, v: "[X]")
        assert len(findings) == 0
