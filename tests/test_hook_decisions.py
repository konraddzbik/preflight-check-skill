"""Unit tests for the hook decision logic.

Calls the handlers directly (no subprocess) so the strict/warn/default/pass-through
branches are actually covered, per the review's testability recommendation.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from core.hook_handler import _handle_pre_tool_use, _handle_user_prompt_submit
from core.redactor import Redactor

CRITICAL_PROMPT = "deploy with AKIAIOSFODNN7EXAMPLE now"


@pytest.fixture
def redactor() -> Redactor:
    return Redactor.from_default_catalog()


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "preflight.log"


def _run(handler, payload, redactor, mode, log_path):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = handler(payload, redactor, mode, log_path)
    out = buf.getvalue()
    return code, (json.loads(out) if out.strip() else {})


class TestUserPromptSubmit:
    def test_strict_blocks_critical(self, redactor, log_path):
        code, _ = _run(
            _handle_user_prompt_submit, {"prompt": CRITICAL_PROMPT}, redactor, "strict", log_path
        )
        assert code == 2  # blocked

    def test_default_warns(self, redactor, log_path):
        code, out = _run(
            _handle_user_prompt_submit, {"prompt": CRITICAL_PROMPT}, redactor, "default", log_path
        )
        assert code == 0
        assert "WARNING" in out["hookSpecificOutput"]["additionalContext"]

    def test_clean_prompt_passes(self, redactor, log_path):
        code, out = _run(
            _handle_user_prompt_submit, {"prompt": "just say hi"}, redactor, "default", log_path
        )
        assert code == 0
        assert out == {}


class TestPreToolUse:
    def test_default_redacts_in_place(self, redactor, log_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"}}
        code, out = _run(_handle_pre_tool_use, payload, redactor, "default", log_path)
        assert code == 0
        hso = out["hookSpecificOutput"]
        assert hso["permissionDecision"] == "allow"
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(hso["updatedInput"])

    def test_strict_denies_critical(self, redactor, log_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"}}
        code, out = _run(_handle_pre_tool_use, payload, redactor, "strict", log_path)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_warn_only_does_not_modify(self, redactor, log_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"}}
        code, out = _run(_handle_pre_tool_use, payload, redactor, "warn-only", log_path)
        hso = out["hookSpecificOutput"]
        assert "updatedInput" not in hso
        assert "WARNING" in hso["additionalContext"]

    def test_clean_input_passes(self, redactor, log_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": "echo hello"}}
        code, out = _run(_handle_pre_tool_use, payload, redactor, "default", log_path)
        assert out == {}

    def test_log_records_offsets_not_values(self, redactor, log_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"}}
        _run(_handle_pre_tool_use, payload, redactor, "default", log_path)
        logged = log_path.read_text()
        assert "AKIAIOSFODNN7EXAMPLE" not in logged  # value never hits disk
        assert "offset" in logged
