"""Guard against version drift across the hand-maintained manifests."""

from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "version not found in pyproject.toml"
    return m.group(1)


def test_all_manifest_versions_match() -> None:
    """pyproject, plugin.json, and both marketplace.json version fields must agree."""
    expected = _pyproject_version()

    plugin = json.loads((_ROOT / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((_ROOT / ".claude-plugin" / "marketplace.json").read_text())

    versions = {
        "pyproject.toml": expected,
        "plugin.json": plugin["version"],
        "marketplace.json:metadata": market["metadata"]["version"],
        "marketplace.json:plugins[0]": market["plugins"][0]["version"],
    }
    mismatches = {k: v for k, v in versions.items() if v != expected}
    assert not mismatches, f"version drift (expected {expected}): {mismatches}"
