"""
Placeholder generation and stable value mapping.

When redacting, we want the same secret to map to the same placeholder
within a session — so Claude can still reason coherently about "the AWS
key" or "the user's email" without seeing the actual value.

The mapping is stored locally and never sent anywhere.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path


class PlaceholderRegistry:
    """
    Thread-safe registry mapping (category, value) -> placeholder.

    Placeholders look like: [REDACTED_PESEL_001], [REDACTED_AWS_ACCESS_KEY_002]

    Can optionally persist to disk so placeholders remain stable across
    multiple invocations within the same session.
    """

    def __init__(self, state_path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._state_path = state_path
        # Map: category -> { value -> placeholder }
        self._mapping: dict[str, dict[str, str]] = {}
        # Map: category -> next counter
        self._counters: dict[str, int] = {}
        if state_path and state_path.exists():
            self._load()

    def get_placeholder(self, category: str, value: str) -> str:
        """Return a stable placeholder for this (category, value) pair."""
        with self._lock:
            if category not in self._mapping:
                self._mapping[category] = {}
                self._counters[category] = 0

            if value in self._mapping[category]:
                return self._mapping[category][value]

            self._counters[category] += 1
            placeholder = f"[REDACTED_{category}_{self._counters[category]:03d}]"
            self._mapping[category][value] = placeholder
            if self._state_path:
                self._save()
            return placeholder

    def reverse_map(self) -> dict[str, tuple[str, str]]:
        """
        Build placeholder -> (category, original_value) map.

        Useful for un-redacting in trusted local contexts (e.g., a CLI
        that displays the original after user confirms).
        """
        with self._lock:
            return {
                placeholder: (category, value)
                for category, items in self._mapping.items()
                for value, placeholder in items.items()
            }

    def clear(self) -> None:
        """Wipe the registry (e.g., at end of session)."""
        with self._lock:
            self._mapping.clear()
            self._counters.clear()
            if self._state_path and self._state_path.exists():
                self._state_path.unlink()

    def _load(self) -> None:
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._mapping = data.get("mapping", {})
            self._counters = data.get("counters", {})
        except (json.JSONDecodeError, OSError):
            # Corrupt or missing state — start fresh, do not crash
            self._mapping = {}
            self._counters = {}

    def _save(self) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"mapping": self._mapping, "counters": self._counters}
            self._state_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            # Restrict permissions — this file contains the original secrets
            self._state_path.chmod(0o600)
        except OSError:
            # If we can't persist, keep running with in-memory state
            pass
