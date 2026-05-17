"""Tests for the PlaceholderRegistry."""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path

from core.placeholders import PlaceholderRegistry


class TestBasicMapping:
    def test_stable_mapping(self) -> None:
        reg = PlaceholderRegistry()
        p1 = reg.get_placeholder("PESEL", "44051401359")
        p2 = reg.get_placeholder("PESEL", "44051401359")
        assert p1 == p2

    def test_different_values_get_different_placeholders(self) -> None:
        reg = PlaceholderRegistry()
        p1 = reg.get_placeholder("EMAIL", "a@b.com")
        p2 = reg.get_placeholder("EMAIL", "c@d.com")
        assert p1 != p2

    def test_placeholder_format(self) -> None:
        reg = PlaceholderRegistry()
        p = reg.get_placeholder("PESEL", "44051401359")
        assert p == "[REDACTED_PESEL_001]"

    def test_counter_increments(self) -> None:
        reg = PlaceholderRegistry()
        reg.get_placeholder("EMAIL", "a@b.com")
        p2 = reg.get_placeholder("EMAIL", "c@d.com")
        assert p2 == "[REDACTED_EMAIL_002]"


class TestReverseMap:
    def test_reverse_map(self) -> None:
        reg = PlaceholderRegistry()
        reg.get_placeholder("PESEL", "44051401359")
        rmap = reg.reverse_map()
        assert "[REDACTED_PESEL_001]" in rmap
        cat, val = rmap["[REDACTED_PESEL_001]"]
        assert cat == "PESEL"
        assert val == "44051401359"


class TestClear:
    def test_clear_wipes_state(self) -> None:
        reg = PlaceholderRegistry()
        reg.get_placeholder("PESEL", "44051401359")
        reg.clear()
        assert reg.reverse_map() == {}

    def test_clear_deletes_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        reg = PlaceholderRegistry(state_path=path)
        reg.get_placeholder("PESEL", "44051401359")
        assert path.exists()
        reg.clear()
        assert not path.exists()


class TestPersistence:
    def test_save_and_load(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        try:
            reg1 = PlaceholderRegistry(state_path=path)
            p1 = reg1.get_placeholder("PESEL", "44051401359")

            reg2 = PlaceholderRegistry(state_path=path)
            p2 = reg2.get_placeholder("PESEL", "44051401359")
            assert p1 == p2
        finally:
            path.unlink(missing_ok=True)


class TestThreadSafety:
    def test_concurrent_access(self) -> None:
        reg = PlaceholderRegistry()
        results: list[str] = []
        errors: list[Exception] = []

        def worker(i: int) -> None:
            try:
                p = reg.get_placeholder("EMAIL", f"user{i}@test.com")
                results.append(p)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 50
        assert len(set(results)) == 50
