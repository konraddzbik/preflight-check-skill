"""
Redactor orchestrator.

Loads the pattern catalog, runs all enabled detectors against input text,
deduplicates overlapping matches (highest severity wins), and applies
stable placeholders from the registry.

Usage:
    from core.redactor import Redactor

    redactor = Redactor.from_default_catalog()
    result = redactor.redact("My PESEL is 44051401359")
    print(result.text)     # "My PESEL is [REDACTED_PESEL_001]"
    print(result.findings) # [Finding(category='PESEL', ...)]
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.detectors.gitleaks_wrapper import gitleaks_findings_to_candidates, run_gitleaks
from core.detectors.validators import VALIDATORS
from core.placeholders import PlaceholderRegistry

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class Finding:
    """A single detected secret/PII match."""

    pattern_id: str
    category_group: str   # cloud_keys, polish_pii, eu_pii, us_pii
    severity: str
    start: int
    end: int
    value: str
    placeholder: str


@dataclass
class RedactionResult:
    """Result of a redact() call."""

    text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def had_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    def summary(self) -> dict[str, int]:
        """Count findings by category for logging/reporting."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.pattern_id] = counts.get(f.pattern_id, 0) + 1
        return counts


class Redactor:
    """Orchestrates pattern matching + validation + placeholder substitution."""

    def __init__(
        self,
        catalog: dict[str, Any],
        registry: PlaceholderRegistry | None = None,
    ) -> None:
        self.catalog = catalog
        self.registry = registry or PlaceholderRegistry()
        self._compiled = self._compile_patterns()

    @classmethod
    def from_default_catalog(
        cls, registry: PlaceholderRegistry | None = None
    ) -> Redactor:
        """Load the bundled catalog.yaml."""
        catalog_path = Path(__file__).parent / "catalog.yaml"
        return cls.from_catalog_file(catalog_path, registry=registry)

    @classmethod
    def from_catalog_file(
        cls, path: Path, registry: PlaceholderRegistry | None = None
    ) -> Redactor:
        catalog = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(catalog=catalog, registry=registry)

    def _compile_patterns(self) -> list[dict[str, Any]]:
        """Compile all enabled patterns from the catalog."""
        compiled: list[dict[str, Any]] = []
        for group_name in ("cloud_keys", "polish_pii", "eu_pii", "us_pii"):
            group = self.catalog.get(group_name) or []
            for entry in group:
                if not entry.get("enabled", True):
                    continue
                try:
                    regex = re.compile(entry["pattern"])
                except re.error as e:
                    # Bad pattern in catalog — skip rather than crash everything
                    print(f"[redactor] Bad pattern {entry['id']}: {e}")
                    continue
                validator_name = entry.get("validator")
                validator = VALIDATORS.get(validator_name) if validator_name else None
                compiled.append(
                    {
                        "id": entry["id"],
                        "group": group_name,
                        "regex": regex,
                        "validator": validator,
                        "severity": entry.get("severity", "medium"),
                    }
                )
        return compiled

    def redact(self, text: str) -> RedactionResult:
        """Detect all secrets/PII and return redacted text + findings."""
        if not text:
            return RedactionResult(text=text or "")

        with ThreadPoolExecutor(max_workers=2) as pool:
            regex_future = pool.submit(self._run_regex_detection, text)
            gitleaks_future = pool.submit(self._run_gitleaks_detection, text)
            candidates = regex_future.result()
            candidates.extend(gitleaks_future.result(timeout=10))

        chosen = self._resolve_overlaps(candidates)
        chosen_sorted = sorted(chosen, key=lambda f: f.start, reverse=True)
        out = text
        for f in chosen_sorted:
            out = out[: f.start] + f.placeholder + out[f.end :]

        return RedactionResult(text=out, findings=list(reversed(chosen_sorted)))

    def _run_regex_detection(self, text: str) -> list[Finding]:
        candidates: list[Finding] = []
        for pat in self._compiled:
            for match in pat["regex"].finditer(text):
                value = match.group(0)
                validator = pat["validator"]
                if validator is not None and not validator(value):
                    continue
                placeholder = self.registry.get_placeholder(pat["id"], value)
                candidates.append(
                    Finding(
                        pattern_id=pat["id"],
                        category_group=pat["group"],
                        severity=pat["severity"],
                        start=match.start(),
                        end=match.end(),
                        value=value,
                        placeholder=placeholder,
                    )
                )
        return candidates

    def _run_gitleaks_detection(self, text: str) -> list[Finding]:
        try:
            raw = run_gitleaks(text)
            if not raw:
                return []
            return gitleaks_findings_to_candidates(
                text, raw, self.registry.get_placeholder
            )
        except Exception:
            return []

    @staticmethod
    def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
        """Remove overlapping matches, keeping highest severity / longest span."""
        if not findings:
            return []
        sorted_by_priority = sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -(f.end - f.start)),
        )
        accepted: list[Finding] = []
        for f in sorted_by_priority:
            overlaps = any(
                not (f.end <= a.start or f.start >= a.end) for a in accepted
            )
            if not overlaps:
                accepted.append(f)
        return sorted(accepted, key=lambda f: f.start)
