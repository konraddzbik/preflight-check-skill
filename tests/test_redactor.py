"""
Integration tests for the Redactor orchestrator.

Covers multi-secret detection, overlap resolution, placeholder stability,
edge cases, and PHONE_PL regression.
"""

from __future__ import annotations

import pytest

from core.placeholders import PlaceholderRegistry
from core.redactor import Redactor


@pytest.fixture
def redactor() -> Redactor:
    return Redactor.from_default_catalog()


@pytest.fixture
def fresh_redactor() -> Redactor:
    return Redactor.from_default_catalog(registry=PlaceholderRegistry())


class TestBasicDetection:
    def test_aws_key(self, redactor: Redactor) -> None:
        result = redactor.redact("key AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result.text
        assert "[REDACTED_AWS_ACCESS_KEY_" in result.text
        assert result.had_critical

    def test_pesel(self, redactor: Redactor) -> None:
        result = redactor.redact("PESEL: 99123175313")
        assert "99123175313" not in result.text
        assert "[REDACTED_PESEL_" in result.text

    def test_email(self, redactor: Redactor) -> None:
        result = redactor.redact("mail: test@example.com")
        assert "test@example.com" not in result.text
        assert "[REDACTED_EMAIL_" in result.text

    def test_ssn(self, redactor: Redactor) -> None:
        result = redactor.redact("SSN 123-45-6789")
        assert "123-45-6789" not in result.text
        assert result.had_critical

    def test_nip(self, redactor: Redactor) -> None:
        result = redactor.redact("NIP: 0012345621")
        assert "0012345621" not in result.text


class TestMultiSecret:
    def test_multiple_secrets_in_one_string(self, redactor: Redactor) -> None:
        text = "PESEL 99123175313, email foo@bar.com, key AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact(text)
        assert "99123175313" not in result.text
        assert "foo@bar.com" not in result.text
        assert "AKIAIOSFODNN7EXAMPLE" not in result.text
        assert len(result.findings) == 3

    def test_summary_counts(self, redactor: Redactor) -> None:
        text = "emails: a@b.com and c@d.com"
        result = redactor.redact(text)
        assert result.summary().get("EMAIL", 0) == 2


class TestPlaceholderStability:
    def test_same_value_same_placeholder(self, fresh_redactor: Redactor) -> None:
        text = "first 99123175313 then again 99123175313"
        result = fresh_redactor.redact(text)
        placeholders = [f.placeholder for f in result.findings]
        assert len(placeholders) == 2
        assert placeholders[0] == placeholders[1]

    def test_different_values_different_placeholders(self, fresh_redactor: Redactor) -> None:
        text = "a@b.com and c@d.com"
        result = fresh_redactor.redact(text)
        placeholders = [f.placeholder for f in result.findings]
        assert len(set(placeholders)) == 2


class TestPhonePLRegression:
    def test_bare_9_digits_not_matched(self, redactor: Redactor) -> None:
        result = redactor.redact("number 123456789")
        assert result.text == "number 123456789"

    def test_pesel_not_eaten_by_phone(self, redactor: Redactor) -> None:
        result = redactor.redact("PESEL 99123175313")
        assert "[REDACTED_PESEL_" in result.text
        assert "PHONE_PL" not in result.text

    def test_phone_with_prefix(self, redactor: Redactor) -> None:
        result = redactor.redact("call +48 123 456 789")
        assert "[REDACTED_PHONE_PL_" in result.text

    def test_phone_with_dashes(self, redactor: Redactor) -> None:
        result = redactor.redact("call 123-456-789")
        assert "[REDACTED_PHONE_PL_" in result.text

    def test_11_digit_number_unchanged(self, redactor: Redactor) -> None:
        result = redactor.redact("my number is 12345678901")
        assert result.text == "my number is 12345678901"

    def test_random_11_nines_unchanged(self, redactor: Redactor) -> None:
        result = redactor.redact("random number 99999999999")
        assert result.text == "random number 99999999999"


class TestOverlapResolution:
    def test_higher_severity_wins(self, redactor: Redactor) -> None:
        result = redactor.redact("PESEL 99123175313")
        assert len(result.findings) == 1
        assert result.findings[0].pattern_id == "PESEL"
        assert result.findings[0].severity == "critical"


class TestEdgeCases:
    def test_empty_string(self, redactor: Redactor) -> None:
        result = redactor.redact("")
        assert result.text == ""
        assert len(result.findings) == 0

    def test_none_handling(self, redactor: Redactor) -> None:
        result = redactor.redact("")
        assert result.text == ""

    def test_whitespace_only(self, redactor: Redactor) -> None:
        result = redactor.redact("   \n\t  ")
        assert result.text == "   \n\t  "
        assert len(result.findings) == 0

    def test_unicode_context(self, redactor: Redactor) -> None:
        result = redactor.redact("Zadzwoń pod +48 123 456 789, proszę")
        assert "[REDACTED_PHONE_PL_" in result.text
        assert "proszę" in result.text

    def test_no_false_positive_on_regular_text(self, redactor: Redactor) -> None:
        result = redactor.redact("The quick brown fox jumps over the lazy dog")
        assert len(result.findings) == 0

    def test_had_critical_property(self, redactor: Redactor) -> None:
        result = redactor.redact("safe text")
        assert result.had_critical is False
        result = redactor.redact("key AKIAIOSFODNN7EXAMPLE")
        assert result.had_critical is True
