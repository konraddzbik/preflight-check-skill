"""
Validator tests — checksum logic against synthetic but valid vectors.

NOTE: All values are synthetic. Never commit real PII.
"""

from __future__ import annotations

import pytest

from core.detectors.validators import (
    validate_iban,
    validate_luhn,
    validate_nip,
    validate_pesel,
    validate_regon,
)


class TestPesel:
    @pytest.mark.parametrize("value", [
        "99123175313",   # 1999-12-31, serial 7531 (synthetic)
        "05312248267",   # 2005-11-22, month offset 20 (synthetic)
        "00410100000",   # 2100 birth, month offset 40 (no real person)
        "85061578907",   # 1985-06-15, serial 7890 (synthetic)
    ])
    def test_valid(self, value: str) -> None:
        assert validate_pesel(value) is True

    @pytest.mark.parametrize("value,reason", [
        ("12345678901", "random digits"),
        ("99999999999", "all nines"),
        ("99123175314", "off-by-one checksum"),
        ("99133175313", "month 13 invalid"),
        ("99120075313", "day 00 invalid"),
        ("99123275313", "day 32 invalid"),
        ("9912317531", "too short"),
        ("991231753130", "too long"),
        ("", "empty"),
        ("abc", "non-digit"),
        ("00000000000", "all zeros"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_pesel(value) is False, reason


class TestNip:
    @pytest.mark.parametrize("value", [
        "0012345621",
        "001-234-56-21",
        "0011111157",
    ])
    def test_valid(self, value: str) -> None:
        assert validate_nip(value) is True

    @pytest.mark.parametrize("value,reason", [
        ("1234567890", "random digits"),
        ("0000000000", "all zeros"),
        ("0012345620", "off-by-one checksum"),
        ("001234562", "too short"),
        ("00123456211", "too long"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_nip(value) is False, reason


class TestRegon:
    def test_valid_9_digit(self) -> None:
        assert validate_regon("100000014") is True

    def test_valid_14_digit(self) -> None:
        assert validate_regon("10000001400014") is True

    def test_invalid_9_digit(self) -> None:
        assert validate_regon("123456789") is False

    def test_invalid_14_digit_bad_prefix(self) -> None:
        assert validate_regon("10000001500014") is False

    def test_invalid_length(self) -> None:
        assert validate_regon("12345") is False

    def test_empty(self) -> None:
        assert validate_regon("") is False


class TestIban:
    @pytest.mark.parametrize("value", [
        "PL74000000000000000000000001",
        "PL74 0000 0000 0000 0000 0000 0001",
        "DE89370400440532013000",
        "GB29NWBK60161331926819",
        "FR7630006000011234567890189",
    ])
    def test_valid(self, value: str) -> None:
        assert validate_iban(value) is True

    @pytest.mark.parametrize("value,reason", [
        ("PL00000000000000000000000001", "bad check digits"),
        ("INVALID", "non-IBAN string"),
        ("PL61", "too short"),
        ("AB", "way too short"),
        ("", "empty"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_iban(value) is False, reason


class TestLuhn:
    @pytest.mark.parametrize("value", [
        "4111111111111111",
        "4111 1111 1111 1111",
        "79927398713",         # 11-digit Luhn test but under min length
        "4111111111111111",    # classic test number
        "5500000000000004",    # MC test
    ])
    def test_valid(self, value: str) -> None:
        from core.detectors.validators import _digits_only
        digits = _digits_only(value)
        if 13 <= len(digits) <= 19:
            assert validate_luhn(value) is True

    @pytest.mark.parametrize("value,reason", [
        ("4111111111111112", "off-by-one"),
        ("4111", "too short"),
        ("", "empty"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_luhn(value) is False, reason
