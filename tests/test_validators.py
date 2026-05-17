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
        "44051401359",   # 1944 birth
        "02070803628",   # 2002 birth (month offset 20)
        "00410100000",   # 2100 birth (month offset 40)
        "85010100005",   # 1985 birth
    ])
    def test_valid(self, value: str) -> None:
        assert validate_pesel(value) is True

    @pytest.mark.parametrize("value,reason", [
        ("12345678901", "random digits"),
        ("99999999999", "all nines"),
        ("44051401358", "off-by-one checksum"),
        ("44131401359", "month 13 invalid"),
        ("44050001359", "day 00 invalid"),
        ("44053201359", "day 32 invalid"),
        ("4405140135", "too short"),
        ("440514013590", "too long"),
        ("", "empty"),
        ("abc", "non-digit"),
        ("00000000000", "all zeros"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_pesel(value) is False, reason


class TestNip:
    @pytest.mark.parametrize("value", [
        "5260250274",
        "526-025-02-74",
        "7680002466",
    ])
    def test_valid(self, value: str) -> None:
        assert validate_nip(value) is True

    @pytest.mark.parametrize("value,reason", [
        ("1234567890", "random digits"),
        ("0000000000", "all zeros"),
        ("5260250273", "off-by-one checksum"),
        ("526025027", "too short"),
        ("52602502741", "too long"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_nip(value) is False, reason


class TestRegon:
    def test_valid_9_digit(self) -> None:
        assert validate_regon("123456785") is True

    def test_valid_14_digit(self) -> None:
        assert validate_regon("12345678512347") is True

    def test_invalid_9_digit(self) -> None:
        assert validate_regon("123456789") is False

    def test_invalid_14_digit_bad_prefix(self) -> None:
        assert validate_regon("12345678912347") is False

    def test_invalid_length(self) -> None:
        assert validate_regon("12345") is False

    def test_empty(self) -> None:
        assert validate_regon("") is False


class TestIban:
    @pytest.mark.parametrize("value", [
        "PL61109010140000071219812874",
        "PL61 1090 1014 0000 0712 1981 2874",
        "DE89370400440532013000",
        "GB29NWBK60161331926819",
        "FR7630006000011234567890189",
    ])
    def test_valid(self, value: str) -> None:
        assert validate_iban(value) is True

    @pytest.mark.parametrize("value,reason", [
        ("PL00109010140000071219812874", "bad check digits"),
        ("INVALID", "non-IBAN string"),
        ("PL61", "too short"),
        ("AB", "way too short"),
        ("", "empty"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_iban(value) is False, reason


class TestLuhn:
    @pytest.mark.parametrize("value", [
        "4532015112830366",
        "4532 0151 1283 0366",
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
        ("4532015112830367", "off-by-one"),
        ("4532", "too short"),
        ("", "empty"),
    ])
    def test_invalid(self, value: str, reason: str) -> None:
        assert validate_luhn(value) is False, reason
