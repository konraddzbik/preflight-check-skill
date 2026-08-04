"""
Checksum validators for PII detection.

These are the critical part of the detector: regex alone produces too many
false positives on things like order numbers, timestamps, or hashes. Each
validator returns True only if the candidate passes its mathematical check.

References:
    PESEL:  https://en.wikipedia.org/wiki/PESEL
    NIP:    https://pl.wikipedia.org/wiki/Numer_identyfikacji_podatkowej
    REGON:  https://pl.wikipedia.org/wiki/REGON
    IBAN:   ISO 13616, mod-97 check (https://en.wikipedia.org/wiki/International_Bank_Account_Number)
    Luhn:   ISO/IEC 7812-1 (https://en.wikipedia.org/wiki/Luhn_algorithm)
"""

from __future__ import annotations

import re
from collections.abc import Callable


def _digits_only(value: str) -> str:
    """Strip non-digits from a string."""
    return re.sub(r"\D", "", value)


def validate_pesel(value: str) -> bool:
    """
    Validate a Polish PESEL number.

    PESEL is 11 digits: YYMMDDPPPPK where:
        - YYMMDD encodes the date of birth (with month offset for century)
        - PPPP is a serial number, last digit encodes sex
        - K is the checksum digit

    Checksum: weights [1,3,7,9,1,3,7,9,1,3], sum mod 10, subtract from 10,
              mod 10 again to get the check digit.
    """
    digits = _digits_only(value)
    if len(digits) != 11:
        return False

    # Basic date sanity check — month with century offset
    # 01-12: 1900s, 21-32: 2000s, 41-52: 2100s, 61-72: 2200s, 81-92: 1800s
    try:
        month = int(digits[2:4])
    except ValueError:
        return False
    valid_month_ranges = [(1, 12), (21, 32), (41, 52), (61, 72), (81, 92)]
    if not any(lo <= month <= hi for lo, hi in valid_month_ranges):
        return False

    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    checksum = sum(int(d) * w for d, w in zip(digits[:10], weights, strict=True))
    check_digit = (10 - (checksum % 10)) % 10
    return check_digit == int(digits[10])


def validate_nip(value: str) -> bool:
    """
    Validate a Polish NIP (tax ID).

    NIP is 10 digits with weighted checksum.
    Weights: [6, 5, 7, 2, 3, 4, 5, 6, 7], sum mod 11 = check digit.
    A checksum result of 10 means the NIP is invalid.
    """
    digits = _digits_only(value)
    if len(digits) != 10:
        return False
    if digits == "0000000000":
        return False

    weights = [6, 5, 7, 2, 3, 4, 5, 6, 7]
    checksum = sum(int(d) * w for d, w in zip(digits[:9], weights, strict=True))
    check_digit = checksum % 11
    if check_digit == 10:
        return False
    return check_digit == int(digits[9])


def validate_regon(value: str) -> bool:
    """
    Validate a Polish REGON (business registry number).

    Two forms:
      - 9 digits: weights [8, 9, 2, 3, 4, 5, 6, 7], mod 11
      - 14 digits: 9-digit prefix must be valid; full validates with
        weights [2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8], mod 11

    If checksum result is 10, the digit is 0.
    """
    digits = _digits_only(value)

    if len(digits) == 9:
        weights = [8, 9, 2, 3, 4, 5, 6, 7]
        checksum = sum(int(d) * w for d, w in zip(digits[:8], weights, strict=True))
        check_digit = checksum % 11
        if check_digit == 10:
            check_digit = 0
        return check_digit == int(digits[8])

    if len(digits) == 14:
        # First validate the embedded 9-digit REGON
        if not validate_regon(digits[:9]):
            return False
        weights = [2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8]
        checksum = sum(int(d) * w for d, w in zip(digits[:13], weights, strict=True))
        check_digit = checksum % 11
        if check_digit == 10:
            check_digit = 0
        return check_digit == int(digits[13])

    return False


def validate_iban(value: str) -> bool:
    """
    Validate an IBAN using mod-97 check (ISO 13616).

    Algorithm:
      1. Move the first 4 characters to the end.
      2. Replace each letter with two digits (A=10, B=11, ..., Z=35).
      3. Interpret as an integer and check that mod 97 == 1.

    Length constraints vary by country (15-34 chars); we accept 15-34 here.
    """
    cleaned = re.sub(r"\s", "", value).upper()
    if not (15 <= len(cleaned) <= 34):
        return False
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", cleaned):
        return False

    rearranged = cleaned[4:] + cleaned[:4]
    # Convert letters to digit pairs
    numeric = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged
    )
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def validate_luhn(value: str) -> bool:
    """
    Validate a number using the Luhn algorithm.

    Used for credit card numbers and various ID schemes. Standard credit
    cards are 13-19 digits; we require that range to reduce false positives
    on arbitrary long digit strings.
    """
    digits = _digits_only(value)
    if not (13 <= len(digits) <= 19):
        return False

    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Registry mapping validator names (from catalog.yaml) to callables.
# Keep this synchronized with catalog.yaml `validator:` fields.
VALIDATORS: dict[str, Callable[[str], bool]] = {
    "validate_pesel": validate_pesel,
    "validate_nip": validate_nip,
    "validate_regon": validate_regon,
    "validate_iban": validate_iban,
    "validate_luhn": validate_luhn,
}
