"""Contact normalization: E.164 phones, lowercased emails, subject keys."""

from __future__ import annotations

import hashlib
import re

from .errors import NormalizationError

NANP_REGIONS = frozenset(
    {"US", "CA", "AG", "AI", "AS", "BB", "BM", "BS", "DM", "DO", "GD", "GU", "JM", "KN",
     "KY", "LC", "MP", "MS", "PR", "SX", "TC", "TT", "VC", "VG", "VI"}
)

_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_phone(raw: str, region: str | None = None) -> str:
    """Return E.164. NANP numbers may be given without a plus; others need one."""
    if not isinstance(raw, str) or not raw.strip():
        raise NormalizationError("phone number is empty")
    text = raw.strip()
    digits = re.sub(r"[^0-9]", "", text)
    if text.startswith("+"):
        candidate = "+" + digits
        if candidate.startswith("+1"):
            return _check_nanp(candidate, raw)
        if not _E164.match(candidate):
            raise NormalizationError(f"not a valid international number: {raw!r}")
        return candidate
    if text.startswith("00"):
        return normalize_phone("+" + digits[2:], region)
    if region is None:
        raise NormalizationError(
            f"phone {raw!r} has no '+' prefix and no default region is configured"
        )
    if region.upper() not in NANP_REGIONS:
        raise NormalizationError(
            f"region {region!r} is not supported without a '+' prefix; give the number as +<country code>..."
        )
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        raise NormalizationError(f"not a 10-digit NANP number: {raw!r}")
    return _check_nanp("+1" + digits, raw)


def _check_nanp(candidate: str, raw: str) -> str:
    if len(candidate) != 12:
        raise NormalizationError(f"not a valid NANP number: {raw!r}")
    area, exchange = candidate[2], candidate[5]
    if area in "01" or exchange in "01":
        raise NormalizationError(f"not a valid NANP number: {raw!r}")
    return candidate


def normalize_email(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise NormalizationError("email is empty")
    value = raw.strip().lower()
    if not _EMAIL.match(value):
        raise NormalizationError(f"not a valid email address: {raw!r}")
    return value


def detect_kind(raw: str) -> str:
    return "email" if "@" in raw else "phone"


def normalize_contact(raw: str, kind: str | None = None, region: str | None = None) -> tuple[str, str]:
    """Return (contact_kind, contact_norm)."""
    kind = kind or detect_kind(raw)
    if kind == "phone":
        return kind, normalize_phone(raw, region)
    if kind == "email":
        return kind, normalize_email(raw)
    raise NormalizationError(f"unknown contact kind: {kind!r}")


def subject_key(contact_norm: str, supplied: str | None = None) -> str:
    """The stable person key: the caller's own key if given, else sha256 of the normalized contact."""
    if supplied:
        return supplied
    return hashlib.sha256(contact_norm.encode("utf-8")).hexdigest()
