"""Shared validation of org ids and object keys so a caller-supplied name can never escape its prefix."""

from __future__ import annotations

import re

_ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_KEY_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._=-]{0,199}$")


def check_org_id(org_id: str, error: type[Exception]) -> str:
    if not isinstance(org_id, str) or not _ORG_RE.match(org_id):
        raise error(f"org id {org_id!r} is not 1-64 characters of letters, digits, '_' or '-'")
    return org_id


def check_object_key(key: str, error: type[Exception]) -> str:
    """An object key is slash-separated parts; no empty part, no '.', no '..'."""
    if not isinstance(key, str) or not key or len(key) > 900:
        raise error("object key must be a non-empty string of at most 900 characters")
    for part in key.split("/"):
        if part in (".", "..") or not _KEY_PART_RE.match(part):
            raise error(f"object key {key!r} has an empty, relative or unsafe part {part!r}")
    return key
