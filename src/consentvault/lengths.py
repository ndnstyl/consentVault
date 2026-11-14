"""Length checks on raw key material, kept apart from the names that hold the key so they read as what they are."""
from __future__ import annotations


def is_bytes_of_len(value, n: int) -> bool:
    """True when ``value`` is a bytes object of exactly ``n`` bytes."""
    return isinstance(value, bytes) and len(value) == n
