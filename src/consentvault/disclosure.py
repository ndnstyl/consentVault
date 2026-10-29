"""Disclosure registry: the exact wording a person saw, stored once by hash."""

from __future__ import annotations

import hashlib
from typing import Collection, Iterable

import psycopg

from .errors import InvalidEventError, UnknownDisclosureError


def sha256_of(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def register(
    conn: psycopg.Connection,
    body: str,
    label: str,
    locale: str,
    channels: Iterable[str],
    purposes: Iterable[str],
    allowed_purposes: Collection[str] | None = None,
) -> str:
    """Store a disclosure body (idempotent) and return its sha256 hex digest.

    Purposes are lower-cased and, when ``allowed_purposes`` is given, checked against the configured list.
    The body is stored and hashed as its exact UTF-8 bytes, whitespace included: nothing here, in the admin lane or
    in the capture widget trims wording, so the hash a widget sends is the hash of exactly what it displayed.
    """
    from .ledger import CHANNELS, _clean_set, clean_purposes

    if not isinstance(body, str) or not body or not body.strip():
        raise InvalidEventError("disclosure body is empty")
    chans = _clean_set(channels, CHANNELS, "channel")
    purps = clean_purposes(purposes, allowed_purposes)
    digest = sha256_of(body)
    conn.execute(
        "INSERT INTO consentvault.disclosure (sha256, body, label, locale, channels, purposes)"
        " VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (org_id, sha256) DO NOTHING",
        (digest, body, label, locale, chans, purps),
    )
    held = get(conn, digest)
    if list(held["channels"]) != chans or list(held["purposes"]) != purps:
        raise InvalidEventError(
            f"disclosure {digest} is already registered with different channels or purposes "
            f"({list(held['channels'])}, {list(held['purposes'])}); the scope of held wording never changes"
        )
    return digest


def get(conn: psycopg.Connection, sha: str) -> dict:
    row = conn.execute("SELECT * FROM consentvault.disclosure WHERE sha256 = %s", (sha,)).fetchone()
    if row is None:
        raise UnknownDisclosureError(f"disclosure {sha!r} is not held by the vault")
    return row
