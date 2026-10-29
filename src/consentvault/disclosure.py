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
    *,
    strip: bool = False,
) -> str:
    """Store a disclosure body (idempotent) and return its sha256 hex digest.

    Purposes are lower-cased and, when ``allowed_purposes`` is given, checked against the configured list.
    The digest is over the body exactly as given. A body with leading or trailing whitespace is refused unless
    ``strip`` is true, because the capture widget hashes the text it shows with that whitespace removed and a
    wording stored with it would never match a hash the widget sends.
    """
    from .ledger import CHANNELS, _clean_set, clean_purposes

    if not body or not body.strip():
        raise InvalidEventError("disclosure body is empty")
    if strip:
        body = body.strip()
    elif body != body.strip():
        raise InvalidEventError(
            "the disclosure body has leading or trailing whitespace; the capture widget hashes the trimmed text, "
            "so register the trimmed wording (pass strip=True; the command line strips by default)"
        )
    chans = _clean_set(channels, CHANNELS, "channel")
    purps = clean_purposes(purposes, allowed_purposes)
    digest = sha256_of(body)
    conn.execute(
        "INSERT INTO consentvault.disclosure (sha256, body, label, locale, channels, purposes)"
        " VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (sha256) DO NOTHING",
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
