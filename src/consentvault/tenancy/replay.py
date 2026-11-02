"""Replay guard shared by every vault task (``consentvault.replay_guard``, migration 0003)."""

from __future__ import annotations

import uuid
from datetime import datetime

import psycopg

from ..safelog import describe
from .errors import ReplayError, TenancyError


def claim_nonce(conn: psycopg.Connection, org_id: uuid.UUID | str, nonce: str, expires_at: datetime) -> None:
    """Record a nonce (a JWT ``jti``, a webhook nonce) for an organisation; raise ``ReplayError`` if it was seen."""
    if expires_at.tzinfo is None:
        raise TenancyError("expires_at must be timezone-aware")
    try:
        row = conn.execute("SELECT consentvault.claim_replay_nonce(%s, %s, %s) AS fresh",
                           (str(uuid.UUID(str(org_id))), nonce, expires_at)).fetchone()
    except ValueError as exc:
        raise TenancyError(f"org_id is not a UUID: {describe(exc)}") from exc
    except psycopg.Error as exc:
        raise TenancyError(f"replay guard refused the claim: {describe(exc)}") from exc
    if not row["fresh"]:
        raise ReplayError("nonce already presented for this organisation")


def sweep(conn: psycopg.Connection) -> int:
    """Delete expired nonces (worker role). Returns the number removed."""
    try:
        return conn.execute("SELECT consentvault.sweep_replay_guard() AS gone").fetchone()["gone"]
    except psycopg.Error as exc:
        raise TenancyError(f"replay guard sweep failed: {describe(exc)}") from exc
