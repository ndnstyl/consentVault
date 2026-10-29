"""The contact gate: may this contact point be contacted on this channel for this purpose?

Fails closed. A database that cannot answer, a contact that cannot be read, or the absence of
consent all return ``allowed=False`` with a named reason; nothing here ever guesses yes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import psycopg

from .errors import ConsentVaultError, NormalizationError
from .ledger import CHANNELS
from .normalize import normalize_contact

REASON_DB_DOWN = "database_unreachable"
REASON_NO_CONSENT = "no_consent_on_record"
REASON_BAD_CONTACT = "invalid_contact"
REASON_BAD_CHANNEL = "invalid_channel"
REASON_BAD_PURPOSE = "invalid_purpose"
REASON_GRANTED = "granted"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    basis_event_ids: tuple[str, ...] = ()


def _deny(reason: str, basis: tuple[str, ...] = ()) -> Decision:
    return Decision(False, reason, basis)


def may_contact(
    conn: psycopg.Connection,
    contact: str,
    channel: str,
    purpose: str,
    region: str | None = None,
) -> Decision:
    """Answer the contact question from ``current_permission``. Never raises for a database fault."""
    if channel not in CHANNELS:
        return _deny(f"{REASON_BAD_CHANNEL}:{channel}")
    if not purpose or not str(purpose).strip() or str(purpose).strip() == "*":
        return _deny(REASON_BAD_PURPOSE)
    try:
        kind, norm = normalize_contact(contact, None, region)
    except NormalizationError as exc:
        return _deny(f"{REASON_BAD_CONTACT}:{exc}")
    purpose = purpose.strip().lower()
    try:
        row = conn.execute(
            "SELECT allowed, reason, deciding_event_id FROM consentvault.current_permission"
            " WHERE contact_kind = %s AND contact_norm = %s AND channel = %s AND purpose = %s",
            (kind, norm, channel, purpose),
        ).fetchone()
        if row is None:
            stopped_all = conn.execute(
                "SELECT reason FROM consentvault.current_permission"
                " WHERE contact_kind = %s AND contact_norm = %s AND channel = %s AND purpose = '*'",
                (kind, norm, channel),
            ).fetchone()
            if stopped_all is not None:
                return _deny(stopped_all["reason"])
            return _deny(REASON_NO_CONSENT)
        basis = conn.execute(
            "SELECT event_id::text AS event_id FROM ("
            "  SELECT DISTINCT ON (kind) event_id, seq FROM ("
            "    SELECT event_id, seq, CASE WHEN event_type = 'grant' THEN 'g'"
            "           WHEN event_type = 'release' AND origin = 'consumer' AND release_outcome = 'released' THEN 'r'"
            "           WHEN event_type IN ('revoke', 'suppress') THEN 's' END AS kind"
            "    FROM consentvault.event"
            "    WHERE contact_kind = %s AND contact_norm = %s AND %s = ANY(channels) AND (%s = ANY(purposes) OR '*' = ANY(purposes))"
            "  ) x WHERE kind IS NOT NULL ORDER BY kind, seq DESC"
            ") y ORDER BY seq",
            (kind, norm, channel, purpose),
        ).fetchall()
    except Exception as exc:  # fail closed: any fault at all is a named denial, never a guess
        return _deny(f"{REASON_DB_DOWN}:{type(exc).__name__}")
    ids = tuple(r["event_id"] for r in basis)
    if row["allowed"]:
        return Decision(True, REASON_GRANTED, ids)
    return _deny(row["reason"], ids)


def record_contact(
    conn: psycopg.Connection,
    contact: str,
    channel: str,
    outcome: str,
    ref: str | None = None,
    *,
    purpose: str | None = None,
    region: str | None = None,
    contacted_at: datetime | None = None,
    recorded_by: str | None = None,
) -> int:
    """Log an outbound attempt (used by the release rule). Returns the contact_log id."""
    if channel not in CHANNELS:
        raise NormalizationError(f"unknown channel {channel!r}; allowed: {list(CHANNELS)}")
    kind, norm = normalize_contact(contact, None, region)
    purpose = purpose.strip().lower() if purpose else None
    when = contacted_at or datetime.now(timezone.utc)
    if when.tzinfo is None:
        raise NormalizationError("contacted_at must be timezone-aware")
    try:
        row = conn.execute(
            "INSERT INTO consentvault.contact_log"
            " (contact_kind, contact_norm, channel, purpose, contacted_at, outcome, ref, recorded_by)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING contact_log_id",
            (kind, norm, channel, purpose, when, outcome, ref, recorded_by),
        ).fetchone()
    except psycopg.Error as exc:
        raise ConsentVaultError(f"contact log write refused by the database: {exc}") from exc
    return row["contact_log_id"]
