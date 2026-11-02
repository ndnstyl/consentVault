"""Inbound signals: a connected system tells the vault what it believes about a person (POST /v1/signals).

Resolution (contracts/suppression-sync.md, data-model 9.2), judged against the LEDGER by arrival order, never by the
time the system claims:

- the same (system, external reference) again: the first answer, unchanged (deduplication);
- a stop (``denied``): if the ledger already holds the person as denied -> ``no_change`` (no event, no push);
  otherwise a stop event is recorded (``applied_as_event``), always, whether or not the vault knew the person;
- a grant (``permitted``): if the ledger holds a stop -> ``conflict_stop_wins`` (nothing recorded, a signal can never
  lift a stop); if it already holds permission -> ``no_change``; if the ledger holds nothing, a grant becomes an event
  only with registered wording and the normal checks (``applied_as_event``), otherwise ``ignored_stale``.

A signal never claims a verified contact point, so it never lifts a stop. Events it causes are pushed to every OTHER
connected system, never back to the sender (no echo).

Events written here are ``suppress`` and ``grant`` with origin and method ``import`` and source ``signal``: a stop a
connected system reports is a hard stop (only a staff or regulatory decision lifts it), the conservative reading.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime

import psycopg

from ..safelog import caller_detail
from ..errors import ConsentVaultError, NormalizationError
from ..ledger import CHANNELS, record_tenant_event
from ..normalize import normalize_contact
from ..tenancy import crypto as tc
from ..tenancy.keys_protocol import WrappedKey
from .errors import InvalidContactError, SignalValidationError

EXTERNAL_REF_COLUMN = "external_ref"
CLAIMED_STATES = ("denied", "permitted")
RESOLUTIONS = ("applied_as_event", "no_change", "ignored_stale", "conflict_stop_wins")
_FIELDS = {"contact", "channel", "purpose", "claimed_state", "claimed_at", "external_ref", "disclosure_sha256"}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_PURPOSE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class Signal:
    contact: str
    channel: str
    purpose: str
    claimed_state: str
    claimed_at: datetime | None
    external_ref: str
    disclosure_sha256: str | None


@dataclass(frozen=True)
class SignalResult:
    signal_id: uuid.UUID
    resolution: str
    event_id: str | None
    replay: bool = False


def parse_signal(body) -> Signal:
    """Validate the request body; every problem is named in ``fields``."""
    if not isinstance(body, dict):
        raise SignalValidationError("the body must be a JSON object", {"body": "must be an object"})
    problems: dict[str, str] = {f"{k}": "unknown field" for k in body if k not in _FIELDS}
    for required in ("contact", "channel", "purpose", "claimed_state", "external_ref"):
        if not isinstance(body.get(required), str) or not body.get(required).strip():
            problems.setdefault(required, "is required and must be a non-empty string")
    channel = body.get("channel")
    if isinstance(channel, str) and channel and channel not in CHANNELS:
        problems["channel"] = f"must be one of {list(CHANNELS)}"
    state = body.get("claimed_state")
    if isinstance(state, str) and state and state not in CLAIMED_STATES:
        problems["claimed_state"] = f"must be one of {list(CLAIMED_STATES)}"
    purpose = (body.get("purpose") or "").strip().lower() if isinstance(body.get("purpose"), str) else ""
    if purpose and purpose != "*" and not _PURPOSE.match(purpose):
        problems["purpose"] = "use lower-case letters, digits, '_', '-' or '.', or '*' on a stop"
    if purpose == "*" and state == "permitted":
        problems["purpose"] = "'*' is valid only on a stop"
    ref = body.get("external_ref")
    if isinstance(ref, str) and len(ref) > 200:
        problems["external_ref"] = "must be at most 200 characters"
    claimed_at = None
    if body.get("claimed_at") is not None:
        try:
            claimed_at = datetime.fromisoformat(str(body["claimed_at"]).replace("Z", "+00:00"))
            if claimed_at.tzinfo is None:
                raise ValueError("no timezone")
        except ValueError:
            problems["claimed_at"] = "must be ISO 8601 with a timezone"
    sha = body.get("disclosure_sha256")
    if sha is not None and not (isinstance(sha, str) and _SHA.match(sha)):
        problems["disclosure_sha256"] = "must be 64 lowercase hex characters"
    if problems:
        raise SignalValidationError("the signal is missing a field or carries a malformed one", problems)
    return Signal(body["contact"], channel, purpose, state, claimed_at, ref, sha)


def ensure_contact_key(conn: psycopg.Connection, crypto: tc.TenantCrypto, org_id, contact_fp: str) -> bytes:
    """The contact's data key, creating the contact's key row first when the vault has never seen the person (the same
    row ``ledger.record_tenant_event`` makes, so a later event finds it)."""
    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (contact_fp,)).fetchone()
    if held is None:
        key = crypto.new_contact_key(org_id)
        salt = os.urandom(32).hex()
        conn.execute(
            "INSERT INTO consentvault.contact_key (org_id, contact_fp, wrapped_key, key_version, salt_ct)"
            " VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (org_id, contact_fp, key.wrapped.ciphertext, key.wrapped.key_version,
             tc.encrypt_field(key.data_key, org_id, contact_fp, "contact_salt", salt)))
        held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (contact_fp,)).fetchone()
    return crypto.open_contact_key(org_id, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))


def process_signal(
    conn: psycopg.Connection,
    crypto: tc.TenantCrypto,
    *,
    org_id,
    system_id,
    signal: Signal,
    region: str | None = None,
    allowed_purposes=None,
) -> SignalResult:
    """Resolve one signal. Run it inside ``org_transaction`` with a token that holds the ``capture`` scope."""
    try:
        kind, norm = normalize_contact(signal.contact, None, region)
    except NormalizationError as exc:
        raise InvalidContactError(caller_detail(exc)) from exc
    fp = crypto.contact_fingerprint(org_id, kind, norm)
    data_key = ensure_contact_key(conn, crypto, org_id, fp)
    mac = tc.payload_mac(data_key, f"{system_id}\x1f{signal.external_ref}".encode("utf-8"))
    prior = _lookup(conn, system_id, mac)
    if prior is not None:
        return prior
    try:
        with conn.transaction():  # the event, its pushes and the signal row land together or not at all
            return _resolve(conn, crypto, org_id, system_id, signal, norm, fp, data_key, mac, region, allowed_purposes)
    except psycopg.errors.UniqueViolation:
        again = _lookup(conn, system_id, mac)  # the same signal arrived twice at once; the first one won
        if again is None:
            raise
        return again


def _lookup(conn, system_id, mac) -> SignalResult | None:
    row = conn.execute("SELECT * FROM consentvault.sync_signal_lookup(%s, %s)", (system_id, mac)).fetchone()
    if row is None:
        return None
    return SignalResult(row["signal_id"], row["resolution"], str(row["event_id"]) if row["event_id"] else None, True)


def _resolve(conn, crypto, org_id, system_id, signal, norm, fp, data_key, mac, region, allowed_purposes) -> SignalResult:
    ledger = conn.execute("SELECT consentvault.sync_ledger_state(%s, %s, %s) AS s",
                          (fp, signal.channel, signal.purpose)).fetchone()["s"]
    resolution, event_id = "no_change", None
    # the ledger writer queues the event's pushes in this transaction, skipping the system that sent the signal
    common = dict(contact=norm, channels=[signal.channel], purposes=[signal.purpose], method="import", origin="import",
                  source="signal", recorded_by=f"system:{system_id}", region=region, source_system_id=system_id)
    if signal.claimed_state == "denied":
        if ledger != "denied":
            event_id = record_tenant_event(conn, crypto, event_type="suppress", **common).event_id
            resolution = "applied_as_event"
    elif ledger == "denied":
        resolution = "conflict_stop_wins"
    elif ledger is None:
        resolution = "ignored_stale"
        if signal.disclosure_sha256:
            try:
                event_id = record_tenant_event(conn, crypto, event_type="grant", disclosure_sha256=signal.disclosure_sha256,
                                               allowed_purposes=allowed_purposes, **common).event_id
                resolution = "applied_as_event"
            except ConsentVaultError:  # unregistered wording, scope beyond it, a refused purpose: not a grant
                event_id = None
    signal_id = uuid.uuid4()
    conn.execute(
        "SELECT consentvault.sync_signal_record(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (signal_id, system_id, fp, signal.channel, signal.purpose, signal.claimed_state, signal.claimed_at, resolution,
         uuid.UUID(event_id) if event_id else None,
         tc.encrypt_field(data_key, org_id, str(signal_id), EXTERNAL_REF_COLUMN, signal.external_ref), mac))
    return SignalResult(signal_id, resolution, event_id)
