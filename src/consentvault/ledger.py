"""The ledger: the only writer of events, and the chain verifier."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Collection, Iterable

import psycopg
from psycopg import sql

from .safelog import describe
from . import disclosure as disclosure_mod
from .errors import (
    ChainError,
    ClockSkewError,
    EmptyConsentError,
    GrantScopeError,
    InvalidEventError,
    LedgerError,
    UnknownDisclosureError,
    UnknownPurposeError,
)
from .normalize import normalize_contact, subject_key as make_subject_key

GENESIS = "0" * 64
CURRENT_HASH_VERSION = 1
ALL_PURPOSES = "*"
MAX_CAPTURE_SKEW = timedelta(minutes=5)

EVENT_TYPES = ("grant", "revoke", "suppress", "release")
METHODS = ("checkbox", "verbal", "written", "keyword", "staff", "import")
ORIGINS = ("consumer", "staff", "regulatory", "import")
CHANNELS = ("voice", "artificial_voice", "sms", "email")
RELEASE_OUTCOMES = ("released", "refused")
CONTACT_VERIFICATIONS = ("none", "otp", "inbound_keyword")
VERIFIED = ("otp",)

# hash_version -> the evidence columns digested into row_hash (prev_hash is prefixed, row_hash excluded).
# A column added later gets a new version in a new migration; old rows verify under their own version forever.
HASH_VERSIONS: dict[int, tuple[str, ...]] = {
    1: (
        "seq", "event_id", "subject_key", "contact_kind", "contact_norm", "contact_salt", "contact_commit", "event_type",
        "channels", "purposes", "disclosure_sha256", "method", "origin",
        "captured_at", "received_at", "edge_received_at", "page_url", "client_ip", "user_agent",
        "session_ref", "bot_check", "payload_sha256", "source", "recorded_by",
        "release_of_event_id", "release_outcome", "release_cause", "contact_verification",
        "hash_version",
    ),
    # Version 2 (multi-tenant rows): every column stored in the clear, so the content digest, and with it the chain
    # link, is recomputable by anyone and survives crypto-shredding. Re-pointing a row to another fingerprint,
    # organisation, source, brand or key version breaks it. The personal fields are covered through
    # evidence_sha256, a digest of their plaintext (salted by the contact's secret salt), see EVIDENCE_V2.
    2: (
        "seq", "event_id", "org_id", "subject_fp", "contact_kind", "contact_fp", "contact_commit", "subject_commit",
        "evidence_sha256", "event_type", "channels", "purposes", "disclosure_sha256", "method", "origin",
        "captured_at", "received_at", "edge_received_at", "bot_check", "payload_sha256", "source", "source_id",
        "brand_ids", "key_version", "recorded_by", "release_of_event_id", "release_outcome", "release_cause",
        "contact_verification", "hash_version",
    ),
}

# Version-2 plaintext evidence, digested into evidence_sha256: (field, ciphertext column, record the AAD binds to).
# The salt is held once per contact in consentvault.contact_key.salt_ct (bound to the contact fingerprint).
EVIDENCE_V2: tuple[str, ...] = (
    "contact_norm", "contact_salt", "subject_key", "page_url", "client_ip", "user_agent", "session_ref",
    "attribution_sha256",
)
_CIPHER_COLUMNS_V2: dict[str, str] = {
    "contact_norm": "contact_ct", "subject_key": "subject_key_ct", "page_url": "page_url_ct",
    "client_ip": "client_ip_ct", "user_agent": "user_agent_ct", "session_ref": "session_ref_ct",
    "attribution": "attribution_ct",
}

# Each organisation has its own chain and lock; the home organisation keeps the single-company lock key.
_LOCK_SQL = "SELECT pg_advisory_xact_lock(consentvault.ledger_lock_key(consentvault.current_org()))"
_HEAD_SQL = ("SELECT seq, row_hash FROM consentvault.event WHERE org_id = consentvault.current_org()"
             " ORDER BY seq DESC LIMIT 1")


def _insert_event_sql(cols) -> sql.Composed:
    """INSERT into consentvault.event for ``cols``; every column is a quoted identifier, every value a parameter."""
    return sql.SQL("INSERT INTO consentvault.event ({}) VALUES ({})").format(
        sql.SQL(", ").join(sql.Identifier(c) for c in cols), sql.SQL(", ").join(sql.Placeholder() for _ in cols))


@dataclass(frozen=True)
class Event:
    seq: int
    event_id: str
    row_hash: str
    prev_hash: str
    # the sync outbox result for a tenant event (sync.outbox.EnqueueResult): the pushes queued in the same transaction
    pushes: Any = field(default=None, compare=False)


@dataclass(frozen=True)
class Break:
    seq: int
    event_id: str
    reason: str


def _canon_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise LedgerError("naive datetime in an evidence column")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_canon_value(v) for v in value]
    return value


def canonical_dumps(obj):
    """The one canonical JSON form: sorted keys, no spaces, ASCII only.

    Self-contained on purpose (only ``json``): the evidence bundle embeds this function's source, so the
    exported verifier and the vault serialise identically by construction.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_json(row: dict, hash_version: int) -> str:
    """Deterministic JSON of the evidence columns for a hash version."""
    try:
        columns = HASH_VERSIONS[hash_version]
    except KeyError:
        raise LedgerError(f"unknown hash_version {hash_version}") from None
    payload = {c: _canon_value(row[c]) for c in columns}
    return canonical_dumps(payload)


def link_hash(prev_hash, contact_commit, subject_commit, content_sha256):
    """The chain hash of one row from the previous hash and three digests.

    Self-contained on purpose (only ``hashlib`` and ``canonical_dumps``): the evidence bundle embeds this
    function's source, so a verifier recomputes every chain link, including links of events it never sees in full.
    """
    link = {"contact_commit": contact_commit, "content_sha256": content_sha256, "subject_commit": subject_commit}
    return hashlib.sha256((prev_hash + canonical_dumps(link)).encode("utf-8")).hexdigest()


def contact_commitment(contact_salt: str, contact_norm: str) -> str:
    """sha256(contact_salt || contact_norm), the contact's own salt: what a row commits to about whose it is. Without the row's salt a
    phone number or email cannot be tested against it."""
    return hashlib.sha256((contact_salt + contact_norm).encode("utf-8")).hexdigest()


def subject_commitment(contact_salt: str, subject_key: str) -> str:
    """sha256(contact_salt || subject_key), salted the same way: a default subject key is itself derived from the
    contact point, so an unsalted digest of it would be just as guessable."""
    return hashlib.sha256((contact_salt + subject_key).encode("utf-8")).hexdigest()


def content_sha256(row: dict, hash_version: int) -> str:
    """sha256 of the canonical JSON of every evidence column the hash version names."""
    return hashlib.sha256(canonical_json(row, hash_version).encode("utf-8")).hexdigest()


def compute_row_hash(prev_hash: str, row: dict, hash_version: int) -> str:
    if hash_version == 2:
        # the subject commitment is stored: the salt behind it is encrypted and may have been shredded
        return link_hash(prev_hash, row["contact_commit"], row["subject_commit"], content_sha256(row, hash_version))
    return link_hash(prev_hash, row["contact_commit"], subject_commitment(row["contact_salt"], row["subject_key"]),
                     content_sha256(row, hash_version))


def evidence_sha256(evidence: dict) -> str:
    """sha256 of the canonical JSON of the version-2 plaintext evidence fields (EVIDENCE_V2)."""
    return hashlib.sha256(canonical_dumps({c: _canon_value(evidence[c]) for c in EVIDENCE_V2}).encode("utf-8")).hexdigest()


def attribution_digest(attribution: dict | None) -> str | None:
    if attribution is None:
        return None
    if not isinstance(attribution, dict):
        raise InvalidEventError("attribution must be a JSON object")
    return hashlib.sha256(canonical_dumps(attribution).encode("utf-8")).hexdigest()


def _clean_set(values: Iterable[str], allowed: tuple[str, ...] | None, what: str) -> list[str]:
    if isinstance(values, str):
        values = [values]
    out = sorted({v.strip() for v in values if v and v.strip()})
    if not out:
        raise EmptyConsentError(f"event names no {what}")
    if allowed is not None:
        bad = [v for v in out if v not in allowed]
        if bad:
            raise InvalidEventError(f"unknown {what}: {bad}; allowed: {list(allowed)}")
    return out


_PURPOSE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def clean_purposes(
    values: Iterable[str], allowed: Collection[str] | None = None, *, allow_all: bool = False,
) -> list[str]:
    """Lower-case, de-duplicate and validate purposes.

    ``allowed`` is the configured purpose list; when given, every purpose must be on it. ``"*"`` (every purpose)
    is accepted only when ``allow_all`` is true and only as the sole purpose.
    """
    if isinstance(values, str):
        values = [values]
    out = sorted({v.strip().lower() for v in values if v and v.strip()})
    if not out:
        raise EmptyConsentError("event names no purpose")
    if ALL_PURPOSES in out:
        if not allow_all:
            raise UnknownPurposeError("'*' (every purpose) is valid only on a stop event")
        if out != [ALL_PURPOSES]:
            raise UnknownPurposeError("'*' must be the only purpose when it is used")
        return out
    malformed = [v for v in out if not _PURPOSE_RE.match(v)]
    if malformed:
        raise UnknownPurposeError(f"malformed purpose(s) {malformed}: use lower-case letters, digits, '_', '-' or '.'")
    if allowed is not None:
        listed = {a.strip().lower() for a in allowed}
        bad = [v for v in out if v not in listed]
        if bad:
            raise UnknownPurposeError(f"purpose(s) {bad} are not on the configured purpose list {sorted(listed)}")
    return out


def _validate(
    conn: psycopg.Connection, *, contact, event_type, channels, purposes, method, origin, disclosure_sha256,
    contact_kind, region, captured_at, edge_received_at, release_of_event_id, release_outcome, release_cause,
    allowed_purposes, contact_verification,
) -> tuple[list[str], list[str], str, str]:
    """Every check a writer makes before it touches the chain. Returns (channels, purposes, contact kind, norm)."""
    if event_type not in EVENT_TYPES:
        raise InvalidEventError(f"unknown event_type {event_type!r}; allowed: {list(EVENT_TYPES)}")
    if method not in METHODS:
        raise InvalidEventError(f"unknown method {method!r}; allowed: {list(METHODS)}")
    if origin not in ORIGINS:
        raise InvalidEventError(f"unknown origin {origin!r}; allowed: {list(ORIGINS)}")
    if contact_verification not in CONTACT_VERIFICATIONS:
        raise InvalidEventError(
            f"unknown contact_verification {contact_verification!r}; allowed: {list(CONTACT_VERIFICATIONS)}")
    if contact_verification != "none" and (event_type != "grant" or origin != "consumer"):
        raise InvalidEventError("contact_verification other than 'none' is only for a consumer grant")
    chans = _clean_set(channels, CHANNELS, "channel")
    purps = clean_purposes(purposes, allowed_purposes, allow_all=event_type in ("revoke", "suppress"))
    kind, norm = normalize_contact(contact, contact_kind, region)
    held = None
    if disclosure_sha256 is not None:
        held = disclosure_mod.get(conn, disclosure_sha256)
    elif event_type == "grant":
        raise UnknownDisclosureError("a grant must reference a disclosure the vault holds")
    if event_type == "grant":
        outside_channels = sorted(set(chans) - set(held["channels"]))
        outside_purposes = sorted(set(purps) - set(held["purposes"]))
        if outside_channels or outside_purposes:
            raise GrantScopeError(
                "the grant goes beyond its disclosure: "
                f"channels not covered {outside_channels}, purposes not covered {outside_purposes}"
            )
    if captured_at is not None and captured_at.tzinfo is None:
        raise InvalidEventError("captured_at must be timezone-aware")
    if edge_received_at is not None and edge_received_at.tzinfo is None:
        raise InvalidEventError("edge_received_at must be timezone-aware")

    if event_type == "release":
        if release_outcome not in RELEASE_OUTCOMES:
            raise InvalidEventError(f"a release event needs release_outcome in {list(RELEASE_OUTCOMES)}")
        if release_of_event_id is None:
            raise InvalidEventError("a release event must name the grant it decides (release_of_event_id)")
        if (release_outcome == "refused") != bool(release_cause):
            raise InvalidEventError("release_cause is required for a refusal and forbidden for a release")
    elif release_of_event_id is not None or release_outcome is not None or release_cause is not None:
        raise InvalidEventError("release_* columns are only for release events")

    return chans, purps, kind, norm


def record_event(
    conn: psycopg.Connection,
    *,
    contact: str,
    event_type: str,
    channels: Iterable[str],
    purposes: Iterable[str],
    method: str,
    origin: str,
    disclosure_sha256: str | None = None,
    contact_kind: str | None = None,
    region: str | None = None,
    subject_key: str | None = None,
    captured_at: datetime | None = None,
    page_url: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    session_ref: str | None = None,
    bot_check: str | None = None,
    payload_sha256: str | None = None,
    source: str | None = None,
    recorded_by: str | None = None,
    edge_received_at: datetime | None = None,
    release_of_event_id: str | uuid.UUID | None = None,
    release_outcome: str | None = None,
    release_cause: str | None = None,
    allowed_purposes: Collection[str] | None = None,
    contact_verification: str = "none",
    arrived_at: datetime | None = None,
) -> Event:
    """Append one event to the chain. The only writer of consentvault.event."""
    chans, purps, kind, norm = _validate(
        conn, contact=contact, event_type=event_type, channels=channels, purposes=purposes, method=method,
        origin=origin, disclosure_sha256=disclosure_sha256, contact_kind=contact_kind, region=region,
        captured_at=captured_at, edge_received_at=edge_received_at, release_of_event_id=release_of_event_id,
        release_outcome=release_outcome, release_cause=release_cause, allowed_purposes=allowed_purposes,
        contact_verification=contact_verification)

    values: dict[str, Any] = {
        "event_id": uuid.uuid4(),
        "subject_key": make_subject_key(norm, subject_key),
        "contact_kind": kind,
        "contact_norm": norm,
        "contact_salt": None,
        "contact_commit": None,
        "event_type": event_type,
        "channels": chans,
        "purposes": purps,
        "disclosure_sha256": disclosure_sha256,
        "method": method,
        "origin": origin,
        "captured_at": captured_at,
        "received_at": None,
        "edge_received_at": edge_received_at,
        "page_url": page_url,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "session_ref": session_ref,
        "bot_check": bot_check,
        "payload_sha256": payload_sha256,
        "source": source,
        "recorded_by": recorded_by,
        "release_of_event_id": uuid.UUID(str(release_of_event_id)) if release_of_event_id is not None else None,
        "release_outcome": release_outcome,
        "release_cause": release_cause,
        "contact_verification": contact_verification,
        "hash_version": CURRENT_HASH_VERSION,
    }
    try:
        with conn.transaction():
            conn.execute(_LOCK_SQL)
            received = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            if captured_at is not None and captured_at > (arrived_at or received) + MAX_CAPTURE_SKEW:
                raise ClockSkewError(
                    f"captured_at {captured_at.isoformat()} is later than the vault's receipt time plus "
                    f"{int(MAX_CAPTURE_SKEW.total_seconds() // 60)} minutes; the vault orders events by arrival, "
                    "and a claimed time in the future is refused"
                )
            values["contact_salt"] = conn.execute(
                "SELECT consentvault.mint_contact_salt(%s) AS salt", (norm,)).fetchone()["salt"]
            values["contact_commit"] = contact_commitment(values["contact_salt"], norm)
            values["received_at"] = received
            values["captured_at"] = captured_at or received
            head = conn.execute(_HEAD_SQL).fetchone()
            values["seq"] = head["seq"] + 1 if head else 1
            prev = head["row_hash"] if head else GENESIS
            row_hash = compute_row_hash(prev, values, CURRENT_HASH_VERSION)
            cols = list(values) + ["prev_hash", "row_hash"]
            params = list(values.values()) + [prev, row_hash]
            conn.execute(_insert_event_sql(cols), params)
    except psycopg.Error as exc:
        raise LedgerError(f"event refused by the database: {describe(exc)}") from exc
    return Event(seq=values["seq"], event_id=str(values["event_id"]), row_hash=row_hash, prev_hash=prev)


def record_tenant_event(
    conn: psycopg.Connection,
    crypto,
    *,
    contact: str,
    event_type: str,
    channels: Iterable[str],
    purposes: Iterable[str],
    method: str,
    origin: str,
    disclosure_sha256: str | None = None,
    contact_kind: str | None = None,
    region: str | None = None,
    subject_key: str | None = None,
    captured_at: datetime | None = None,
    page_url: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    session_ref: str | None = None,
    bot_check: str | None = None,
    payload: bytes | None = None,
    source: str | None = None,
    source_id: str | uuid.UUID | None = None,
    brand_ids: Iterable[str | uuid.UUID] = (),
    attribution: dict | None = None,
    recorded_by: str | None = None,
    edge_received_at: datetime | None = None,
    release_of_event_id: str | uuid.UUID | None = None,
    release_outcome: str | None = None,
    release_cause: str | None = None,
    allowed_purposes: Collection[str] | None = None,
    contact_verification: str = "none",
    source_system_id: str | uuid.UUID | None = None,
    display: dict | None = None,
    arrived_at: datetime | None = None,
) -> Event:
    """Append one hash-version-2 event to the current organisation's chain.

    The pushes the event causes to connected systems are queued in the same transaction
    (``sync.outbox.enqueue_event_pushes``), so the event and its pushes commit together or not at all; an
    ``OutboxError`` rolls the event back. ``source_system_id`` names the connected system whose signal caused the
    event (it is never pushed its own signal back).

    The contact record list is written in the same transaction (``records.write_event_records``): the record of the
    contact point, its derived index, and, when the capture carried a ``display`` ``{name?, company?}``, the sealed name
    and company. A failure there rolls the event back too. ``display`` is never part of the event, its evidence or its
    chain; it goes only to the display table, under the organisation's display key.

    Needs an entered tenant (``tenancy.tokens.org_transaction``) and a ``tenancy.crypto.TenantCrypto``. The contact
    point, subject key, salt and evidence fields are stored only as ciphertexts under the contact's data key; the row
    carries keyed fingerprints and digests, so deleting the contact's key shreds the person while every chain link
    still verifies.
    """
    from .tenancy import crypto as tc  # the multi-tenant layer needs the 'cloud' extra; the core does not
    from .tenancy.errors import TenantRequiredError
    from .tenancy.keys_protocol import WrappedKey

    chans, purps, kind, norm = _validate(
        conn, contact=contact, event_type=event_type, channels=channels, purposes=purposes, method=method,
        origin=origin, disclosure_sha256=disclosure_sha256, contact_kind=contact_kind, region=region,
        captured_at=captured_at, edge_received_at=edge_received_at, release_of_event_id=release_of_event_id,
        release_outcome=release_outcome, release_cause=release_cause, allowed_purposes=allowed_purposes,
        contact_verification=contact_verification)
    if payload is not None and not isinstance(payload, bytes):
        raise InvalidEventError("payload must be bytes (it is stored only as a keyed hash)")
    try:
        brands = sorted({uuid.UUID(str(b)) for b in brand_ids})
        source_uuid = uuid.UUID(str(source_id)) if source_id is not None else None
        release_uuid = uuid.UUID(str(release_of_event_id)) if release_of_event_id is not None else None
    except ValueError as exc:
        raise InvalidEventError(f"source_id, brand_ids and release_of_event_id must be UUIDs: {describe(exc)}") from exc
    attribution_sha = attribution_digest(attribution)
    subject = make_subject_key(norm, subject_key)
    event_id = uuid.uuid4()
    rid = str(event_id)

    try:
        with conn.transaction():
            org = conn.execute("SELECT consentvault.current_org() AS org").fetchone()["org"]
            if org is None:
                raise TenantRequiredError("no tenant entered: open the write inside tenancy.tokens.org_transaction")
            conn.execute(_LOCK_SQL)
            received = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            if captured_at is not None and captured_at > (arrived_at or received) + MAX_CAPTURE_SKEW:
                raise ClockSkewError(
                    f"captured_at {captured_at.isoformat()} is later than the vault's receipt time plus "
                    f"{int(MAX_CAPTURE_SKEW.total_seconds() // 60)} minutes; the vault orders events by arrival, "
                    "and a claimed time in the future is refused"
                )
            fp = crypto.contact_fingerprint(org, kind, norm)
            # a capture token may not read evidence rows: the writer reads through two owner functions
            held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
            if held is None:
                ck = crypto.new_contact_key(org)
                data_key, key_version = ck.data_key, ck.wrapped.key_version
                salt = os.urandom(32).hex()
                conn.execute(
                    "INSERT INTO consentvault.contact_key (org_id, contact_fp, wrapped_key, key_version, salt_ct)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (org, fp, ck.wrapped.ciphertext, key_version,
                     tc.encrypt_field(data_key, org, fp, "contact_salt", salt)))
            else:
                key_version = held["key_version"]
                data_key = crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), key_version))
                salt = tc.decrypt_text(data_key, org, fp, "contact_salt", held["salt_ct"])
            plain = {"contact_norm": norm, "subject_key": subject, "page_url": page_url, "client_ip": client_ip,
                     "user_agent": user_agent, "session_ref": session_ref,
                     "attribution": canonical_dumps(attribution) if attribution is not None else None}
            cipher = {_CIPHER_COLUMNS_V2[f]: (tc.encrypt_field(data_key, org, rid, f, v) if v is not None else None)
                      for f, v in plain.items()}
            evidence = {**plain, "contact_salt": salt, "attribution_sha256": attribution_sha}
            head = conn.execute("SELECT * FROM consentvault.ledger_head()").fetchone()
            prev = head["row_hash"] if head else GENESIS
            row: dict[str, Any] = {
                "seq": head["seq"] + 1 if head else 1,
                "event_id": event_id,
                "org_id": org,
                "subject_fp": crypto.subject_fingerprint(org, subject),
                "contact_kind": kind,
                "contact_fp": fp,
                "contact_commit": contact_commitment(salt, norm),
                "subject_commit": subject_commitment(salt, subject),
                "evidence_sha256": evidence_sha256(evidence),
                "event_type": event_type,
                "channels": chans,
                "purposes": purps,
                "disclosure_sha256": disclosure_sha256,
                "method": method,
                "origin": origin,
                "captured_at": captured_at or received,
                "received_at": received,
                "edge_received_at": edge_received_at,
                "bot_check": bot_check,
                "payload_sha256": tc.payload_mac(data_key, payload) if payload is not None else None,
                "source": source,
                "source_id": source_uuid,
                "brand_ids": brands,
                "key_version": key_version,
                "recorded_by": recorded_by,
                "release_of_event_id": release_uuid,
                "release_outcome": release_outcome,
                "release_cause": release_cause,
                "contact_verification": contact_verification,
                "hash_version": 2,
            }
            row_hash = compute_row_hash(prev, row, 2)
            cols = list(row) + list(cipher) + ["prev_hash", "row_hash"]
            params = list(row.values()) + list(cipher.values()) + [prev, row_hash]
            conn.execute(_insert_event_sql(cols), params)
            from .sync.outbox import enqueue_event_pushes
            pushes = enqueue_event_pushes(conn, event_id=rid, contact_fp=fp, contact=norm, data_key=data_key,
                                          source_system_id=source_system_id)
            from .records import write_event_records
            write_event_records(conn, crypto, org=org, event_id=rid, contact_fp=fp, contact_kind=kind, contact_norm=norm,
                                display=display)
            # confirmations.md section 5 (core change R1): one send intent per enabled rule of this grant's source, in the
            # event's own transaction, so the event and its intents commit together or not at all
            # (only a grant is confirmed; a stop, a release or an erasure's stop enqueues nothing, and the operator console role
            # that writes an erasure's stop holds no right to the enqueue function)
            if event_type == "grant":
                from .confirmations import enqueue_confirmation_intents
                enqueue_confirmation_intents(conn, event_id=rid, contact_fp=fp)
    except psycopg.Error as exc:
        raise LedgerError(f"event refused by the database: {describe(exc)}") from exc
    return Event(seq=row["seq"], event_id=rid, row_hash=row_hash, prev_hash=prev, pushes=pushes)


def _plaintext_breaks(conn: psycopg.Connection, crypto, row: dict) -> list[Break]:
    """Decrypt a version-2 row and check its fingerprint, commitments and evidence digest against the plaintext.

    A row covered by a completed erasure of its contact (its sequence at or before the sequence the erasure recorded) is
    skipped: its links still verify; its content no longer can, and a key held now is a returning person's. A row with no
    contact key that no completed erasure covers is a break (``contact_key_missing``): only an erasure makes a row read as
    erased. A completed erasure of the contact with no recorded sequence (``erasure_coverage``) is a break for every row of
    that contact (``erasure_without_sequence``); nothing is ever decided by a clock. A ciphertext that fails authentication
    is a break. A key provider that cannot answer raises.
    """
    from .tenancy import crypto as tc
    from .tenancy.errors import FieldCryptoError
    from .tenancy.keys_protocol import WrappedKey

    seq, eid, org = row["seq"], str(row["event_id"]), row["org_id"]
    cover = conn.execute("SELECT coalesce(bool_or(c.erasure_id IS NULL), false) AS unsequenced,"
                         " coalesce(bool_or(c.covers_through_seq >= %s), false) AS covered"
                         " FROM consentvault.erasure_request r LEFT JOIN consentvault.erasure_coverage c"
                         " ON c.org_id = r.org_id AND c.erasure_id = r.erasure_id"
                         " WHERE r.org_id = %s AND r.contact_fp = %s AND r.status = 'completed'",
                         (seq, org, row["contact_fp"])).fetchone()
    if cover["unsequenced"]:
        return [Break(seq, eid, "erasure_without_sequence")]
    if cover["covered"]:
        # a completed erasure covering this sequence destroyed the key it was sealed under; the row reads as erased
        # (its links and hashes are checked by the caller either way)
        return []
    held = conn.execute("SELECT wrapped_key, key_version, salt_ct FROM consentvault.contact_key"
                        " WHERE org_id = %s AND contact_fp = %s", (org, row["contact_fp"])).fetchone()
    if held is None:
        return [Break(seq, eid, "contact_key_missing")]
    data_key = crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    try:
        salt = tc.decrypt_text(data_key, org, row["contact_fp"], "contact_salt", held["salt_ct"])
        plain = {f: (tc.decrypt_text(data_key, org, eid, f, row[col]) if row[col] is not None else None)
                 for f, col in _CIPHER_COLUMNS_V2.items()}
    except FieldCryptoError:
        return [Break(seq, eid, "ciphertext_invalid")]
    breaks: list[Break] = []
    attribution = json.loads(plain["attribution"]) if plain["attribution"] is not None else None
    evidence = {**plain, "contact_salt": salt, "attribution_sha256": attribution_digest(attribution)}
    if evidence_sha256(evidence) != row["evidence_sha256"]:
        breaks.append(Break(seq, eid, "evidence_mismatch"))
    if contact_commitment(salt, plain["contact_norm"]) != row["contact_commit"]:
        breaks.append(Break(seq, eid, "contact_commit_mismatch"))
    if subject_commitment(salt, plain["subject_key"]) != row["subject_commit"]:
        breaks.append(Break(seq, eid, "subject_commit_mismatch"))
    if crypto.contact_fingerprint(org, row["contact_kind"], plain["contact_norm"]) != row["contact_fp"]:
        breaks.append(Break(seq, eid, "contact_fp_mismatch"))
    if crypto.subject_fingerprint(org, plain["subject_key"]) != row["subject_fp"]:
        breaks.append(Break(seq, eid, "subject_fp_mismatch"))
    return breaks


def _anchor_breaks(rows_by_key: dict[tuple[Any, int], dict], anchors: list[dict], label: str) -> list[Break]:
    breaks: list[Break] = []
    for a in anchors:
        row = rows_by_key.get((a["org_id"], a["seq"]))
        if row is None:
            breaks.append(Break(a["seq"], "", f"anchored_row_missing:{label}"))
        elif row["row_hash"] != a["row_hash"]:
            breaks.append(Break(a["seq"], str(row["event_id"]), f"anchored_row_changed:{label}"))
    return breaks


def read_file_sink(path: str) -> list[dict]:
    """Read the anchors a file sink holds (one JSON object per line). A sink that cannot be read is an error."""
    anchors: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("chain") == "raw_post":  # the raw post chain's anchors are read by rawpost.verify_raw_anchors
                        continue
                    anchor = {"seq": int(rec["seq"]), "row_hash": str(rec["row_hash"])}
                    if rec.get("org_id"):
                        anchor["org_id"] = str(uuid.UUID(str(rec["org_id"])))
                    anchors.append(anchor)
                except (ValueError, KeyError, TypeError) as exc:
                    raise ChainError(f"anchor sink {path} line {n} is not an anchor record: {describe(exc)}") from exc
    except OSError as exc:
        raise ChainError(f"cannot read the anchor sink {path}: {describe(exc)}") from exc
    return anchors


def verify_chain(conn: psycopg.Connection, *, sink_file: str | None = None, crypto=None) -> list[Break]:
    """Recompute every row hash and link, then check every anchor. Returns the breaks found (empty = intact).

    Each organisation's chain is checked on its own (genesis, sequence and links per organisation); a caller inside a
    tenant sees only its own. An anchor (a row in ``chain_head``, and every record of ``sink_file`` when given) names
    a sequence number and the row hash it had. If the ledger no longer holds that row, or holds a different one, the
    tail was cut or changed after the anchor was taken, and that is a break. A sink record without an ``org_id``
    belongs to the home organisation.

    Version-2 rows verify from their stored digests for everyone. With ``crypto`` (a ``TenantCrypto``) their
    ciphertexts are also decrypted and the fingerprints, commitments and evidence digest re-checked.
    """
    breaks: list[Break] = []
    seen: dict[tuple[Any, int], dict] = {}
    expected_prev = GENESIS
    expected_seq = 1
    current_org: Any = object()
    for row in conn.execute("SELECT * FROM consentvault.event ORDER BY org_id, seq"):
        if row["org_id"] != current_org:
            current_org, expected_prev, expected_seq = row["org_id"], GENESIS, 1
        seen[(row["org_id"], row["seq"])] = {"event_id": row["event_id"], "row_hash": row["row_hash"]}
        eid = str(row["event_id"])
        if row["seq"] != expected_seq:
            breaks.append(Break(row["seq"], eid, "seq_gap"))
        if row["prev_hash"] != expected_prev:
            breaks.append(Break(row["seq"], eid, "prev_hash_mismatch"))
        if row["hash_version"] not in HASH_VERSIONS:
            breaks.append(Break(row["seq"], eid, "unknown_hash_version"))
        elif compute_row_hash(row["prev_hash"], row, row["hash_version"]) != row["row_hash"]:
            breaks.append(Break(row["seq"], eid, "row_hash_mismatch"))
        if row["hash_version"] == 2:
            if crypto is not None:
                breaks += _plaintext_breaks(conn, crypto, row)
        elif row["contact_commit"] != contact_commitment(row["contact_salt"], row["contact_norm"]):
            breaks.append(Break(row["seq"], eid, "contact_commit_mismatch"))
        expected_prev = row["row_hash"]
        expected_seq = row["seq"] + 1
    # ordered by time, not head_id: in multi mode the runtime role cannot read the internal bigint ids
    db_anchors = conn.execute(
        "SELECT org_id, seq, row_hash FROM consentvault.chain_head ORDER BY anchored_at, seq").fetchall()
    breaks += _anchor_breaks(seen, db_anchors, "chain_head")
    if sink_file and (os.path.exists(sink_file) or db_anchors):
        home = conn.execute("SELECT consentvault.home_org() AS org").fetchone()["org"]
        sink = [{**a, "org_id": uuid.UUID(str(a["org_id"])) if a.get("org_id") else home}
                for a in read_file_sink(sink_file)]
        breaks += _anchor_breaks(seen, sink, "sink")
    return breaks
