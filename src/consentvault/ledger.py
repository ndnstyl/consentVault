"""The ledger: the only writer of events, and the chain verifier."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Collection, Iterable

import psycopg

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
VERIFIED = ("otp", "inbound_keyword")

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
}

_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext('consentvault.ledger'))"


@dataclass(frozen=True)
class Event:
    seq: int
    event_id: str
    row_hash: str
    prev_hash: str


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
    return link_hash(prev_hash, row["contact_commit"], subject_commitment(row["contact_salt"], row["subject_key"]),
                     content_sha256(row, hash_version))


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
) -> Event:
    """Append one event to the chain. The only writer of consentvault.event."""
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
            if captured_at is not None and captured_at > received + MAX_CAPTURE_SKEW:
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
            head = conn.execute("SELECT seq, row_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1").fetchone()
            values["seq"] = head["seq"] + 1 if head else 1
            prev = head["row_hash"] if head else GENESIS
            row_hash = compute_row_hash(prev, values, CURRENT_HASH_VERSION)
            cols = list(values) + ["prev_hash", "row_hash"]
            params = list(values.values()) + [prev, row_hash]
            conn.execute(
                f"INSERT INTO consentvault.event ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})",
                params,
            )
    except psycopg.Error as exc:
        raise LedgerError(f"event refused by the database: {exc}") from exc
    return Event(seq=values["seq"], event_id=str(values["event_id"]), row_hash=row_hash, prev_hash=prev)


def _anchor_breaks(rows_by_seq: dict[int, dict], anchors: list[dict], label: str) -> list[Break]:
    breaks: list[Break] = []
    for a in anchors:
        row = rows_by_seq.get(a["seq"])
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
                    anchors.append({"seq": int(rec["seq"]), "row_hash": str(rec["row_hash"])})
                except (ValueError, KeyError, TypeError) as exc:
                    raise ChainError(f"anchor sink {path} line {n} is not an anchor record: {exc}") from exc
    except OSError as exc:
        raise ChainError(f"cannot read the anchor sink {path}: {exc}") from exc
    return anchors


def verify_chain(conn: psycopg.Connection, *, sink_file: str | None = None) -> list[Break]:
    """Recompute every row hash and link, then check every anchor. Returns the breaks found (empty = intact).

    An anchor (a row in ``chain_head``, and every record of ``sink_file`` when given) names a sequence number and
    the row hash it had. If the ledger no longer holds that row, or holds a different one, the tail was cut or
    changed after the anchor was taken, and that is a break.
    """
    breaks: list[Break] = []
    expected_prev = GENESIS
    expected_seq = 1
    cur = conn.execute("SELECT * FROM consentvault.event ORDER BY seq")
    seen: dict[int, dict] = {}
    for row in cur:
        seen[row["seq"]] = {"event_id": row["event_id"], "row_hash": row["row_hash"]}
        eid = str(row["event_id"])
        if row["seq"] != expected_seq:
            breaks.append(Break(row["seq"], eid, "seq_gap"))
        if row["prev_hash"] != expected_prev:
            breaks.append(Break(row["seq"], eid, "prev_hash_mismatch"))
        if row["hash_version"] not in HASH_VERSIONS:
            breaks.append(Break(row["seq"], eid, "unknown_hash_version"))
        elif compute_row_hash(row["prev_hash"], row, row["hash_version"]) != row["row_hash"]:
            breaks.append(Break(row["seq"], eid, "row_hash_mismatch"))
        if row["contact_commit"] != contact_commitment(row["contact_salt"], row["contact_norm"]):
            breaks.append(Break(row["seq"], eid, "contact_commit_mismatch"))
        expected_prev = row["row_hash"]
        expected_seq = row["seq"] + 1
    db_anchors = conn.execute("SELECT seq, row_hash FROM consentvault.chain_head ORDER BY head_id").fetchall()
    breaks += _anchor_breaks(seen, db_anchors, "chain_head")
    if sink_file and (os.path.exists(sink_file) or db_anchors):
        breaks += _anchor_breaks(seen, read_file_sink(sink_file), "sink")
    return breaks
