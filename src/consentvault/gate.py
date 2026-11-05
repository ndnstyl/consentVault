"""The contact check: the facts and history recorded for a contact point, and nothing else.

ConsentVault is a record of consent. It does not decide whether anyone may be contacted, so the answer carries no verdict:
no ``allowed``, no ``proceed`` or ``hold``, no deny-by-default. It lists every line of the contact point's history as it
was written (grants, stops, and any release row written before the rule changed), every stop with its source and the posts
that triggered it, and every lift with the post that lifted it. A contact point with no line answers ``no_record_found``.
A record that cannot be read answers ``unavailable`` with the reason, never a stand-in verdict. The check never writes to a
raw post.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import psycopg

from . import dbclock
from .safelog import describe
from .errors import ConsentVaultError, NormalizationError
from .ledger import CHANNELS
from .normalize import normalize_contact

NOTICE = "The records held for this contact point, as recorded. ConsentVault records consent and does not decide."

STATUS_FOUND = "records_found"
STATUS_NONE = "no_record_found"
STATUS_UNAVAILABLE = "unavailable"
REASON_DB_DOWN = "database_unreachable"

STOP_TYPES = ("revoke", "suppress")


def _iso(t: datetime | None) -> str | None:
    return None if t is None else t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class ContactFacts:
    """What the vault holds for one contact point. ``history`` is every event line in the order written, ``stops`` the
    stop lines among them, ``lifts`` the links from a stop to the post that lifted it. No field says what to do."""

    status: str
    reason: str | None = None
    history: tuple[dict, ...] = ()
    stops: tuple[dict, ...] = ()
    lifts: tuple[dict, ...] = ()

    @property
    def read(self) -> bool:
        return self.status != STATUS_UNAVAILABLE

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(line["event_id"] for line in self.history)

    @property
    def label(self) -> str:
        """The evidence-status label a recorded check carries."""
        return f"{STATUS_UNAVAILABLE}:{self.reason}" if self.status == STATUS_UNAVAILABLE else self.status

    def as_dict(self) -> dict:
        out = {"status": self.status, "history": list(self.history), "stops": list(self.stops), "lifts": list(self.lifts)}
        if self.reason is not None:
            out["reason"] = self.reason
        return out


def unavailable(reason: str) -> ContactFacts:
    return ContactFacts(STATUS_UNAVAILABLE, reason)


_LINE_COLUMNS = ("seq, event_id::text AS event_id, event_type, origin, method, source, recorded_by, channels, purposes,"
                 " captured_at, received_at, disclosure_sha256, payload_sha256, contact_verification,"
                 " release_of_event_id::text AS release_of_event_id, release_outcome, release_cause")


# A person's history is read in the order the posts arrived, never the order the projection happened to write their events (a
# crash can project an earlier post after a later one). An event that cites no post is placed by its own receipt time.
_POST_OF_EVENT = ("(SELECT {col} FROM consentvault.event_source_post s JOIN consentvault.raw_post p"
                  " ON p.org_id = s.org_id AND p.post_id = s.post_id WHERE s.org_id = event.org_id AND s.event_id = event.event_id"
                  " AND s.role = 'trigger' LIMIT 1)")
# Equal arrival times fall back to the post's own seq (its place in the arrival chain), then the event's seq.
_ARRIVAL_ORDER = (f"coalesce({_POST_OF_EVENT.format(col='p.received_at')}, received_at), "
                  f"coalesce({_POST_OF_EVENT.format(col='p.seq')}, 0), seq")


def _line(row) -> dict:
    out = {
        "event_id": row["event_id"], "seq": row["seq"], "event_type": row["event_type"], "origin": row["origin"],
        "method": row["method"], "source": row["source"], "recorded_by": row["recorded_by"],
        "channels": list(row["channels"]), "purposes": list(row["purposes"]), "captured_at": _iso(row["captured_at"]),
        "received_at": _iso(row["received_at"]), "disclosure_sha256": row["disclosure_sha256"],
        "payload_sha256": row["payload_sha256"], "contact_verification": row["contact_verification"],
    }
    if row["event_type"] == "release":  # a row written before no release could be: shown as the history it is
        out.update(release_of_event_id=row["release_of_event_id"], release_outcome=row["release_outcome"],
                   release_cause=row["release_cause"])
    return out


def _facts(rows, lifts=(), posts=None) -> ContactFacts:
    lines = []
    for r in rows:
        line = _line(r)
        if posts is not None:
            line["source_post_ids"] = list(posts.get(line["event_id"], ()))
        lines.append(line)
    lifted: dict[str, list[str]] = {}
    for lift in lifts:
        lifted.setdefault(lift["stop_event_id"], []).append(lift["lifting_post_id"])
    stops = tuple({**line, "lifted_by_post_ids": lifted.get(line["event_id"], [])}
                  for line in lines if line["event_type"] in STOP_TYPES)
    if not lines:
        return ContactFacts(STATUS_NONE)
    return ContactFacts(STATUS_FOUND, None, tuple(lines), stops, tuple(lifts))


def contact_facts(conn: psycopg.Connection, contact: str, region: str | None = None) -> ContactFacts:
    """The facts and history held for one contact point of the single-company vault. Raises ``NormalizationError`` for a
    contact point that is not a phone number or an email address; a database fault is the answer ``unavailable``."""
    kind, norm = normalize_contact(contact, None, region)
    try:
        rows = conn.execute(
            f"SELECT {_LINE_COLUMNS} FROM consentvault.event WHERE contact_kind = %s AND contact_norm = %s ORDER BY " + _ARRIVAL_ORDER,
            (kind, norm)).fetchall()
    except Exception as exc:  # the answer is "unavailable" with the named cause, never a guess
        return unavailable(f"{REASON_DB_DOWN}:{type(exc).__name__}")
    return _facts(rows)


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
        raise ConsentVaultError(f"contact log write refused by the database: {describe(exc)}") from exc
    return row["contact_log_id"]


def record_tenant_contact(
    conn: psycopg.Connection,
    *,
    org,
    data_key: bytes,
    contact_fp: str,
    contact_kind: str,
    contact_norm: str,
    channel: str,
    outcome: str,
    contacted_at: datetime,
    recorded_by: str,
    ref: str | None = None,
    purpose: str | None = None,
) -> str:
    """Log an outbound message in the entered organisation (confirmations.md section 10, core change C4): the contact point is kept
    only as a ciphertext under the contact's data key, bound to the organisation, this row and the column ``contact_ct`` (the clear
    column stays null, which the tenancy migration already allows). ``contacted_at`` is the time the caller's clock stamped;
    ``recorded_at`` keeps the database default, because the release rule compares it with the ledger's own receipt times. The
    insert returns nothing, so a capture-scope token needs no read of the table. Returns the row's uuid."""
    import uuid as _uuid

    from .tenancy import crypto as tc

    if channel not in CHANNELS:
        raise NormalizationError(f"unknown channel {channel!r}; allowed: {list(CHANNELS)}")
    if contacted_at.tzinfo is None:
        raise NormalizationError("contacted_at must be timezone-aware")
    row_id = _uuid.uuid4()
    try:
        conn.execute(
            "INSERT INTO consentvault.contact_log (org_id, contact_log_uuid, contact_kind, contact_norm, channel, purpose, contacted_at,"
            " outcome, ref, recorded_by, contact_fp, contact_ct) VALUES ((SELECT consentvault.current_org()), %s, %s, NULL, %s, %s, %s,"
            " %s, %s, %s, %s, %s)",
            (row_id, contact_kind, channel, purpose, contacted_at, outcome, ref, recorded_by, contact_fp,
             tc.encrypt_field(data_key, org, str(row_id), "contact_ct", contact_norm)))
    except psycopg.Error as exc:
        raise ConsentVaultError(f"contact log write refused by the database: {describe(exc)}") from exc
    return str(row_id)




# Multi-tenant check: the same facts for one contact fingerprint, recorded as a decision row ----------------------------

MAX_BATCH = 1000


@dataclass(frozen=True)
class GateItem:
    contact: object
    channel: object
    purpose: object


def tenant_facts(conn: psycopg.Connection, kind: str, fp: str) -> ContactFacts:
    """The facts and history the entered organisation holds for one contact fingerprint: its events, the posts that triggered
    them, and the stop lifts. Reads only; the caller holds a read scope."""
    rows = conn.execute(
        f"SELECT {_LINE_COLUMNS} FROM consentvault.event WHERE org_id = consentvault.current_org()"
        " AND contact_kind = %s AND contact_fp = %s ORDER BY " + _ARRIVAL_ORDER, (kind, fp)).fetchall()
    posts: dict[str, list[str]] = {}
    for r in conn.execute(
            "SELECT s.event_id::text AS event_id, s.post_id::text AS post_id FROM consentvault.event_source_post s"
            " JOIN consentvault.event e ON e.org_id = s.org_id AND e.event_id = s.event_id"
            " WHERE s.org_id = consentvault.current_org() AND s.role = 'trigger' AND e.contact_kind = %s AND e.contact_fp = %s"
            " ORDER BY s.recorded_at, s.post_id", (kind, fp)):
        posts.setdefault(r["event_id"], []).append(r["post_id"])
    lifts = tuple({"stop_event_id": r["stop_event_id"], "lifting_post_id": r["lifting_post_id"],
                   "linked_at": _iso(r["linked_at"])} for r in conn.execute(
        "SELECT stop_event_id::text AS stop_event_id, lifting_post_id::text AS lifting_post_id, linked_at"
        " FROM consentvault.stop_lift WHERE org_id = consentvault.current_org() AND contact_fp = %s"
        " ORDER BY linked_at, lifting_post_id", (fp,)))
    return _facts(rows, lifts, posts)


def _answer(facts: ContactFacts, decision_id: str | None, evaluated_at: str) -> dict:
    return {**facts.as_dict(), "decision_id": decision_id, "evaluated_at": evaluated_at, "notice": NOTICE}


class TenantGate:
    """One contact check inside the entered organisation: validate, read the records, record the check. Construct inside
    ``org_transaction`` with a ``gate_read`` token."""

    def __init__(self, conn: psycopg.Connection, crypto, *, org, requested_by: str | None,
                 region: str | None = None, now: datetime | None = None):
        from .tenancy.pipeline import org_channels, org_purposes

        self.conn, self.crypto, self.org = conn, crypto, org
        self.requested_by, self.region = requested_by, region
        self._pinned_now = now   # tests only; a check with none reads the database's clock
        self.channels = org_channels(conn)
        self.purposes = org_purposes(conn)

    def validate(self, item: GateItem) -> tuple[str, str, str, str]:
        """(kind, norm, channel, purpose) or an ``ApiError`` naming the bad field."""
        from .tenancy.admin_base import ApiError
        from .tenancy.pipeline import normalize

        channel, purpose = item.channel, item.purpose
        if not isinstance(channel, str) or channel not in self.channels:
            raise ApiError("invalid_channel", "the channel is not one this organization has")
        if not isinstance(purpose, str) or purpose.strip().lower() not in self.purposes:
            raise ApiError("UnknownPurposeError", "the purpose is not in this organization's configured list")
        kind, norm = normalize(item.contact, self.region)
        return kind, norm, channel, purpose.strip().lower()

    def check(self, item: GateItem, *, batch_id: str | None = None) -> tuple[int, dict]:
        """(HTTP status, answer). 200 with the facts, or 503 when the records could not be read."""
        from .tenancy.errors import KeyProviderError

        kind, norm, channel, purpose = self.validate(item)
        now = self._pinned_now or dbclock.now(self.conn)
        evaluated_at = _iso(now)
        try:
            fp = self.crypto.contact_fingerprint(self.org, kind, norm)
        except KeyProviderError:  # no fingerprint, so nothing to file the check under: answered, not recorded
            return 503, _answer(unavailable("key"), None, evaluated_at)
        try:
            with self.conn.transaction():  # a savepoint: a failed read leaves the check recordable
                facts = tenant_facts(self.conn, kind, fp)
        except psycopg.Error:
            facts = unavailable("database")
        decision_id = self._record(fp, channel, purpose, facts, batch_id)
        return (200 if facts.read else 503), _answer(facts, decision_id, evaluated_at)

    def _record(self, fp: str, channel: str, purpose: str, facts: ContactFacts, batch_id: str | None) -> str:
        import uuid as _uuid

        decision_id = str(_uuid.uuid4())
        try:
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO consentvault.gate_decision (org_id, decision_id, contact_fp, channel, purpose,"
                    " evidence_status, basis_event_ids, reasons, requested_by, batch_id)"
                    " VALUES (consentvault.current_org(), %s, %s, %s, %s, %s, %s::uuid[], %s, %s, %s)",
                    (decision_id, fp, channel, purpose, facts.label, list(facts.event_ids), [], self.requested_by,
                     batch_id))
                # the usage tally rides the same savepoint: a check is counted if and only if it is recorded
                self.conn.execute("INSERT INTO consentvault.gate_check_tally (org_id, day)"
                                  " VALUES (consentvault.current_org(), (clock_timestamp() AT TIME ZONE 'UTC')::date)")
        except psycopg.Error as exc:
            raise GateRecordError(f"the contact check could not be recorded: {type(exc).__name__}") from exc
        return decision_id


class GateRecordError(ConsentVaultError):
    """A contact check could not be recorded, so it is not answered."""
