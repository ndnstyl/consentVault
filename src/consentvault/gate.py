"""The contact gate: may this contact point be contacted on this channel for this purpose?

Fails closed. A database that cannot answer, a contact that cannot be read, or the absence of
consent all return ``allowed=False`` with a named reason; nothing here ever guesses yes.
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
        return _deny(f"{REASON_BAD_CONTACT}:{describe(exc)}")
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


# Multi-tenant gate: evidence status and the client's approved policy ---------------------------------------------------

MAX_BATCH = 1000


@dataclass(frozen=True)
class GateItem:
    contact: object
    channel: object
    purpose: object


def _fail_answer(outcome, decision_id, evaluated_at) -> dict:
    from .gate_rules.engine import NOTICE

    return {"evidence_status": outcome.evidence_status, "policy_action": outcome.policy_action,
            "policy_version": outcome.policy_version, "decision_id": decision_id,
            "evaluated_at": evaluated_at, "notice": NOTICE}


def _answer(outcome, decision_id: str, evaluated_at: str) -> dict:
    from .gate_rules.engine import NOTICE

    return {
        "evidence_status": outcome.evidence_status,
        "policy_action": outcome.policy_action,
        "policy_version": outcome.policy_version,
        "approved_by": outcome.approved_by,
        "approved_at": _iso(outcome.approved_at),
        "basis_event_ids": list(outcome.basis_event_ids),
        "reasons": list(outcome.reasons),
        "decision_id": decision_id,
        "evaluated_at": evaluated_at,
        "notice": NOTICE,
    }


def _iso(t: datetime | None) -> str | None:
    return None if t is None else t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def tenant_evidence(conn: psycopg.Connection, kind: str, fp: str, channel: str, purpose: str):
    """What the entered organisation's records show for one contact fingerprint, channel and purpose."""
    from .gate_rules.engine import Basis, Evidence, evidence_from_permission

    row = conn.execute(
        "SELECT allowed, reason, deciding_event_id FROM consentvault.current_permission"
        " WHERE org_id = consentvault.current_org() AND contact_kind = %s AND contact_fp = %s"
        " AND channel = %s AND purpose = %s", (kind, fp, channel, purpose)).fetchone()
    star = None
    if row is None:
        s = conn.execute(
            "SELECT reason FROM consentvault.current_permission WHERE org_id = consentvault.current_org()"
            " AND contact_kind = %s AND contact_fp = %s AND channel = %s AND purpose = '*'",
            (kind, fp, channel)).fetchone()
        star = s["reason"] if s else None
    ev = evidence_from_permission(row, star)
    basis = conn.execute(
        "SELECT event_id::text AS event_id, kind FROM ("
        "  SELECT DISTINCT ON (kind) event_id, seq, kind FROM ("
        "    SELECT event_id, seq, CASE WHEN event_type = 'grant' THEN 'g'"
        "           WHEN event_type = 'release' AND origin = 'consumer' AND release_outcome = 'released' THEN 'r'"
        "           WHEN event_type IN ('revoke', 'suppress') THEN 's' END AS kind"
        "    FROM consentvault.event"
        "    WHERE org_id = consentvault.current_org() AND contact_kind = %s AND contact_fp = %s"
        "      AND %s = ANY(channels) AND (%s = ANY(purposes) OR '*' = ANY(purposes))"
        "  ) x WHERE kind IS NOT NULL ORDER BY kind, seq DESC"
        ") y ORDER BY seq", (kind, fp, channel, purpose)).fetchall()
    ids = tuple(r["event_id"] for r in basis)
    grant = None
    g = next((r["event_id"] for r in basis if r["kind"] == "g"), None)
    if g is not None and ev.kind == "consent_record_found":
        gr = conn.execute(
            "SELECT e.channels, e.received_at, e.contact_verification, d.channels AS d_channels"
            "  FROM consentvault.event e LEFT JOIN consentvault.disclosure d"
            "    ON d.org_id = e.org_id AND d.sha256 = e.disclosure_sha256"
            " WHERE e.org_id = consentvault.current_org() AND e.event_id = %s::uuid", (g,)).fetchone()
        grant = Basis(g, tuple(gr["channels"]), gr["received_at"], gr["contact_verification"],
                      tuple(gr["d_channels"] or ()))
    return Evidence(ev.status, ev.reason, ids, grant)


class TenantGate:
    """One gate request inside the entered organisation: validate, read the records, apply the approved policy,
    record the decision. Construct inside ``org_transaction`` with a ``gate_read`` token."""

    def __init__(self, conn: psycopg.Connection, crypto, *, org, requested_by: str | None,
                 region: str | None = None, now: datetime | None = None):
        from .gate_rules.policy import PolicyStoreError, approved_policy
        from .tenancy.pipeline import org_channels, org_purposes

        self.conn, self.crypto, self.org = conn, crypto, org
        self.requested_by, self.region = requested_by, region
        self._pinned_now = now   # tests only; a gate with none reads the database's clock at each check
        self.channels = org_channels(conn)
        self.purposes = org_purposes(conn)
        self.policy_error: str | None = None
        try:
            self.policy = approved_policy(conn)
        except PolicyStoreError:
            self.policy, self.policy_error = None, "policy"

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
        """(HTTP status, answer). 200 with the policy outcome, or 503 when the records could not be read."""
        from .gate_rules import engine
        from .gate_rules.policy import PolicyStoreError, missing_elements
        from .tenancy.errors import KeyProviderError

        kind, norm, channel, purpose = self.validate(item)
        now = self._pinned_now or dbclock.now(self.conn)
        evaluated_at = _iso(now)
        try:
            fp = self.crypto.contact_fingerprint(self.org, kind, norm)
        except KeyProviderError:
            out = engine.unavailable("key", self.policy, channel, purpose)
            return 503, _fail_answer(out, None, evaluated_at)
        cause = self.policy_error
        out = None
        if cause is None:
            try:
                with self.conn.transaction():  # a savepoint: a failed read leaves the decision recordable
                    ev = tenant_evidence(self.conn, kind, fp, channel, purpose)
                    version = self.policy.checklist_version(purpose) if self.policy else None
                    if version is not None and ev.kind == engine.FOUND and ev.grant is not None:
                        ev = engine.incomplete(ev, missing_elements(self.conn, ev.grant.event_id, version))
                    out = engine.decide(ev, self.policy, channel=channel, purpose=purpose, contact_fp=fp,
                                        now=now)
            except PolicyStoreError:
                cause = "doc_check_results"
            except engine.PolicyRuleError:
                cause = "policy_rule"
            except psycopg.Error:
                cause = "database"
        if out is None:
            out = engine.unavailable(cause, self.policy, channel, purpose)
        decision_id = self._record(fp, channel, purpose, out, batch_id)
        if cause is not None:
            return 503, _fail_answer(out, decision_id, evaluated_at)
        return 200, _answer(out, decision_id, evaluated_at)

    def _record(self, fp: str, channel: str, purpose: str, out, batch_id: str | None) -> str:
        import uuid as _uuid

        decision_id = str(_uuid.uuid4())
        try:
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO consentvault.gate_decision (org_id, decision_id, contact_fp, channel, purpose,"
                    " evidence_status, policy_action, policy_version, approved_by, approved_at, basis_event_ids,"
                    " reasons, requested_by, batch_id)"
                    " VALUES (consentvault.current_org(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::uuid[], %s, %s, %s)",
                    (decision_id, fp, channel, purpose, out.evidence_status, out.policy_action, out.policy_version,
                     out.approved_by, out.approved_at, list(out.basis_event_ids), list(out.reasons),
                     self.requested_by, batch_id))
                # the usage tally rides the same savepoint: a decision is counted if and only if it is recorded
                self.conn.execute("INSERT INTO consentvault.gate_check_tally (org_id, day)"
                                  " VALUES (consentvault.current_org(), (clock_timestamp() AT TIME ZONE 'UTC')::date)")
        except psycopg.Error as exc:
            raise GateRecordError(f"the gate decision could not be recorded: {type(exc).__name__}") from exc
        return decision_id


class GateRecordError(ConsentVaultError):
    """A gate answer could not be recorded, so it is not given."""
