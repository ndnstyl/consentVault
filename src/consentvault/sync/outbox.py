"""The transactional outbox: queue the pushes a consent event causes, inside the transaction that records it.

**The hook** (called by ``ledger.record_tenant_event`` itself since the integration pass, so capture, release and
signal writes all go through it): right after the INSERT of an event, inside the same ``conn.transaction()``, call

    enqueue_event_pushes(conn, event_id=<the new event id>, contact_fp=<its fingerprint>, contact=<normalised
                         contact point>, data_key=<the contact's data key, already open in that function>)

and let any exception propagate, so the event and its queued pushes commit together or not at all. Pass
``source_system_id`` when the event was caused by a signal from a connected system (that system is never pushed
its own signal back). The function:

1. advances the state version of every (channel, purpose) the event touches, from the ledger itself
   (``consentvault.sync_advance_state``); a key whose state did not move queues nothing, so repeating a stop or a
   grant never pushes twice;
2. for each key that moved and each connected system (paused ones included), builds the push body, encrypts it under
   the contact's data key and queues it (``consentvault.sync_enqueue``); older queued pushes for the same key and
   system that nobody has started delivering become ``superseded``, so only the latest state is ever sent.

The caller needs the token scope it already has (``capture``, ``capture_verified`` or ``admin``); no table privilege is
involved. The hook refuses (``OutboxTransactionError``) when it is called outside a transaction, because an outbox
write that commits on its own would break the guarantee it exists for.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import psycopg

from ..safelog import db_code, describe, refusal_code
from ..tenancy import crypto as tc
from .errors import OutboxError, OutboxTransactionError

# the database's refusal of a push-start stamp on an attempt another worker has taken (its registered code, never its text)
PUSH_START_REFUSED = db_code("sync_attempt_started", "consentvault sync: a push started on an attempt that is no longer open")


def push_start_taken_over(exc: BaseException) -> bool:
    """Whether a push-start stamp was refused because the attempt is no longer open: another worker took the row."""
    return isinstance(exc, psycopg.errors.ObjectNotInPrerequisiteState) and refusal_code(exc) == PUSH_START_REFUSED

PAYLOAD_COLUMN = "outbox_payload"
ERROR_COLUMN = "delivery_error"


@dataclass(frozen=True)
class StateChange:
    channel: str
    purpose: str
    version: int
    state: str
    basis_event_id: str
    reason: str
    at: datetime


@dataclass(frozen=True)
class Queued:
    outbox_id: str
    system_id: str
    change: StateChange


@dataclass(frozen=True)
class EnqueueResult:
    changes: tuple[StateChange, ...]
    queued: tuple[Queued, ...]


def iso_z(value: datetime) -> str:
    """UTC ISO 8601 with a trailing Z, the format of every timestamp on the wire."""
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_body(*, org_id, contact: str, contact_fp: str, contact_form: str, change: StateChange) -> bytes:
    """The exact bytes that are signed and sent (suppression-sync.md): keys sorted, no whitespace."""
    if contact_form not in ("plaintext", "fingerprint"):
        raise OutboxError(f"unknown contact_form {contact_form!r}")
    body = {
        "org_id": str(org_id),
        "contact": contact if contact_form == "plaintext" else contact_fp,
        "channel": change.channel,
        "purpose": change.purpose,
        "state": change.state,
        "version": change.version,
        "basis_event_id": str(change.basis_event_id),
        "reason": change.reason,
        "at": iso_z(change.at),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def enqueue_event_pushes(
    conn: psycopg.Connection,
    *,
    event_id,
    contact_fp: str,
    contact: str,
    data_key: bytes,
    source_system_id=None,
) -> EnqueueResult:
    """Queue the pushes caused by one just-inserted event. See the module docstring for the contract."""
    if conn.info.transaction_status != psycopg.pq.TransactionStatus.INTRANS:
        raise OutboxTransactionError(
            "enqueue_event_pushes must run inside the transaction that inserts the event "
            "(conn.transaction()), so the event and its pushes commit together")
    skip = uuid.UUID(str(source_system_id)) if source_system_id is not None else None
    try:
        org = conn.execute("SELECT consentvault.current_org() AS org").fetchone()["org"]
        moved = conn.execute("SELECT * FROM consentvault.sync_advance_state(%s, %s)",
                             (uuid.UUID(str(event_id)), contact_fp)).fetchall()
        changes = tuple(StateChange(r["channel"], r["purpose"], r["version"], r["state"], str(r["basis_event_id"]),
                                    r["reason"], r["at"]) for r in moved)
        # Twenty takes its own signals back (the documented echo exception, twenty.md 3.6), and a ledger event that moved no
        # state still queues a Twenty refresh: the record converges on any fresh fact, not only on the reconcile
        echo = _echo_targets(conn)
        if not changes:
            for system_id in sorted(echo):
                outbox_id = uuid.uuid4()
                conn.execute("SELECT consentvault.sync_enqueue_refresh(%s, %s, %s, %s)",
                             (outbox_id, system_id, contact_fp,
                              tc.encrypt_field(data_key, org, str(outbox_id), PAYLOAD_COLUMN, b'{"kind":"refresh"}')))
            return EnqueueResult((), ())
        targets = conn.execute("SELECT * FROM consentvault.sync_targets()").fetchall()
        queued: list[Queued] = []
        for change in changes:
            for target in targets:
                if skip is not None and target["system_id"] == skip and skip not in echo:
                    continue
                outbox_id = uuid.uuid4()
                body = build_body(org_id=org, contact=contact, contact_fp=contact_fp,
                                  contact_form=target["contact_form"], change=change)
                payload_ct = tc.encrypt_field(data_key, org, str(outbox_id), PAYLOAD_COLUMN, body)
                got = conn.execute(
                    "SELECT consentvault.sync_enqueue(%s, %s, %s, %s, %s, %s, %s) AS id",
                    (outbox_id, target["system_id"], contact_fp, change.channel, change.purpose, change.version,
                     payload_ct)).fetchone()["id"]
                if got is not None:
                    queued.append(Queued(str(got), str(target["system_id"]), change))
        return EnqueueResult(changes, tuple(queued))
    except psycopg.Error as exc:
        raise OutboxError(f"the pushes for event {event_id} could not be queued: {describe(exc)}") from exc


def _echo_targets(conn) -> set:
    """The connected systems that take their own signals back (the Twenty connector, twenty.md 3.6)."""
    return {r["system_id"] for r in conn.execute("SELECT * FROM consentvault.sync_echo_targets()").fetchall()}


def decrypt_payload(data_key: bytes, org_id, outbox_id, payload_ct: bytes) -> bytes:
    """Open a queued body (the worker's side)."""
    return tc.decrypt_field(data_key, org_id, str(outbox_id), PAYLOAD_COLUMN, payload_ct)
