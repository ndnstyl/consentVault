"""Erasure of one person, and the lifecycle ledger every irreversible step writes outside the database.

Erasing one person deletes the one ``contact_key`` row of the current organisation (``consentvault.erase_contact``,
no organisation argument). Their ciphertexts become unreadable; ``contact_fp`` and every event stay, so the gate still
matches a returning contact to its old stop.

Order of an erasure, each step guarding the next:
1. inside the organisation, take the lifecycle lock and check for a covering legal hold (refused or queued, named);
1b. write the person's stop (``record_erasure_stop``, entered in the ledger as ``erasure_stop`` first): one suppress event over every channel of the organisation and every
   purpose, by fingerprint, method ``written``, source ``erasure``, ``recorded_by = erasure:<id>``. The gate reads events
   by fingerprint, so it answers stopped for this person from now on, whether or not the key still exists, and a later
   capture of the same person meets the stop until a verified grant lifts it under the release rule. Written at the first unheld confirm and again at completion if a grant or release came after it, before the key goes (its ciphertexts need the key);
2. wait while any push of the person's state to a connected system is queued, failed or in flight: the request is held
   with ``wait_reason = pending_suppression_delivery`` (a visible state) and ``resume_waiting`` runs it once every push
   is delivered or dead. Erasing first would leave the stop undeliverable (its payload dies with the key);
3. append an intent entry ``{kind: erasure_intent, contact_fp, erasure_id, erased_at}`` to the lifecycle ledger in the
   write-once archive store (no personal data). If the store refuses, nothing is deleted;
4. delete the contact key (the database re-checks the hold), expire the contact's cached export packages, close the
   request, audit, all in the same transaction as step 1;
5. after commit, append the commit entry ``{kind: erasure_commit, erasure_id, intent_seq}`` and record it in
   ``erasure_ledger_commit`` (``commit_erasures``; a commit that cannot be written yet is an alarm row and is retried by
   the next sweep), then delete cached package objects where the cache store can delete (an Object Lock store cannot:
   those copies are unreadable from step 4 on, and the answer says so).

The ledger is what a restored database replays (``restore.py``): only an intent with a commit is replayed, so an
erasure whose transaction never committed is never executed by a restore.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Optional

import psycopg
import psycopg.sql

from .. import dbclock, history, safelog
from ..safelog import constraint_name, db_refusal_id, describe
from .admin_base import ROLE_ADMIN, ApiError, Ctx, body_dict, iso, need_text, to_uuid
from .errors import TenancyError
from .tokens import TokenKey, mint_org_token, org_transaction

_log = safelog.get("consentvault.tenancy.erasure")

LEDGER_PREFIX = "lifecycle-ledger/"
LEDGER_RETAIN_DAYS = 3650
MAX_LEDGER_ENTRIES = 1_000_000
_MAX_PROBE = 10000


class LifecycleError(TenancyError):
    """An erasure, hold, offboarding or restore step failed; the message names the step and what was left."""


class LedgerUnavailableError(LifecycleError):
    """The write-once archive store did not take (or return) a lifecycle ledger entry; nothing irreversible ran."""


class LedgerIntegrityError(LifecycleError):
    """A lifecycle ledger entry does not chain to the one before it, or does not parse."""


class CachePurgeError(LifecycleError):
    """The contact is erased, but a cached export package object could not be deleted (it is unreadable)."""


# ---- shared plumbing -----------------------------------------------------------------------------------------------------
OPERATOR_CREDENTIAL_PREFIX = "operator:"


@contextmanager
def operator_org(conn: psycopg.Connection, token_key: TokenKey, org_id, scopes=("admin",),
                 operator_id: Optional[str] = None) -> Iterator[uuid.UUID]:
    """Enter one organisation on the operator console's connection for an operator or job step (a two-minute token).

    With ``operator_id`` the signed token names the operator ('operator:<id>'): the database functions that record an
    operator's act (release_hold_as_operator) read the operator from it, never from a parameter."""
    cid = None
    if operator_id is not None:
        if not isinstance(operator_id, str) or not 1 <= len(operator_id) <= 200:
            raise LifecycleError("the operator id is missing or malformed")
        cid = OPERATOR_CREDENTIAL_PREFIX + operator_id
    token = mint_org_token(token_key, to_uuid(org_id, "organization"), list(scopes), credential_id=cid, ttl_seconds=120)
    with org_transaction(conn, token) as org:
        yield org


def audit_org(conn, *, actor_kind: str, actor_id: Optional[str], action: str, target_kind: str, target_id,
              reason: Optional[str], request_id: str) -> None:
    """Append to the entered organisation's audit chain, through ``audit.append`` (which checks the action name against
    ``audit.ACTIONS`` and the request id's shape)."""
    from . import audit

    try:
        audit.append(conn, actor_kind=actor_kind, actor_id=actor_id, action=action, target_kind=target_kind,
                     target_id=None if target_id is None else str(target_id),
                     reason=None if reason is None else reason[:500], request_id=request_id)
    except audit.AuditError as exc:
        raise LifecycleError(f"could not append audit row {action!r}: {describe(exc)}") from exc


def audit_platform(conn, *, operator_id: str, action: str, target_kind: str, target_id, reason: Optional[str],
                   request_id: str) -> None:
    from . import audit

    try:
        audit.append_platform(conn, operator_id=operator_id, action=action, target_kind=target_kind,
                              target_id=None if target_id is None else str(target_id),
                              reason=None if reason is None else reason[:500], request_id=request_id)
    except audit.AuditError as exc:
        raise LifecycleError(f"could not append platform audit row {action!r}: {describe(exc)}") from exc


def hold_in(exc: BaseException) -> Optional[str]:
    """The hold id a database refusal names (``legal_hold_active:<id>``), or None."""
    return db_refusal_id(exc, "legal_hold_active")


def hold_refusal(hold_id: str, detail: str) -> ApiError:
    return ApiError("legal_hold_active", detail, {"hold_id": str(hold_id)})


def covering_hold(conn, contact_fp: Optional[str]) -> Optional[str]:
    """The first active hold of the entered organisation covering the fingerprint (None: org-scope holds only)."""
    row = conn.execute("SELECT consentvault.legal_hold_covering(%s) AS h", (contact_fp,)).fetchone()
    return None if row["h"] is None else str(row["h"])


# How the tenant may see a hold (``consentvault.hold_disclosure``): its own hold by name, an operator's hold only as a neutral
# held state with no reason text, and a legal-process hold the customer has not been told of not at all.
VIEW_OWN, VIEW_NEUTRAL, VIEW_HIDDEN = "member", "operator", "undisclosed"


def hold_view(conn, hold_id) -> str:
    """Inside the entered organisation: ``member``, ``operator`` or ``undisclosed``. A hold that is not there is an error."""
    row = conn.execute("SELECT consentvault.hold_disclosure(%s) AS v", (hold_id,)).fetchone()
    if row is None or row["v"] not in (VIEW_OWN, VIEW_NEUTRAL, VIEW_HIDDEN):
        raise LifecycleError(f"hold {hold_id} is not a hold of the entered organization")
    return row["v"]


def held_note(conn, hold_id) -> Optional[str]:
    """The reason a tenant audit row may carry for work a hold queued: the client's own hold by id, any other none."""
    return f"queued behind legal hold {hold_id}" if hold_view(conn, hold_id) == VIEW_OWN else None


def own_covering_hold(conn, contact_fp: str) -> Optional[str]:
    """The first active hold the client placed itself that covers the fingerprint (readable on the tenant's path)."""
    row = conn.execute("SELECT hold_id FROM consentvault.legal_hold WHERE org_id = (SELECT consentvault.current_org())"
                       " AND released_at IS NULL AND set_by_kind = 'member' AND (scope = 'org' OR %s = ANY (contact_fps))"
                       " ORDER BY set_at, hold_id LIMIT 1", (contact_fp,)).fetchone()
    return None if row is None else str(row["hold_id"])


def ledger_hint(conn) -> int:
    """Where to start probing for the next ledger sequence: one past the highest the database remembers."""
    row = conn.execute(
        "SELECT greatest((SELECT max(ledger_seq) FROM consentvault.erasure_request"
        "                  WHERE org_id = (SELECT consentvault.current_org())),"
        "                (SELECT max(commit_seq) FROM consentvault.erasure_ledger_commit"
        "                  WHERE org_id = (SELECT consentvault.current_org())),"
        "                (SELECT max(greatest(set_ledger_seq, release_ledger_seq)) FROM consentvault.legal_hold"
        "                  WHERE org_id = (SELECT consentvault.current_org()))) AS m").fetchone()
    return (row["m"] or 0) + 1


# ---- the lifecycle ledger ------------------------------------------------------------------------------------------------
class LifecycleLedger:
    """One chained, write-once sequence of lifecycle entries per organisation, in an ``EvidenceStore`` (the log-archive
    Object Lock bucket in the managed service). Entries carry fingerprints and ids only, never a contact point.

    Object keys are ``lifecycle-ledger/<seq:012d>.json``; each entry names the sha256 of the one before it. Appending
    probes forward from a hint, so a restored database whose memory is behind the ledger never overwrites an entry.
    """

    def __init__(self, store, *, clock: Optional[Callable[[], datetime]] = None, retain_days: int = LEDGER_RETAIN_DAYS):
        """``clock`` is the database's clock (``dbclock.datetime_clock``): an entry's time and its retention end are the
        database's, never this host's. There is no default, so a ledger cannot be built on the host clock."""
        self._store, self._retain, self._clock = store, retain_days, clock or self._no_clock

    @staticmethod
    def _no_clock() -> datetime:
        raise LedgerUnavailableError("this ledger has no clock: build it with the database's (dbclock.datetime_clock)")

    @staticmethod
    def _key(seq: int) -> str:
        return f"{LEDGER_PREFIX}{seq:012d}.json"

    def _get(self, org: str, seq: int) -> Optional[bytes]:
        from ..providers.errors import EvidenceNotFoundError, ProviderError

        try:
            return self._store.get(org, self._key(seq))
        except EvidenceNotFoundError:  # loud-failure-exempt: absence is the ruled answer that marks the ledger's end
            return None
        except ProviderError as exc:
            raise LedgerUnavailableError(f"the lifecycle ledger entry {seq} of {org} could not be read: "
                                         f"{type(exc).__name__}") from exc

    def append(self, org_id, entry: dict, *, hint: int = 1) -> tuple[int, str]:
        """Write the next entry; returns (seq, sha256 of the stored bytes)."""
        from ..providers.errors import EvidenceExistsError, ProviderError

        org = str(org_id)
        seq = max(1, int(hint))
        for _ in range(_MAX_PROBE):  # the hint ran ahead of the ledger: walk back to its end
            if seq == 1 or self._get(org, seq - 1) is not None:
                break
            seq -= 1
        for _ in range(_MAX_PROBE):
            prev = self._get(org, seq - 1) if seq > 1 else None
            if seq > 1 and prev is None:
                raise LedgerIntegrityError(f"the lifecycle ledger of {org} has a gap before entry {seq}")
            written_at = self._clock()
            body = dict(entry, v=1, seq=seq, org_id=org, at=written_at.isoformat(),
                        prev_sha256=hashlib.sha256(prev).hexdigest() if prev is not None else None)
            data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            try:
                self._store.put(org, self._key(seq), data, retain_until=written_at + timedelta(days=self._retain))
            except EvidenceExistsError:  # loud-failure-exempt: the slot is taken (the database was behind); probe the next
                seq += 1
                continue
            except ProviderError as exc:
                raise LedgerUnavailableError(f"the archive store did not take lifecycle ledger entry {seq} of {org}: "
                                             f"{type(exc).__name__}; nothing irreversible ran") from exc
            return seq, hashlib.sha256(data).hexdigest()
        raise LedgerUnavailableError(f"no free lifecycle ledger slot for {org} within {_MAX_PROBE} probes")

    def now(self) -> datetime:
        return self._clock()

    def sealed_retention(self, org_id) -> dict[int, datetime]:
        """For each organisation key version that seals a value in an entry (a hold's reason), the end of the retention
        of the last such entry. An entry is kept for ``retain_days`` from its ``at``, the retention it was written with."""
        from .holds import sealed_key_version

        out: dict[int, datetime] = {}
        for e in self.entries(org_id):
            versions = {sealed_key_version(v) for v in e.values() if isinstance(v, str) and v.startswith("ocv1:")}
            if not versions:
                continue
            try:
                until = datetime.fromisoformat(e["at"]) + timedelta(days=self._retain)
            except (KeyError, TypeError, ValueError) as exc:
                raise LedgerIntegrityError(f"lifecycle ledger entry {e.get('seq')} of {org_id} has no readable time"
                                           ) from exc
            for v in versions:
                out[v] = max(out.get(v, until), until)
        return out

    def entries(self, org_id) -> list[dict]:
        """Every entry in order, each checked against the one before it."""
        org, out, prev = str(org_id), [], None
        for seq in range(1, MAX_LEDGER_ENTRIES + 1):
            raw = self._get(org, seq)
            if raw is None:
                return out
            try:
                e = json.loads(raw)
            except ValueError as exc:
                raise LedgerIntegrityError(f"lifecycle ledger entry {seq} of {org} does not parse") from exc
            want = hashlib.sha256(prev).hexdigest() if prev is not None else None
            if e.get("prev_sha256") != want or e.get("seq") != seq or e.get("org_id") != org:
                raise LedgerIntegrityError(f"lifecycle ledger entry {seq} of {org} does not chain to the one before it")
            out.append(e)
            prev = raw
        raise LedgerIntegrityError(f"the lifecycle ledger of {org} is longer than {MAX_LEDGER_ENTRIES} entries")


# ---- client admin: request and read ----------------------------------------------------------------------------------------
WAIT_DELIVERY = "pending_suppression_delivery"
WAIT_INTENT = "uncommitted_ledger_intent"


# the columns of a request every path reads (the runtime role never reads which hold holds it: ``erasure_hold`` names
# the client's own hold only)
ERASURE_COLUMNS = ("org_id, erasure_id, contact_fp, reason, requested_by, requested_at, status, confirmed_by, confirmed_at,"
                   " held_since, decline_reason, completed_at, ledger_seq, ledger_sha256, wait_reason, wait_since")


# ---- the stop an erasure leaves behind --------------------------------------------------------------------------------
ERASURE_SOURCE = "erasure"


def erasure_stop_marker(erasure_id, stop_seq: int = 0, *, unconfirmed: bool = False) -> str:
    """The stop event's identity: the erasure and the sequence number of the ledger entry that records it
    (``erasure:<id>:<seq>``; a restore's unconfirmed replay reads ``erasure-unconfirmed:<id>:<seq>``)."""
    return f"{'erasure-unconfirmed' if unconfirmed else 'erasure'}:{erasure_id}:{int(stop_seq)}"


def erasure_stop_present(conn, fp: str, erasure_id, stop_seq: int) -> Optional[str]:
    """The id of the stop event the database already holds for this ledger entry (confirmed or replayed as unconfirmed),
    or None. Exact identity: erasure and entry sequence number."""
    row = conn.execute("SELECT event_id FROM consentvault.event WHERE org_id = (SELECT consentvault.current_org())"
                       " AND contact_fp = %s AND source = %s AND recorded_by = ANY(%s) ORDER BY seq DESC LIMIT 1",
                       (fp, ERASURE_SOURCE, [erasure_stop_marker(erasure_id, stop_seq),
                                             erasure_stop_marker(erasure_id, stop_seq, unconfirmed=True)])).fetchone()
    return None if row is None else str(row["event_id"])


def record_erasure_stop(conn, crypto, *, fp: str, erasure_id, ledger: Optional[LifecycleLedger] = None,
                        channels: Optional[list] = None, unconfirmed: bool = False,
                        stop_seq: Optional[int] = None) -> Optional[str]:
    """Write the stop for one erasure (once), over every channel of the entered organisation, by fingerprint.

    Runs inside ``operator_org`` and before the contact key is deleted: the event's ciphertexts and commitments need the
    key. Returns the event id, the id of the stop already written for this request, or None when the organisation has no
    channel or holds no event for this fingerprint (nothing was ever consented to, so a later capture is a first
    consent). Raises ``LifecycleError`` when events exist but the key is already gone.

    With ``ledger`` the stop is entered in the lifecycle ledger first (``{kind: erasure_stop, contact_fp, erasure_id,
    channels, stopped_at}``, no personal data), so a restore replays it; a restore passes ``channels`` from that entry
    and no ledger. ``unconfirmed`` marks a stop a restore replays from an entry with no commit (``recorded_by`` reads
    ``erasure-unconfirmed:<id>:<seq>``). A restore passes ``stop_seq`` (the entry's sequence number): the stop is written
    only when the database holds none for that exact entry. If the ledger refuses, no stop is written and nothing is erased.
    """
    from .. import door
    from . import crypto as tc
    from .keys_protocol import WrappedKey
    from .pipeline import org_channels

    from ..ledger import _LOCK_SQL

    conn.execute(_LOCK_SQL)  # first: the read of the earlier stop and the write of a new one see the same chain head
    if stop_seq is not None:  # a replay: this exact entry is either recorded already or it is written once
        present = erasure_stop_present(conn, fp, erasure_id, stop_seq)
        if present is not None:
            return present
    else:
        prior = conn.execute("SELECT event_id, seq FROM consentvault.event WHERE org_id ="
                             " (SELECT consentvault.current_org()) AND contact_fp = %s AND source = %s"
                             " AND recorded_by LIKE %s ORDER BY seq DESC LIMIT 1",
                             (fp, ERASURE_SOURCE, f"erasure:{erasure_id}:%")).fetchone()
        if prior is not None and conn.execute(
                "SELECT 1 FROM consentvault.event WHERE org_id = (SELECT consentvault.current_org())"
                " AND contact_fp = %s AND seq > %s AND event_type IN ('grant', 'release') LIMIT 1",
                (fp, prior["seq"])).fetchone() is None:
            return str(prior["event_id"])  # nothing has lifted or contradicted it since: one stop per request
    channels = sorted(channels if channels is not None else org_channels(conn))
    last = conn.execute("SELECT event_id, contact_kind, contact_ct FROM consentvault.event"
                        " WHERE org_id = (SELECT consentvault.current_org()) AND contact_fp = %s"
                        " ORDER BY seq DESC LIMIT 1", (fp,)).fetchone()
    if last is None:   # a contact whose only rows are in history (after an organisation's cutover)
        last = conn.execute("SELECT event_id, contact_kind, contact_ct FROM consentvault.history_events"
                            " WHERE org_id = (SELECT consentvault.current_org()) AND contact_fp = %s AND contact_ct IS NOT NULL"
                            " ORDER BY seq DESC LIMIT 1", (fp,)).fetchone()
    if not channels or last is None:
        return None
    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
    if held is None:
        raise LifecycleError(f"erasure {erasure_id}: this contact has events but no key, so its stop cannot be written; "
                             "nothing was erased")
    org = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"]
    if ledger is not None:
        stop_seq, _ = ledger.append(org, {"kind": "erasure_stop", "contact_fp": fp, "erasure_id": str(erasure_id),
                                          "channels": channels, "stopped_at": dbclock.now(conn).isoformat()},
                                    hint=ledger_hint(conn))
    marker = erasure_stop_marker(erasure_id, stop_seq or 0, unconfirmed=unconfirmed)
    data_key = crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    norm = tc.decrypt_text(data_key, org, str(last["event_id"]), "contact_norm", bytes(last["contact_ct"]))
    if conn.execute("SELECT EXISTS (SELECT 1 FROM consentvault.effect_watermark WHERE org_id = (SELECT consentvault.current_org())) AS c"
                    ).fetchone()["c"]:
        # after the organisation's cutover the stop is the post and its history row; the frozen event table gets no row, and a post
        # that cannot be stored is a refused erasure, never a stop that was only half written
        stored = door.store_erasure_stop_post(conn, crypto, erasure_id=erasure_id, contact_fp=fp, channels=channels, marker=marker,
                                              source=ERASURE_SOURCE)
        return history.event_id_of(stored.post_id)
    ev = door.write_system_event(conn, crypto, contact=norm, contact_kind=last["contact_kind"], event_type="suppress",
                                 channels=channels, purposes=["*"], method="written", origin="consumer",
                                 source=ERASURE_SOURCE, recorded_by=marker)
    try:   # the stop as a post is the history's copy of the stop: it is written in its own savepoint, so a failure here never undoes the stop event
        with conn.transaction():
            door.store_erasure_stop_post(conn, crypto, erasure_id=erasure_id, contact_fp=fp, channels=channels, marker=marker,
                                         source=ERASURE_SOURCE)
    except Exception as exc:  # loud-failure-exempt: logged by name; the stop event above stands and the completeness check reports the erased contact with no stop post
        _log.error("the erasure stop could not be stored as a post; the stop event stands", error=type(exc).__name__)
    return str(ev.event_id)


def _erasure_obj(r: dict, conn) -> dict:
    """The request as the client reads it. A hold the client placed is named; any other hold reads as a neutral held
    state, with no reason and no hold id."""
    open_ = r["status"] == "pending_operator_confirmation"
    held = open_ and (r["held_since"] is not None or r.get("wait_reason") is not None)
    reason, held_by = None, None
    if held and r["held_since"] is not None:
        h = conn.execute("SELECT disclosure, hold_id FROM consentvault.erasure_hold(%s)", (r["erasure_id"],)).fetchone()
        if h is None or h["disclosure"] not in (VIEW_OWN, VIEW_NEUTRAL, VIEW_HIDDEN):
            raise LifecycleError(f"erasure {r['erasure_id']} reads as held but names no hold of this organization")
        if h["disclosure"] == VIEW_OWN:
            reason, held_by = "legal_hold", str(h["hold_id"])
    elif held:
        reason = r["wait_reason"]
    return {"erasure_id": str(r["erasure_id"]), "status": "held" if held else r["status"], "held_reason": reason,
            "requested_by": str(r["requested_by"]), "requested_at": iso(r["requested_at"]),
            "completed_at": iso(r["completed_at"]), "contact_fp_hint": r["contact_fp"][:8], "held_by": held_by}


def request_erasure(ctx: Ctx, body: Any, *, crypto, region: Optional[str] = None) -> dict:
    """POST /v1/contacts:erase (admin). The contact is in the body only; the request waits for an operator."""
    from .errors import KeyProviderError
    from .pipeline import normalize

    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    reason = need_text(b, "reason", max_len=500)
    if not isinstance(b.get("contact"), str):
        raise ApiError("invalid_contact", "the contact point is not a valid phone number or email address")
    kind, norm = normalize(b["contact"], region)
    org = ctx.org_id()
    try:
        fp = crypto.contact_fingerprint(org, kind, norm)
    except KeyProviderError as exc:
        raise ApiError("key_unavailable", "the organization key could not be used; nothing was written") from exc
    ctx.conn.execute("SELECT consentvault.lifecycle_lock()")
    own = own_covering_hold(ctx.conn, fp)
    if own is not None:
        raise hold_refusal(own, "a legal hold covers this contact; nothing was queued")
    if ctx.conn.execute("SELECT 1 FROM consentvault.contact_key WHERE org_id = (SELECT consentvault.current_org())"
                        " AND contact_fp = %s", (fp,)).fetchone() is None:
        if ctx.conn.execute("SELECT 1 FROM consentvault.erasure_request WHERE org_id = (SELECT consentvault.current_org())"
                            " AND contact_fp = %s AND status = 'completed' LIMIT 1", (fp,)).fetchone() is not None:
            raise ApiError("contact_already_erased", "this contact was already erased; nothing was queued")
        raise ApiError("contact_not_held", "this organization holds no record of this contact; nothing was queued")
    open_ = ctx.conn.execute("SELECT erasure_id FROM consentvault.erasure_request WHERE org_id ="
                             " (SELECT consentvault.current_org()) AND contact_fp = %s AND status ="
                             " 'pending_operator_confirmation'", (fp,)).fetchone()
    if open_ is not None:
        raise ApiError("erasure_already_requested", "an erasure request for this contact is already open",
                       {"erasure_id": str(open_["erasure_id"])})
    eid = uuid.uuid4()
    try:
        with ctx.conn.transaction():
            ctx.conn.execute("INSERT INTO consentvault.erasure_request (org_id, erasure_id, contact_fp, reason,"
                             " requested_by) VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s)",
                             (eid, fp, reason, ctx.actor.member_uuid))
    except psycopg.errors.UniqueViolation as exc:
        if constraint_name(exc) != "erasure_request_one_open_idx":
            raise
        raise ApiError("erasure_already_requested", "an erasure request for this contact is already open") from exc
    except psycopg.IntegrityError as exc:
        hid = hold_in(exc)
        if hid is None:
            raise
        raise hold_refusal(hid, "a legal hold covers this contact; nothing was queued") from exc
    audit_org(ctx.conn, actor_kind=ctx.actor.kind, actor_id=ctx.actor.id, action="erasure.requested",
              target_kind="erasure", target_id=eid, reason=reason, request_id=ctx.request_id)
    held = covering_hold(ctx.conn, fp)  # an operator's hold: queued, and the client reads a neutral held state
    if held is not None:
        ctx.conn.execute("UPDATE consentvault.erasure_request SET held_by = %s, held_since = clock_timestamp()"
                         " WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s", (held, eid))
        audit_org(ctx.conn, actor_kind=ctx.actor.kind, actor_id=ctx.actor.id, action="erasure.held",
                  target_kind="erasure", target_id=eid, reason=held_note(ctx.conn, held), request_id=ctx.request_id)
        return {"erasure_id": str(eid), "status": "held", "held_reason": None}
    return {"erasure_id": str(eid), "status": "pending_operator_confirmation"}


_LOAD = psycopg.sql.SQL("SELECT {cols} FROM consentvault.erasure_request WHERE org_id ="
                        " (SELECT consentvault.current_org()) AND erasure_id = %s").format(
    cols=psycopg.sql.SQL(ERASURE_COLUMNS))  # the column list is the constant above, composed, never concatenated
_LOAD_LOCKED = psycopg.sql.SQL("{q} FOR UPDATE").format(q=_LOAD)


def _load(conn, erasure_id, *, lock: bool = False) -> dict:
    eid = to_uuid(erasure_id, "erasure")
    row = conn.execute(_LOAD_LOCKED if lock else _LOAD, (eid,)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such erasure request in this organization")
    return row


def get_erasure(ctx: Ctx, erasure_id) -> dict:
    """GET /v1/erasures/{id} (admin)."""
    ctx.actor.require(ROLE_ADMIN)
    return _erasure_obj(_load(ctx.conn, erasure_id), ctx.conn)


# ---- the irreversible step ---------------------------------------------------------------------------------------------------
def pending_pushes(conn, contact_fp: str) -> int:
    """Pushes of this person's state to a connected system not yet delivered or dead (queued, failed or in flight)."""
    return conn.execute("SELECT count(*) AS n FROM consentvault.outbox WHERE org_id = (SELECT consentvault.current_org())"
                        " AND contact_fp = %s AND status IN ('pending', 'failed', 'sent') AND push_kind <> 'clear'",
                        (contact_fp,)).fetchone()["n"]


def _wait(conn, req: dict, reason: str, *, actor_kind: str, actor_id: str, request_id: str, detail: str) -> bool:
    """Hold an open request with a visible wait reason. True when the wait is new (audited once, not per check)."""
    new = req.get("wait_reason") != reason
    conn.execute("UPDATE consentvault.erasure_request SET wait_reason = %s, wait_since = CASE WHEN wait_reason = %s"
                 " THEN wait_since ELSE clock_timestamp() END WHERE org_id = (SELECT consentvault.current_org())"
                 " AND erasure_id = %s", (reason, reason, req["erasure_id"]))
    if new:
        audit_org(conn, actor_kind=actor_kind, actor_id=actor_id, action="erasure.held", target_kind="erasure",
                  target_id=req["erasure_id"], reason=f"{reason}: {detail}", request_id=request_id)
    return new


def erase_in_org(conn, *, ledger: LifecycleLedger, crypto, erasure_id, actor_kind: str, actor_id: str, request_id: str) -> dict:
    """Erase the contact of one open request of the entered organisation. Runs inside ``operator_org``.

    Raises ``ApiError('legal_hold_active')`` (nothing changed) or ``LedgerUnavailableError`` (nothing deleted). While a
    push of the person's state is still queued, failed or in flight, nothing is erased: the request is held with
    ``pending_suppression_delivery`` and the answer says so (``status: held``). Returns the request's answer plus
    ``export_objects``, which the caller purges after commit, then ``commit_erasures`` writes the ledger commit.
    """
    org = conn.execute("SELECT consentvault.lifecycle_lock() AS o").fetchone()["o"]
    req = _load(conn, erasure_id, lock=True)
    if req["status"] != "pending_operator_confirmation":
        raise ApiError("validation_failed", f"the erasure request is {req['status']}", {"status": req["status"]})
    fp = req["contact_fp"]
    held = covering_hold(conn, fp)
    if held is not None:
        raise hold_refusal(held, "a legal hold covers this contact; the erasure is queued until it is released")
    if req["held_since"] is not None:  # the hold that queued this request is gone (covering_hold found none): clear the mark
        conn.execute("UPDATE consentvault.erasure_request SET held_by = NULL, held_since = NULL WHERE org_id ="
                     " (SELECT consentvault.current_org()) AND erasure_id = %s", (req["erasure_id"],))
    stop_id = record_erasure_stop(conn, crypto, fp=fp, erasure_id=req["erasure_id"], ledger=ledger)
    from ..sync.connectors import twenty as twenty_connector  # the Twenty clear (twenty.md 5.1): queued before the delivery wait

    twenty_connector.enqueue_clears(conn, crypto, org, req["erasure_id"], fp)
    clear_reason, clear_systems = twenty_connector.clear_wait(conn, req["erasure_id"])
    if clear_reason is not None:
        conn.execute("UPDATE consentvault.erasure_request SET confirmed_by = coalesce(confirmed_by, %s), confirmed_at ="
                     " coalesce(confirmed_at, clock_timestamp()) WHERE org_id = (SELECT consentvault.current_org())"
                     " AND erasure_id = %s", (actor_id, req["erasure_id"]))
        _wait(conn, req, clear_reason, actor_kind=actor_kind, actor_id=actor_id, request_id=request_id,
              detail=f"the clear of connected system(s) {', '.join(clear_systems)} is "
                     + ("dead: an operator redrives it" if clear_reason == "system_clear_dead" else "not yet delivered"))
        return {"erasure_id": str(req["erasure_id"]), "status": "held", "held_reason": clear_reason,
                "systems": clear_systems, "contact_fp_hint": fp[:8], "key_deleted": False, "export_objects": []}
    waiting = pending_pushes(conn, fp)
    if waiting:
        conn.execute("UPDATE consentvault.erasure_request SET confirmed_by = coalesce(confirmed_by, %s), confirmed_at ="
                     " coalesce(confirmed_at, clock_timestamp()) WHERE org_id = (SELECT consentvault.current_org())"
                     " AND erasure_id = %s", (actor_id, req["erasure_id"]))
        _wait(conn, req, WAIT_DELIVERY, actor_kind=actor_kind, actor_id=actor_id, request_id=request_id,
              detail=f"{waiting} push(es) of this person's state are not yet delivered or dead")
        return {"erasure_id": str(req["erasure_id"]), "status": "held", "held_reason": WAIT_DELIVERY,
                "pending_pushes": waiting, "contact_fp_hint": fp[:8], "key_deleted": False, "export_objects": []}
    erased_at = dbclock.now(conn)
    seq, digest = ledger.append(org, {"kind": "erasure_intent", "contact_fp": fp, "erasure_id": str(req["erasure_id"]),
                                      "erased_at": erased_at.isoformat()}, hint=ledger_hint(conn))
    try:
        deleted = conn.execute("SELECT consentvault.erase_contact(%s) AS d", (fp,)).fetchone()["d"]
    except psycopg.Error as exc:
        hid = hold_in(exc)
        if hid:
            raise hold_refusal(hid, "a legal hold covers this contact; the erasure is queued") from exc
        raise LifecycleError(f"intent entry {seq} is written but the contact key delete failed "
                             f"({type(exc).__name__}); nothing was erased and a restore never replays an intent without "
                             "its commit; a retry completes it") from exc
    jobs = conn.execute(
        "UPDATE consentvault.export_job SET expires_at = least(coalesce(expires_at, clock_timestamp()), clock_timestamp())"
        " WHERE org_id = (SELECT consentvault.current_org()) AND contact_fp = %s RETURNING package_object_key",
        (fp,)).fetchall()
    conn.execute("UPDATE consentvault.erasure_request SET status = 'completed', completed_at = %s, confirmed_by ="
                 " coalesce(confirmed_by, %s), confirmed_at = coalesce(confirmed_at, %s), held_by = NULL,"
                 " held_since = NULL, wait_reason = NULL, wait_since = NULL, ledger_seq = %s, ledger_sha256 = %s"
                 " WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s",
                 (erased_at, actor_id, erased_at, seq, digest, req["erasure_id"]))
    audit_org(conn, actor_kind=actor_kind, actor_id=actor_id, action="erasure.completed", target_kind="erasure",
              target_id=req["erasure_id"], reason=f"contact key deleted: {bool(deleted)}; intent entry {seq}; "
                     + (f"stop event {stop_id}" if stop_id else "no stop written (no events on record)"),
              request_id=request_id)
    return {"erasure_id": str(req["erasure_id"]), "status": "completed", "completed_at": iso(erased_at),
            "key_deleted": bool(deleted), "stop_event_id": stop_id, "ledger_seq": seq, "contact_fp_hint": fp[:8],
            "export_objects": [j["package_object_key"] for j in jobs if j["package_object_key"]]}


def commit_erasures(conn, *, ledger: LifecycleLedger, request_id: str) -> list[str]:
    """Inside the entered organisation: append the commit entry of every completed erasure the ledger does not yet hold
    a commit for, and record it. Run after the erasure's transaction committed (a completed row read here proves it)."""
    org = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"]
    rows = conn.execute(
        "SELECT r.erasure_id, r.contact_fp, r.ledger_seq FROM consentvault.erasure_request r"
        " WHERE r.org_id = (SELECT consentvault.current_org()) AND r.status = 'completed'"
        " AND NOT EXISTS (SELECT 1 FROM consentvault.erasure_ledger_commit c"
        "                 WHERE c.org_id = r.org_id AND c.erasure_id = r.erasure_id)"
        " ORDER BY r.completed_at, r.erasure_id").fetchall()
    done = []
    for r in rows:
        seq, _ = ledger.append(org, {"kind": "erasure_commit", "erasure_id": str(r["erasure_id"]),
                                     "contact_fp": r["contact_fp"], "intent_seq": r["ledger_seq"]},
                               hint=ledger_hint(conn))
        conn.execute("INSERT INTO consentvault.erasure_ledger_commit (org_id, erasure_id, intent_seq, commit_seq)"
                     " VALUES ((SELECT consentvault.current_org()), %s, %s, %s) ON CONFLICT DO NOTHING",
                     (r["erasure_id"], r["ledger_seq"], seq))
        done.append(str(r["erasure_id"]))
    commit_stops(conn, ledger=ledger)
    return done


def commit_stops(conn, *, ledger: LifecycleLedger) -> list[int]:
    """Inside the entered organisation: append ``{kind: erasure_stop_commit, stop_seq, erasure_id, contact_fp}`` for every
    ``erasure_stop`` entry whose stop event the database now holds and the ledger holds no commit for. Run after the
    stop's transaction committed (the event read here proves it). A stop entry whose transaction rolled back has no event,
    so it never gets a commit and a restore never replays it (the same two-step rule as an erasure's intent and commit).
    The stop event names its entry's sequence number, so the match is exact."""
    org = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"]
    entries = ledger.entries(org)
    committed = {e.get("stop_seq") for e in entries if e.get("kind") == "erasure_stop_commit"}
    done = []
    for e in entries:
        if e.get("kind") != "erasure_stop" or e["seq"] in committed:
            continue
        if erasure_stop_present(conn, e["contact_fp"], e["erasure_id"], e["seq"]) is not None:
            ledger.append(org, {"kind": "erasure_stop_commit", "stop_seq": e["seq"], "erasure_id": e["erasure_id"],
                                "contact_fp": e["contact_fp"]}, hint=ledger_hint(conn))
            done.append(e["seq"])
    return done


ALARM_COMMIT_PENDING = "lifecycle.ledger_commit_pending"
ALARM_COMMIT_OVERDUE = "lifecycle.ledger_commit_overdue"
COMMIT_OVERDUE = timedelta(hours=1)


def overdue_intents(conn, *, ledger: LifecycleLedger, now: Optional[datetime] = None) -> list[dict]:
    """Inside the entered organisation: every ledger intent older than an hour that has no commit although a commit is
    due. A stop entry is due when the database holds its stop event (a rolled-back confirm has none: nothing to commit);
    an erasure intent is due unless its request was declined."""
    org = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"]
    now = now or dbclock.now(conn)
    entries = ledger.entries(org)
    stop_done = {e.get("stop_seq") for e in entries if e.get("kind") == "erasure_stop_commit"}
    settled = {e.get("erasure_id") for e in entries if e.get("kind") == "erasure_commit"}
    out = []
    for e in entries:
        kind = e.get("kind")
        if kind == "erasure_stop":
            if e["seq"] in stop_done:
                continue
            at = e["at"]
            due = erasure_stop_present(conn, e["contact_fp"], e["erasure_id"], e["seq"]) is not None
        elif kind == "erasure_intent":
            if e["erasure_id"] in settled:  # any commit settles the erasure: a retry that succeeded ends the alarm
                continue
            at = e["at"]
            st = conn.execute("SELECT status FROM consentvault.erasure_request WHERE org_id ="
                              " (SELECT consentvault.current_org()) AND erasure_id = %s", (e["erasure_id"],)).fetchone()
            due = st is not None and st["status"] != "declined"
        else:
            continue
        if due and now - datetime.fromisoformat(at) > COMMIT_OVERDUE:
            out.append({"kind": kind, "seq": e["seq"], "erasure_id": e["erasure_id"], "at": at})
    return out


def commit_sweep(conn: psycopg.Connection, *, token_key: TokenKey, ledger: LifecycleLedger, request_id: str,
                 org_id=None) -> dict:
    """The hourly job: write every commit entry that is due (every organisation, or one), then raise an operator alarm for
    each organisation that still holds an intent older than an hour without its commit. Answers what was written and
    what is overdue; the caller exits non-zero when anything is overdue."""
    from ..alarms import raise_operator_alarm

    orgs = [to_uuid(org_id, "organization")] if org_id is not None else \
        [r["o"] for r in conn.execute("SELECT o FROM consentvault.restore_org_ids() AS o")]
    report: dict = {"orgs": {}, "overdue": 0}
    for org in orgs:
        commit = commit_after(conn, token_key=token_key, ledger=ledger, org_id=org, request_id=request_id)
        with operator_org(conn, token_key, org):
            late = overdue_intents(conn, ledger=ledger)
            if late:
                raise_operator_alarm(conn, name=ALARM_COMMIT_OVERDUE, error_class="LedgerCommitOverdue", ref_kind="org",
                                     ref_id=org, request_id=request_id)
        report["orgs"][str(org)] = {"commit": commit, "overdue": late}
        report["overdue"] += len(late)
    return report


def commit_after(conn, *, token_key: TokenKey, ledger: LifecycleLedger, org_id, request_id: str) -> dict:
    """The commit sweep in its own transaction, after the erasure committed. A ledger that cannot take the commit yet
    leaves an alarm row and a visible ``pending`` answer; the erasure stands and the next sweep writes the commit (a
    restore before then holds the request as ``uncommitted_ledger_intent`` for the operator, never erases blind)."""
    from ..alarms import AlarmWriteError, raise_operator_alarm

    try:
        with operator_org(conn, token_key, org_id):
            return {"status": "written", "erasures": commit_erasures(conn, ledger=ledger, request_id=request_id)}
    except LedgerUnavailableError as exc:
        cause = describe(exc)
    try:
        with operator_org(conn, token_key, org_id):
            raise_operator_alarm(conn, name=ALARM_COMMIT_PENDING, error_class="LedgerUnavailableError",
                                 ref_kind="org", ref_id=org_id, request_id=request_id)
    except AlarmWriteError as exc:
        raise LedgerUnavailableError(f"the erasure is complete but its ledger commit could not be written ({cause}) "
                                     f"and the alarm row failed too ({describe(exc)}); run the commit sweep by hand") from exc
    return {"status": "pending", "cause": cause}


def purge_export_cache(org_id, keys: list[str], cache) -> dict:
    """Delete cached package objects where the cache can delete. Every copy is already unreadable (its key is gone)."""
    delete = getattr(cache, "delete", None) if cache is not None else None
    if not keys or delete is None:
        return {"expired_jobs": len(keys), "deleted": 0, "unreadable_only": len(keys)}
    for key in keys:
        try:
            delete(str(org_id), key)
        except Exception as exc:  # any provider failure is raised by name; the contact stays erased
            raise CachePurgeError(f"the contact is erased, but cached package {key} could not be deleted "
                                  f"({type(exc).__name__}); it cannot be read without the erased key") from exc
    return {"expired_jobs": len(keys), "deleted": len(keys), "unreadable_only": 0}


def confirm_erasure(conn: psycopg.Connection, *, token_key: TokenKey, ledger: LifecycleLedger, crypto, operator_id: str,
                    request_id: str, org_id, erasure_id, export_cache=None) -> dict:
    """POST /v1/erasures/{id}:confirm (operator). Erases now, or queues the request behind a covering hold and answers
    ``legal_hold_active`` naming it (the queued state is committed before the refusal is raised)."""
    queued: Optional[str] = None
    with operator_org(conn, token_key, org_id) as org:
        conn.execute("SELECT consentvault.lifecycle_lock()")
        req = _load(conn, erasure_id, lock=True)
        held = covering_hold(conn, req["contact_fp"]) if req["status"] == "pending_operator_confirmation" else None
        if held is not None:
            # a person who asked to be erased is not contacted while a hold keeps their data: only the key waits
            record_erasure_stop(conn, crypto, fp=req["contact_fp"], erasure_id=req["erasure_id"], ledger=ledger)
            conn.execute("UPDATE consentvault.erasure_request SET held_by = %s, held_since = coalesce(held_since,"
                         " clock_timestamp()), confirmed_by = %s, confirmed_at = clock_timestamp()"
                         " WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s",
                         (held, operator_id, req["erasure_id"]))
            audit_org(conn, actor_kind="operator", actor_id=operator_id, action="erasure.held", target_kind="erasure",
                      target_id=req["erasure_id"], reason=held_note(conn, held), request_id=request_id)
            queued = held
        else:
            out = erase_in_org(conn, ledger=ledger, crypto=crypto, erasure_id=erasure_id, actor_kind="operator", actor_id=operator_id,
                               request_id=request_id)
            audit_platform(conn, operator_id=operator_id, action="erasure.confirmed", target_kind="erasure",
                           target_id=out["erasure_id"], reason=out.get("held_reason"), request_id=request_id)
    if queued is not None:
        commit_after(conn, token_key=token_key, ledger=ledger, org_id=org, request_id=request_id)  # the stop's commit
        raise hold_refusal(queued, "a legal hold covers this contact; the confirmed erasure is queued until release")
    if out["status"] != "completed":
        out.pop("export_objects")
        out["ledger_commit"] = commit_after(conn, token_key=token_key, ledger=ledger, org_id=org, request_id=request_id)
        return out
    out["ledger_commit"] = commit_after(conn, token_key=token_key, ledger=ledger, org_id=org, request_id=request_id)
    out["export_cache"] = purge_export_cache(org, out.pop("export_objects"), export_cache)
    return out


def resume_waiting(conn: psycopg.Connection, *, token_key: TokenKey, ledger: LifecycleLedger, crypto, request_id: str,
                   org_id=None, export_cache=None) -> dict:
    """The job that runs confirmed erasures held for ``pending_suppression_delivery`` once every push of the person is
    delivered or dead (every organisation, or one). A request a hold now covers is queued behind it, as a confirmation
    would be. Answers what completed, what still waits and what a hold queued; nothing is skipped silently."""
    orgs = [to_uuid(org_id, "organization")] if org_id is not None else \
        [r["o"] for r in conn.execute("SELECT o FROM consentvault.restore_org_ids() AS o")]
    done: dict = {"completed": [], "still_waiting": [], "held": [], "export_cache": [], "ledger_commit": []}
    for org in orgs:
        with operator_org(conn, token_key, org):
            ids = [r["erasure_id"] for r in conn.execute(
                "SELECT erasure_id FROM consentvault.erasure_request WHERE org_id = (SELECT consentvault.current_org())"
                " AND status = 'pending_operator_confirmation' AND held_by IS NULL AND confirmed_at IS NOT NULL"
                " AND (wait_reason IS NULL OR wait_reason IN (%s, 'waiting_for_system_clear', 'system_clear_dead'))"
                " ORDER BY requested_at", (WAIT_DELIVERY,))]
        for eid in ids:
            with operator_org(conn, token_key, org):
                conn.execute("SELECT consentvault.lifecycle_lock()")
                req = _load(conn, eid, lock=True)
                hold = covering_hold(conn, req["contact_fp"])
                if hold is not None:
                    conn.execute("UPDATE consentvault.erasure_request SET held_by = %s, held_since = clock_timestamp()"
                                 " WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s", (hold, eid))
                    audit_org(conn, actor_kind="system", actor_id="erasure-resume", action="erasure.held",
                              target_kind="erasure", target_id=eid, reason=held_note(conn, hold), request_id=request_id)
                    done["held"].append(str(eid))
                    continue
                out = erase_in_org(conn, ledger=ledger, crypto=crypto, erasure_id=eid, actor_kind="system", actor_id="erasure-resume",
                                   request_id=request_id)
            if out["status"] != "completed":
                done["still_waiting"].append(str(eid))
                continue
            done["completed"].append(str(eid))
            done["export_cache"].append(purge_export_cache(org, out.pop("export_objects"), export_cache))
        # every organisation, not only those completed here: an erasure a hold release ran also gets its commit
        commit = commit_after(conn, token_key=token_key, ledger=ledger, org_id=org, request_id=request_id)
        if commit["status"] != "written" or commit["erasures"]:
            done["ledger_commit"].append({"org_id": str(org), **commit})
    return done


def decline_erasure(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id,
                    erasure_id, reason: str, crypto=None) -> dict:
    """The operator declines a request (visible state, reason kept)."""
    reason = need_text({"reason": reason}, "reason", max_len=500)
    with operator_org(conn, token_key, org_id):
        req = _load(conn, erasure_id, lock=True)
        if req["status"] != "pending_operator_confirmation":
            raise ApiError("validation_failed", f"the erasure request is {req['status']}", {"status": req["status"]})
        conn.execute("UPDATE consentvault.erasure_request SET status = 'declined', decline_reason = %s, held_by = NULL,"
                     " held_since = NULL, wait_reason = NULL, wait_since = NULL WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s",
                     (reason, req["erasure_id"]))
        if crypto is not None:  # the Twenty clear is superseded and current state written back (twenty.md 5.1)
            from ..sync.connectors import twenty as twenty_connector

            twenty_connector.on_decline(conn, crypto, org_id, req["erasure_id"], req["contact_fp"])
        audit_org(conn, actor_kind="operator", actor_id=operator_id, action="erasure.declined", target_kind="erasure",
                  target_id=req["erasure_id"], reason=reason, request_id=request_id)
        return _erasure_obj(_load(conn, erasure_id), conn)
