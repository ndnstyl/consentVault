"""The Twenty CRM connector, outbound (contracts: twenty.md sections 1.2, 1.7, 2, 5.1, 6).

The worker hands it one claimed person group (every open push of one system and contact, ``sync_claim_person``) and it writes
the Person's fields computed from the ledger at send time (a push is a signal to write, never the data written), so applying a
push twice, or an old one after a new one, writes the same fields.

One delivery, in order (2.2): the start condition (120 seconds left before the organisation's drain deadline); open the sealed
API key and the hash key; resolve the matches (links first, else a lookup; at most 10, ``ambiguous_match`` beyond); for each
Person: the Person's lease (``sync_lease_person``), GET, the combined state of its contributing contacts (rule R16, computed
only once the lease is held), the integer sequence rule, PATCH (the lease extended first, and refused more than 15 seconds after
that extension on the monotonic clock: rule R27), GET again to read back, the link remembered, the lease released. A clear
writes the state of the Person's other contributing contacts and blanks only when none is left (R17); a soft-deleted Person
keeps the clear open (R25) and alarms the customer from 7 days and the operator from 30 (R31); a destroyed one acknowledges it.

Every call carries its deadline: the door's 10 seconds (15 with its answer), the lease heartbeat of 30 seconds before every call,
the delivery's own 120 seconds. Every failure is a named outcome on the row, never a silent skip.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

import psycopg

from ...safelog import describe
from ...normalize import normalize_contact
from ...tenancy import crypto as tc
from ...tenancy.errors import TenancyError
from ...tenancy.keys_protocol import WrappedKey
from ...tenancy.tokens import org_transaction
from ..errors import CredentialError, StaleAttemptError, SyncError, TransportError
from ..outbox import ERROR_COLUMN, PAYLOAD_COLUMN, iso_z, push_start_taken_over
from . import twenty_api as api
from ... import safelog

log = safelog.get("consentvault.sync.twenty")

LEASE_SECONDS = 30            # a Person lease and the claim heartbeat run 30 seconds from each extension
SEND_DEADLINE_SECONDS = 15.0  # no PATCH more than 15 s after the extension that covers it (monotonic clock)
CALL_DEADLINE_SECONDS = 15    # the door's 10 s plus its answer
DELIVERY_DEADLINE_SECONDS = 120
START_MARGIN_SECONDS = 120    # a delivery starts only with 120 s left before the drain deadline
MAX_MATCHES = 10
RELEASE_SECONDS = 60
DELETED_RECHECK_SECONDS = 3600   # a clear waiting on a soft-deleted Person looks again hourly (the restore webhook wakes it)
ALARM_DAYS = (7, 30)          # the deleted-record wait's alarms; the database counts them in hours (168, 720)
MAX_BACKOFF_SECONDS = 3600    # the longest retry step the database accepts
CHANNELS = tuple(api.STATUS_FIELDS)
ALARM_CUSTOMER = "connector.clear_waiting_deleted_record"
ALARM_OPERATOR = "erasure.clear_blocked_by_deleted_record"
ALARM_HIDDEN = "connector.stop_hidden"
ALARM_STATE = "connector.state"
SECRET_PURPOSES = ("api_key", "webhook_secret")
PERSON_ID_COLUMN = "connector_person_id"


# ---- sealed secrets (1.2) ------------------------------------------------------------------------------------------------
def _aad(org_id, system_id, purpose: str) -> bytes:
    return f"consentvault/connector-secret/v1\x1f{org_id}\x1f{system_id}\x1f{purpose}".encode()


def seal_secret(custody, org_id, system_id, purpose: str, secret: bytes) -> tuple[bytes, bytes]:
    """Envelope-seal a secret of any length: a fresh 32-byte key seals it (AES-GCM, authenticated data org, system, purpose),
    the organisation key wraps that key. Returns ``(wrapped_key, sealed_secret)``."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if purpose not in SECRET_PURPOSES or not isinstance(secret, bytes) or not 1 <= len(secret) <= 8192:
        raise CredentialError(f"a connector secret is 1 to 8192 bytes under a known purpose, not {purpose!r}")
    key, nonce = os.urandom(32), os.urandom(12)
    sealed = nonce + AESGCM(key).encrypt(nonce, secret, _aad(org_id, system_id, purpose))
    return custody.wrap(str(org_id), key), sealed


def open_secret(custody, org_id, system_id, purpose: str, wrapped, sealed) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if wrapped is None or sealed is None:
        raise CredentialError(f"system {system_id} has no {purpose}; it cannot be called")
    try:
        key = custody.unwrap(str(org_id), bytes(wrapped))
        blob = bytes(sealed)
        return AESGCM(key).decrypt(blob[:12], blob[12:], _aad(org_id, system_id, purpose))
    except InvalidTag as exc:
        raise CredentialError(f"the {purpose} of system {system_id} does not open (wrong key or altered)") from exc
    except Exception as exc:  # the custody provider's own error types differ; every one is named here and carried
        raise CredentialError(f"the {purpose} of system {system_id} cannot be opened: {type(exc).__name__}") from exc


def new_hash_key(custody, org_id) -> bytes:
    """32 random bytes, wrapped by the organisation key (never derived from it, so a rotation never changes a hash)."""
    return custody.wrap(str(org_id), os.urandom(32))


def open_hash_key(custody, org_id, wrapped) -> bytes:
    if wrapped is None:
        raise CredentialError("this organisation has no connector hash key; connect a Twenty system first")
    try:
        key = custody.unwrap(str(org_id), bytes(wrapped))
    except Exception as exc:  # named and carried, as every custody failure
        raise CredentialError(f"the connector hash key cannot be opened: {type(exc).__name__}") from exc
    if len(key) != 32:
        raise CredentialError("the connector hash key is not 32 bytes after opening")
    return key


def person_id_hash(hash_key: bytes, person_id: str) -> str:
    """The keyed hash a Twenty Person id is looked up by (links, leases, flag history, destroyed markers)."""
    return hmac.new(hash_key, b"twenty-person\x1f" + str(person_id).encode(), hashlib.sha256).hexdigest()


def load_keys(conn, custody, org_id, system_id, *, purposes=("api_key",)) -> dict:
    """Open a system's secrets and the organisation's hash key inside the entered tenant. Any failure is ``CredentialError``."""
    out: dict = {}
    for purpose in purposes:
        row = conn.execute("SELECT * FROM consentvault.connector_secret_get(%s, %s)", (system_id, purpose)).fetchone()
        out[purpose] = open_secret(custody, org_id, system_id, purpose, row and row["wrapped"], row and row["sealed"])
    row = conn.execute("SELECT * FROM consentvault.connector_secret_get(NULL, 'hash_key')").fetchone()
    out["hash_key"] = open_hash_key(custody, org_id, row and row["wrapped"])
    return out


def _hint_key(hash_key: bytes) -> bytes:
    return hmac.new(hash_key, b"consentvault/twenty-point-hint/v1", hashlib.sha256).digest()


def seal_hint(hash_key: bytes, org_id, system_id, h: str, person_id: str) -> bytes:
    """A Person id an event named, sealed under the organisation's connector key (no contact key is needed: the point may be
    one the vault has not seen yet)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    return nonce + AESGCM(_hint_key(hash_key)).encrypt(nonce, person_id.encode(), f"{org_id}\x1f{system_id}\x1f{h}".encode())


def open_hint(hash_key: bytes, org_id, system_id, h: str, blob) -> str:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    b = bytes(blob)
    try:
        return AESGCM(_hint_key(hash_key)).decrypt(b[:12], b[12:], f"{org_id}\x1f{system_id}\x1f{h}".encode()).decode()
    except InvalidTag as exc:
        raise CredentialError("a point hint does not open (wrong key or altered)") from exc


def seal_person_id(data_key: bytes, org_id, system_id, h: str, person_id: str) -> bytes:
    return tc.encrypt_field(data_key, org_id, f"{system_id}:{h}", PERSON_ID_COLUMN, person_id)


def open_person_id(data_key: bytes, org_id, system_id, h: str, blob) -> str:
    return tc.decrypt_text(data_key, org_id, f"{system_id}:{h}", PERSON_ID_COLUMN, blob)


# ---- the fields (1.4, 1.7) -------------------------------------------------------------------------------------------------
def derive_fields(rows) -> dict:
    """The eight vault-owned fields from ``sync_person_state`` rows. Blank (null) when no contact contributes."""
    if not rows or rows[0]["contributors"] == 0:
        return {f: None for f in api.OWNED}
    by = {r["channel"]: r["state"] for r in rows}
    r0 = rows[0]
    out = {api.STATUS_FIELDS[ch]: by.get(ch, "none") for ch in CHANNELS}
    out[api.F_CHECK] = r0["last_check"] or "none"
    out[api.F_CHECK_AT] = iso_z(r0["last_check_at"]) if r0["last_check_at"] else None
    out[api.F_SEQ] = str(int(r0["as_of_seq"])) if r0["as_of_seq"] is not None else None
    deciding = next((r["evidence_record"] for r in rows if r["state"] == "denied" and r["evidence_record"]), None) \
        or next((r["evidence_record"] for r in rows if r["evidence_record"]), None)
    out[api.F_LINK] = api.EVIDENCE_URL.format(record_id=deciding) if deciding else None
    return out


def _instant(value: str):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None  # loud-failure-exempt: a text that is not an instant is compared as text below; a difference is drift


def _same(a, b) -> bool:
    """Field equality as Twenty reads it back: a DATE_TIME compared as an instant, text as text, '' and null kept apart."""
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) and isinstance(b, str) and "T" in a and "T" in b:
        pa, pb = _instant(a), _instant(b)
        if pa is not None and pb is not None and pa.tzinfo is not None and pb.tzinfo is not None:
            return abs((pa - pb).total_seconds()) < 0.001
    return a == b


def differs(person: dict, want: dict) -> list[str]:
    return [f for f in api.OWNED if not _same(person.get(f), want[f])]


def hides_a_stop(person: dict, want: dict) -> bool:
    """Twenty shows a channel less restrictive than the ledger (permitted or none where the ledger is denied)."""
    return any(want[f] == "denied" and person.get(f) != "denied" for f in api.STATUS_FIELDS.values())


# ---- outcomes -------------------------------------------------------------------------------------------------------------
@dataclass
class Outcome:
    kind: str                       # acknowledged | retry | dead | release (not an attempt)
    error_class: str | None = None
    http_status: int | None = None
    detail: str = ""
    confirmation: str | None = None
    release_seconds: int = RELEASE_SECONDS


@dataclass
class TwentyReport:
    """What one Twenty delivery did, counted (the activity list and the run report)."""
    persons: int = 0
    written: int = 0
    unchanged: int = 0
    drift_corrected: int = 0
    seq_above_vault: int = 0
    ambiguous_match: int = 0
    deleted_waits: int = 0
    refused_late_send: int = 0
    lease_busy: int = 0
    unknown_outcome: int = 0


class _NoBudget(SyncError):
    """The pacing bucket is empty: release the claim (not an attempt) until it refills."""


class _Stalled(SyncError):
    """More than 15 seconds passed since the lease extension: send nothing, release (rule R27)."""


class _DeadlinePassed(SyncError):
    """The delivery's own 120 seconds ended: the rest is released and finishes on the next claim."""


class TwentyDelivery:
    """Delivers one claimed group. Built by the worker with its crypto, custody and call transport."""

    def __init__(self, crypto: tc.TenantCrypto, custody, transport: api.CallTransport, *,
                 clock: Callable[[], datetime], monotonic: Callable[[], float] = time.monotonic,
                 region: str | None = None) -> None:
        if transport is None or not hasattr(transport, "call"):
            raise TransportError("the Twenty connector needs a call transport (the egress door's /call)")
        self.crypto, self.custody, self.transport = crypto, custody, transport
        self.clock, self.monotonic, self.region = clock, monotonic, region
        self.after_extension = None   # a test seam: runs between the lease extension and the send check (a worker stall)

    # -- small database steps, each its own transaction under the drain's token --------------------------------------------
    def _db(self, conn, token, sql, args=(), *, one=False, many=False):
        with org_transaction(conn, token):
            cur = conn.execute(sql, args)
            if one:
                return cur.fetchone()
            if many:
                return cur.fetchall()
            return None

    def _count(self, conn, token, system_id, name: str, n: int = 1) -> None:
        if n:
            self._db(conn, token, "SELECT consentvault.connector_count(%s, %s, %s)", (system_id, name, n))

    def _operator_alarm(self, conn, token, name: str, error_class: str, ref_kind: str, ref_id) -> None:
        from ...alarms import raise_operator_alarm

        with org_transaction(conn, token):
            raise_operator_alarm(conn, name=name, error_class=error_class, ref_kind=ref_kind, ref_id=ref_id)

    # -- the delivery ------------------------------------------------------------------------------------------------------
    def deliver(self, conn: psycopg.Connection, token: str, org_id, rows: list, *, drain_deadline: datetime,
                backoff: Callable[[int], timedelta] | None = None) -> tuple[Outcome, TwentyReport]:
        """Deliver one person group and finish every row with one outcome. Returns that outcome and the counts. A lease taken
        over raises ``StaleAttemptError`` (nothing more is written); a door failure raises ``TransportError``."""
        rep = TwentyReport()
        system_id, fp = rows[0]["system_id"], rows[0]["contact_fp"]
        is_clear = any(r["push_kind"] == "clear" for r in rows)
        if (drain_deadline - self.clock()).total_seconds() < START_MARGIN_SECONDS:
            return self._finish(conn, token, org_id, rows, Outcome("release", detail="under 120 s left before the drain deadline"),
                                backoff), rep
        # this push's attempt starts now: every row of the group is stamped (last_attempt_at, the database's clock) and the
        # database counts the backoff from it, so a group pushed after others in the same batch is never dated to the claim
        try:
            self._db(conn, token, "SELECT consentvault.sync_attempt_started(%s, %s)",
                     ([r["outbox_id"] for r in rows], [r["attempt"] for r in rows]))
        except psycopg.errors.ObjectNotInPrerequisiteState as exc:
            if not push_start_taken_over(exc):
                raise
            raise StaleAttemptError(f"push group {[str(r['outbox_id']) for r in rows]} was taken over before its push started",
                                    code="push_taken_over_before_start") from exc
        try:
            data_key, keys, kind, norm = self._prepare(conn, token, org_id, system_id, fp, rows)
        except (TenancyError, CredentialError, SyncError, ValueError) as exc:  # loud-failure-exempt: recorded as the row's prepare_failed attempt and logged at ERROR
            return self._finish(conn, token, org_id, rows, self._prepare_failed(exc), backoff), rep
        base_url = (rows[0]["config"] or {}).get("base_url") or rows[0]["endpoint"]
        started = self.monotonic()
        ids, atts = [r["outbox_id"] for r in rows], [r["attempt"] for r in rows]
        state = {"t_ext": None, "send": False}

        def heartbeat() -> None:
            if self.monotonic() - started > DELIVERY_DEADLINE_SECONDS:
                raise _DeadlinePassed("the 120 s delivery deadline passed")
            self._db(conn, token, "SELECT consentvault.sync_extend_lease(%s, %s, %s)", (ids, atts, LEASE_SECONDS))
            state["t_ext"] = self.monotonic()
            took = self._db(conn, token, "SELECT consentvault.sync_rate_take(%s, 1) AS ok", (system_id,),
                            one=True)["ok"]
            if not took:
                raise _NoBudget("the pacing bucket is empty")
            if self.after_extension is not None:
                self.after_extension(state["send"])
            if state["send"] and self.monotonic() - state["t_ext"] > SEND_DEADLINE_SECONDS:
                raise _Stalled("more than 15 s since the lease extension")

        client = api.TwentyClient(base_url, keys["api_key"].decode("utf-8"), self.transport, before_call=heartbeat)
        try:
            out = self._deliver_persons(conn, token, org_id, system_id, fp, kind, norm, is_clear, client, keys, data_key,
                                        base_url, rows, rep, state)
        except psycopg.errors.ObjectNotInPrerequisiteState as exc:
            raise StaleAttemptError(f"the lease of push group {ids} was taken over: {describe(exc)}") from exc
        except (_NoBudget, _Stalled, _DeadlinePassed, api.TwentyError) as exc:  # loud-failure-exempt: every one becomes the rows' named outcome below (release, retry or dead with its class)
            out = self._outcome_of(conn, token, system_id, exc, rep)
        return self._finish(conn, token, org_id, rows, out, backoff, data_key=data_key), rep

    def _prepare(self, conn, token, org_id, system_id, fp, rows):
        data_key = self.crypto.open_contact_key(org_id, WrappedKey(bytes(rows[0]["wrapped_key"]), rows[0]["key_version"]))
        for r in rows:   # every body must open: an altered one is a prepare failure, never ignored
            tc.decrypt_field(data_key, org_id, str(r["outbox_id"]), PAYLOAD_COLUMN, r["payload_ct"])
        with org_transaction(conn, token):
            keys = load_keys(conn, self.custody, org_id, system_id)
            sealed = conn.execute("SELECT * FROM consentvault.sync_contact_sealed(%s)", (fp,)).fetchone()
        if sealed is None:
            raise CredentialError("no sealed contact point for this fingerprint")
        contact = tc.decrypt_text(data_key, org_id, str(sealed["event_id"]), "contact_norm", sealed["contact_ct"])
        kind, norm = normalize_contact(contact, sealed["contact_kind"], self.region)
        return data_key, keys, kind, norm

    @staticmethod
    def _prepare_failed(exc: BaseException) -> Outcome:
        log.error("consentvault twenty: a push could not be prepared; counted as an attempt", error=type(exc).__name__)
        return Outcome("retry", "prepare_failed", None, f"preparation failed: {type(exc).__name__}")

    def _outcome_of(self, conn, token, system_id, exc: BaseException, rep: TwentyReport) -> Outcome:
        if isinstance(exc, _NoBudget):
            return Outcome("release", detail=describe(exc))
        if isinstance(exc, _Stalled):
            rep.refused_late_send += 1
            self._count(conn, token, system_id, "refused_late_send")
            return Outcome("release", detail="more than 15 s since the lease extension; nothing sent", release_seconds=1)
        if isinstance(exc, _DeadlinePassed):
            return Outcome("release", detail=describe(exc), release_seconds=1)
        if not isinstance(exc, api.TwentyError):
            raise SyncError(f"unexpected delivery failure {type(exc).__name__}") from exc
        self._after_error(conn, token, system_id, exc)
        if exc.error_class == "timeout":
            rep.unknown_outcome += 1
        return Outcome(exc.outcome, exc.error_class, exc.http_status, describe(exc))

    def _after_error(self, conn, token, system_id, exc: api.TwentyError) -> None:
        if exc.error_class == "key_rejected":
            # the 10-minute window and its count are the database's clock (connector_window_hit), never this process's
            got = self._db(conn, token, "SELECT consentvault.connector_window_hit(%s, 'key_rejected', 600, 2) AS n", (system_id,),
                           one=True)
            if got["n"] >= 2:
                self._set_state(conn, token, system_id, "needs_attention:key_rejected")
        elif exc.error_class == "target_private":
            self._set_state(conn, token, system_id, "unreachable_private")
        elif exc.error_class in ("timeout", "unreachable"):
            self._count(conn, token, system_id, "call_failed")
            if exc.error_class == "timeout":   # unknown outcome: the reconcile rechecks the Person (rule R22)
                self._db(conn, token, "SELECT consentvault.sync_request_reconcile(%s)", (system_id,))

    def _set_state(self, conn, token, system_id, new: str) -> None:
        changed = self._db(conn, token, "SELECT consentvault.connector_set_state(%s, %s) AS c", (system_id, new), one=True)["c"]
        if changed:   # one connector.state alarm per change, never one per row
            self._operator_alarm(conn, token, ALARM_STATE, new.replace(":", "_"), "system", system_id)

    def _persons_for(self, conn, token, org_id, system_id, fp, kind, norm, client, data_key, rep, hash_key=None) -> list[str]:
        links = self._db(conn, token, "SELECT * FROM consentvault.connector_links_of(%s, %s, NULL)", (system_id, [fp]), many=True)
        ids = [open_person_id(data_key, org_id, system_id, link["person_id_hash"], link["person_id_ct"]) for link in links]
        # every Person an event named as carrying this point (an additional email or phone Twenty's filter cannot reach)
        hints = self._db(conn, token, "SELECT * FROM consentvault.connector_hints_of(%s, %s)", (system_id, fp), many=True)
        named = [open_hint(hash_key, org_id, system_id, r["person_id_hash"], r["person_id_ct"]) for r in hints] if hash_key else []
        if ids:   # a delivery already found this contact's Persons: later writes skip the lookup
            return list(dict.fromkeys(ids + named))[:MAX_MATCHES]
        found = client.find(kind, norm, region=self.region, cap=MAX_MATCHES + 1)
        if len(found) > MAX_MATCHES:
            rep.ambiguous_match += 1
            self._count(conn, token, system_id, "ambiguous_match")
        return list(dict.fromkeys([p["id"] for p in found] + named))[:MAX_MATCHES]

    def _deliver_persons(self, conn, token, org_id, system_id, fp, kind, norm, is_clear, client, keys, data_key, base_url,
                         rows, rep, state) -> Outcome:
        persons = self._persons_for(conn, token, org_id, system_id, fp, kind, norm, client, data_key, rep, keys["hash_key"])
        relooked = waiting_deleted = False
        applied = 0
        i = 0
        while i < len(persons):
            pid = persons[i]
            i += 1
            h = person_id_hash(keys["hash_key"], pid)
            if self._db(conn, token, "SELECT consentvault.connector_is_destroyed(%s, %s) AS d", (system_id, h), one=True)["d"]:
                self._count(conn, token, system_id, "after_destroyed")
                continue
            rep.persons += 1
            if not self._db(conn, token, "SELECT consentvault.sync_lease_person(%s, %s, %s, %s) AS ok",
                            (system_id, h, rows[0]["outbox_id"], rows[0]["attempt"]), one=True)["ok"]:
                rep.lease_busy += 1
                return Outcome("release", detail="another delivery holds this Person's lease", release_seconds=5)
            try:
                result = self._write_person(conn, token, org_id, system_id, fp, pid, h, client, data_key, rep, state)
            finally:
                self._db(conn, token, "SELECT consentvault.sync_release_person(%s, %s, %s)", (system_id, h, rows[0]["outbox_id"]))
            if result != "gone":
                applied += 1
                continue
            linked = bool(self._db(conn, token, "SELECT 1 AS x FROM consentvault.connector_links_of(%s, %s, %s)",
                                   (system_id, [fp], h), one=True))
            if is_clear and linked:
                waiting_deleted = True   # R25: a 404 on a linked Person with no person.destroyed is not an acknowledgement
                self._deleted_wait(conn, token, system_id, fp, h, rows)
            elif linked and not relooked:
                relooked = True          # a 404 on a stored id: skip that Person and look up again in this delivery
                more = [p["id"] for p in client.find(kind, norm, region=self.region, cap=MAX_MATCHES) if p["id"] not in persons]
                persons += more[: max(0, MAX_MATCHES - len(persons))]
        if waiting_deleted:
            rep.deleted_waits += 1
            return Outcome("release", detail="a deleted Twenty record may be restored; the clear waits for it",
                           release_seconds=DELETED_RECHECK_SECONDS)
        if applied == 0:
            return Outcome("acknowledged", confirmation="not_in_system")
        return Outcome("acknowledged", confirmation="cleared" if is_clear else "applied")

    def _get(self, client, pid):
        """The Person, or None when it answers 404 (counted and handled by the caller, never written)."""
        try:
            return client.person(pid)
        except api.PersonGone as exc:  # loud-failure-exempt: a 404 is an answer, not an error; the caller waits, re-looks or acknowledges it by name
            return self._gone(exc)

    @staticmethod
    def _gone(exc: BaseException):
        log.info("consentvault twenty: a Person answered 404; it is skipped or waited on, never written", error=type(exc).__name__)
        return None

    def _write_person(self, conn, token, org_id, system_id, fp, pid, h, client, data_key, rep, state) -> str:
        person = self._get(client, pid)
        if person is None:
            return "gone"
        # contributing contacts are the points the Person holds now (1.7); the delivering contact counts only if it is one
        fps = [self.crypto.contact_fingerprint(org_id, k, n) for k, n in api.contact_points(person, self.region)]
        srows = self._db(conn, token, "SELECT * FROM consentvault.sync_person_state(%s, %s)", (system_id, fps), many=True)
        want = derive_fields(srows)
        diff = differs(person, want)
        theirs, raw = api.parse_seq(person.get(api.F_SEQ)), person.get(api.F_SEQ)
        ours = int(want[api.F_SEQ]) if want[api.F_SEQ] else None
        if raw is not None and (theirs is None or (ours is not None and theirs > ours)):
            rep.seq_above_vault += 1   # a restored vault restarts its sequence and staff can type: never trusted
            self._count(conn, token, system_id, "seq_above_vault")
        if not diff:
            rep.unchanged += 1
            self._link(conn, token, org_id, system_id, h, fp, pid, data_key, ours)
            return "applied"
        if any(person.get(f) is not None for f in diff):
            rep.drift_corrected += 1
            self._count(conn, token, system_id, "drift_corrected")
        state["send"] = True          # the heartbeat right before the PATCH checks the 15 s send deadline (R27)
        try:
            self._send(client, pid, want)
        finally:
            state["send"] = False
        back = self._get(client, pid)
        if back is None:
            return "gone"
        if differs(back, want):
            raise api.TwentyError("the read-back differs from what was written (a second writer or a Twenty rule)",
                                  error_class="readback_mismatch", outcome="retry")
        rep.written += 1
        self._link(conn, token, org_id, system_id, h, fp, pid, data_key, ours)
        return "applied"

    def _send(self, client, pid, want) -> None:
        try:
            client.patch(pid, want)
        except api.PersonGone as exc:
            self._gone(exc)
            raise api.TwentyError("the Person answered 404 to the write after answering the read",
                                  error_class="readback_mismatch", outcome="retry") from exc

    def _link(self, conn, token, org_id, system_id, h, fp, pid, data_key, seq) -> None:
        self._db(conn, token, "SELECT consentvault.connector_link_put(%s, %s, %s, %s, %s, true)",
                 (system_id, h, fp, seal_person_id(data_key, org_id, system_id, h, pid), seq))

    def _deleted_wait(self, conn, token, system_id, fp, h, rows) -> None:
        """A clear met a soft-deleted Person: keep the erasure open and alarm on the wait's age (R31): the customer's pinned
        admin alarm from 7 days, raised again daily; the operator alarm added at 30. The connector never deletes the record."""
        # the wait's start, its age and the alarm's cadence are the database's clock (connector_deleted_wait), never this process's
        wait = self._db(conn, token, "SELECT * FROM consentvault.connector_deleted_wait(%s, %s, %s)", (system_id, h, fp), one=True)
        if wait is None:
            raise SyncError("a clear met a deleted Person but its link vanished mid-delivery")
        level = wait["level"]
        if not wait["due"]:
            return
        erasure_id = next(r["erasure_id"] for r in rows if r["push_kind"] == "clear")
        # the customer's pinned admin alarm names the erasure and the system only; the record id and its link are opened for
        # an admin by deleted_record_waits (never in an alarm row, never in an email)
        self._operator_alarm(conn, token, ALARM_CUSTOMER, "clear_waiting_deleted_record", "erasure", erasure_id)
        if level == 2:
            self._operator_alarm(conn, token, ALARM_OPERATOR, "clear_blocked_by_deleted_record", "erasure", erasure_id)

    # -- finishing the rows ------------------------------------------------------------------------------------------------
    def _finish(self, conn, token, org_id, rows, out: Outcome, backoff, *, data_key=None) -> Outcome:
        if out.kind == "release":
            with org_transaction(conn, token):
                for r in rows:   # due again that long from the database's now
                    conn.execute("SELECT consentvault.sync_release(%s, %s, %s)",
                                 (r["outbox_id"], r["attempt"], int(out.release_seconds)))
            return out
        for r in rows:
            kind, backoff_s = out.kind, None
            if kind == "retry":
                # the step only, capped; whether the retry window has closed (dead) and when the next attempt is due are the
                # database's clock, counted from this push's own start as sync_attempt_started stamped it
                step = backoff(r["attempt"]) if backoff else timedelta(seconds=30 * 2 ** max(r["attempt"] - 1, 0))
                backoff_s = max(1, min(int(step.total_seconds()), MAX_BACKOFF_SECONDS))
            error_ct = None
            if out.detail and data_key is not None:
                error_ct = tc.encrypt_field(data_key, org_id, f"{r['outbox_id']}:{r['attempt']}", ERROR_COLUMN, out.detail)
            with org_transaction(conn, token):
                conn.execute("SELECT consentvault.sync_complete_connector(%s, %s, %s, %s, %s, %s, %s, %s)",
                             (r["outbox_id"], r["attempt"], kind, out.http_status,
                              out.error_class if kind != "acknowledged" else None, error_ct, backoff_s,
                              out.confirmation if kind == "acknowledged" else None))
        return out


# ---- setup (1.1 to 1.6) and the admin's actions ---------------------------------------------------------------------------
def new_receiver_id() -> tuple[str, str]:
    """32 random bytes, base64url: the receiver id (shown once in the URL) and its SHA-256 (the only thing stored)."""
    import base64

    rid = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    return rid, hashlib.sha256(rid.encode()).hexdigest()


def receiver_url(receiver_id: str, api_base: str = "https://api.consentvault.ai") -> str:
    return f"{api_base.rstrip('/')}/v1/connectors/twenty/{receiver_id}/webhook"


def checked_origin(base_url: str, *, allow_http_loopback: bool = False):
    """The one address check, for creation and for a changed address (twenty.md 1.1): an https origin with no path, query,
    fragment or credentials, and not a private, loopback, link-local, reserved or local-name host written literally (the egress
    door refuses a name that resolves there). ``allow_http_loopback`` is the contract suite's local Twenty only."""
    import ipaddress
    import urllib.parse

    from ...urlguard import UrlRefusedError, require_url

    try:
        require_url(base_url, schemes=("https",), loopback_http=allow_http_loopback)
    except UrlRefusedError as exc:
        raise CredentialError(f"endpoint_not_https: {describe(exc)}") from exc
    parts = urllib.parse.urlparse(base_url)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise CredentialError("validation_failed: the Twenty address is an origin only, with no path, query or fragment")
    host = (parts.hostname or "").lower()
    if not (allow_http_loopback and parts.scheme == "http"):
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise CredentialError("unreachable_private: Twenty must be reachable from the internet at an https address")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None  # loud-failure-exempt: a host name, not a literal address; the egress door checks what it resolves to
        if ip is not None and not ip.is_global:
            raise CredentialError("unreachable_private: Twenty must be reachable from the internet at an https address")
    return f"{parts.scheme}://{parts.netloc}", parts


def create_twenty_system(conn, custody, org_id, *, name: str, base_url: str, api_key: str, retry_window_hours: int = 24,
                         allow_http_loopback: bool = False) -> dict:
    """Create a Twenty system under an admin token (``org_transaction`` already entered): status paused, connecting; the API key
    sealed; the receiver id minted; the organisation's hash key made once. ``allow_http_loopback`` is for the contract suite's
    local Twenty only. Returns the system id and the receiver id (shown once)."""
    if not isinstance(api_key, str) or not 8 <= len(api_key) <= 8192:
        raise CredentialError("validation_failed: fields.api_key is required")
    origin, parts = checked_origin(base_url, allow_http_loopback=allow_http_loopback)
    sid = conn.execute(
        "INSERT INTO consentvault.connected_system (org_id, name, kind, connector, endpoint, signature, contact_form,"
        " retry_window_hours, status, credentials_ct, config, echo_to_source, connector_state)"
        " VALUES (%s, %s, 'crm', 'twenty', %s, 'none', 'plaintext', %s, 'paused', NULL, %s, true, 'connecting')"
        " RETURNING system_id",
        (org_id, name, "https://" + parts.netloc, retry_window_hours,
         json.dumps({"base_url": origin, "reconcile_interval_minutes": 15}))).fetchone()["system_id"]
    wrapped, sealed = seal_secret(custody, org_id, sid, "api_key", api_key.encode("utf-8"))
    conn.execute("SELECT consentvault.connector_secret_put(%s, 'api_key', %s, %s)", (sid, wrapped, sealed))
    if conn.execute("SELECT * FROM consentvault.connector_secret_get(NULL, 'hash_key')").fetchone() is None:
        conn.execute("SELECT consentvault.connector_secret_put(NULL, 'hash_key', %s, NULL)", (new_hash_key(custody, org_id),))
    rid, rhash = new_receiver_id()
    conn.execute("SELECT consentvault.connector_receiver_mint(%s, %s)", (sid, rhash))
    return {"system_id": sid, "receiver_id": rid}


def activate(conn, system_id) -> None:
    """Steps 2 to 5 passed: the system becomes active and healthy (the admin lane's column grant on status)."""
    conn.execute("UPDATE consentvault.connected_system SET status = 'active' WHERE org_id = (SELECT consentvault.current_org())"
                 " AND system_id = %s AND connector = 'twenty' AND status = 'paused'", (system_id,))
    conn.execute("SELECT consentvault.connector_set_state(%s, 'healthy')", (system_id,))


def set_webhook_secret(conn, custody, org_id, system_id, secret: str) -> None:
    """Admin only: seal the webhook secret Twenty shows (also the "Replace secret" action)."""
    if not isinstance(secret, str) or not 16 <= len(secret) <= 512:
        raise CredentialError("validation_failed: the webhook secret is 16 to 512 characters")
    wrapped, sealed = seal_secret(custody, org_id, system_id, "webhook_secret", secret.encode("utf-8"))
    conn.execute("SELECT consentvault.connector_secret_put(%s, 'webhook_secret', %s, %s)", (system_id, wrapped, sealed))


def set_address(conn, custody, org_id, system_id, *, base_url: str, api_key: str | None) -> str:
    """Admin only: a new address needs the key again in the same call; the receiver is re-minted. Returns the new receiver id."""
    if not api_key:
        raise CredentialError("validation_failed: fields.api_key is required with a new address")
    origin, parts = checked_origin(base_url)
    wrapped, sealed = seal_secret(custody, org_id, system_id, "api_key", api_key.encode("utf-8"))
    rid, rhash = new_receiver_id()
    conn.execute("SELECT consentvault.sync_twenty_set_address(%s, %s, %s, %s, %s)",
                 (system_id, "https://" + parts.netloc, wrapped, sealed, rhash))
    return rid


def disconnect(conn, system_id, reason: str) -> dict:
    """Admin only (5.2): stop pushes, retire the receiver, destroy the key and secret, drop flag history; an open clear goes dead."""
    row = conn.execute("SELECT * FROM consentvault.sync_twenty_disconnect(%s, %s)", (system_id, reason)).fetchone()
    return {"superseded": row["superseded"], "clears_dead": row["clears_dead"]}


def enqueue_refresh(conn, crypto, org_id, system_id, contact_fp: str) -> str | None:
    """Queue a refresh push for one contact (a Person appeared, a restore, a decline, a hold or a release). Rule R1 and the
    erased-contact block are the database's; None when nothing was queued."""
    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (contact_fp,)).fetchone()
    if held is None:
        return None
    data_key = crypto.open_contact_key(org_id, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    oid = uuid.uuid4()
    ct = tc.encrypt_field(data_key, org_id, str(oid), PAYLOAD_COLUMN, b'{"kind":"refresh"}')
    got = conn.execute("SELECT consentvault.sync_enqueue_refresh(%s, %s, %s, %s) AS id",
                       (oid, system_id, contact_fp, ct)).fetchone()["id"]
    return str(got) if got else None


def live_systems(conn) -> list:
    return conn.execute("SELECT system_id FROM consentvault.connected_system WHERE org_id = (SELECT consentvault.current_org())"
                        " AND connector = 'twenty' AND status IN ('active', 'paused') ORDER BY system_id").fetchall()


def enqueue_clears(conn, crypto, org_id, erasure_id, contact_fp: str) -> list[str]:
    """Queue (or return) the clear of one erasure request on every live Twenty system of the organisation (5.1). Runs inside
    ``erase_in_org`` under the lifecycle lock, after the erasure stop and before the delivery wait is computed."""
    systems = live_systems(conn)
    if not systems:
        return []
    conn.execute("SELECT consentvault.connector_lifecycle_locked()")
    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (contact_fp,)).fetchone()
    if held is None:
        raise CredentialError("an erasure being confirmed has no contact key: nothing can seal its clear")
    data_key = crypto.open_contact_key(org_id, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    out = []
    for s in systems:
        oid = uuid.uuid4()
        ct = tc.encrypt_field(data_key, org_id, str(oid), PAYLOAD_COLUMN, b'{"kind":"clear"}')
        out.append(str(conn.execute("SELECT consentvault.sync_enqueue_clear(%s, %s, %s, %s) AS id",
                                    (erasure_id, s["system_id"], oid, ct)).fetchone()["id"]))
    return out


def clear_wait(conn, erasure_id) -> tuple[str | None, list[str]]:
    """The erasure's wait reason from its Twenty clears (rule R3): ``system_clear_dead`` for a dead clear the operator has not
    waived, else ``waiting_for_system_clear`` for one still open; None when every clear is acknowledged, waived or there is
    none. Also the systems it waits on."""
    rows = conn.execute("SELECT o.status, o.system_id FROM consentvault.outbox o WHERE o.org_id ="
                        " (SELECT consentvault.current_org()) AND o.erasure_id = %s AND o.push_kind = 'clear'",
                        (erasure_id,)).fetchall()
    dead = [str(r["system_id"]) for r in rows if r["status"] == "dead"]
    open_ = [str(r["system_id"]) for r in rows if r["status"] in ("pending", "failed", "sent")]
    if dead:
        return "system_clear_dead", dead
    if open_:
        return "waiting_for_system_clear", open_
    return None, []


def deleted_record_waits(conn, crypto, org_id) -> list[dict]:
    """For the organisation's admins only: every clear waiting on a soft-deleted Person, with the record id in their own Twenty
    and the link to it (opened from the link sealed under the erasing contact's key, which exists while the erasure is open).
    Never a name, an email or a phone."""
    out = []
    for s in conn.execute("SELECT system_id, config, endpoint FROM consentvault.connector_systems()").fetchall():
        base = (s["config"] or {}).get("base_url") or s["endpoint"]
        for link in conn.execute("SELECT * FROM consentvault.connector_links_of(%s, NULL, NULL)", (s["system_id"],)).fetchall():
            if link["deleted_since"] is None:
                continue
            held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (link["contact_fp"],)).fetchone()
            if held is None:
                raise SyncError("a deleted-record wait has no contact key: the erasure completed without its clear")
            key = crypto.open_contact_key(org_id, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
            pid = open_person_id(key, org_id, s["system_id"], link["person_id_hash"], link["person_id_ct"])
            out.append({"system_id": str(s["system_id"]), "record_id": pid, "link": api.record_link(base, pid),
                        "since": link["deleted_since"], "alarm_level": link["alarm_level"]})
    return out


# ---- the erasure lifecycle's Twenty hooks (5.1); each is a no-op for an organisation with no Twenty system ------------------
def _refresh_all(conn, crypto, org_id, contact_fp: str) -> int:
    return sum(enqueue_refresh(conn, crypto, org_id, s["system_id"], contact_fp) is not None for s in live_systems(conn))


def on_decline(conn, crypto, org_id, erasure_id, contact_fp: str) -> int:
    """A decline marks the request's open or dead clears ``declined`` (an acknowledged one stays: it was delivered) and queues a
    refresh, because suppression may have dropped status pushes and a clear may have blanked the fields (rules R6, R7)."""
    n = conn.execute("SELECT consentvault.connector_clear_supersede(%s, 'declined', ARRAY['pending', 'failed', 'dead']) AS n",
                     (erasure_id,)).fetchone()["n"]
    if not live_systems(conn):
        return n
    _refresh_all(conn, crypto, org_id, contact_fp)
    return n


def on_hold_placed(conn, crypto, org_id, contact_fps: list[str] | None) -> int:
    """A legal hold blocks the clear and never a stop (5.1): every pending request of a covered contact that has a Twenty clear
    is marked held, its open, dead or acknowledged clear becomes ``held`` (the refresh below writes data back, so the clear must
    run again), and a refresh is queued. ``contact_fps`` None means an organisation-wide hold."""
    if not live_systems(conn):
        return 0
    reqs = conn.execute("SELECT * FROM consentvault.connector_requests_with_clear(%s)", (contact_fps,)).fetchall()
    for r in reqs:
        conn.execute("SELECT consentvault.connector_clear_supersede(%s, 'held', ARRAY['pending', 'failed', 'dead', 'acknowledged'],"
                     " NULL, true)", (r["erasure_id"],))
        _refresh_all(conn, crypto, org_id, r["contact_fp"])
    return len(reqs)


def on_hold_released(conn, crypto, org_id, contact_fps: list[str] | None) -> int:
    """A release queues a refresh for every covered contact with a Twenty link (rule R7); the resume re-runs each request."""
    if not live_systems(conn):
        return 0
    n = 0
    for s in live_systems(conn):
        for link in conn.execute("SELECT DISTINCT contact_fp FROM consentvault.connector_links_of(%s, %s, NULL)",
                                 (s["system_id"], contact_fps)).fetchall():
            n += enqueue_refresh(conn, crypto, org_id, s["system_id"], link["contact_fp"]) is not None
    return n


def waive_clear(conn, erasure_id, system_id, *, operator_id: str, reason: str) -> None:
    """``:proceed-without-clear`` (5.1, rule R15): refused unless the system is disconnected and its API key destroyed; the
    clear becomes ``waived`` and the request records who, when and why. A reachable system is redriven, never waived."""
    if not reason or not reason.strip():
        raise CredentialError("validation_failed: fields.reason is required")
    if not conn.execute("SELECT consentvault.connector_waivable(%s) AS ok", (system_id,)).fetchone()["ok"]:
        raise CredentialError("validation_failed: fields.system: the system must be disconnected and its key destroyed")
    n = conn.execute("SELECT consentvault.connector_clear_supersede(%s, 'waived', ARRAY['dead'], %s) AS n",
                     (erasure_id, system_id)).fetchone()["n"]
    if n != 1:
        raise CredentialError("validation_failed: only a dead clear of this request on this system can be waived")
    conn.execute("UPDATE consentvault.erasure_request SET clear_waived_by = %s, clear_waived_at = clock_timestamp(),"
                 " clear_waived_reason = %s WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s",
                 (operator_id, reason.strip()[:500], erasure_id))
