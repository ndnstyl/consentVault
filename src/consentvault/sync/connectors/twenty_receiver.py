"""The Twenty webhook receiver and the inbound rules shared with the reconcile (contracts: twenty.md sections 3.1 to 3.7).

``POST /v1/connectors/twenty/{receiver_id}/webhook``. No bearer and no session: the receiver id resolves (by its SHA-256) to one
organisation and system, a tenant token with scope ``capture`` only is minted for the rest of the request, and the signature
over the RAW body is the authentication. Order (3.2): body cap; the two headers; the 5-minute window (Twenty sends
milliseconds); the hex HMAC-SHA256 of ``"{timestamp}:{raw body}"`` in constant time; the signature claimed once as a nonce;
only then the JSON is parsed. Every refusal answers one shape, ``401 {"error": "invalid_client"}``; an unknown, retired or
disconnected receiver answers ``404`` with no detail. The reason is counted on the system's activity list, and 5 bad signatures
in 10 minutes move the system to ``needs_attention:webhook_failing`` with one alarm.

What counts (3.4): a TRANSITION of the stop flag to true (false to true, or first sight with the flag true) records a stop
against every contact point on the Person for every channel the organisation has, purpose ``*``, method and origin ``import``,
through the ordinary ``process_signal``; each erased point is skipped (3.7), never the Person. True to false changes nothing in
the ledger. Consent is never created from Twenty. A hard delete (``person.destroyed``) drops the Person's links and flag history
and leaves one destroyed marker, after which every event for that Person is ignored; a soft delete deletes nothing.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

import psycopg

from ...safelog import describe
from ...ledger import CHANNELS
from ...tenancy import crypto as tc
from ...tenancy.errors import ReplayError, TenancyError
from ...tenancy.replay import claim_nonce
from ...tenancy.tokens import TokenKey, mint_org_token, org_transaction
from ..errors import CredentialError, SyncError
from ..signals import Signal, process_signal
from . import twenty_api as api
from .twenty import enqueue_refresh, load_keys, person_id_hash, seal_hint

BODY_CAP = 256 * 1024
WINDOW_SECONDS = 300
REQUEST_BUDGET_SECONDS = 4.0     # Twenty waits 5 seconds (read in its 2.46.0 server); the answer leaves inside it
BAD_SIGNATURE_ALARM = 5          # in a 10-minute bucket
H_TS, H_SIG = "x-twenty-webhook-timestamp", "x-twenty-webhook-signature"
HANDLED = {"person.created", "person.updated", "person.upserted", "person.deleted", "person.destroyed", "person.restored"}
INVALID = (401, {"error": "invalid_client"})
UNKNOWN = (404, {})


@dataclass
class Inbound:
    """What one inbound Person event did, counted (the activity list; never a contact, never a Twenty id)."""
    stops_recorded: int = 0
    signals: int = 0
    skipped_erased: int = 0
    refreshes: int = 0
    after_destroyed: int = 0
    flag_set_after_lift: int = 0
    contact_points_over_cap: int = 0
    unmatchable_points: int = 0
    payload_incomplete: int = 0

    def counts(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if isinstance(v, int) and v}


class BudgetExceeded(SyncError):
    """The request's time budget ended before every signal was recorded: answer a loud 503; the reconcile completes the rest."""


def org_channels(conn) -> list[str]:
    """The channels the organisation has (3.4: a channel it lacks is skipped). An organisation with no channel rows has the
    core four."""
    rows = conn.execute("SELECT channel FROM consentvault.channel WHERE org_id = (SELECT consentvault.current_org())").fetchall()
    have = [r["channel"] for r in rows if r["channel"] in CHANNELS]
    return have or list(CHANNELS)


def apply_person_event(conn, crypto, org_id, system_id, *, event: str, record: dict, hash_key: bytes,
                       region: str | None = None, deadline: Callable[[], None] = lambda: None) -> Inbound:
    """The inbound rules for one Person, inside an entered tenant holding the ``capture`` scope. Shared by the receiver and
    the reconcile (which passes ``event="person.updated"`` for every Person it reads)."""
    res = Inbound()
    pid = record.get("id")
    if not isinstance(pid, str) or not pid:
        raise SyncError("the event carries no Person id")
    h = person_id_hash(hash_key, pid)
    if event == "person.destroyed":
        conn.execute("SELECT consentvault.connector_destroy(%s, %s)", (system_id, h))
        return res
    if conn.execute("SELECT consentvault.connector_is_destroyed(%s, %s) AS d", (system_id, h)).fetchone()["d"]:
        res.after_destroyed += 1   # Twenty gives no ordering: a late event for a destroyed Person is ignored (marker)
        return res
    if event == "person.deleted":
        return res                 # a soft delete deletes nothing; links, flag history and leases stay (3.3)
    if "cvStopFlag" not in record or "emails" not in record or "phones" not in record:
        res.payload_incomplete += 1
        conn.execute("SELECT consentvault.sync_request_reconcile(%s)", (system_id,))
        return res
    if event == "person.restored":
        conn.execute("SELECT consentvault.connector_person_back(%s, %s)", (system_id, h))
    points = api.contact_points(record, region)
    res.unmatchable_points += api.unmatchable_points(record, region)
    res.contact_points_over_cap += api.over_cap(record, region)
    fps = {crypto.contact_fingerprint(org_id, k, n): (k, n) for k, n in points}
    erased = set(conn.execute("SELECT consentvault.connector_erased_points(%s) AS e", (list(fps),)).fetchone()["e"])
    res.skipped_erased += len(erased)
    live = {f: p for f, p in fps.items() if f not in erased}
    linked = {r["contact_fp"] for r in conn.execute("SELECT * FROM consentvault.connector_links_of(%s, NULL, %s)",
                                                   (system_id, h)).fetchall()}
    added = [f for f in live if f not in linked]
    for f in live:                              # the event names this Person as carrying each point: remember it, so a
        conn.execute("SELECT consentvault.connector_hint_put(%s, %s, %s, %s)",   # delivery finds a point Twenty's filter
                     (system_id, h, f, seal_hint(hash_key, org_id, system_id, h, pid)))   # cannot (1.7)
    removed = linked - set(fps)
    flag = record.get("cvStopFlag") is True
    seen = conn.execute("SELECT consentvault.connector_flag_seen_get(%s, %s) AS f", (system_id, h)).fetchone()["f"]
    updated_at = str(record.get("updatedAt") or "")
    channels = org_channels(conn)

    def stop(points_to_stop) -> None:
        for f in points_to_stop:
            _kind, norm = live[f]
            for ch in channels:
                deadline()
                got = process_signal(conn, crypto, org_id=org_id, system_id=system_id, region=region, signal=Signal(
                    contact=norm, channel=ch, purpose="*", claimed_state="denied", claimed_at=None,
                    external_ref=f"twenty:{pid}:{updated_at}:{f[:16]}:{ch}", disclosure_sha256=None))
                res.signals += 1
                res.stops_recorded += got.resolution == "applied_as_event"

    if flag and seen is not True:
        stop(list(live))                       # a transition: false to true, or first sight with the flag true
    elif flag and added:
        stop(added)                            # R26: a point added to a Do-not-contact Person gets the stop
    if flag and seen is True:
        res.flag_set_after_lift += any(
            conn.execute("SELECT consentvault.sync_ledger_state(%s, %s, '*') AS s", (f, channels[0])).fetchone()["s"]
            != "denied" for f in live)
    if seen is not flag:
        conn.execute("SELECT consentvault.connector_flag_seen_set(%s, %s, %s)", (system_id, h, flag))
    if event in ("person.created", "person.restored") or added or removed:
        for f in live:                          # R23: refresh every contributing contact and recheck the Person
            res.refreshes += enqueue_refresh(conn, crypto, org_id, system_id, f) is not None
        conn.execute("SELECT consentvault.sync_request_reconcile(%s)", (system_id,))
    return res


def record_counts(conn, system_id, res: Inbound) -> None:
    for name, n in res.counts().items():
        conn.execute("SELECT consentvault.connector_count(%s, %s, %s)", (system_id, name, n))


class TwentyReceiver:
    """The receiver route. ``connect`` returns a fresh autocommit connection as the runtime role."""

    def __init__(self, connect: Callable[[], psycopg.Connection], crypto: tc.TenantCrypto, custody, token_key: TokenKey, *,
                 region: str | None = None, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 monotonic: Callable[[], float] = time.monotonic, budget_seconds: float = REQUEST_BUDGET_SECONDS) -> None:
        self.connect, self.crypto, self.custody, self.token_key = connect, crypto, custody, token_key
        self.region, self.clock, self.monotonic, self.budget = region, clock, monotonic, budget_seconds

    def handle(self, receiver_id: str, headers: dict, raw_body: bytes) -> tuple[int, dict]:
        started = self.monotonic()
        if not isinstance(raw_body, (bytes, bytearray)):
            raise SyncError("the receiver needs the raw body bytes")
        if len(raw_body) > BODY_CAP:
            return 400, {"error": "validation_failed", "fields": {"body": "over 256 KB"}}
        hdr = {str(k).lower(): v for k, v in (headers or {}).items()}
        rhash = hashlib.sha256(str(receiver_id).encode()).hexdigest()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM consentvault.sync_receiver_resolve(%s)", (rhash,)).fetchone()
            if row is None:
                return UNKNOWN
            org_id, system_id = row["org_id"], row["system_id"]
            token = mint_org_token(self.token_key, org_id, ("capture",), credential_id=None, ttl_seconds=60)
            with org_transaction(conn, token):
                reason = self._verify(conn, org_id, system_id, hdr, bytes(raw_body))
                if reason is not None:
                    self._refused(conn, system_id, reason)
            if reason is not None:
                return INVALID
            body = self._parse(raw_body)
            if body is None:
                return 400, {"error": "validation_failed", "fields": {"body": "not a JSON object with a record"}}
            event = body.get("eventName")
            if event not in HANDLED:
                with org_transaction(conn, token):
                    conn.execute("SELECT consentvault.connector_count(%s, 'unsupported_event', 1)", (system_id,))
                return 202, {"ok": True, "ignored": "unsupported_event"}
            return self._apply(conn, token, org_id, system_id, "person.updated" if event == "person.upserted" else event,
                               body["record"], started)

    @staticmethod
    def _parse(raw_body: bytes):
        try:
            body = json.loads(bytes(raw_body).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):  # loud-failure-exempt: a malformed body is answered 400 validation_failed by name
            return None
        return body if isinstance(body, dict) and isinstance(body.get("record"), dict) else None

    def _apply(self, conn, token, org_id, system_id, event: str, record: dict, started: float) -> tuple[int, dict]:
        dedupe = "twenty:dedupe:" + hashlib.sha256(
            f"{system_id}\x1f{record.get('id')}\x1f{record.get('updatedAt')}\x1f{event}".encode()).hexdigest()

        def deadline() -> None:
            if self.monotonic() - started > self.budget:
                raise BudgetExceeded("the webhook's time budget ended; the reconcile completes the rest")

        try:
            with org_transaction(conn, token):
                expires = conn.execute("SELECT clock_timestamp() + interval '24 hours' AS e").fetchone()["e"]   # the database's day
                claim_nonce(conn, org_id, dedupe, expires)
                keys = load_keys(conn, self.custody, org_id, system_id, purposes=())
                res = apply_person_event(conn, self.crypto, org_id, system_id, event=event, record=record,
                                         hash_key=keys["hash_key"], region=self.region, deadline=deadline)
                record_counts(conn, system_id, res)
                conn.execute("SELECT consentvault.connector_count(%s, 'webhook_verified', 1)", (system_id,))
        except ReplayError:  # loud-failure-exempt: a repeat of a processed change is counted 'dedupe' and acknowledged
            return self._note(conn, token, system_id, "dedupe", 202, {"ok": True, "dedupe": True})
        except BudgetExceeded:  # loud-failure-exempt: answered 503 by name, counted, and the reconcile is requested to finish it
            with org_transaction(conn, token):
                conn.execute("SELECT consentvault.sync_request_reconcile(%s)", (system_id,))
            return self._note(conn, token, system_id, "webhook_budget_exceeded", 503,
                              {"error": "unavailable", "message": "the stop was not fully recorded; the reconcile completes it"})
        return 202, {"ok": True}

    @staticmethod
    def _note(conn, token, system_id, name: str, status: int, body: dict) -> tuple[int, dict]:
        with org_transaction(conn, token):
            conn.execute("SELECT consentvault.connector_count(%s, %s, 1)", (system_id, name))
        return status, body

    def _verify(self, conn, org_id, system_id, hdr: dict, raw: bytes) -> str | None:
        ts, sig = hdr.get(H_TS), hdr.get(H_SIG)
        if not ts or not sig:
            return "signature_missing"
        if not (isinstance(ts, str) and ts.isascii() and re.fullmatch(r"[0-9]{1,16}", ts, re.ASCII)):   # ASCII digits only: milliseconds since the epoch, as Twenty sends
            return "stale_timestamp"
        ms = int(ts)
        # the freshness window is judged on the database's clock, the clock every other time here is kept on
        db_now = conn.execute("SELECT extract(epoch FROM clock_timestamp())::float8 AS t").fetchone()["t"]
        if abs(db_now - ms / 1000.0) > WINDOW_SECONDS:
            return "stale_timestamp"
        try:
            secret = load_keys(conn, self.custody, org_id, system_id, purposes=("webhook_secret",))["webhook_secret"]
        except CredentialError:  # loud-failure-exempt: counted 'secret_missing' and answered 401; the wizard shows the step undone
            return "secret_missing"
        if not api.verify_signature(secret, str(ts), raw, str(sig)):
            return "signature_bad"
        try:
            claim_nonce(conn, org_id, "twenty:sig:" + str(sig),
                        datetime.fromtimestamp(ms / 1000.0, timezone.utc) + timedelta(seconds=WINDOW_SECONDS * 2))
        except ReplayError:  # loud-failure-exempt: counted 'replay' and answered 401 invalid_client
            return "replay"
        except TenancyError as exc:
            raise SyncError(f"the replay guard refused the signature claim: {describe(exc)}") from exc
        return None

    def _refused(self, conn, system_id, reason: str) -> None:
        """Count the refusal by name, and raise webhook_failing once at 5 bad signatures in a 10-minute bucket."""
        conn.execute("SELECT consentvault.connector_count(%s, %s, 1)", (system_id, reason))
        if reason != "signature_bad":
            return
        # the 10-minute window and its count are the database's clock (connector_window_hit), never this process's
        n = conn.execute("SELECT consentvault.connector_window_hit(%s, 'sigbad', 600, %s) AS n",
                         (system_id, BAD_SIGNATURE_ALARM)).fetchone()
        if n["n"] >= BAD_SIGNATURE_ALARM:
            changed = conn.execute("SELECT consentvault.connector_set_state(%s, 'needs_attention:webhook_failing') AS c",
                                   (system_id,)).fetchone()["c"]
            if changed:
                from ...alarms import raise_operator_alarm

                raise_operator_alarm(conn, name="connector.state", error_class="needs_attention_webhook_failing",
                                     ref_kind="system", ref_id=system_id)
