"""The sync worker: drains the outbox of every active organisation, one organisation per transaction.

It runs as the worker role. ``consentvault.dispatch_orgs('sync')`` hands it one short-lived token per active
organisation (scope ``worker:sync``); every read and write below goes through an owner-rights function that filters on
that organisation itself. The worker never holds a privilege on a table and never reads an evidence row: it receives,
per push, ciphertexts and the contact's wrapped key, which only the organisation's key service can open.

Delivery rules (data-model 9.1, suppression-sync.md):
- ordering key (org, system, contact, channel, purpose): a push starts only when no OLDER push of that key is queued,
  failed or in flight (enforced in ``sync_claim``, so any number of workers keep the order);
- 2xx acknowledged; 5xx, 408, 429, a timeout or an unreachable receiver retry with exponential backoff until the
  system's window (default 24 hours, counted from the push's creation or its redrive) ends, then dead;
  any other 4xx is a poison message and dead at once;
- a push that is superseded while it waits is never sent; one in flight finishes, and a failed one is superseded
  instead of retried when a newer state exists;
- a push the vault could not even attempt because OUR side failed (the key service, the sealed credential, the egress
  door) is released, not counted against the receiver or the window, and the run reports the failure loudly;
- dead pushes raise ONE alarm per (system, error class) per run, never one per row, and stay unalarmed until the
  alarm was actually raised.

Every call has a deadline: the claim lease bounds one attempt, the run deadline bounds one organisation's drain, and
the transport carries its own timeout.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

import psycopg

from ..tenancy import crypto as tc
from ..tenancy.errors import TenancyError
from ..tenancy.keys_protocol import WrappedKey
from ..tenancy.tokens import org_transaction
from .connectors import webhook
from .errors import AlarmSinkError, CredentialError, SyncError, TransportError, WorkerError
from .outbox import ERROR_COLUMN, decrypt_payload
from .systems import Custody, open_credentials

log = logging.getLogger("consentvault.sync")

RELEASE_DELAY_SECONDS = 60


PREPARE_FAILED = "prepare_failed"
ALARM_SYNC_DEAD = "sync.dead"


@dataclass(frozen=True)
class WorkerConfig:
    batch_size: int = 4
    lease_seconds: int = 60  # must cover a whole batch at the send timeout: batch_size x send_timeout_seconds
    backoff_base_seconds: float = 30.0
    backoff_cap_seconds: float = 3600.0
    max_batches_per_org: int = 200
    org_deadline_seconds: float = 240.0  # below the 300 s life of a token minted just before the organisation's drain
    max_pushes_per_org: int = 200  # per run: one busy organisation never holds the others back
    send_timeout_seconds: float = float(webhook.EGRESS_TIMEOUT_SECONDS)

    def __post_init__(self) -> None:
        if self.batch_size < 1 or self.max_pushes_per_org < 1:
            raise WorkerError("batch_size and max_pushes_per_org must be at least 1")
        if self.lease_seconds < self.batch_size * self.send_timeout_seconds:
            raise WorkerError(
                f"lease_seconds {self.lease_seconds} is shorter than a batch of {self.batch_size} pushes at the "
                f"{self.send_timeout_seconds:g} s send timeout; a lease would expire mid-batch and another worker "
                "could send the same push out of order. Raise the lease or shrink the batch")

    def backoff(self, attempt: int) -> timedelta:
        return timedelta(seconds=min(self.backoff_base_seconds * (2 ** max(attempt - 1, 0)), self.backoff_cap_seconds))


@dataclass(frozen=True)
class Alarm:
    org_id: uuid.UUID
    system_id: uuid.UUID
    system_name: str
    error_class: str | None
    count: int
    oldest: datetime | None

    def message(self) -> str:
        return (f"{self.count} push(es) to connected system {self.system_name!r} ({self.system_id}) of organisation "
                f"{self.org_id} are dead ({self.error_class or 'unknown error class'}); oldest {self.oldest}. "
                "Fix the system, then redrive.")


class AlarmSink(Protocol):
    def raise_alarm(self, alarm: Alarm) -> None: ...


class LoggingAlarmSink:
    """Writes the alarm at ERROR level. The email and job-health sinks are the notification lane's."""

    def raise_alarm(self, alarm: Alarm) -> None:
        log.error("consentvault sync alarm: %s", alarm.message())


@dataclass
class OrgReport:
    org_id: uuid.UUID
    claimed: int = 0
    acknowledged: int = 0
    retried: int = 0
    dead: int = 0
    superseded: int = 0
    released: int = 0
    stale: int = 0
    alarms: int = 0
    capped: bool = False  # the per-run push cap was reached; the rest waits for the next run (not an error)
    errors: list[str] = field(default_factory=list)


@dataclass
class RunReport:
    orgs: list[OrgReport] = field(default_factory=list)

    @property
    def errors(self) -> list[str]:
        return [f"{o.org_id}: {e}" for o in self.orgs for e in o.errors]

    @property
    def ok(self) -> bool:
        return not self.errors


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SyncWorker:
    def __init__(self, crypto: tc.TenantCrypto, custody: Custody, transport: webhook.Transport,
                 alarms: AlarmSink | None = None, *, config: WorkerConfig | None = None,
                 clock: Callable[[], datetime] = _utcnow) -> None:
        self.crypto = crypto
        self.custody = custody
        self.transport = transport
        self.alarms = alarms or LoggingAlarmSink()
        self.config = config or WorkerConfig()
        self.clock = clock
        self._runs = 0
        timeout = getattr(transport, "timeout", None)
        if isinstance(timeout, (int, float)) and timeout > self.config.send_timeout_seconds:
            raise WorkerError(f"the transport's timeout ({timeout:g} s) is longer than the worker's send timeout "
                              f"({self.config.send_timeout_seconds:g} s) the lease is sized for")

    # one pass over every active organisation ----------------------------------------------------------------------

    def run_once(self, conn: psycopg.Connection, *, raise_on_error: bool = True) -> RunReport:
        """Drain every organisation once. Raises ``WorkerError`` (carrying the report) when anything failed."""
        report = RunReport()
        try:
            org_ids = [r["org_id"] for r in conn.execute("SELECT * FROM consentvault.dispatch_org_ids('sync') AS org_id")]
        except psycopg.Error as exc:
            raise WorkerError(f"the worker could not list the organisations: {type(exc).__name__}: {exc}") from exc
        if org_ids:  # a different organisation goes first each run, so none is always last
            start = self._runs % len(org_ids)
            org_ids = org_ids[start:] + org_ids[:start]
        self._runs += 1
        for org_id in org_ids:
            org_report = OrgReport(org_id)
            report.orgs.append(org_report)
            try:
                # minted just before this organisation's drain, so a slow organisation never outlives the next token
                token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]
                self.run_org(conn, org_id, token, org_report)
            except Exception as exc:  # one organisation's failure never hides another's; it is named in the report
                org_report.errors.append(f"{type(exc).__name__}: {exc}")
        if raise_on_error and not report.ok:
            err = WorkerError("the sync run finished with failures: " + "; ".join(report.errors))
            err.report = report  # type: ignore[attr-defined]
            raise err
        return report

    def run_loop(self, connect: Callable[[], psycopg.Connection], stop: threading.Event, interval_seconds: float = 5.0) -> None:
        """Run until ``stop`` is set. A failed pass is logged at ERROR and the loop goes on; none is ever silent."""
        while not stop.is_set():
            try:
                with connect() as conn:
                    self.run_once(conn)
            except SyncError as exc:
                log.error("consentvault sync pass failed: %s", exc)
            stop.wait(interval_seconds)

    # one organisation ----------------------------------------------------------------------------------------------

    def run_org(self, conn: psycopg.Connection, org_id, token: str, report: OrgReport | None = None) -> OrgReport:
        cfg = self.config
        report = report or OrgReport(org_id)
        started = self.clock()
        deadline = started + timedelta(seconds=cfg.org_deadline_seconds)
        pushes = 0
        stop = False
        for _ in range(cfg.max_batches_per_org):
            if pushes >= cfg.max_pushes_per_org:
                break
            if self.clock() >= deadline:
                report.errors.append(f"the {cfg.org_deadline_seconds:.0f} s deadline for this organisation passed with "
                                     "work still queued; the next run continues")
                break
            with org_transaction(conn, token):
                rows = conn.execute("SELECT * FROM consentvault.sync_claim(%s, %s, %s)",
                                    (min(cfg.batch_size, cfg.max_pushes_per_org - pushes), cfg.lease_seconds,
                                     self.clock())).fetchall()
            if not rows:
                break
            report.claimed += len(rows)
            for row in rows:
                if stop or self.clock() >= deadline:  # the deadline is checked before every push
                    if not stop:
                        report.errors.append(f"the {cfg.org_deadline_seconds:.0f} s deadline for this organisation "
                                             "passed with work still queued; the next run continues")
                    stop = True
                    self._release(conn, token, row, report)
                    continue
                try:
                    self._deliver(conn, token, org_id, row, report)
                    pushes += 1
                except TransportError as exc:
                    stop = True
                    report.errors.append(f"delivery door failure: {exc}")
                    self._release(conn, token, row, report)
            if stop:
                break
        else:
            report.errors.append(f"{cfg.max_batches_per_org} batches did not drain this organisation; the next run continues")
        report.capped = pushes >= cfg.max_pushes_per_org
        with org_transaction(conn, token):
            conn.execute("SELECT consentvault.sync_refresh_redrives()")
        self._alarm(conn, token, org_id, report)
        return report

    # one push --------------------------------------------------------------------------------------------------------

    def _release(self, conn, token, row, report: OrgReport) -> None:
        try:
            with org_transaction(conn, token):
                conn.execute("SELECT consentvault.sync_release(%s, %s, %s)",
                             (row["outbox_id"], row["attempt"],
                              self.clock() + timedelta(seconds=RELEASE_DELAY_SECONDS)))
            report.released += 1
        except psycopg.errors.ObjectNotInPrerequisiteState:
            report.stale += 1

    def _deliver(self, conn, token, org_id, row, report: OrgReport) -> None:
        outbox_id, attempt = row["outbox_id"], row["attempt"]
        data_key = None
        try:
            data_key = self.crypto.open_contact_key(org_id, WrappedKey(bytes(row["wrapped_key"]), row["key_version"]))
            body = decrypt_payload(data_key, org_id, outbox_id, row["payload_ct"])
            secret = open_credentials(self.custody, org_id, row["system_id"], row["credentials_ct"])
        except (TenancyError, CredentialError) as exc:
            # counted as an attempt: retried with backoff and dead when the window ends (alarmed then), never a
            # silent loop of releases
            report.errors.append(f"push {outbox_id} to {row['system_name']!r} could not be prepared "
                                 f"({type(exc).__name__}: {exc}); counted as an attempt")
            outcome = webhook.Outcome("retry", PREPARE_FAILED, None, f"preparation failed: {type(exc).__name__}")
        else:
            request = webhook.build_request(
                endpoint=row["endpoint"], signature=row["signature"], secret=secret, body=body, outbox_id=outbox_id,
                org_id=org_id, contact_fp=row["contact_fp"], channel=row["channel"], purpose=row["purpose"],
                version=row["version"])
            outcome = webhook.classify(self.transport.send(request))  # TransportError propagates: the door
        now = self.clock()
        next_at = None
        if outcome.kind == "retry":
            deadline = row["window_start"] + timedelta(hours=row["retry_window_hours"])
            if now >= deadline:
                outcome = webhook.Outcome("dead", outcome.error_class, outcome.http_status,
                                          f"the retry window of {row['retry_window_hours']} h ended; last: {outcome.detail}")
            else:
                next_at = min(now + self.config.backoff(attempt), deadline)
        error_ct = None
        if outcome.detail and data_key is not None:
            error_ct = tc.encrypt_field(data_key, org_id, f"{outbox_id}:{attempt}", ERROR_COLUMN, outcome.detail)
        try:
            with org_transaction(conn, token):
                final = conn.execute(
                    "SELECT consentvault.sync_complete(%s, %s, %s, %s, %s, %s, %s, %s) AS final",
                    (outbox_id, attempt, outcome.kind, outcome.http_status, outcome.error_class, error_ct, next_at,
                     now)).fetchone()["final"]
        except psycopg.errors.ObjectNotInPrerequisiteState as exc:
            report.stale += 1
            log.warning("consentvault sync: attempt %s of push %s was finished after its lease was taken over: %s",
                        attempt, outbox_id, exc)
            return
        if final == "acknowledged":
            report.acknowledged += 1
        elif final == "dead":
            report.dead += 1
        elif final == "superseded":
            report.superseded += 1
        else:
            report.retried += 1

    # alarms ------------------------------------------------------------------------------------------------------------

    def _alarm(self, conn, token, org_id, report: OrgReport) -> None:
        with org_transaction(conn, token):
            groups = conn.execute("SELECT * FROM consentvault.sync_dead_groups()").fetchall()
        from ..alarms import raise_operator_alarm
        for g in groups:
            alarm = Alarm(org_id, g["system_id"], g["system_name"], g["error_class"], g["n"], g["oldest"])
            try:
                self.alarms.raise_alarm(alarm)
                with org_transaction(conn, token):  # the row the operator watches, beside any other sink
                    raise_operator_alarm(conn, name=ALARM_SYNC_DEAD, error_class=g["error_class"] or "unknown",
                                         ref_kind="system", ref_id=g["system_id"])
                    conn.execute("SELECT consentvault.sync_ack_alarms(%s)", (list(g["outbox_ids"]),))
            except Exception as exc:  # any sink or row failure: the rows stay unalarmed and the next run retries
                report.errors.append(str(AlarmSinkError(
                    f"the alarm for system {g['system_name']!r} could not be raised: {type(exc).__name__}: {exc}")))
                continue
            report.alarms += 1
