"""The sync worker: drains the outbox of every active organisation, one organisation per transaction.

Given a ``connect`` function, ``run_once`` drains organisations in parallel with a bounded pool (``max_parallel_orgs``
threads, each on its own connection). Work is shared round-robin one push at a time, so a slow receiver holds one thread
for one push and another organisation's stop waits behind it for at most that push. Each organisation keeps its own
token (minted just before its first push), its own deadline and its own push cap.

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

While a database restore is unreconciled (``consentvault.restore_pending()``) the worker pushes nothing: the database
may be missing stops, and a push of an older state could undo one a receiver already holds. The run answers
``paused = "restore_in_progress"`` and logs it at WARNING on every pass until the reconciliation completes.

Every call has a deadline: the claim lease bounds one attempt, the run deadline bounds one organisation's drain, and
the transport carries its own timeout.
"""

from __future__ import annotations

from ..safelog import describe
from .. import safelog
import threading
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

import psycopg

from ..tenancy import crypto as tc
from ..tenancy.errors import TenancyError
from ..tenancy.keys_protocol import WrappedKey
from ..tenancy.tokens import org_transaction
from .connectors import webhook
from .errors import AlarmSinkError, CredentialError, StaleAttemptError, SyncError, TransportError, WorkerError
from .outbox import ERROR_COLUMN, decrypt_payload, push_start_taken_over
from .systems import Custody, open_credentials

log = safelog.get("consentvault.sync")

RELEASE_DELAY_SECONDS = 60
MAX_BACKOFF_SECONDS = 3600  # the longest retry step the database accepts (sync_complete)
PAUSED_RESTORE = "restore_in_progress"


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
    max_parallel_orgs: int = 8  # threads draining organisations at once when a ``connect`` function is given

    def __post_init__(self) -> None:
        if self.batch_size < 1 or self.max_pushes_per_org < 1:
            raise WorkerError("batch_size and max_pushes_per_org must be at least 1")
        if not 1 <= self.max_parallel_orgs <= 64:
            raise WorkerError("max_parallel_orgs must be from 1 to 64")
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
        log.error("consentvault sync alarm: pushes to a connected system are dead; fix the system, then redrive", count=alarm.count,
                  system_name=alarm.system_name, system_id=alarm.system_id, org_id=alarm.org_id, error_class=alarm.error_class,
                  oldest=alarm.oldest)


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
    run_errors: list[str] = field(default_factory=list)  # a failure of the run itself (a pool thread's connection)
    paused: str | None = None  # the run pushed nothing on purpose (a restore is unreconciled); not an error, never silent

    @property
    def errors(self) -> list[str]:
        return self.run_errors + [f"{o.org_id}: {e}" for o in self.orgs for e in o.errors]

    @property
    def ok(self) -> bool:
        return not self.errors


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SyncWorker:
    def __init__(self, crypto: tc.TenantCrypto, custody: Custody, transport: webhook.Transport,
                 alarms: AlarmSink | None = None, *, config: WorkerConfig | None = None,
                 clock: Callable[[], datetime] = _utcnow, twenty=None) -> None:
        self.twenty = twenty  # the Twenty connector's delivery (connectors/twenty.py); None: Twenty systems are named as unserved
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

    def run_once(self, conn: psycopg.Connection, *, raise_on_error: bool = True,
                 connect: Callable[[], psycopg.Connection] | None = None) -> RunReport:
        """Drain every organisation once. Raises ``WorkerError`` (carrying the report) when anything failed.

        With ``connect`` (and ``max_parallel_orgs`` above 1) organisations drain in parallel on a bounded pool, one push
        per turn; without it they drain one after another on ``conn``.
        """
        report = RunReport()
        try:
            retired = conn.execute("SELECT consentvault.any_organisation_cut_over() AS c").fetchone()["c"]
        except psycopg.Error as exc:
            raise WorkerError(f"the worker could not read whether the cutover has happened: {describe(exc)}") from exc
        if retired:
            raise WorkerError("the outbox worker is retired after the cutover: the effects layer sends the queued pushes, as effect intents",
                              code="outbox_worker_retired")
        try:
            restoring = conn.execute("SELECT consentvault.restore_pending() AS p").fetchone()["p"]
        except psycopg.Error as exc:
            raise WorkerError(f"the worker could not read whether a restore is pending: {describe(exc)}") from exc
        if restoring:
            report.paused = PAUSED_RESTORE
            log.warning("consentvault sync paused: a database restore is not yet reconciled; nothing is pushed until it is")
            return report
        try:
            org_ids = [r["org_id"] for r in conn.execute("SELECT * FROM consentvault.dispatch_org_ids('sync') AS org_id")]
        except psycopg.Error as exc:
            raise WorkerError(f"the worker could not list the organisations: {describe(exc)}") from exc
        if org_ids:  # a different organisation goes first each run, so none is always last
            start = self._runs % len(org_ids)
            org_ids = org_ids[start:] + org_ids[:start]
        self._runs += 1
        reports = {org_id: OrgReport(org_id) for org_id in org_ids}
        report.orgs.extend(reports.values())
        threads = min(self.config.max_parallel_orgs, len(org_ids))
        if connect is not None and threads > 1:
            self._drain_parallel(connect, org_ids, reports, report, threads)
        else:
            for org_id in org_ids:
                org_report = reports[org_id]
                try:
                    # minted just before this organisation's drain, so a slow organisation never outlives the next token
                    token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]
                    self.run_org(conn, org_id, token, org_report)
                except Exception as exc:  # one organisation's failure never hides another's; it is named in the report
                    org_report.errors.append(f"{describe(exc)}")
        if raise_on_error and not report.ok:
            err = WorkerError("the sync run finished with failures: " + "; ".join(report.errors))
            err.report = report  # type: ignore[attr-defined]
            raise err
        return report

    def _drain_parallel(self, connect, org_ids, reports, report: RunReport, threads: int) -> None:
        lock = threading.Lock()
        waiting: deque = deque(("new", o) for o in org_ids)

        def take():
            with lock:
                return waiting.popleft() if waiting else None

        def turn(conn, item) -> None:
            kind, ref = item
            org_report = reports[ref if kind == "new" else ref.org_id]
            try:
                if kind == "new":
                    token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (ref,)).fetchone()["t"]
                    ref = _OrgDrain(self, ref, token, org_report)
                if ref.step(conn, 1):
                    with lock:
                        waiting.append(("drain", ref))
            except Exception as exc:  # one organisation's failure never hides another's; it is named in the report
                org_report.errors.append(f"{describe(exc)}")

        def work() -> None:
            try:
                conn = connect()
            except Exception as exc:
                with lock:
                    report.run_errors.append(f"a pool thread could not open its connection: {describe(exc)}")
                return
            try:
                while (item := take()) is not None:
                    turn(conn, item)
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="cv-sync") as pool:
            for f in [pool.submit(work) for _ in range(threads)]:
                f.result()
        for _kind, ref in waiting:  # nothing could run them (every thread failed to connect): say so, never skip
            name = ref if _kind == "new" else ref.org_id
            reports[name].errors.append("not drained: no pool thread could run it")

    def run_loop(self, connect: Callable[[], psycopg.Connection], stop: threading.Event, interval_seconds: float = 5.0) -> None:
        """Run until ``stop`` is set. A failed pass is logged at ERROR and the loop goes on; none is ever silent."""
        while not stop.is_set():
            try:
                with connect() as conn:
                    self.run_once(conn, connect=connect)
            except SyncError as exc:
                log.error("consentvault sync pass failed", error=type(exc).__name__)
            stop.wait(interval_seconds)

    # one organisation ----------------------------------------------------------------------------------------------

    def run_org(self, conn: psycopg.Connection, org_id, token: str, report: OrgReport | None = None) -> OrgReport:
        drain = _OrgDrain(self, org_id, token, report or OrgReport(org_id))
        while drain.step(conn, self.config.batch_size):
            pass
        return drain.report

    # one push --------------------------------------------------------------------------------------------------------

    def _release(self, conn, token, row, report: OrgReport) -> None:
        try:
            with org_transaction(conn, token):
                conn.execute("SELECT consentvault.sync_release(%s, %s, %s)",
                             (row["outbox_id"], row["attempt"], RELEASE_DELAY_SECONDS))   # due again that long from the database's now
            report.released += 1
        except psycopg.errors.ObjectNotInPrerequisiteState:
            report.stale += 1

    def _deliver(self, conn, token, org_id, row, report: OrgReport) -> None:
        outbox_id, attempt = row["outbox_id"], row["attempt"]
        # this push's attempt starts now: stamped on the row (last_attempt_at), and the backoff counts from this stamp, so a
        # batch's later pushes are not dated to the claim and their delay never comes out short
        try:
            with org_transaction(conn, token):
                started = conn.execute("SELECT consentvault.sync_attempt_started(%s, %s) AS t",
                                       ([outbox_id], [attempt])).fetchone()["t"]   # the database's clock
        except psycopg.errors.ObjectNotInPrerequisiteState as exc:
            if not push_start_taken_over(exc):
                raise
            # another worker took this row before its push started: it is that worker's now; counted stale, as a take-over
            # found at completion is, and the run goes on
            report.stale += 1
            log.warning("consentvault sync: a push was taken over before it started", attempt=attempt, outbox_id=outbox_id,
                        error=type(exc).__name__)
            return
        data_key = None
        try:
            data_key = self.crypto.open_contact_key(org_id, WrappedKey(bytes(row["wrapped_key"]), row["key_version"]))
            body = decrypt_payload(data_key, org_id, outbox_id, row["payload_ct"])
            secret = open_credentials(self.custody, org_id, row["system_id"], row["credentials_ct"])
        except (TenancyError, CredentialError) as exc:
            # counted as an attempt: retried with backoff and dead when the window ends (alarmed then), never a
            # silent loop of releases
            report.errors.append(f"push {outbox_id} to {row['system_name']!r} could not be prepared "
                                 f"({describe(exc)}); counted as an attempt")
            outcome = webhook.Outcome("retry", PREPARE_FAILED, None, f"preparation failed: {type(exc).__name__}")
        else:
            request = webhook.build_request(
                endpoint=row["endpoint"], signature=row["signature"], secret=secret, body=body, outbox_id=outbox_id,
                org_id=org_id, contact_fp=row["contact_fp"], channel=row["channel"], purpose=row["purpose"],
                version=row["version"])
            outcome = webhook.classify(self.transport.send(request))  # TransportError propagates: the door
        backoff_s = None
        if outcome.kind == "retry":
            # the step only, capped; whether the retry window has closed (dead) and when the next attempt is due are the
            # database's clock, counted from this push's own start as sync_attempt_started stamped it, so the wait between
            # attempts is exactly the backoff however long the push or the pushes before it in the batch took
            backoff_s = max(1, min(int(self.config.backoff(attempt).total_seconds()), MAX_BACKOFF_SECONDS))
        error_ct = None
        if outcome.detail and data_key is not None:
            error_ct = tc.encrypt_field(data_key, org_id, f"{outbox_id}:{attempt}", ERROR_COLUMN, outcome.detail)
        try:
            with org_transaction(conn, token):
                final = conn.execute(
                    "SELECT consentvault.sync_complete(%s, %s, %s, %s, %s, %s, %s) AS final",
                    (outbox_id, attempt, outcome.kind, outcome.http_status, outcome.error_class, error_ct,
                     backoff_s)).fetchone()["final"]
        except psycopg.errors.ObjectNotInPrerequisiteState as exc:
            report.stale += 1
            log.warning("consentvault sync: a push attempt was finished after its lease was taken over", attempt=attempt,
                        outbox_id=outbox_id, error=type(exc).__name__)
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
                    f"the alarm for system {g['system_name']!r} could not be raised: {describe(exc)}")))
                continue
            report.alarms += 1


class _OrgDrain:
    """One organisation's drain, advanced a batch at a time so a pool can interleave organisations one push at a time."""

    def __init__(self, worker: SyncWorker, org_id, token: str, report: OrgReport) -> None:
        self.w, self.org_id, self.token, self.report = worker, org_id, token, report
        cfg = worker.config
        self.deadline = worker.clock() + timedelta(seconds=cfg.org_deadline_seconds)
        self.pushes = 0
        self.turns = 0
        self.halted = False  # a door failure: no more sends this run
        self.done = False
        self.twenty_checked = False

    def _deadline_error(self) -> None:
        self.report.errors.append(f"the {self.w.config.org_deadline_seconds:.0f} s deadline for this organisation passed "
                                  "with work still queued; the next run continues")

    def step(self, conn: psycopg.Connection, limit: int) -> bool:
        """Claim and deliver up to ``limit`` pushes. True while more work may remain; False once the drain finished."""
        if self.done:
            return False
        w, cfg, report = self.w, self.w.config, self.report
        if self.pushes >= cfg.max_pushes_per_org:
            return self._finish(conn)
        if self.turns >= cfg.max_batches_per_org:
            report.errors.append(f"{cfg.max_batches_per_org} batches did not drain this organisation; the next run continues")
            return self._finish(conn)
        if w.clock() >= self.deadline:
            self._deadline_error()
            return self._finish(conn)
        with org_transaction(conn, self.token):
            rows = conn.execute("SELECT * FROM consentvault.sync_claim(%s, %s)",
                                (min(limit, cfg.max_pushes_per_org - self.pushes), cfg.lease_seconds)).fetchall()
        group = self._twenty_turn(conn)
        if not rows and not group:
            return self._finish(conn)
        if not rows:
            self.turns += 1
            return self._finish(conn) if self.halted else True
        self.turns += 1
        report.claimed += len(rows)
        for row in rows:
            if self.halted or w.clock() >= self.deadline:  # the deadline is checked before every push
                if not self.halted:
                    self._deadline_error()
                self.halted = True
                w._release(conn, self.token, row, report)
                continue
            try:
                w._deliver(conn, self.token, self.org_id, row, report)
                self.pushes += 1
            except TransportError as exc:
                self.halted = True
                report.errors.append(f"delivery door failure: {describe(exc)}")
                w._release(conn, self.token, row, report)
        return self._finish(conn) if self.halted else True

    def _twenty_turn(self, conn: psycopg.Connection) -> bool:
        """Claim and deliver ONE Twenty person group (twenty.md 2.2 step 0). True when a group was claimed."""
        w, report = self.w, self.report
        if self.halted or w.clock() >= self.deadline:
            return False
        if w.twenty is None:
            if not self.twenty_checked:
                self.twenty_checked = True
                with org_transaction(conn, self.token):
                    unserved = conn.execute("SELECT count(*) AS n FROM consentvault.connector_systems()"
                                            " WHERE status = 'active'").fetchone()["n"]
                if unserved:
                    report.errors.append(f"{unserved} Twenty system(s) are active but this worker has no Twenty connector "
                                         "(no call transport); their pushes wait")
            return False
        with org_transaction(conn, self.token):
            group = conn.execute("SELECT * FROM consentvault.sync_claim_person(%s)", (w.config.lease_seconds,)).fetchall()
        if not group:
            return False
        report.claimed += len(group)
        try:
            out, _counts = w.twenty.deliver(conn, self.token, self.org_id, group, drain_deadline=self.deadline,
                                            backoff=w.config.backoff)
        except StaleAttemptError as exc:
            report.stale += len(group)
            log.warning("consentvault sync: a Twenty delivery's lease was taken over", error=type(exc).__name__)
            return True
        except TransportError as exc:
            self.halted = True
            report.errors.append(f"delivery door failure: {describe(exc)}")
            for row in group:
                w._release(conn, self.token, row, report)
            return True
        self.pushes += len(group)
        if out.kind == "acknowledged":
            report.acknowledged += len(group)
        elif out.kind == "dead":
            report.dead += len(group)
        elif out.kind == "release":
            report.released += len(group)
        else:
            report.retried += len(group)
        return True

    def _finish(self, conn: psycopg.Connection) -> bool:
        self.done = True
        self.report.capped = self.pushes >= self.w.config.max_pushes_per_org
        with org_transaction(conn, self.token):
            conn.execute("SELECT consentvault.sync_refresh_redrives()")
        self.w._alarm(conn, self.token, self.org_id, self.report)
        return False
