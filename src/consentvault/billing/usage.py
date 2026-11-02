"""The daily usage count and the Stripe meter report.

For every live organisation the job counts the closed UTC day's consent events (and gate checks, through an injected
counter), stores the count in ``usage_day``, and reports each count to its Stripe meter with the idempotency key
``<org id>:<day>:<meter>``. A report Stripe already acknowledged is never sent twice; a re-run of a day is safe because
Stripe deduplicates on the key as well.

A count that cannot be read is stored as NULL and is never reported as zero. Stripe answering 429/5xx is retried with
backoff; after the last try the failure is raised through the alarm sink by name, and the run ends with
``UsageReportError`` naming every organisation and meter that failed. One organisation's failure never stops the rest.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Callable

import psycopg

from ..safelog import describe
from ..alarms import raise_operator_alarm
from ..tenancy.errors import TenantTokenError
from ..tenancy.tokens import org_transaction
from .errors import (GateCountUnavailableError, StripeRejectedError, StripeUnavailableError,
                     UsageReportError)
from .plans import ALARM_ENTERPRISE_INCOMPLETE, ENTERPRISE_INCOMPLETE
from .stripe_client import StripeClient

METER_EVENT_NAMES = {"events": "consentvault_consent_events", "gate_checks": "consentvault_gate_checks"}
RETRY_DELAYS = (1.0, 4.0, 16.0)
DEDUPE_SAFE_SECONDS = 20 * 3600  # Stripe deduplicates a meter event identifier for about 24 hours; stay well inside it
ABANDONED_FLOOR = date(2000, 1, 1)
INVOICE_GRACE = timedelta(hours=1)  # Stripe finalises a period's draft invoice about an hour after the period ends
GRACE_MARGIN = timedelta(minutes=5)  # a closing-day send is made only while at least this much of the window is left
DAILY_RUN_MAX_AGE_SECONDS = 26 * 3600  # the daily run is scheduled once a day; two hours of slack, then it is missed

GateCounter = Callable[[psycopg.Connection, uuid.UUID, date], int]
Alarm = Callable[[str, str], None]


def stderr_alarm(name: str, detail: str) -> None:
    """The default alarm: one line through the allowlist logger. An alarm's detail is written by this module from ids, days and an
    error's description (class and SQLSTATE), never an error's text; the logger hashes a detail that does not have that shape."""
    from .. import safelog
    safelog.get("consentvault.billing.alarm").error("ALARM", alarm=name, detail=detail)


def unavailable_gate_counter(conn: psycopg.Connection, org_id: uuid.UUID, day: date) -> int:
    """The counter to use until the gate lane keeps a count: it says so, loudly, instead of answering zero."""
    raise GateCountUnavailableError("no gate-check count is kept yet; gate checks are not reported (never as zero)")


def db_gate_counter(conn: psycopg.Connection, org_id: uuid.UUID, day: date) -> int:
    """The organisation's gate checks on one UTC day, from the tally the gate keeps in the same savepoint as each decision.
    A day the tally does not cover is ``GateCountUnavailableError`` (no count), never zero."""
    with conn.transaction():  # a savepoint inside the caller's tenant transaction
        n = conn.execute("SELECT consentvault.usage_gate_checks_for_day(%s) AS n", (day,)).fetchone()["n"]
    if n is None:
        raise GateCountUnavailableError(f"no gate-check tally covers {day}; its count is not reported (never as zero)")
    return int(n)


def idempotency_key(org_id: uuid.UUID | str, day: date, meter: str) -> str:
    return f"{org_id}:{day.isoformat()}:{meter}"


@dataclass
class OrgUsage:
    org_id: uuid.UUID
    events: int | None = None
    gate_checks: int | None = None
    reported: list[str] = field(default_factory=list)
    skipped: str | None = None
    failures: list[str] = field(default_factory=list)
    alarm: Callable[[str, str], None] = field(default=stderr_alarm, repr=False)


@dataclass
class UsageRun:
    day: date
    orgs: list[OrgUsage] = field(default_factory=list)
    platform_failures: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[str]:
        return self.platform_failures + [f for o in self.orgs for f in o.failures]


def db_now(conn: psycopg.Connection) -> datetime:
    """The database's clock: whether Stripe's invoice window is open, which day is closed and which retry is due are decided
    on it, never on this process's clock (a worker minutes off would bill into a shut window or skip an open one)."""
    return conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]


def closed_day(now: datetime | None = None) -> date:
    """Yesterday in UTC: the most recent day that is complete."""
    return ((now or datetime.now(timezone.utc)).astimezone(timezone.utc) - timedelta(days=1)).date()


def run_daily_usage(worker: psycopg.Connection, client: StripeClient, day: date, *, gate_counter: GateCounter,
                    alarm: Alarm = stderr_alarm, sleep: Callable[[float], None] = time.sleep,
                    delays: tuple[float, ...] = RETRY_DELAYS, now: datetime | None = None,
                    clock: Callable[[], datetime] | None = None) -> UsageRun:
    """Count and report one closed day for every live organisation. Raises ``UsageReportError`` if anything failed.
    ``clock`` is read again before each closing-day send (the run can outlast the invoice window)."""
    # ``now`` and ``clock`` are a test's seam; a run reads the database's clock, and again before each closing-day send
    clock = clock or ((lambda: now) if now else (lambda: db_now(worker)))
    at = now or clock()
    run = UsageRun(day)
    jobs = worker.execute("SELECT org_id, token FROM consentvault.dispatch_orgs('usage')").fetchall()
    for job in jobs:
        usage = OrgUsage(job["org_id"])
        run.orgs.append(usage)
        try:
            _one_org(worker, client, job["token"], usage, day, gate_counter, alarm, sleep, delays, at, clock)
        except (psycopg.Error, TenantTokenError) as exc:
            usage.failures.append(f"{usage.org_id}: database or token {type(exc).__name__}")
            alarm("usage_count_failed", f"organisation {usage.org_id}, day {day}: {describe(exc)}")
    if run.failures:
        raise UsageReportError(f"usage report for {day} failed for: " + "; ".join(run.failures))
    return run


def run_daily_job(worker: psycopg.Connection, client: StripeClient, *, now: datetime | None = None,
                  gate_counter: GateCounter = unavailable_gate_counter, alarm: Alarm = stderr_alarm,
                  sleep: Callable[[float], None] = time.sleep, delays: tuple[float, ...] = RETRY_DELAYS) -> UsageRun:
    """The scheduled daily run: yesterday's closed UTC day for every live organisation. When the run completes, whatever
    its per-organisation failures (each alarmed by name), the run's heartbeat is stored; a run that dies leaves none, and
    the retry pass goes red once the last one is older than ``DAILY_RUN_MAX_AGE_SECONDS``."""
    day = closed_day(now or db_now(worker))   # yesterday by the database's clock
    try:
        run = run_daily_usage(worker, client, day, gate_counter=gate_counter, alarm=alarm, sleep=sleep, delays=delays,
                              now=now)
    except UsageReportError:
        worker.execute("SELECT consentvault.usage_run_finish(%s)", (day,))
        raise
    worker.execute("SELECT consentvault.usage_run_finish(%s)", (day,))
    return run


def _one_org(worker, client, token, usage: OrgUsage, day, gate_counter, alarm, sleep, delays, at, clock) -> None:
    org = usage.org_id
    usage.alarm = alarm
    with org_transaction(worker, token):
        events = worker.execute("SELECT consentvault.usage_events_for_day(%s) AS n", (day,)).fetchone()["n"]
        gate: int | None
        try:
            gate = gate_counter(worker, org, day)
        except GateCountUnavailableError as exc:
            gate = None
            usage.failures.append(f"{org}: gate_checks count unavailable")
            alarm("gate_check_count_unavailable", f"organisation {org}, day {day}: {describe(exc)}")
        worker.execute("SELECT consentvault.usage_record_day(%s, %s, %s)", (day, events, gate))
        target = worker.execute("SELECT * FROM consentvault.usage_target(%s)", (day,)).fetchone()
    usage.events, usage.gate_checks = target["events"], target["gate_checks"]
    with org_transaction(worker, token):
        plan = worker.execute("SELECT * FROM consentvault.usage_plan_of_record()").fetchone()
    if not _in_force(plan):
        usage.skipped = "no subscription in force"
        return
    if plan["plan_id"] == ENTERPRISE_INCOMPLETE:  # the plan of record the webhook keeps; no live Stripe read
        with org_transaction(worker, token):
            raise_operator_alarm(worker, name=ALARM_ENTERPRISE_INCOMPLETE, error_class="EnterpriseContractIncomplete",
                                 ref_kind="org", ref_id=org)
        usage.skipped = "enterprise contract incomplete"
        usage.failures.append(f"{org}: enterprise contract has no included volumes; overage not reported")
        alarm("enterprise_contract_incomplete", f"organisation {org}, day {day}: counts kept, overage not reported")
        return
    # Every day of the current period Stripe has not acknowledged, oldest first: the day itself, and any day an
    # incomplete contract held back. A day belongs to the period its own date falls in: a day before the current
    # period's start is abandoned (named once, never billed into this period), whichever day this run is for.
    start = plan["period_start"].astimezone(timezone.utc) if plan["period_start"] else None
    first = start.date() if start else None
    with org_transaction(worker, token):
        before = (worker.execute("SELECT * FROM consentvault.usage_unreported_days(%s, %s)",
                                 (ABANDONED_FLOOR, first - timedelta(days=1))).fetchall() if first else [])
        days = (worker.execute("SELECT * FROM consentvault.usage_unreported_days(%s, %s)",
                               (first or day, day)).fetchall() if (first or day) <= day else [])
    closing, abandoned = _split_closing(before, start, at, plan)
    why = _closing_block(plan, start, at)
    closing_day = start.date() - timedelta(days=1) if start else None
    for row in abandoned:
        if any(row[m] is not None and m not in (row["stripe_ack"] or {}) for m in METER_EVENT_NAMES):
            reason = f"; {why}" if why and row["day"] == closing_day else ""
            _verdict(worker, token, usage, row["day"], "abandoned", "usage_day_abandoned",
                     f"day {row['day']} abandoned before the period start",
                     f"counts held back before the period starting {first.isoformat()} were never reported; "
                     f"they are not billed into this period{reason}")
    deadline = _closing_deadline(start)
    for row in closing:
        _report_day(worker, client, token, usage, plan["stripe_customer_id"], row, alarm, sleep, delays,
                    record_reported=row["day"] == day, deadline=deadline, clock=clock)
    for row in days:
        _report_day(worker, client, token, usage, plan["stripe_customer_id"], row, alarm, sleep, delays,
                    record_reported=row["day"] == day)


def _closing_deadline(start: datetime | None) -> datetime | None:
    return start + INVOICE_GRACE - GRACE_MARGIN if start else None


def _closing_block(plan, start: datetime | None, at: datetime) -> str | None:
    """Why the period's closing day cannot be billed to its own period, or None when it can."""
    if start is None:
        return None
    if at >= _closing_deadline(start):
        return ("Stripe's invoice window for the closing period is shut or within "
                f"{int(GRACE_MARGIN.total_seconds() // 60)} minutes of shutting")
    changed, began = plan["price_changed_at"], plan["prev_period_start"]
    if changed is not None and (began is None or changed >= began):
        return ("the subscription's price changed during that period, and Stripe drops usage sent late for a "
                "replaced price")
    return None


def _split_closing(rows, start: datetime | None, at: datetime, plan):
    """Split the unreported days before the current period's start into the closing day to bill and the days abandoned.
    The day just before the start is the old period's closing day: its usage is stamped inside the old period, and Stripe
    keeps that period's invoice open for ``INVOICE_GRACE`` after the period ends, so while that window is open (with a
    margin) and the price did not change during that period, the day is billed to its own period. Any earlier day, or
    the closing day otherwise, is abandoned."""
    if start is None or _closing_block(plan, start, at):
        return [], list(rows)
    closing_day = start.date() - timedelta(days=1)
    return [r for r in rows if r["day"] == closing_day], [r for r in rows if r["day"] != closing_day]


def _verdict(worker, token, usage: OrgUsage, day, key, alarm_name, failure, detail, alarm=None) -> bool:
    """Record a verdict on a day once. The first time it alarms; while it stands the run stays red; once an operator has
    acknowledged it the run is green again. Returns True when it is acknowledged."""
    org = usage.org_id
    with org_transaction(worker, token):
        state = worker.execute("SELECT consentvault.usage_note_verdict(%s, %s) AS s", (day, key)).fetchone()["s"]
    if state == "acknowledged":
        return True
    usage.failures.append(f"{org}: {failure}")
    if state == "new":
        (alarm or usage.alarm)(alarm_name, f"organisation {org}, day {day.isoformat()}: {detail}; acknowledge with "
                                           f"key '{key}'")
    return False


def _report_day(worker, client, token, usage: OrgUsage, customer, row, alarm, sleep, delays, *, record_reported,
                deadline: datetime | None = None, clock: Callable[[], datetime] | None = None) -> None:
    org, day = usage.org_id, row["day"]
    usage.alarm = alarm
    stamp = int(datetime.combine(day, datetime.min.time(), timezone.utc).timestamp()) + 86399
    for meter, value in (("events", row["events"]), ("gate_checks", row["gate_checks"])):
        if value is None or meter in (row["stripe_ack"] or {}):
            continue  # an unread count was alarmed on its own day and is never reported as zero
        if deadline is not None and (clock or (lambda: db_now(worker)))() >= deadline:   # the database's clock
            _verdict(worker, token, usage, day, "abandoned", "usage_day_abandoned",
                     f"day {day} abandoned: the invoice window closed during the run",
                     f"{meter} for the closing day could not be sent before Stripe's invoice window for its period "
                     "shut (a margin is kept); it is not billed into the next period")
            return
        key = idempotency_key(org, day, meter)
        with org_transaction(worker, token):  # the mark is committed before Stripe is called
            earlier = worker.execute("SELECT consentvault.usage_claim_send(%s, %s) AS age", (day, meter)).fetchone()["age"]
        if earlier is not None and earlier > DEDUPE_SAFE_SECONDS:
            # Stripe took this send (the mark survives only when it did, or may have) and the confirmation was lost.
            _verdict(worker, token, usage, day, f"unconfirmed:{meter}", "usage_send_unconfirmed",
                     f"{meter} for {day} sent but unconfirmed",
                     f"{meter} was sent {earlier / 3600:.0f} hours ago with no saved confirmation; past Stripe's "
                     "dedupe window it is not sent again")
            continue
        try:
            ack = _send(client, METER_EVENT_NAMES[meter], customer, value, key, stamp, sleep, delays)
        except (StripeUnavailableError, StripeRejectedError) as exc:
            with org_transaction(worker, token):  # nothing was accepted: the retry is scheduled
                if earlier is None:  # the mark is this attempt's own: it goes
                    worker.execute("SELECT consentvault.usage_clear_send(%s, %s)", (day, meter))
                else:  # an earlier attempt's mark stays: that send may have been taken
                    worker.execute("SELECT consentvault.usage_schedule_retry(%s)", (day,))
            _verdict(worker, token, usage, day, f"failed:{meter}", "usage_report_failed",
                     f"{meter} for {day} not reported ({type(exc).__name__})",
                     f"meter {meter}: {describe(exc)}; a retry is scheduled")
            continue
        with org_transaction(worker, token):
            worker.execute("SELECT consentvault.usage_mark_reported(%s, %s, %s)", (day, meter, ack))
            worker.execute("SELECT consentvault.usage_clear_verdict(%s, %s)", (day, f"failed:{meter}"))
        if record_reported:
            usage.reported.append(meter)
        else:
            usage.reported.append(f"{meter}@{day.isoformat()}")


def acknowledge_day(worker, org_id, day, key, by) -> None:
    """An operator clears a standing verdict (key ``abandoned``, ``unconfirmed:<meter>`` or ``failed:<meter>``) on one
    day for one organisation; the job is green again once none stands. A verdict is acknowledged once, and each
    acknowledgement is written to the audit table with who made it. Raises ``UsageReportError`` for no such verdict, an
    organisation that is not live, or a verdict already acknowledged."""
    jobs = worker.execute("SELECT org_id, token FROM consentvault.dispatch_orgs('usage')").fetchall()
    token = next((j["token"] for j in jobs if j["org_id"] == org_id), None)
    if token is None:
        raise UsageReportError(f"organisation {org_id} is not a live usage organisation; nothing to acknowledge")
    try:
        with org_transaction(worker, token):
            worker.execute("SELECT consentvault.usage_acknowledge_verdict(%s, %s, %s)", (day, key, by))
    except psycopg.errors.NoDataFound as exc:
        raise UsageReportError(f"no such verdict {key!r} on {day} for organisation {org_id}") from exc
    except psycopg.errors.ObjectNotInPrerequisiteState as exc:
        raise UsageReportError(f"verdict {key!r} on {day} for organisation {org_id} is already acknowledged") from exc


def run_usage_retries(worker, client, *, now: datetime | None = None, alarm: Alarm = stderr_alarm,
                      sleep: Callable[[float], None] = time.sleep, delays: tuple[float, ...] = RETRY_DELAYS, check_daily_run: bool = True,
                      clock: Callable[[], datetime] | None = None) -> UsageRun:
    """The scheduled retry pass (run it every few minutes): resend only the days whose refused or unreachable send came
    due, inside the current period. Raises ``UsageReportError`` while any send still fails."""
    clock = clock or ((lambda: now) if now else (lambda: db_now(worker)))  # the database's clock unless a test fixes the time
    at = now or clock()
    run = UsageRun(closed_day(at))
    for job in worker.execute("SELECT org_id, token FROM consentvault.dispatch_orgs('usage')").fetchall():
        usage = OrgUsage(job["org_id"])
        run.orgs.append(usage)
        try:
            with org_transaction(worker, job["token"]):
                plan = worker.execute("SELECT * FROM consentvault.usage_plan_of_record()").fetchone()
            if not _in_force(plan) or plan["plan_id"] == ENTERPRISE_INCOMPLETE:
                continue
            start = plan["period_start"].astimezone(timezone.utc) if plan["period_start"] else None
            first = start.date() if start else None
            with org_transaction(worker, job["token"]):
                due = worker.execute("SELECT * FROM consentvault.usage_retry_due()").fetchall()   # due by the database's clock
            usage.alarm = alarm
            closing, _late = _split_closing([r for r in due if first is not None and r["day"] < first], start, at, plan)
            closing_days = {r["day"] for r in closing}
            for row in due:
                if first is None or row["day"] >= first or row["day"] in closing_days:
                    in_closing = first is not None and row["day"] < first
                    _report_day(worker, client, job["token"], usage, plan["stripe_customer_id"], row, alarm, sleep,
                                delays, record_reported=True, deadline=_closing_deadline(start) if in_closing else None,
                                clock=clock)
                else:  # a day of an earlier period is never billed into this one: it is named, once
                    _verdict(worker, job["token"], usage, row["day"], "abandoned", "usage_day_abandoned",
                             f"day {row['day']} abandoned before the period start",
                             f"a retry came due for a day before the period starting {first.isoformat()}; "
                             "it is not billed into this period")
        except (psycopg.Error, TenantTokenError) as exc:
            usage.failures.append(f"{usage.org_id}: database or token {type(exc).__name__}")
            alarm("usage_count_failed", f"organisation {usage.org_id}, retry pass: {describe(exc)}")
    if check_daily_run:
        age = worker.execute("SELECT consentvault.usage_run_age() AS a").fetchone()["a"]   # the database's clock
        if age is None or age > DAILY_RUN_MAX_AGE_SECONDS:
            seen = "has never finished" if age is None else f"last finished {age / 3600:.0f} hours ago"
            run.platform_failures.append(f"the daily usage run {seen}; it is due every 24 hours")
            alarm("usage_daily_run_missed", f"the daily usage run {seen} (limit {DAILY_RUN_MAX_AGE_SECONDS // 3600} "
                                            "hours); nothing is counted or reported until it runs")
    if run.failures:
        raise UsageReportError("usage retry failed for: " + "; ".join(run.failures))
    return run


def _in_force(plan) -> bool:
    return not (plan is None or not plan["stripe_customer_id"] or not plan["stripe_subscription_id"]
                or plan["subscription_status"] in ("canceled", "incomplete_expired", "incomplete"))


def _send(client, event_name, customer, value, key, stamp, sleep, delays) -> str:
    last: StripeUnavailableError | None = None
    for attempt in range(len(delays) + 1):
        try:
            answer = client.create_meter_event(event_name=event_name, customer=customer, value=value,
                                               identifier=key, timestamp=stamp)
            return str(answer.get("identifier") or key)
        except StripeUnavailableError as exc:
            last = exc
            if attempt < len(delays):
                sleep(delays[attempt])
    raise StripeUnavailableError(f"Stripe unavailable after {len(delays) + 1} tries: {describe(last)}")

