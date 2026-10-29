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

from ..tenancy.errors import TenantTokenError
from ..tenancy.tokens import org_transaction
from .errors import (GateCountUnavailableError, StripeRejectedError, StripeUnavailableError,
                     UsageReportError)
from .stripe_client import StripeClient

METER_EVENT_NAMES = {"events": "consentvault_consent_events", "gate_checks": "consentvault_gate_checks"}
RETRY_DELAYS = (1.0, 4.0, 16.0)

GateCounter = Callable[[psycopg.Connection, uuid.UUID, date], int]
Alarm = Callable[[str, str], None]


def stderr_alarm(name: str, detail: str) -> None:
    import sys

    print(f"ALARM {name}: {detail}", file=sys.stderr)


def unavailable_gate_counter(conn: psycopg.Connection, org_id: uuid.UUID, day: date) -> int:
    """The counter to use until the gate lane keeps a count: it says so, loudly, instead of answering zero."""
    raise GateCountUnavailableError("no gate-check count is kept yet; gate checks are not reported (never as zero)")


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


@dataclass
class UsageRun:
    day: date
    orgs: list[OrgUsage] = field(default_factory=list)

    @property
    def failures(self) -> list[str]:
        return [f for o in self.orgs for f in o.failures]


def closed_day(now: datetime | None = None) -> date:
    """Yesterday in UTC: the most recent day that is complete."""
    return ((now or datetime.now(timezone.utc)).astimezone(timezone.utc) - timedelta(days=1)).date()


def run_daily_usage(worker: psycopg.Connection, client: StripeClient, day: date, *, gate_counter: GateCounter,
                    alarm: Alarm = stderr_alarm, sleep: Callable[[float], None] = time.sleep,
                    delays: tuple[float, ...] = RETRY_DELAYS) -> UsageRun:
    """Count and report one closed day for every live organisation. Raises ``UsageReportError`` if anything failed."""
    run = UsageRun(day)
    jobs = worker.execute("SELECT org_id, token FROM consentvault.dispatch_orgs('usage')").fetchall()
    for job in jobs:
        usage = OrgUsage(job["org_id"])
        run.orgs.append(usage)
        try:
            _one_org(worker, client, job["token"], usage, day, gate_counter, alarm, sleep, delays)
        except (psycopg.Error, TenantTokenError) as exc:
            usage.failures.append(f"{usage.org_id}: database or token {type(exc).__name__}")
            alarm("usage_count_failed", f"organisation {usage.org_id}, day {day}: {type(exc).__name__}: {exc}")
    if run.failures:
        raise UsageReportError(f"usage report for {day} failed for: " + "; ".join(run.failures))
    return run


def _one_org(worker, client, token, usage: OrgUsage, day, gate_counter, alarm, sleep, delays) -> None:
    org = usage.org_id
    with org_transaction(worker, token):
        events = worker.execute("SELECT consentvault.usage_events_for_day(%s) AS n", (day,)).fetchone()["n"]
        gate: int | None
        try:
            gate = gate_counter(worker, org, day)
        except GateCountUnavailableError as exc:
            gate = None
            usage.failures.append(f"{org}: gate_checks count unavailable")
            alarm("gate_check_count_unavailable", f"organisation {org}, day {day}: {exc}")
        worker.execute("SELECT consentvault.usage_record_day(%s, %s, %s)", (day, events, gate))
        target = worker.execute("SELECT * FROM consentvault.usage_target(%s)", (day,)).fetchone()
    usage.events, usage.gate_checks = target["events"], target["gate_checks"]
    if not target["stripe_customer_id"] or not target["stripe_subscription_id"] \
            or target["subscription_status"] in ("canceled", "incomplete_expired", "incomplete"):
        usage.skipped = "no subscription in force"
        return
    stamp = int(datetime.combine(day, datetime.min.time(), timezone.utc).timestamp()) + 86399
    for meter, value in (("events", usage.events), ("gate_checks", usage.gate_checks)):
        if value is None or meter in (target["stripe_ack"] or {}):
            continue
        key = idempotency_key(org, day, meter)
        try:
            ack = _send(client, METER_EVENT_NAMES[meter], target["stripe_customer_id"], value, key, stamp, sleep, delays)
        except (StripeUnavailableError, StripeRejectedError) as exc:
            usage.failures.append(f"{org}: {meter} not reported ({type(exc).__name__})")
            alarm("usage_report_failed", f"organisation {org}, meter {meter}, day {day}: {exc}")
            continue
        with org_transaction(worker, token):
            worker.execute("SELECT consentvault.usage_mark_reported(%s, %s, %s)", (day, meter, ack))
        usage.reported.append(meter)


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
    raise StripeUnavailableError(f"Stripe unavailable after {len(delays) + 1} tries: {last}")
