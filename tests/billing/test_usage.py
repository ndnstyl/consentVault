"""The daily usage count and the Stripe meter report: counts per organisation, idempotency keys, retries, named alarms."""

import uuid
from datetime import date, datetime, timedelta, timezone

import psycopg
import pytest

from consentvault import db
from consentvault.billing import usage
from consentvault.billing.errors import GateCountUnavailableError, StripeRejectedError, UsageReportError
from consentvault.billing.usage import closed_day, idempotency_key, run_daily_usage, unavailable_gate_counter
from consentvault.tenancy.tokens import org_transaction

from .fakes import UNAVAILABLE
from .helpers import link, subscribed
from isolation.harness import make_login_role

YESTERDAY = closed_day()


def worker_conn(tenancy, pg_server):
    dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    return db.connect(dsn)


class Alarms:
    def __init__(self):
        self.raised: list[tuple[str, str]] = []

    def __call__(self, name, detail):
        self.raised.append((name, detail))

    @property
    def names(self):
        return [n for n, _ in self.raised]


def backdate_events(tenancy, org, day: date, copies: int, first_seq: int = 1000) -> None:
    """Put ``copies`` extra events of ``org`` on a past day, as a DBA could (triggers off for the session only)."""
    stamp = datetime.combine(day, datetime.min.time(), timezone.utc) + timedelta(hours=9)
    with tenancy.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("CREATE TEMP TABLE one ON COMMIT DROP AS SELECT * FROM consentvault.event"
                   " WHERE org_id = %s ORDER BY seq LIMIT 1", (org.org_id,))
        for i in range(copies):
            su.execute("UPDATE one SET event_id = gen_random_uuid(), seq = %s, received_at = %s, captured_at = %s,"
                       " row_hash = encode(sha256(gen_random_uuid()::text::bytea), 'hex')",
                       (first_seq + i, stamp, stamp))
            su.execute("INSERT INTO consentvault.event SELECT * FROM one")


def gates(n):
    return lambda conn, org, day: n


def usage_rows(tenancy, org):
    with tenancy.superuser() as su:
        return su.execute("SELECT * FROM consentvault.usage_day WHERE org_id = %s ORDER BY day", (org.org_id,)).fetchall()


def test_counts_each_org_separately_and_reports_with_idempotency_keys(tenancy, stripe, pg_server):
    for org, n in ((tenancy.a, 3), (tenancy.b, 5)):
        backdate_events(tenancy, org, YESTERDAY, n)
    cus_a, sub_a = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus_a, sub_a, "active")
    cus_b, sub_b = subscribed(stripe, tenancy.b)
    link(tenancy, tenancy.b, cus_b, sub_b, "active")
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w:
        run = run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(40), alarm=alarms, sleep=lambda s: None)
    assert alarms.raised == []
    got = {o.org_id: (o.events, o.gate_checks) for o in run.orgs if o.org_id in (tenancy.a.org_id, tenancy.b.org_id)}
    assert got == {tenancy.a.org_id: (3, 40), tenancy.b.org_id: (5, 40)}
    sent = {(e["customer"], e["event_name"]): (e["value"], e["identifier"]) for e in stripe.meter_events}
    assert sent[(cus_a, "consentvault_consent_events")] == (3, idempotency_key(tenancy.a.org_id, YESTERDAY, "events"))
    assert sent[(cus_b, "consentvault_gate_checks")] == (40, f"{tenancy.b.org_id}:{YESTERDAY.isoformat()}:gate_checks")
    row = usage_rows(tenancy, tenancy.a)[0]
    assert (row["events"], row["gate_checks"], row["reported_at"] is not None) == (3, 40, True)
    assert set(row["stripe_ack"]) == {"events", "gate_checks"}


def test_a_second_run_of_the_same_day_sends_nothing_again(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(10), alarm=Alarms())
        sent = len(stripe.meter_events)
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(10), alarm=Alarms())
    assert sent >= 2 and len(stripe.meter_events) == sent


def test_stripe_503_is_retried_with_backoff_then_succeeds(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    stripe.fail["create_meter_event"] = UNAVAILABLE
    stripe.fail_times["create_meter_event"] = 2
    waits, alarms = [], Alarms()
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=alarms, sleep=waits.append)
    assert waits[:2] == [1.0, 4.0] and alarms.raised == []
    assert usage_rows(tenancy, tenancy.a)[0]["reported_at"] is not None


def test_stripe_staying_down_raises_a_named_alarm_and_the_run_fails_loudly(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    stripe.fail["create_meter_event"] = UNAVAILABLE
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match=str(tenancy.a.org_id)):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=alarms, sleep=lambda s: None)
    assert set(alarms.names) == {"usage_report_failed"}
    assert stripe.count("create_meter_event") == 2 * 4  # two meters, one try plus three retries each
    row = usage_rows(tenancy, tenancy.a)[0]
    assert row["reported_at"] is None and row["stripe_ack"] == {}
    stripe.fail.clear()  # next run: the count is held, Stripe is back, and only now is anything sent
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    assert usage_rows(tenancy, tenancy.a)[0]["reported_at"] is not None


def test_stripe_refusing_a_report_is_not_retried_and_alarms_by_name(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    stripe.fail["create_meter_event"] = StripeRejectedError("Stripe refused: no such meter")
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=alarms, sleep=lambda s: None)
    assert stripe.count("create_meter_event") == 2 and "usage_report_failed" in alarms.names


def test_one_orgs_failure_does_not_stop_the_next_org(tenancy, stripe, pg_server):
    cus_a, sub_a = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus_a, sub_a, "active")
    cus_b, sub_b = subscribed(stripe, tenancy.b)
    link(tenancy, tenancy.b, cus_b, sub_b, "active")
    real = stripe.create_meter_event

    def flaky(**kw):
        if kw["customer"] == cus_a:
            raise StripeRejectedError("a's meter is broken")
        return real(**kw)

    stripe.create_meter_event = flaky
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    assert {e["customer"] for e in stripe.meter_events} == {cus_b}


def test_an_unreadable_gate_count_is_stored_null_alarmed_and_never_reported_as_zero(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 4)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="gate_checks count unavailable"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=unavailable_gate_counter, alarm=alarms)
    assert "gate_check_count_unavailable" in alarms.names
    row = usage_rows(tenancy, tenancy.a)[0]
    assert row["gate_checks"] is None and row["events"] == 4
    assert [e["event_name"] for e in stripe.meter_events] == ["consentvault_consent_events"]
    assert row["reported_at"] is None  # the day is not complete until both meters are acknowledged


def test_an_org_with_no_subscription_is_counted_but_not_reported(tenancy, stripe, pg_server):
    with worker_conn(tenancy, pg_server) as w:
        run = run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(0), alarm=Alarms())
    assert stripe.meter_events == [] and all(o.skipped for o in run.orgs)
    assert len(usage_rows(tenancy, tenancy.a)) == 1


def test_a_canceled_subscription_is_not_reported(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a, status="canceled")
    link(tenancy, tenancy.a, cus, sub, "canceled")
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(0), alarm=Alarms())
    assert stripe.meter_events == []


def test_today_is_not_a_closed_day(tenancy, stripe, pg_server):
    today = datetime.now(timezone.utc).date()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, today, gate_counter=gates(0), alarm=Alarms())


def test_a_reported_days_count_cannot_be_rewritten(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(7), alarm=Alarms())
        token = w.execute("SELECT token FROM consentvault.dispatch_orgs('usage') WHERE org_id = %s",
                          (tenancy.a.org_id,)).fetchone()["token"]
        with org_transaction(w, token):
            w.execute("SELECT consentvault.usage_record_day(%s, 999, 999)", (YESTERDAY,))
    row = usage_rows(tenancy, tenancy.a)[0]
    assert (row["events"], row["gate_checks"]) == (0, 7)


def test_closed_day_is_yesterday_in_utc():
    assert closed_day(datetime(2026, 10, 29, 0, 5, tzinfo=timezone.utc)) == date(2026, 10, 28)
    assert closed_day(datetime(2026, 1, 1, 3, 0, tzinfo=timezone.utc)) == date(2025, 12, 31)


def test_an_incomplete_enterprise_contract_still_counts_but_reports_no_overage_and_alarms(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 4)
    cus = stripe.add_customer(str(tenancy.a.org_id))
    sub = stripe.add_subscription(cus, "active", str(tenancy.a.org_id), "price_enterprise_acme")
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, 'price_enterprise_acme', 'active',"
                    " 'enterprise_contract_incomplete', 'Enterprise', NULL, NULL, NULL, NULL)",
                    (tenancy.a.org_id, cus, sub))
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w:
        with pytest.raises(UsageReportError, match="enterprise contract"):
            run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(9), alarm=alarms, sleep=lambda s: None)
    assert "enterprise_contract_incomplete" in alarms.names
    assert [e for e in stripe.meter_events if e["customer"] == cus] == []
    row = usage_rows(tenancy, tenancy.a)[0]
    assert (row["events"], row["gate_checks"], row["reported_at"]) == (4, 9, None)  # counted, kept, not reported
    with tenancy.superuser() as su:
        names = [r["name"] for r in su.execute("SELECT name FROM consentvault.operator_alarm WHERE org_id = %s",
                                               (tenancy.a.org_id,)).fetchall()]
    assert "billing.enterprise_contract_incomplete" in names
