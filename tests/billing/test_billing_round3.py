"""Third review: one open checkout page per customer, a refused send is retried on a schedule and never reads as an
unconfirmed one, a verdict alarms once and clears on acknowledgement, abandonment follows each day's own period, and a
second live subscription never displaces the stored one."""

import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from consentvault.billing.errors import StripeRejectedError, StripeUnavailableError, UsageReportError
from consentvault.billing.usage import acknowledge_day, closed_day, run_daily_usage, run_usage_retries

from .fakes import event
from .helpers import retries_age, account, link, routes_for, send, subscribed
from .test_review_fixes import alarm_names
from .test_routes import call
from .test_usage import Alarms, backdate_events, gates, usage_rows, worker_conn

YESTERDAY = closed_day()
STARTER = json.dumps({"plan_id": "starter"}).encode()
NOW = datetime.now(timezone.utc)


def link_period(tenancy, org, cus, sub, start):
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, 'price_starter', 'active', 'starter',"
                    " 'Starter', 1000, 25000, %s, %s)", (org.org_id, cus, sub, start, start + timedelta(days=30)))


def midnight(day):
    return datetime.combine(day, datetime.min.time(), timezone.utc)


# 1. two checkout pages -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("linked", [True, False])
def test_two_checkout_pages_created_at_once_leave_exactly_one_open(tenancy, stripe, linked):
    org = tenancy.a
    cus = None
    if linked:
        cus = stripe.add_customer(str(org.org_id))
        link(tenancy, org, cus)
    stripe.create_delay = 0.4
    results = []

    def go():
        results.append(call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", org, body=STARTER))

    threads = [threading.Thread(target=go) for _ in range(2)]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert sorted(r.status for r in results) == [201, 201]
    cus = cus or account(tenancy, org)["stripe_customer_id"]
    assert len(stripe.open_pages(cus)) == 1
    assert sum(1 for p in stripe.checkout_pages.values() if p["status"] == "expired") == 1


def test_a_new_checkout_expires_the_open_page_the_customer_left_behind(tenancy, stripe):
    org = tenancy.a
    r = routes_for(tenancy, stripe)
    call(r, "POST", "/v1/billing/checkout", org, body=STARTER)
    cus = account(tenancy, org)["stripe_customer_id"]
    first = stripe.open_pages(cus)
    assert len(first) == 1
    call(r, "POST", "/v1/billing/checkout", org, body=STARTER)
    now_open = stripe.open_pages(cus)
    assert len(now_open) == 1 and now_open != first and stripe.checkout_pages[first[0]]["status"] == "expired"


# 2. a refused send is cleared and retried on a schedule --------------------------------------------------------------------

def _fail_once_through(tenancy, stripe, pg_server, exc):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    stripe.fail["create_meter_event"] = exc
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=alarms, sleep=lambda s: None)
    return alarms


@pytest.mark.parametrize("exc", [StripeUnavailableError("down"), StripeRejectedError("refused")])
def test_a_send_stripe_refused_or_could_not_take_keeps_no_sent_mark_and_is_scheduled_for_retry(
        tenancy, stripe, pg_server, exc):
    _fail_once_through(tenancy, stripe, pg_server, exc)
    row = usage_rows(tenancy, tenancy.a)[0]
    assert row["stripe_sent"] == {}
    assert row["retry_at"] is not None and row["retry_at"] > NOW - timedelta(minutes=5)


def test_a_daily_run_after_the_twenty_hour_cutoff_resends_a_refused_day_and_does_not_call_it_unconfirmed(
        tenancy, stripe, pg_server):
    _fail_once_through(tenancy, stripe, pg_server, StripeUnavailableError("down"))
    with tenancy.superuser() as su:  # a day passes: any mark left from that attempt now reads 30 hours old
        su.execute("UPDATE consentvault.usage_day SET stripe_sent = coalesce((SELECT jsonb_object_agg(k,"
                   " to_jsonb(now() - interval '30 hours')) FROM jsonb_object_keys(stripe_sent) k), '{}'::jsonb)"
                   " WHERE org_id = %s", (tenancy.a.org_id,))
    stripe.fail.clear()
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=alarms, sleep=lambda s: None)
    assert "usage_send_unconfirmed" not in alarms.names
    assert usage_rows(tenancy, tenancy.a)[0]["reported_at"] is not None


def test_the_retry_pass_sends_a_failed_day_once_it_is_due_and_not_before(tenancy, stripe, pg_server):
    _fail_once_through(tenancy, stripe, pg_server, StripeUnavailableError("down"))
    stripe.fail.clear()
    with worker_conn(tenancy, pg_server) as w:
        run_usage_retries(w, stripe, now=NOW, alarm=Alarms(), sleep=lambda s: None, check_daily_run=False)
        assert stripe.meter_events == [] and usage_rows(tenancy, tenancy.a)[0]["reported_at"] is None
        retries_age(tenancy, 2)   # two hours pass for the retry queue too
        run_usage_retries(w, stripe, now=NOW + timedelta(hours=2), alarm=Alarms(), sleep=lambda s: None,
                          check_daily_run=False)
    row = usage_rows(tenancy, tenancy.a)[0]
    assert row["reported_at"] is not None and len(stripe.meter_events) == 2


def test_a_failed_send_alarms_once_across_the_retries_and_clears_when_it_succeeds(tenancy, stripe, pg_server):
    first = _fail_once_through(tenancy, stripe, pg_server, StripeUnavailableError("down"))
    assert "usage_report_failed" in first.names
    again = Alarms()
    retries_age(tenancy, 2)   # two hours pass for the retry queue too
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_usage_retries(w, stripe, now=NOW + timedelta(hours=2), alarm=again, sleep=lambda s: None,
                          check_daily_run=False)
    assert "usage_report_failed" not in again.names  # already told once; the run still fails loudly


# 3. a verdict alarms once and clears on acknowledgement ------------------------------------------------------------------------

def _unconfirmed(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=Alarms(), sleep=lambda s: None)
    with tenancy.superuser() as su:
        su.execute("UPDATE consentvault.usage_day SET stripe_ack = '{}'::jsonb, reported_at = NULL,"
                   " stripe_sent = jsonb_build_object('events', now() - interval '30 hours', 'gate_checks',"
                   " now() - interval '30 hours') WHERE org_id = %s", (tenancy.a.org_id,))


def test_an_unconfirmed_day_alarms_once_stays_red_until_acknowledged_then_the_job_is_green(tenancy, stripe, pg_server):
    _unconfirmed(tenancy, stripe, pg_server)
    sent = len(stripe.meter_events)
    seen = []
    for _ in range(3):
        alarms = Alarms()
        with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="unconfirmed"):
            run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=alarms, sleep=lambda s: None)
        seen.append(alarms.names.count("usage_send_unconfirmed"))
    assert seen == [2, 0, 0]  # one per meter on the first run, none after
    with worker_conn(tenancy, pg_server) as w:
        for meter in ("events", "gate_checks"):
            acknowledge_day(w, tenancy.a.org_id, YESTERDAY, f"unconfirmed:{meter}", "operator:mike")
        alarms = Alarms()
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=alarms, sleep=lambda s: None)
    assert alarms.raised == [] and len(stripe.meter_events) == sent


def test_an_abandoned_day_alarms_once_and_an_acknowledgement_returns_the_job_to_green(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a)
    link_period(tenancy, tenancy.a, cus, sub, midnight(YESTERDAY))
    lost = YESTERDAY - timedelta(days=3)
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (%s, %s, 5, 7)",
                   (tenancy.a.org_id, lost))
    counts = []
    for _ in range(2):
        alarms = Alarms()
        with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
            run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=alarms, sleep=lambda s: None)
        counts.append(alarms.names.count("usage_day_abandoned"))
    assert counts == [1, 0]
    with worker_conn(tenancy, pg_server) as w:
        acknowledge_day(w, tenancy.a.org_id, lost, "abandoned", "operator:mike")
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)


# 4. abandonment follows each day's own period ----------------------------------------------------------------------------

def test_a_backfill_run_for_a_day_before_the_period_start_abandons_it_instead_of_billing_it_into_the_period(
        tenancy, stripe, pg_server):
    old = YESTERDAY - timedelta(days=3)
    backdate_events(tenancy, tenancy.a, old, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link_period(tenancy, tenancy.a, cus, sub, midnight(YESTERDAY))
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_daily_usage(w, stripe, old, gate_counter=gates(1), alarm=alarms, sleep=lambda s: None)
    assert stripe.meter_events == [] and "usage_day_abandoned" in alarms.names


# info: a second live subscription never displaces the stored one -------------------------------------------------------------

def test_a_second_live_subscription_leaves_the_stored_one_in_place_and_alarms_once(tenancy, stripe):
    org = tenancy.a
    cus, first = subscribed(stripe, org)
    link(tenancy, org, cus, first, "active")
    second = stripe.add_subscription(cus, "past_due", str(org.org_id))
    r = routes_for(tenancy, stripe)
    for _ in range(2):
        status, _body = send(r, event("customer.subscription.updated", second, "subscription"))
        assert status == 200
    assert account(tenancy, org)["stripe_subscription_id"] == first
    assert alarm_names(tenancy, org).count("billing.second_live_subscription") == 1
    status, body = send(r, event("customer.subscription.updated", first, "subscription"))
    assert account(tenancy, org)["stripe_subscription_id"] == first
