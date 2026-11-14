"""Sixth review: a failed one-off invoice never makes an organisation past due, and the day that closes a period is billed
to that period while Stripe's invoice grace window is open."""

from datetime import datetime, timedelta, timezone

import pytest

from consentvault.billing.errors import UsageReportError
from consentvault.billing.usage import closed_day, run_daily_usage

from .fakes import event
from .helpers import link, routes_for, send, set_status, status_of, subscribed
from .test_billing_round3 import link_period, midnight
from .test_usage import Alarms, backdate_events, gates, usage_rows, worker_conn

YESTERDAY = closed_day()
TODAY = YESTERDAY + timedelta(days=1)


# 4. payment failures -----------------------------------------------------------------------------------------------------

def test_a_failed_one_off_invoice_with_no_subscription_does_not_make_the_org_past_due(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "active")
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub, "active")
    inv = stripe.add_invoice(cus, None, "open")
    status, body = send(routes_for(tenancy, stripe), event("invoice.payment_failed", inv, "invoice"))
    assert (status, body["outcome"]) == (200, "ignored_no_subscription")
    assert status_of(tenancy, org) == "active"


def test_a_failed_subscription_invoice_still_makes_the_org_past_due(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "active")
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub, "active")
    inv = stripe.add_invoice(cus, sub, "open")
    status, body = send(routes_for(tenancy, stripe), event("invoice.payment_failed", inv, "invoice"))
    assert status == 200 and status_of(tenancy, org) == "past_due"


# 5. the closing day of a period ---------------------------------------------------------------------------------------------

def _renewing(tenancy, stripe, minutes_after_midnight=5):
    """A period that started a few minutes after midnight UTC today: yesterday is the old period's closing day."""
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link_period(tenancy, tenancy.a, cus, sub, midnight(TODAY) + timedelta(minutes=minutes_after_midnight))
    return cus


def test_the_closing_day_is_billed_to_its_own_period_while_the_invoice_grace_window_is_open(tenancy, stripe, pg_server):
    cus = _renewing(tenancy, stripe)
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(7), alarm=alarms, sleep=lambda s: None,
                        now=midnight(TODAY) + timedelta(minutes=10))
    assert "usage_day_abandoned" not in alarms.names
    sent = {(e["event_name"], e["value"]) for e in stripe.meter_events if e["customer"] == cus}
    assert sent == {("consentvault_consent_events", 2), ("consentvault_gate_checks", 7)}
    assert all(e["timestamp"] < int((midnight(TODAY) + timedelta(minutes=5)).timestamp()) for e in stripe.meter_events)
    assert usage_rows(tenancy, tenancy.a)[0]["reported_at"] is not None


def test_once_the_grace_window_has_closed_the_closing_day_is_abandoned_and_named(tenancy, stripe, pg_server):
    _renewing(tenancy, stripe)
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(7), alarm=alarms, sleep=lambda s: None,
                        now=midnight(TODAY) + timedelta(minutes=5, hours=2))
    assert stripe.meter_events == [] and "usage_day_abandoned" in alarms.names


def test_only_the_closing_day_gets_the_grace_the_day_before_it_is_still_abandoned(tenancy, stripe, pg_server):
    _renewing(tenancy, stripe)
    earlier = YESTERDAY - timedelta(days=1)
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (%s, %s, 5, 7)",
                   (tenancy.a.org_id, earlier))
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(7), alarm=alarms, sleep=lambda s: None,
                        now=midnight(TODAY) + timedelta(minutes=10))
    assert [d for n, d in alarms.raised if n == "usage_day_abandoned"][0].count(earlier.isoformat()) == 1
    assert {e["value"] for e in stripe.meter_events} == {2, 7}  # the closing day went out; the earlier one did not
