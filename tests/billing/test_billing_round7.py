"""Seventh review: the closing day is billed only while the invoice window is certainly open (the clock is read again before
each send, with a margin), and never after the subscription's price changed during that period (Stripe drops late usage
for a replaced price)."""

from datetime import timedelta

import pytest

from consentvault.billing.errors import UsageReportError
from consentvault.billing.usage import closed_day, run_daily_usage

from .test_billing_round3 import link_period, midnight
from .test_billing_round6 import TODAY, YESTERDAY, _renewing
from .helpers import subscribed
from .test_usage import Alarms, backdate_events, gates, worker_conn

START = midnight(TODAY) + timedelta(minutes=5)


def _run(tenancy, stripe, pg_server, *, clock, now=START + timedelta(minutes=10), alarms=None):
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(7), alarm=alarms or Alarms(), sleep=lambda s: None,
                        now=now, clock=clock)


# the clock is read again before each send -------------------------------------------------------------------------------------

def test_a_closing_day_send_is_made_while_the_clock_is_inside_the_margin(tenancy, stripe, pg_server):
    _renewing(tenancy, stripe)
    _run(tenancy, stripe, pg_server, clock=lambda: START + timedelta(minutes=54))
    assert len(stripe.meter_events) == 2


def test_a_closing_day_send_is_abandoned_by_name_once_the_clock_is_past_the_margin(tenancy, stripe, pg_server):
    _renewing(tenancy, stripe)
    alarms = Alarms()
    with pytest.raises(UsageReportError, match="abandoned"):
        _run(tenancy, stripe, pg_server, clock=lambda: START + timedelta(minutes=56), alarms=alarms)
    assert stripe.meter_events == [] and "usage_day_abandoned" in alarms.names


def test_a_run_that_crosses_the_margin_between_two_sends_stops_and_names_the_rest(tenancy, stripe, pg_server):
    _renewing(tenancy, stripe)
    ticks = iter([START + timedelta(minutes=10), START + timedelta(minutes=56), START + timedelta(minutes=57)])
    alarms = Alarms()
    with pytest.raises(UsageReportError, match="abandoned"):
        _run(tenancy, stripe, pg_server, clock=lambda: next(ticks, START + timedelta(minutes=58)), alarms=alarms)
    assert len(stripe.meter_events) == 1 and "usage_day_abandoned" in alarms.names


# a price change during the period -------------------------------------------------------------------------------------------------

def _link(tenancy, org, cus, sub, price, start):
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, %s, 'active', 'starter', 'Starter', 1000,"
                    " 25000, %s, %s)", (org.org_id, cus, sub, price, start, start + timedelta(days=30)))


def _two_periods(tenancy, stripe, *, change_price):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    old_start = START - timedelta(days=30)
    _link(tenancy, tenancy.a, cus, sub, "price_starter", old_start)
    if change_price:
        _link(tenancy, tenancy.a, cus, sub, "price_growth", old_start)  # the price changed mid-cycle
    _link(tenancy, tenancy.a, cus, sub, "price_growth" if change_price else "price_starter", START)  # the renewal
    return old_start


def test_the_closing_day_is_abandoned_by_name_when_the_price_changed_during_that_period(tenancy, stripe, pg_server):
    _two_periods(tenancy, stripe, change_price=True)
    alarms = Alarms()
    with pytest.raises(UsageReportError, match="abandoned"):
        _run(tenancy, stripe, pg_server, clock=lambda: START + timedelta(minutes=10), alarms=alarms)
    assert stripe.meter_events == []
    assert any("price changed" in d for n, d in alarms.raised if n == "usage_day_abandoned")


def test_the_closing_day_is_billed_when_the_price_did_not_change(tenancy, stripe, pg_server):
    _two_periods(tenancy, stripe, change_price=False)
    _run(tenancy, stripe, pg_server, clock=lambda: START + timedelta(minutes=10))
    assert len(stripe.meter_events) == 2


def test_a_price_change_before_the_closing_period_began_does_not_stop_the_closing_day(tenancy, stripe, pg_server):
    old_start = _two_periods(tenancy, stripe, change_price=True)
    with tenancy.superuser() as su:
        su.execute("UPDATE consentvault.billing_account SET price_changed_at = %s WHERE org_id = %s",
                   (old_start - timedelta(days=3), tenancy.a.org_id))
    _run(tenancy, stripe, pg_server, clock=lambda: START + timedelta(minutes=10))
    assert len(stripe.meter_events) == 2
