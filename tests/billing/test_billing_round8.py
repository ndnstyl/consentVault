"""Eighth review: the price-change mark also watches the overage prices, a retry pass reads a live clock, and the newest
down file runs only as the schema owner (or a role that can act as it)."""

import copy
from datetime import timedelta

import psycopg
import pytest

from consentvault.billing.errors import StripeUnavailableError, UsageReportError
from consentvault.billing.usage import run_daily_usage, run_usage_retries

from .fakes import event
from .helpers import account, routes_for, send, subscribed
from .test_billing_round6 import _renewing
from .test_billing_round7 import START
from .test_usage import Alarms, gates, usage_rows, worker_conn


# 1. the overage prices count ---------------------------------------------------------------------------------------------------

def _changed_at(tenancy, org):
    with tenancy.superuser() as su:
        return su.execute("SELECT price_changed_at FROM consentvault.billing_account WHERE org_id = %s",
                          (org.org_id,)).fetchone()["price_changed_at"]


def test_changing_only_the_overage_price_sets_the_price_change_mark(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    r = routes_for(tenancy, stripe)
    assert send(r, event("customer.subscription.updated", sub, "subscription"))[0] == 200
    assert _changed_at(tenancy, org) is None
    assert send(r, event("customer.subscription.updated", sub, "subscription"))[0] == 200  # nothing changed
    assert _changed_at(tenancy, org) is None
    items = stripe.subscriptions[sub]["items"]["data"]
    items[1] = {"price": copy.deepcopy(stripe.prices["price_starter_gc"])}  # same base price, a different overage price
    assert send(r, event("customer.subscription.updated", sub, "subscription"))[0] == 200
    assert account(tenancy, org)["price_id"] == "price_starter"
    assert _changed_at(tenancy, org) is not None


# 2. the retry pass reads a live clock -----------------------------------------------------------------------------------------------

def test_a_retry_pass_that_outlasts_the_window_abandons_the_remaining_sends_by_name(tenancy, stripe, pg_server):
    _renewing(tenancy, stripe)
    stripe.fail["create_meter_event"] = StripeUnavailableError("down")
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, START.date() - timedelta(days=1), gate_counter=gates(7), alarm=Alarms(),
                        sleep=lambda s: None, now=START + timedelta(minutes=10))
    stripe.fail.clear()
    with tenancy.superuser() as su:
        su.execute("UPDATE consentvault.usage_day SET retry_at = %s WHERE org_id = %s", (START, tenancy.a.org_id))
    ticks = iter([START + timedelta(minutes=10), START + timedelta(minutes=56)])
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_usage_retries(w, stripe, now=START + timedelta(minutes=10), alarm=alarms, check_daily_run=False,
                          sleep=lambda s: None, clock=lambda: next(ticks, START + timedelta(minutes=58)))
    assert len(stripe.meter_events) == 1 and "usage_day_abandoned" in alarms.names


# 3. the newest down file runs only as the schema owner or a role that can act as it ---------------------------------------------------

def _down_text():
    from consentvault import db

    return (db.default_migrations_dir() / "down" / "0040_price_change_mark.sql").read_text()


def _down_0041():
    from consentvault import db

    return (db.default_migrations_dir() / "down" / "0041_price_set_mark.sql").read_text()


def test_the_price_mark_down_file_refuses_a_role_that_is_not_the_schema_owner(tenancy):
    with tenancy.superuser() as su:
        su.execute(_down_0041())  # the newer file comes off first
    with tenancy.app() as app, pytest.raises(psycopg.Error, match="schema owner"):
        app.execute(_down_text())


def test_the_price_mark_down_file_runs_as_the_owner_and_leaves_the_functions_owned_by_it(tenancy):
    with tenancy.superuser() as su:
        owner = su.execute("SELECT pg_get_userbyid(nspowner) AS o FROM pg_namespace WHERE nspname = 'consentvault'"
                           ).fetchone()["o"]
        su.execute(_down_0041())
        su.execute(_down_text())
        got = su.execute("SELECT pg_get_userbyid(proowner) AS o FROM pg_proc WHERE oid IN"
                         " ('consentvault.usage_plan_of_record()'::regprocedure)").fetchone()["o"]
    assert got == owner
