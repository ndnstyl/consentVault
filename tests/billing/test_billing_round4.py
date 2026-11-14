"""Fourth review: a foreign dead subscription never swaps in or suspends, the usage jobs have command entry points and a
loud missed-run check, a failed resend clears only its own mark, acknowledgement is worker-only, once, and audited, and the
checkout lock is bounded."""

import argparse
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from consentvault import cli, jobs
from consentvault.billing import routes as routes_mod
from consentvault.billing import usage
from consentvault.billing.errors import StripeUnavailableError, UsageReportError
from consentvault.billing.usage import (acknowledge_day, closed_day, run_daily_job, run_daily_usage,
                                        run_usage_retries)
from consentvault.errors import ConfigError

from .fakes import event
from .helpers import retries_age, account, link, routes_for, send, set_status, status_of, subscribed
from .test_billing_round3 import link_period, midnight
from .test_routes import call
from .test_usage import Alarms, backdate_events, gates, usage_rows, worker_conn
from isolation.harness import make_login_role

YESTERDAY = closed_day()
NOW = datetime.now(timezone.utc)
STARTER = json.dumps({"plan_id": "starter"}).encode()


def open_alarms(tenancy, org, name):
    with tenancy.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.operator_alarm WHERE org_id = %s AND name = %s"
                          " AND acknowledged_at IS NULL", (org.org_id, name)).fetchone()["n"]


# 1. a foreign dead subscription is ignored -----------------------------------------------------------------------------------

def _two_live(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "active")
    cus, first = subscribed(stripe, org)
    link(tenancy, org, cus, first, "active")
    second = stripe.add_subscription(cus, "active", str(org.org_id))
    r = routes_for(tenancy, stripe)
    send(r, event("customer.subscription.updated", second, "subscription"))
    assert open_alarms(tenancy, org, "billing.second_live_subscription") == 1
    return org, cus, first, second, r


@pytest.mark.parametrize("kind", ["customer.subscription.deleted", "customer.subscription.updated"])
def test_the_ignored_second_subscription_ending_neither_swaps_in_nor_suspends_and_clears_its_alarm(
        tenancy, stripe, caplog, kind):
    org, cus, first, second, r = _two_live(tenancy, stripe)
    stripe.subscriptions[second]["status"] = "canceled"
    with caplog.at_level(logging.INFO, logger="consentvault.billing.webhook"):
        status, body = send(r, event(kind, second, "subscription"))
    assert (status, body["outcome"]) == (200, "ignored_second_subscription")
    assert account(tenancy, org)["stripe_subscription_id"] == first
    assert status_of(tenancy, org) == "active"
    assert open_alarms(tenancy, org, "billing.second_live_subscription") == 0
    assert any(second in rec.getMessage() and rec.levelno == logging.INFO for rec in caplog.records)


@pytest.mark.parametrize("kind,invoice_status", [("invoice.paid", "paid"), ("invoice.payment_failed", "open")])
def test_an_invoice_event_for_the_ignored_dead_subscription_changes_nothing(tenancy, stripe, kind, invoice_status):
    org, cus, first, second, r = _two_live(tenancy, stripe)
    stripe.subscriptions[second]["status"] = "canceled"
    inv = stripe.add_invoice(cus, second, invoice_status)
    status, body = send(r, event(kind, inv, "invoice"))
    assert (status, body["outcome"]) == (200, "ignored_second_subscription")
    assert status_of(tenancy, org) == "active" and account(tenancy, org)["stripe_subscription_id"] == first


def test_the_stored_subscription_ending_still_suspends(tenancy, stripe):
    org, cus, first, second, r = _two_live(tenancy, stripe)
    stripe.subscriptions[first]["status"] = "canceled"
    status, body = send(r, event("customer.subscription.deleted", first, "subscription"))
    assert status == 200 and status_of(tenancy, org) == "suspended"


# 2. command entry points -------------------------------------------------------------------------------------------------

class Cfg:
    def __init__(self, dsn):
        self.dsn = dsn

    def require_dsn(self):
        return self.dsn


def _cmd(tenancy, pg_server, stripe, monkeypatch):
    from consentvault import cmd_usage

    monkeypatch.setattr(cmd_usage, "make_client", lambda env=None: stripe)
    dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    return cmd_usage, Cfg(dsn)


def _ns(**kw):
    return argparse.Namespace(**kw)


def test_the_usage_commands_are_registered_and_scheduled_by_job_name():
    cli.build_parser()
    for name in ("usage-daily", "usage-retry", "usage-acknowledge"):
        assert name in cli.REGISTRY
        assert jobs.JOBS[name] == name


def test_the_usage_commands_need_a_stripe_key_file_and_refuse_without_one(monkeypatch):
    from consentvault import cmd_usage

    monkeypatch.delenv("CONSENTVAULT_STRIPE_SECRET_KEY_FILE", raising=False)
    with pytest.raises(ConfigError, match="CONSENTVAULT_STRIPE_SECRET_KEY_FILE"):
        cmd_usage.make_client({})


def test_usage_daily_counts_yesterday_reports_it_and_marks_the_run(tenancy, stripe, pg_server, monkeypatch, capsys):
    cmd_usage, cfg = _cmd(tenancy, pg_server, stripe, monkeypatch)
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    with pytest.raises(UsageReportError, match="gate_checks count unavailable"):  # no gate count is kept yet: loud
        cli.REGISTRY["usage-daily"].run(_ns(day=None), cfg)
    assert [e["value"] for e in stripe.meter_events if e["customer"] == cus] == [2]
    assert usage_rows(tenancy, tenancy.a)[0]["gate_checks"] is None
    with worker_conn(tenancy, pg_server) as w:
        assert w.execute("SELECT consentvault.usage_run_age() AS a").fetchone()["a"] < 60


def test_usage_retry_is_red_when_no_daily_run_has_finished_in_26_hours(tenancy, stripe, pg_server, monkeypatch):
    cmd_usage, cfg = _cmd(tenancy, pg_server, stripe, monkeypatch)
    with pytest.raises(UsageReportError, match="daily usage run"):
        cli.REGISTRY["usage-retry"].run(_ns(), cfg)
    with worker_conn(tenancy, pg_server) as w:
        w.execute("SELECT consentvault.usage_run_finish(%s)", (YESTERDAY,))
    assert cli.REGISTRY["usage-retry"].run(_ns(), cfg) == 0
    with tenancy.superuser() as su:
        su.execute("UPDATE consentvault.usage_run SET finished_at = now() - interval '27 hours'")
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="daily usage run"):
        run_usage_retries(w, stripe, alarm=alarms)
    assert "usage_daily_run_missed" in alarms.names


def test_usage_acknowledge_command_clears_a_standing_verdict(tenancy, stripe, pg_server, monkeypatch):
    cmd_usage, cfg = _cmd(tenancy, pg_server, stripe, monkeypatch)
    cus, sub = subscribed(stripe, tenancy.a)
    link_period(tenancy, tenancy.a, cus, sub, midnight(YESTERDAY))
    lost = YESTERDAY - timedelta(days=3)
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (%s, %s, 5, 7)",
                   (tenancy.a.org_id, lost))
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    ns = _ns(org=str(tenancy.a.org_id), day=lost.isoformat(), key="abandoned", by="operator:mike")
    assert cli.REGISTRY["usage-acknowledge"].run(ns, cfg) == 0
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)


# 3. marks, acknowledgement ---------------------------------------------------------------------------------------------------

def test_a_failed_resend_leaves_a_mark_an_earlier_attempt_made(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks, stripe_sent)"
                   " VALUES (%s, %s, 2, 3, jsonb_build_object('events', now() - interval '1 hour'))"
                   " ON CONFLICT (org_id, day) DO UPDATE SET stripe_sent = excluded.stripe_sent",
                   (tenancy.a.org_id, YESTERDAY))
    stripe.fail["create_meter_event"] = StripeUnavailableError("down")
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=Alarms(), sleep=lambda s: None)
    row = usage_rows(tenancy, tenancy.a)[0]
    assert "events" in row["stripe_sent"] and "gate_checks" not in row["stripe_sent"]  # only its own mark was cleared
    assert row["retry_at"] is not None


def _abandoned_day(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a)
    link_period(tenancy, tenancy.a, cus, sub, midnight(YESTERDAY))
    lost = YESTERDAY - timedelta(days=3)
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (%s, %s, 5, 7)",
                   (tenancy.a.org_id, lost))
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    return lost


WORKER_ONLY = ("usage_acknowledge_verdict(date,text,text)", "usage_run_finish(date)", "usage_run_age()")


@pytest.mark.parametrize("function", WORKER_ONLY)
def test_the_worker_only_functions_are_granted_to_the_worker_role_alone(tenancy, function):
    with tenancy.superuser() as su:
        got = {role: su.execute("SELECT has_function_privilege(%s, %s, 'EXECUTE') AS ok",
                                (role, f"consentvault.{function}")).fetchone()["ok"]
               for role in ("consentvault_worker", "consentvault_app", "consentvault_console")}
        public = su.execute("SELECT has_function_privilege('public', %s, 'EXECUTE') AS ok",
                            (f"consentvault.{function}",)).fetchone()["ok"]
    assert got == {"consentvault_worker": True, "consentvault_app": False, "consentvault_console": False}
    assert public is False


def test_acknowledgement_called_as_the_app_role_is_refused(tenancy, stripe, pg_server):
    lost = _abandoned_day(tenancy, stripe, pg_server)
    with tenancy.app() as app, pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("SELECT consentvault.usage_acknowledge_verdict(%s, 'abandoned', 'someone')", (lost,))


def test_a_second_acknowledgement_is_refused_and_each_one_is_audited(tenancy, stripe, pg_server):
    lost = _abandoned_day(tenancy, stripe, pg_server)
    with worker_conn(tenancy, pg_server) as w:
        acknowledge_day(w, tenancy.a.org_id, lost, "abandoned", "operator:mike")
        with pytest.raises(UsageReportError, match="already acknowledged"):
            acknowledge_day(w, tenancy.a.org_id, lost, "abandoned", "operator:other")
        with pytest.raises(UsageReportError, match="no such verdict"):
            acknowledge_day(w, tenancy.a.org_id, lost, "unconfirmed:events", "operator:mike")
    with tenancy.superuser() as su:
        rows = su.execute("SELECT day, key, acknowledged_by FROM consentvault.usage_verdict_audit"
                          " WHERE org_id = %s", (tenancy.a.org_id,)).fetchall()
        assert [(r["day"], r["key"], r["acknowledged_by"]) for r in rows] == [(lost, "abandoned", "operator:mike")]
        with pytest.raises(psycopg.Error):
            su.execute("UPDATE consentvault.usage_verdict_audit SET acknowledged_by = 'x'")


# 4. info: old periods, failed marks, the newest down file ----------------------------------------------------------------------

def test_a_retry_due_for_a_day_of_an_old_period_is_abandoned_not_billed_into_the_new_one(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY - timedelta(days=5), 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link_period(tenancy, tenancy.a, cus, sub, midnight(YESTERDAY - timedelta(days=10)))
    old = YESTERDAY - timedelta(days=5)
    stripe.fail["create_meter_event"] = StripeUnavailableError("down")
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, old, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    stripe.fail.clear()
    link_period(tenancy, tenancy.a, cus, sub, midnight(YESTERDAY))  # the period rolled over
    alarms = Alarms()
    retries_age(tenancy, 2)   # two hours pass for the retry queue too
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_usage_retries(w, stripe, now=NOW + timedelta(hours=2), alarm=alarms, check_daily_run=False)
    assert stripe.meter_events == [] and "usage_day_abandoned" in alarms.names


def test_a_failed_verdict_clears_when_the_retry_succeeds(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    stripe.fail["create_meter_event"] = StripeUnavailableError("down")
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=Alarms(), sleep=lambda s: None)
    assert set(usage_rows(tenancy, tenancy.a)[0]["stripe_verdict"]) == {"failed:events", "failed:gate_checks"}
    stripe.fail.clear()
    retries_age(tenancy, 2)   # two hours pass for the retry queue too
    with worker_conn(tenancy, pg_server) as w:
        run_usage_retries(w, stripe, now=NOW + timedelta(hours=2), alarm=Alarms(), check_daily_run=False)
    row = usage_rows(tenancy, tenancy.a)[0]
    assert row["stripe_verdict"] == {} and row["reported_at"] is not None


def test_the_newest_down_file_runs_alone_and_leaves_the_earlier_migrations_in_place(tenancy):
    from consentvault import db

    newest = db.default_migrations_dir() / "down" / "0032_usage_run_and_audit.sql"
    with tenancy.superuser() as owner:
        # migration 0065 replaced the run-age read (the database's clock); its own down puts back the form 0032 made
        owner.execute((db.default_migrations_dir() / "down" / "0065_billing_clock.sql").read_text())
        owner.execute(newest.read_text())
        assert owner.execute("SELECT to_regprocedure('consentvault.usage_run_age(timestamptz)') AS f").fetchone()["f"] is None
        assert owner.execute("SELECT to_regclass('consentvault.usage_verdict_audit') AS t").fetchone()["t"] is None
        # the earlier migration still stands, and the acknowledge function it shipped is back
        assert owner.execute("SELECT to_regprocedure('consentvault.usage_acknowledge(date,text,text)') AS f").fetchone()["f"]
        assert owner.execute("SELECT to_regprocedure('consentvault.usage_note_verdict(date,text)') AS f").fetchone()["f"]


# 5. the checkout lock is bounded ---------------------------------------------------------------------------------------------

def test_the_checkout_lock_is_released_when_the_request_returns(tenancy, stripe):
    org = tenancy.a
    cus = stripe.add_customer(str(org.org_id))
    link(tenancy, org, cus)
    stripe.create_delay = 0.3
    t0 = time.monotonic()
    assert call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", org, body=STARTER).status == 201
    held_for = time.monotonic() - t0
    assert held_for < 5  # the lock lasts the Stripe calls and nothing longer
    with tenancy.superuser() as su, su.transaction():
        su.execute("SELECT 1 FROM consentvault.billing_account WHERE org_id = %s FOR UPDATE NOWAIT", (org.org_id,))


def test_a_checkout_waiting_on_the_lock_gives_up_with_a_named_503_inside_its_bound(tenancy, stripe, monkeypatch):
    org = tenancy.a
    cus = stripe.add_customer(str(org.org_id))
    link(tenancy, org, cus)
    monkeypatch.setattr(routes_mod, "CHECKOUT_LOCK_TIMEOUT_MS", 300)
    answers = []
    with tenancy.superuser() as su, su.transaction():
        su.execute("SELECT 1 FROM consentvault.billing_account WHERE org_id = %s FOR UPDATE", (org.org_id,))
        t0 = time.monotonic()
        waiter = threading.Thread(daemon=True, target=lambda: answers.append(
            call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", org, body=STARTER)))
        waiter.start()
        waiter.join(10)  # a deadline: a request that waits past its bound is a failure, never a hang
        hung = waiter.is_alive()
    waiter.join(10)
    assert not hung, "the checkout request kept waiting on the lock past its 300 ms bound"
    assert time.monotonic() - t0 < 12
    res = answers[0]
    assert (res.status, res.payload["error"]) == (503, "service_unavailable")
    assert stripe.count("create_checkout_session") == 0


def test_the_newest_down_file_refuses_while_an_acknowledgement_audit_row_exists(tenancy, stripe, pg_server):
    from consentvault import db

    lost = _abandoned_day(tenancy, stripe, pg_server)
    with worker_conn(tenancy, pg_server) as w:
        acknowledge_day(w, tenancy.a.org_id, lost, "abandoned", "operator:mike")
    newest = db.default_migrations_dir() / "down" / "0032_usage_run_and_audit.sql"
    with tenancy.superuser() as su, pytest.raises(psycopg.Error, match="audit rows exist"):
        su.execute(newest.read_text())
