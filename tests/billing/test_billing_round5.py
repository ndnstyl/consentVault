"""Fifth review: adopting a live subscription after the stored one ended reactivates the organisation, a one-off invoice
never lifts a cancellation, the app role clears only the duplicate-subscription alarm, and the acknowledge command fails
loudly on its own errors."""

from error_names import code_of as _code, named  # noqa: F401
import json
from datetime import timedelta

import psycopg
import pytest

from consentvault import cli

from .fakes import event
from .helpers import account, link, routes_for, send, status_of, subscribed
from .test_billing_round4 import Cfg, _abandoned_day, _two_live, open_alarms
from .test_usage import worker_conn


# adoption ------------------------------------------------------------------------------------------------------------------

def test_a_live_subscription_adopted_after_the_stored_one_was_cancelled_reactivates_and_clears_the_alarm(tenancy, stripe):
    org, cus, first, second, r = _two_live(tenancy, stripe)
    stripe.subscriptions[first]["status"] = "canceled"
    status, body = send(r, event("customer.subscription.deleted", first, "subscription"))
    assert status == 200 and status_of(tenancy, org) == "suspended"
    status, body = send(r, event("customer.subscription.updated", second, "subscription"))
    assert status == 200
    assert account(tenancy, org)["stripe_subscription_id"] == second
    assert status_of(tenancy, org) == "active"
    assert open_alarms(tenancy, org, "billing.second_live_subscription") == 0


# a one-off invoice -----------------------------------------------------------------------------------------------------------

def test_a_paid_one_off_invoice_with_no_subscription_does_not_lift_a_cancellation_suspension(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub, "active")
    stripe.subscriptions[sub]["status"] = "canceled"
    r = routes_for(tenancy, stripe)
    send(r, event("customer.subscription.deleted", sub, "subscription"))
    assert status_of(tenancy, org) == "suspended"
    inv = stripe.add_invoice(cus, None, "paid")
    status, body = send(r, event("invoice.paid", inv, "invoice"))
    assert (status, body["outcome"]) == (200, "ignored_no_subscription")
    assert status_of(tenancy, org) == "suspended"


# the app role's clear function -------------------------------------------------------------------------------------------------

def _raise_alarm(tenancy, org, name):
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.operator_alarm (org_id, name, error_class) VALUES (%s, %s, 'Test')",
                   (org.org_id, name))


def test_the_app_roles_clear_function_clears_only_the_duplicate_subscription_alarm(tenancy):
    org = tenancy.a
    _raise_alarm(tenancy, org, "billing.enterprise_contract_incomplete")
    _raise_alarm(tenancy, org, "billing.second_live_subscription")
    with tenancy.app() as app:
        assert app.execute("SELECT consentvault.billing_clear_alarm(%s, 'billing.second_live_subscription', 'x') AS n",
                           (org.org_id,)).fetchone()["n"] == 1
        with pytest.raises(psycopg.Error, match="duplicate-subscription"):
            app.execute("SELECT consentvault.billing_clear_alarm(%s, 'billing.enterprise_contract_incomplete', 'x')",
                        (org.org_id,))
    assert open_alarms(tenancy, org, "billing.enterprise_contract_incomplete") == 1


# the acknowledge command ---------------------------------------------------------------------------------------------------

def _cli(tenancy, pg_server, monkeypatch, *argv):
    from isolation.harness import make_login_role

    dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    return cli.main(["usage-acknowledge", *argv])


def test_the_acknowledge_command_exits_2_naming_its_own_error(tenancy, stripe, pg_server, monkeypatch, capsys):
    lost = _abandoned_day(tenancy, stripe, pg_server)
    base = ["--org", str(tenancy.a.org_id), "--day", lost.isoformat(), "--by", "operator:mike"]
    assert _cli(tenancy, pg_server, monkeypatch, *base, "--key", "unconfirmed:events") == 2
    missing = capsys.readouterr().err
    assert named("UsageReportError", missing) and "no such verdict" not in missing
    assert _cli(tenancy, pg_server, monkeypatch, *base, "--key", "abandoned") == 0
    assert _cli(tenancy, pg_server, monkeypatch, *base, "--key", "abandoned") == 2
    twice = capsys.readouterr().err
    assert named("UsageReportError", twice) and "already acknowledged" not in twice
    assert _code(missing) != _code(twice)  # each failure keeps its own stable code, so the two are still told apart
    assert _cli(tenancy, pg_server, monkeypatch, "--org", "not-an-id", "--day", lost.isoformat(), "--key", "abandoned",
                "--by", "x") == 2
    bad = capsys.readouterr().err
    assert named("ConfigError", bad) and "organisation id" not in bad


def test_the_acknowledge_command_names_a_database_failure_instead_of_a_traceback(tenancy, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", "postgresql://nobody@127.0.0.1:1/none")
    code = cli.main(["usage-acknowledge", "--org", str(tenancy.a.org_id), "--day", "2026-01-01", "--key", "abandoned",
                     "--by", "x"])
    err = capsys.readouterr().err
    assert code == 2 and named("UsageReportError", err) and "Traceback" not in err
