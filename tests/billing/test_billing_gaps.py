"""Billing gaps closed by the second review: one live subscription per customer, usage days never dropped or resent
silently, a plan with a dropped overage Price off sale, a strict Enterprise free tier, a named 503 after a database
failure in the webhook."""

import json
from datetime import timedelta

import pytest

from consentvault.billing import usage
from consentvault.billing.errors import UsageReportError
from consentvault.billing.routes import BillingRoutes
from consentvault.billing.usage import closed_day, run_daily_usage

from .fakes import SECRET, event
from .helpers import account, link, outcomes, routes_for, send, subscribed
from .test_review_fixes import _enterprise_sub, alarm_names
from .test_routes import call
from .test_usage import Alarms, backdate_events, gates, usage_rows, worker_conn

YESTERDAY = closed_day()
STARTER = json.dumps({"plan_id": "starter"}).encode()


# 1. two checkouts before the first webhook ---------------------------------------------------------------------------

def test_checkout_refuses_when_stripe_already_lists_a_live_subscription_the_vault_has_not_heard_of(tenancy, stripe):
    org = tenancy.a
    cus = stripe.add_customer(str(org.org_id))
    link(tenancy, org, cus)  # the first checkout linked the customer; its webhook has not arrived
    stripe.add_subscription(cus, "active", str(org.org_id))
    res = call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", org, body=STARTER)
    assert (res.status, res.payload["error"]) == (409, "already_subscribed")
    assert stripe.count("create_checkout_session") == 0


def test_a_canceled_subscription_in_stripe_does_not_block_a_new_checkout(tenancy, stripe):
    org = tenancy.a
    cus = stripe.add_customer(str(org.org_id))
    link(tenancy, org, cus)
    stripe.add_subscription(cus, "canceled", str(org.org_id))
    assert call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", org, body=STARTER).status == 201


def test_the_webhook_alarms_when_a_different_live_subscription_would_replace_the_stored_one(tenancy, stripe):
    org = tenancy.a
    cus, first = subscribed(stripe, org)
    link(tenancy, org, cus, first, "active")
    second = stripe.add_subscription(cus, "active", str(org.org_id))
    r = routes_for(tenancy, stripe)
    status, body = send(r, event("customer.subscription.updated", first, "subscription"))
    assert status == 200 and "billing.second_live_subscription" not in alarm_names(tenancy, org)
    status, body = send(r, event("customer.subscription.updated", second, "subscription"))
    assert status == 200
    assert "billing.second_live_subscription" in alarm_names(tenancy, org)


def test_a_new_subscription_after_the_stored_one_ended_is_not_alarmed(tenancy, stripe):
    org = tenancy.a
    cus, first = subscribed(stripe, org, status="canceled")
    link(tenancy, org, cus, first, "canceled")
    second = stripe.add_subscription(cus, "active", str(org.org_id))
    status, _ = send(routes_for(tenancy, stripe), event("customer.subscription.updated", second, "subscription"))
    assert status == 200 and "billing.second_live_subscription" not in alarm_names(tenancy, org)


# 2. days held back before the stored period start ----------------------------------------------------------------------

def test_days_before_the_period_start_that_were_never_reported_are_alarmed_by_day(tenancy, stripe, pg_server):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    start = (usage.datetime.combine(YESTERDAY, usage.datetime.min.time(), usage.timezone.utc))
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, 'price_starter', 'active', 'starter',"
                    " 'Starter', 1000, 25000, %s, %s)", (org.org_id, cus, sub, start, start + timedelta(days=30)))
    lost = [YESTERDAY - timedelta(days=3), YESTERDAY - timedelta(days=2)]
    with tenancy.superuser() as su:
        for d in lost:
            su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (%s, %s, 5, 7)",
                       (org.org_id, d))
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=alarms, sleep=lambda s: None)
    named = [d for n, d in alarms.raised if n == "usage_day_abandoned"]
    assert len(named) == 2 and all(any(day.isoformat() in d for d in named) for day in lost)
    assert not [e for e in stripe.meter_events if e["value"] in (5, 7)]  # still never sent into the wrong period


# 3. accepted by Stripe, confirmation not saved --------------------------------------------------------------------------

def test_a_sent_mark_is_written_before_each_stripe_call(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    seen = []
    real = stripe.create_meter_event

    def watching(**kw):
        meter = "events" if kw["event_name"].endswith("events") else "gate_checks"
        seen.append(meter in usage_rows(tenancy, tenancy.a)[0]["stripe_sent"])
        return real(**kw)

    stripe.create_meter_event = watching
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=Alarms(), sleep=lambda s: None)
    assert seen == [True, True]


def test_a_sent_day_with_no_saved_confirmation_alarms_after_the_dedupe_window_and_is_never_resent(
        tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=Alarms(), sleep=lambda s: None)
    sent = len(stripe.meter_events)
    with tenancy.superuser() as su:  # the confirmation was lost, and the send was 30 hours ago
        su.execute("UPDATE consentvault.usage_day SET stripe_ack = '{}'::jsonb, reported_at = NULL,"
                   " stripe_sent = jsonb_build_object('events', now() - interval '30 hours',"
                   " 'gate_checks', now() - interval '30 hours') WHERE org_id = %s", (tenancy.a.org_id,))
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="unconfirmed"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(3), alarm=alarms, sleep=lambda s: None)
    assert len(stripe.meter_events) == sent
    assert "usage_send_unconfirmed" in alarms.names
    assert any(YESTERDAY.isoformat() in d for n, d in alarms.raised if n == "usage_send_unconfirmed")


def test_a_failed_send_is_still_retried_within_the_dedupe_window_under_the_same_key(tenancy, stripe, pg_server):
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    stripe.fail["create_meter_event"] = usage.StripeUnavailableError("down")
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    stripe.fail.clear()
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    assert usage_rows(tenancy, tenancy.a)[0]["reported_at"] is not None


# 4. a plan whose overage Price was dropped -------------------------------------------------------------------------------

def test_a_plan_whose_overage_price_was_dropped_is_taken_off_sale_with_an_alarm(tenancy, stripe):
    stripe.prices["price_starter_gc"]["metadata"]["meter"] = "bogus"
    alarms = Alarms()
    r = routes_for(tenancy, stripe, alarm=alarms)
    plans = call(r, "GET", "/v1/billing/plans", tenancy.a).payload["items"]
    assert {p["plan_id"] for p in plans} == {"growth"}
    assert any(n == "billing.plan_off_sale" and "starter" in d for n, d in alarms.raised)
    res = call(r, "POST", "/v1/billing/checkout", tenancy.a, body=STARTER)
    assert (res.status, res.payload["error"]) == (404, "not_found")
    assert stripe.count("create_checkout_session") == 0


# 5. Enterprise free tier --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("mutate,mismatch", [
    (lambda p: None, False),
    (lambda p: p.update(tiers_mode="volume"), True),
    (lambda p: p.update(tiers_mode=None), True),
    (lambda p: p["tiers"][0].update(flat_amount=50000), True),
    (lambda p: p["tiers"][0].update(flat_amount_decimal="50000"), True)])
def test_an_enterprise_free_tier_must_be_graduated_with_no_flat_fee(tenancy, stripe, mutate, mismatch):
    org = tenancy.a
    cus, sub = _enterprise_sub(stripe, org, 250000, 9000000)
    mutate(stripe.prices["price_ent_events"])
    session = stripe.add_session(cus, sub, str(org.org_id))
    status, body = send(routes_for(tenancy, stripe), event("checkout.session.completed", session, "checkout.session"))
    assert (status, body["outcome"]) == (200, "linked")
    assert ("billing.enterprise_contract_mismatch" in alarm_names(tenancy, org)) is mismatch


# info: a database failure in the webhook keeps its named 503 ----------------------------------------------------------------

def test_a_database_failure_writing_the_alarm_is_a_named_503_not_a_server_error(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, price_id="price_enterprise_acme")  # incomplete contract: an alarm is due
    session = stripe.add_session(cus, sub, str(org.org_id))
    r = BillingRoutes(connect=routes_for(tenancy, stripe)._connect, mint_token=lambda org_id, scopes: "garbage",
                      client=stripe, webhook_secret=SECRET)
    status, body = send(r, event("checkout.session.completed", session, "checkout.session"))
    assert (status, body["error"]) == (503, "service_unavailable") and "TenantTokenError" in body["detail"]
    assert account(tenancy, org) is None and "linked" not in outcomes(tenancy)
