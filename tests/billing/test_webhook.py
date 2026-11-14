"""The webhook test set: created, paid, failed, past due, canceled, replayed, forged signature, out of order.

Every scenario runs against Stripe-shaped fixtures held in memory; nothing reaches Stripe.
"""

import time

import pytest

from consentvault import db
from consentvault.billing import store, webhook
from consentvault.billing.errors import StripeUnavailableError, WebhookSignatureError
from consentvault.billing.signature import sign_payload, verify_signature

from .fakes import SECRET, UNAVAILABLE, event, signed
from .helpers import (account, history, link, outcomes, routes_for, send, set_status, status_of, subscribed)


# created ------------------------------------------------------------------------------------------------------------

def test_checkout_completed_links_customer_subscription_and_plan(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="active")
    session = stripe.add_session(cus, sub, str(org.org_id))
    status, body = send(routes_for(tenancy, stripe), event("checkout.session.completed", session, "checkout.session"))
    assert (status, body["outcome"], body["replayed"]) == (200, "linked", False)
    row = account(tenancy, org)
    assert row["stripe_customer_id"] == cus and row["stripe_subscription_id"] == sub
    assert (row["plan_id"], row["plan_name"], row["included_events"], row["included_gate_checks"]) == (
        "starter", "Starter", 1000, 25000)
    assert row["price_id"] == "price_starter" and row["status"] == "active"
    assert row["period_start"] is not None and row["period_end"] is not None
    assert status_of(tenancy, org) == "active"  # linking is not a payment: the status moves on the paid invoice


def test_enterprise_limits_come_from_the_subscriptions_contract_metadata(tenancy, stripe):
    org = tenancy.a
    contract = {"contract_included_events": "250000", "contract_included_gate_checks": "9000000",
                "contract_systems": "40"}
    cus, sub = subscribed(stripe, org, status="active", price_id="price_enterprise_acme", contract=contract)
    session = stripe.add_session(cus, sub, str(org.org_id))
    status, body = send(routes_for(tenancy, stripe), event("checkout.session.completed", session, "checkout.session"))
    assert (status, body["outcome"]) == (200, "linked")
    row = account(tenancy, org)
    assert (row["plan_id"], row["plan_name"], row["included_events"], row["included_gate_checks"]) == (
        "enterprise", "Enterprise", 250000, 9000000)
    assert row["price_id"] == "price_enterprise_acme"


@pytest.mark.parametrize("contract", [{}, {"contract_included_events": "250000"},
                                      {"contract_included_gate_checks": "9000000"},
                                      {"contract_included_events": "lots", "contract_included_gate_checks": "9000000"}])
def test_an_enterprise_subscription_missing_contract_limits_is_flagged_not_recorded_as_unlimited(tenancy, stripe, contract):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="active", price_id="price_enterprise_acme", contract=contract)
    session = stripe.add_session(cus, sub, str(org.org_id))
    status, body = send(routes_for(tenancy, stripe), event("checkout.session.completed", session, "checkout.session"))
    assert (status, body["outcome"]) == (200, "linked")  # billing never refuses the event
    row = account(tenancy, org)
    assert row["plan_id"] == "enterprise_contract_incomplete"
    assert (row["included_events"], row["included_gate_checks"]) == (None, None)
    assert row["stripe_subscription_id"] == sub and row["status"] == "active"
    with tenancy.superuser() as su:
        alarms = su.execute("SELECT name, error_class, ref_kind FROM consentvault.operator_alarm WHERE org_id = %s",
                            (org.org_id,)).fetchall()
    assert [a["name"] for a in alarms] == ["billing.enterprise_contract_incomplete"]


def test_the_incomplete_contract_heals_when_the_values_arrive(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="active", price_id="price_enterprise_acme")
    session = stripe.add_session(cus, sub, str(org.org_id))
    r = routes_for(tenancy, stripe)
    send(r, event("checkout.session.completed", session, "checkout.session"))
    stripe.subscriptions[sub]["metadata"].update(contract_included_events="250000",
                                                 contract_included_gate_checks="9000000")
    send(r, event("customer.subscription.updated", sub, "subscription"))
    row = account(tenancy, org)
    assert (row["plan_id"], row["included_events"], row["included_gate_checks"]) == ("enterprise", 250000, 9000000)


def test_checkout_completed_for_a_customer_of_another_org_does_not_cross_over(tenancy, stripe):
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus)
    forged = stripe.add_session(cus, sub, str(tenancy.b.org_id))  # a session that names B but carries A's customer
    send(routes_for(tenancy, stripe), event("checkout.session.completed", forged, "checkout.session"))
    assert account(tenancy, tenancy.b) is None
    assert account(tenancy, tenancy.a)["stripe_subscription_id"] == sub


def test_checkout_session_that_is_not_a_subscription_is_ignored(tenancy, stripe):
    cus = stripe.add_customer(str(tenancy.a.org_id))
    session = stripe.add_session(cus, None, str(tenancy.a.org_id), mode="payment")
    _, body = send(routes_for(tenancy, stripe), event("checkout.session.completed", session, "checkout.session"))
    assert body["outcome"] == "ignored_mode" and account(tenancy, tenancy.a) is None


# paid ---------------------------------------------------------------------------------------------------------------

def test_first_paid_invoice_moves_trial_to_active_and_writes_history(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "trial")
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    inv = stripe.add_invoice(cus, sub, "paid")
    ev = event("invoice.paid", inv, "invoice")
    _, body = send(routes_for(tenancy, stripe), ev)
    assert body["outcome"] == "applied" and status_of(tenancy, org) == "active"
    last = history(tenancy, org)[-1]
    assert (last["status"], last["cause"], last["actor"]) == ("active", "invoice_paid", f"stripe:{ev['id']}")


# failed / past due --------------------------------------------------------------------------------------------------

def test_payment_failed_moves_active_to_past_due(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    inv = stripe.add_invoice(cus, sub, "open")
    _, body = send(routes_for(tenancy, stripe), event("invoice.payment_failed", inv, "invoice"))
    assert body["outcome"] == "applied" and status_of(tenancy, org) == "past_due"
    assert history(tenancy, org)[-1]["cause"] == "payment_failed"


def test_subscription_updated_past_due_then_recovered(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="past_due")
    link(tenancy, org, cus, sub)
    r = routes_for(tenancy, stripe)
    _, body = send(r, event("customer.subscription.updated", sub, "subscription"))
    assert body["outcome"] == "applied" and status_of(tenancy, org) == "past_due"
    assert account(tenancy, org)["status"] == "past_due"
    stripe.subscriptions[sub]["status"] = "active"
    _, body = send(r, event("customer.subscription.updated", sub, "subscription"))
    assert body["outcome"] == "applied" and status_of(tenancy, org) == "active"
    assert [h["status"] for h in history(tenancy, org)][-2:] == ["past_due", "active"]


def test_payment_failure_on_a_trial_org_is_refused_not_applied(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "trial")
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    inv = stripe.add_invoice(cus, sub, "open")
    _, body = send(routes_for(tenancy, stripe), event("invoice.payment_failed", inv, "invoice"))
    assert body["outcome"] == "refused_transition" and status_of(tenancy, org) == "trial"


# canceled -----------------------------------------------------------------------------------------------------------

def test_subscription_deleted_suspends_and_a_new_paid_subscription_reactivates(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="canceled")
    link(tenancy, org, cus, sub)
    r = routes_for(tenancy, stripe)
    _, body = send(r, event("customer.subscription.deleted", sub, "subscription"))
    assert body["outcome"] == "applied" and status_of(tenancy, org) == "suspended"
    assert account(tenancy, org)["status"] == "canceled"
    assert history(tenancy, org)[-1]["cause"] == "subscription_deleted"
    new_sub = stripe.add_subscription(cus, "active", str(org.org_id))
    inv = stripe.add_invoice(cus, new_sub, "paid")
    _, body = send(r, event("invoice.paid", inv, "invoice"))
    assert body["outcome"] == "applied" and status_of(tenancy, org) == "active"
    assert account(tenancy, org)["stripe_subscription_id"] == new_sub


@pytest.mark.parametrize("terminal", ["offboarding", "closed"])
@pytest.mark.parametrize("kind", ["paid", "failed", "deleted"])
def test_a_webhook_never_moves_an_org_out_of_offboarding_or_closed(tenancy, stripe, terminal, kind):
    org = tenancy.a
    set_status(tenancy, org, terminal)
    cus = stripe.add_customer(str(org.org_id))
    sub = stripe.add_subscription(cus, "canceled" if kind == "deleted" else "active", str(org.org_id))
    link(tenancy, org, cus, sub)
    if kind == "paid":
        ev = event("invoice.paid", stripe.add_invoice(cus, sub, "paid"), "invoice")
    elif kind == "failed":
        ev = event("invoice.payment_failed", stripe.add_invoice(cus, sub, "open"), "invoice")
    else:
        ev = event("customer.subscription.deleted", sub, "subscription")
    _, body = send(routes_for(tenancy, stripe), ev)
    assert body["outcome"] == "refused_terminal" and status_of(tenancy, org) == terminal
    assert len(history(tenancy, org)) == 2  # created, then the operator's move: the webhook added nothing


# replayed -----------------------------------------------------------------------------------------------------------

def test_a_replayed_event_changes_nothing_and_asks_stripe_nothing(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    inv = stripe.add_invoice(cus, sub, "open")
    ev = event("invoice.payment_failed", inv, "invoice")
    r = routes_for(tenancy, stripe)
    send(r, ev)
    before, fetched = len(history(tenancy, org)), stripe.count("retrieve_invoice")
    status, body = send(r, ev)
    assert (status, body["outcome"], body["replayed"]) == (200, "replayed", True)
    assert len(history(tenancy, org)) == before and stripe.count("retrieve_invoice") == fetched
    assert outcomes(tenancy) == {"applied": 1}


def test_the_same_event_delivered_twice_at_once_is_stored_once(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    ev = event("invoice.payment_failed", stripe.add_invoice(cus, sub, "open"), "invoice")
    with db.connect(tenancy.app_dsn) as one, db.connect(tenancy.app_dsn) as two:
        first = webhook.handle_event(one, stripe, ev)
        second = webhook.handle_event(two, stripe, ev)
    assert (first.replayed, second.replayed) == (False, True)
    assert sum(outcomes(tenancy).values()) == 1


# forged signature ---------------------------------------------------------------------------------------------------

def test_forged_signature_is_refused_before_anything_is_stored(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="canceled")
    link(tenancy, org, cus, sub)
    ev = event("customer.subscription.deleted", sub, "subscription")
    r = routes_for(tenancy, stripe)
    body, headers = signed(ev, secret="whsec_not_ours")
    res = r.handle("POST", "/v1/billing/webhook", body=body, headers=headers)
    assert res.status == 400 and res.payload["error"] == "invalid_request"
    assert outcomes(tenancy) == {} and status_of(tenancy, org) == "active" and stripe.calls == []


def test_missing_stale_and_tampered_signatures_are_refused(tenancy, stripe):
    r = routes_for(tenancy, stripe)
    ev = event("invoice.paid", "in_1", "invoice")
    body, headers = signed(ev)
    assert r.handle("POST", "/v1/billing/webhook", body=body, headers={}).status == 400
    stale_body, stale = signed(ev, timestamp=int(time.time()) - 3600)
    assert r.handle("POST", "/v1/billing/webhook", body=stale_body, headers=stale).status == 400
    assert r.handle("POST", "/v1/billing/webhook", body=body + b" ", headers=headers).status == 400
    assert r.handle("POST", "/v1/billing/webhook", body=b"not json",
                    headers=signed(b"not json")[1]).status == 400
    assert outcomes(tenancy) == {}


def test_signature_check_units():
    body = b'{"id":"evt_1"}'
    ts = int(time.time())
    good = f"t={ts},v1={sign_payload(SECRET, body, ts)}"
    assert verify_signature(body, good, SECRET) == ts
    assert verify_signature(body, f"t={ts},v1=deadbeef,v1={sign_payload(SECRET, body, ts)}", SECRET) == ts
    for bad in (None, "", "v1=abc", f"t=x,v1={sign_payload(SECRET, body, ts)}", f"t={ts}", f"t={ts},v1=00"):
        with pytest.raises(WebhookSignatureError):
            verify_signature(body, bad, SECRET)
    with pytest.raises(WebhookSignatureError):
        verify_signature(body, good, "")  # no configured secret refuses everything


# out of order -------------------------------------------------------------------------------------------------------

def test_paid_event_arriving_after_cancellation_cannot_reactivate(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="canceled")
    link(tenancy, org, cus, sub)
    r = routes_for(tenancy, stripe)
    send(r, event("customer.subscription.deleted", sub, "subscription"))
    late_paid = event("invoice.paid", stripe.add_invoice(cus, sub, "paid"), "invoice")
    _, body = send(r, late_paid)
    assert body["outcome"] == "ignored_stale" and status_of(tenancy, org) == "suspended"


def test_failure_event_arriving_after_the_invoice_was_paid_cannot_make_it_past_due(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    paid_now = stripe.add_invoice(cus, sub, "paid")  # Stripe's state now: paid
    _, body = send(routes_for(tenancy, stripe), event("invoice.payment_failed", paid_now, "invoice"))
    assert body["outcome"] == "ignored_stale" and status_of(tenancy, org) == "active"


def test_deleted_event_for_a_subscription_that_is_alive_again_is_stale(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="active")
    link(tenancy, org, cus, sub)
    _, body = send(routes_for(tenancy, stripe), event("customer.subscription.deleted", sub, "subscription"))
    assert body["outcome"] == "ignored_stale" and status_of(tenancy, org) == "active"


def test_paid_invoice_that_beats_the_checkout_confirmation_is_matched_by_the_customer(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "trial")
    cus, sub = subscribed(stripe, org)  # nothing linked yet: checkout.session.completed has not arrived
    _, body = send(routes_for(tenancy, stripe), event("invoice.paid", stripe.add_invoice(cus, sub, "paid"), "invoice"))
    assert body["outcome"] == "applied" and status_of(tenancy, org) == "active"
    assert account(tenancy, org)["stripe_customer_id"] == cus and account(tenancy, org)["stripe_subscription_id"] == sub


def test_event_for_a_customer_we_do_not_know_is_stored_as_unmatched(tenancy, stripe):
    stranger = stripe.add_customer(None)
    sub = stripe.add_subscription(stranger, "canceled")
    _, body = send(routes_for(tenancy, stripe), event("customer.subscription.deleted", sub, "subscription"))
    assert body["outcome"] == "unmatched" and outcomes(tenancy) == {"unmatched": 1}


# other event types, failures ----------------------------------------------------------------------------------------

def test_other_event_types_are_stored_ignored_and_counted(tenancy, stripe):
    r = routes_for(tenancy, stripe)
    for t in ("customer.created", "charge.succeeded", "customer.created"):
        _, body = send(r, event(t, "x_1"))
        assert body["outcome"] == "ignored_type"
    with db.connect(tenancy.app_dsn) as app:
        assert store.event_outcomes(app) == {"ignored_type": 3}
    assert stripe.calls == []


def test_stripe_being_down_returns_502_and_stores_nothing_so_the_retry_is_not_a_replay(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    ev = event("invoice.payment_failed", stripe.add_invoice(cus, sub, "open"), "invoice")
    stripe.fail["retrieve_invoice"] = UNAVAILABLE
    r = routes_for(tenancy, stripe)
    body, headers = signed(ev)
    res = r.handle("POST", "/v1/billing/webhook", body=body, headers=headers)
    assert res.status == 502 and res.payload["error"] == "stripe_unavailable"
    assert outcomes(tenancy) == {} and status_of(tenancy, org) == "active"
    del stripe.fail["retrieve_invoice"]
    status, out = send(r, ev)
    assert (status, out["outcome"]) == (200, "applied") and status_of(tenancy, org) == "past_due"


def test_unreadable_or_objectless_bodies_are_400(tenancy, stripe):
    r = routes_for(tenancy, stripe)
    for payload in ({"id": "evt_1", "type": "invoice.paid", "data": {}}, {"type": "x"}, [1, 2]):
        body, headers = signed(payload if isinstance(payload, dict) else b"[1,2]")
        assert r.handle("POST", "/v1/billing/webhook", body=body, headers=headers).status == 400
