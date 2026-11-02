"""Portal endpoints: plans, billing summary, checkout, customer portal. Admin only; Stripe errors are named."""

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from consentvault.billing.routes import CANCEL_URL, PORTAL_RETURN_URL, SUCCESS_URL, Caller

from .fakes import UNAVAILABLE
from .helpers import account, link, routes_for, set_status, subscribed


def admin(org) -> Caller:
    return Caller(org.org_id, "admin", "req-1")


def call(r, method, path, org=None, role="admin", body=b""):
    caller = Caller(org.org_id, role, "req-1") if org else None
    return r.handle(method, path, body=body, caller=caller)


def test_plans_come_from_the_stripe_prices_sorted_by_amount_and_enterprise_has_no_list_price(tenancy, stripe):
    res = call(routes_for(tenancy, stripe), "GET", "/v1/billing/plans", tenancy.a)
    assert res.status == 200 and res.payload["next_cursor"] is None
    assert [(p["plan_id"], p["interval"]) for p in res.payload["items"]] == [
        ("starter", "month"), ("starter", "year"), ("growth", "month"), ("growth", "year")]
    assert res.payload["items"][0] == {
        "plan_id": "starter", "name": "Starter", "interval": "month", "unit_amount": 4900, "currency": "usd",
        "included_events": 1000, "included_gate_checks": 25000, "systems": 1, "legal_holds": False}
    growth = res.payload["items"][2]
    assert (growth["unit_amount"], growth["included_events"], growth["included_gate_checks"], growth["systems"],
            growth["legal_holds"]) == (49900, 15000, 500000, 5, True)
    assert [p["unit_amount"] for p in res.payload["items"] if p["interval"] == "year"] == [49000, 499000]
    stripe.prices["price_starter"]["metadata"]["included_events"] = "ten thousand"
    bad = call(routes_for(tenancy, stripe, alarm=lambda name, detail: None), "GET", "/v1/billing/plans", tenancy.a)
    assert bad.status == 200  # the one malformed Price is dropped by name; the rest of the list stands
    assert ("starter", "month") not in [(p["plan_id"], p["interval"]) for p in bad.payload["items"]]


@pytest.mark.parametrize("role", ["developer", "compliance_viewer", "operator", "member"])
@pytest.mark.parametrize("method,path", [("GET", "/v1/billing/plans"), ("GET", "/v1/billing"),
                                         ("POST", "/v1/billing/checkout"), ("POST", "/v1/billing/portal")])
def test_every_role_but_admin_is_refused(tenancy, stripe, role, method, path):
    res = call(routes_for(tenancy, stripe), method, path, tenancy.a, role=role, body=b'{"plan_id":"starter"}')
    assert res.status == 403 and res.payload["error"] == "role_not_allowed" and res.payload["fields"] == {"role": role}
    assert stripe.calls == []


def test_no_session_is_unauthenticated(tenancy, stripe):
    res = call(routes_for(tenancy, stripe), "GET", "/v1/billing")
    assert res.status == 401 and res.payload["error"] == "unauthenticated"


def test_unknown_billing_path_is_not_found(tenancy, stripe):
    assert call(routes_for(tenancy, stripe), "GET", "/v1/billing/nope", tenancy.a).status == 404
    assert not routes_for(tenancy, stripe).handles("DELETE", "/v1/billing")


def test_summary_for_a_trial_org_has_no_plan_and_no_usage(tenancy, stripe):
    set_status(tenancy, tenancy.a, "trial")
    res = call(routes_for(tenancy, stripe), "GET", "/v1/billing", tenancy.a)
    assert res.status == 200 and res.payload == {"status": "trial", "past_due_since": None, "plan": None,
                                                  "period": None, "included": None, "used": None,
                                                  "last_reported_at": None}


def test_summary_reports_plan_period_inclusions_and_usage_against_them(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    now = datetime.now(timezone.utc)
    start, end = now - timedelta(days=10), now + timedelta(days=20)
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, 'price_starter', 'active', 'starter',"
                    " 'Starter', 1000, 25000, %s, %s)", (org.org_id, cus, sub, start, end))
    with tenancy.superuser() as su:
        for i, (ev, gc) in enumerate([(120, 2400), (80, 1600)]):
            su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks, reported_at)"
                       " VALUES (%s, %s, %s, %s, now())", (org.org_id, (now - timedelta(days=2 + i)).date(), ev, gc))
        su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks)"
                   " VALUES (%s, %s, 5000, 99999)", (tenancy.b.org_id, (now - timedelta(days=2)).date()))
    res = call(routes_for(tenancy, stripe), "GET", "/v1/billing", org)
    assert res.status == 200
    p = res.payload
    assert p["status"] == "active" and p["plan"] == {"plan_id": "starter", "name": "Starter", "contract_pending": False}
    assert p["included"] == {"events": 1000, "gate_checks": 25000}
    assert p["used"] == {"events": 200, "gate_checks": 4000}  # organisation B's 5000 never appears
    assert p["period"]["start"].endswith("Z") and p["last_reported_at"].endswith("Z")


def test_an_unread_gate_count_is_null_never_zero(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    now = datetime.now(timezone.utc)
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, 'price_starter', 'active', 'starter',"
                    " 'Starter', 1000, 25000, %s, %s)",
                    (org.org_id, cus, sub, now - timedelta(days=5), now + timedelta(days=25)))
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (%s, %s, 70, NULL)",
                   (org.org_id, (now - timedelta(days=1)).date()))
    used = call(routes_for(tenancy, stripe), "GET", "/v1/billing", org).payload["used"]
    assert used == {"events": 70, "gate_checks": None}


def test_checkout_creates_the_customer_with_the_org_id_and_returns_the_hosted_url(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "trial")
    r = routes_for(tenancy, stripe)
    res = call(r, "POST", "/v1/billing/checkout", org, body=json.dumps({"plan_id": "growth"}).encode())
    assert res.status == 201 and res.payload["checkout_url"].startswith("https://checkout.stripe.test/cus_")
    row = account(tenancy, org)
    assert row["stripe_customer_id"] in stripe.customers and row["stripe_subscription_id"] is None
    assert stripe.customers[row["stripe_customer_id"]]["metadata"] == {"org_id": str(org.org_id)}
    name, args = [c for c in stripe.calls if c[0] == "create_checkout_session"][0]
    customer, items, org_id, success, cancel = args
    assert (success, cancel, org_id) == (SUCCESS_URL, CANCEL_URL, str(org.org_id))
    assert items == [{"price": "price_growth", "quantity": 1}, {"price": "price_growth_ev"},
                     {"price": "price_growth_gc"}]
    call(r, "POST", "/v1/billing/checkout", org, body=json.dumps({"plan_id": "starter"}).encode())
    assert stripe.count("create_customer") == 1  # the second checkout reuses the linked customer


def test_annual_checkout_uses_the_annual_price_with_the_same_overage_prices(tenancy, stripe):
    org = tenancy.a
    set_status(tenancy, org, "trial")
    res = call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", org,
               body=json.dumps({"plan_id": "starter", "interval": "year"}).encode())
    assert res.status == 201
    items = [c for c in stripe.calls if c[0] == "create_checkout_session"][0][1][1]
    assert items == [{"price": "price_starter_annual", "quantity": 1}, {"price": "price_starter_ev"},
                     {"price": "price_starter_gc"}]
    bad = call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", tenancy.b,
               body=json.dumps({"plan_id": "starter", "interval": "week"}).encode())
    assert bad.status == 422 and bad.payload["error"] == "validation_failed"


def test_enterprise_cannot_be_bought_at_checkout_it_is_by_consultation(tenancy, stripe):
    res = call(routes_for(tenancy, stripe), "POST", "/v1/billing/checkout", tenancy.a,
               body=b'{"plan_id":"enterprise"}')
    assert res.status == 404 and res.payload["error"] == "not_found"
    assert stripe.count("create_checkout_session") == 0


def test_checkout_refuses_a_second_subscription_an_unknown_plan_and_a_bad_body(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub, "active")
    r = routes_for(tenancy, stripe)
    res = call(r, "POST", "/v1/billing/checkout", org, body=b'{"plan_id":"starter"}')
    assert res.status == 409 and res.payload["error"] == "already_subscribed"
    other = tenancy.b
    assert call(r, "POST", "/v1/billing/checkout", other, body=b'{"plan_id":"platinum"}').payload["error"] == "not_found"
    for bad in (b"", b"{}", b'{"plan_id": 7}', b"not json"):
        res = call(r, "POST", "/v1/billing/checkout", other, body=bad)
        assert res.status == 422 and res.payload["error"] == "validation_failed"


def test_a_suspended_org_may_subscribe_again_but_an_offboarding_one_may_not(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="canceled")
    link(tenancy, org, cus, sub, "canceled")
    set_status(tenancy, org, "suspended")
    r = routes_for(tenancy, stripe)
    assert call(r, "POST", "/v1/billing/checkout", org, body=b'{"plan_id":"starter"}').status == 201
    set_status(tenancy, org, "offboarding")
    res = call(r, "POST", "/v1/billing/checkout", org, body=b'{"plan_id":"starter"}')
    assert res.status == 403 and res.payload["error"] == "org_not_active"


def test_portal_needs_a_customer_then_opens_the_stripe_portal(tenancy, stripe):
    org = tenancy.a
    r = routes_for(tenancy, stripe)
    res = call(r, "POST", "/v1/billing/portal", org)
    assert res.status == 404 and res.payload["error"] == "not_found"
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub, "active")
    res = call(r, "POST", "/v1/billing/portal", org)
    assert res.status == 201 and res.payload == {"portal_url": f"https://billing.stripe.test/{cus}"}
    assert [c for c in stripe.calls if c[0] == "create_portal_session"][0][1] == (cus, PORTAL_RETURN_URL)


@pytest.mark.parametrize("name,method,path,body", [
    ("list_prices", "GET", "/v1/billing/plans", b""),
    ("list_prices", "POST", "/v1/billing/checkout", b'{"plan_id":"starter"}'),
    ("create_portal_session", "POST", "/v1/billing/portal", b"")])
def test_stripe_down_is_502_stripe_unavailable_and_nothing_is_charged(tenancy, stripe, name, method, path, body):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub, "canceled")
    stripe.fail[name] = UNAVAILABLE
    res = call(routes_for(tenancy, stripe), method, path, org, body=body)
    assert res.status == 502 and res.payload["error"] == "stripe_unavailable"
    assert stripe.count("create_checkout_session") == 0
    assert res.payload["request_id"] == "req-1"


def test_summary_names_the_day_the_payment_failure_made_the_org_past_due(tenancy, stripe):
    set_status(tenancy, tenancy.a, "active")
    assert call(routes_for(tenancy, stripe), "GET", "/v1/billing", tenancy.a).payload["past_due_since"] is None
    set_status(tenancy, tenancy.a, "past_due")
    since = call(routes_for(tenancy, stripe), "GET", "/v1/billing", tenancy.a).payload["past_due_since"]
    assert since is not None and since.endswith("Z")
    assert abs(datetime.fromisoformat(since.replace("Z", "+00:00")) - datetime.now(timezone.utc)) < timedelta(minutes=5)
    set_status(tenancy, tenancy.a, "active")  # paid again: no failure date to show
    assert call(routes_for(tenancy, stripe), "GET", "/v1/billing", tenancy.a).payload["past_due_since"] is None
    assert call(routes_for(tenancy, stripe), "GET", "/v1/billing", tenancy.b).payload["past_due_since"] is None
