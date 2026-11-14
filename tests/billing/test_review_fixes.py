"""Fixes from the review of the Enterprise billing change: alarms inside the webhook transaction, the usage job on the
plan of record with held-back days reported once the contract completes, one bad Price never empties the catalog,
whole-number parsing that refuses superscripts, the summary never naming the internal plan, and the Enterprise free
tier checked against the contract."""

from datetime import datetime, timedelta, timezone

import pytest

from consentvault.alarms import AlarmWriteError
from consentvault.billing import routes as routes_mod
from consentvault.billing import webhook
from consentvault.billing.errors import UsageReportError
from consentvault.billing.usage import closed_day, idempotency_key, run_daily_usage

from .fakes import UNAVAILABLE, event
from .helpers import account, link, outcomes, routes_for, send, subscribed
from .test_routes import call
from .test_usage import Alarms, backdate_events, gates, usage_rows, worker_conn

YESTERDAY = closed_day()


def alarm_names(tenancy, org):
    with tenancy.superuser() as su:
        return [r["name"] for r in su.execute("SELECT name FROM consentvault.operator_alarm WHERE org_id = %s"
                                              " ORDER BY name", (org.org_id,)).fetchall()]


def link_plan(tenancy, org, cus, sub, plan_id, events=None, gates_=None, start=None):
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, 'price_enterprise_acme', 'active', %s,"
                    " 'Enterprise', %s, %s, %s, %s)",
                    (org.org_id, cus, sub, plan_id, events, gates_, start, start + timedelta(days=30) if start else None))


# the incomplete-contract alarm is written inside the webhook's transaction ----------------------------------------------

def test_an_alarm_that_cannot_be_written_rolls_the_event_back_and_the_redelivery_writes_exactly_one(
        tenancy, stripe, monkeypatch):
    org = tenancy.a
    cus, sub = subscribed(stripe, org, status="active", price_id="price_enterprise_acme")
    session = stripe.add_session(cus, sub, str(org.org_id))
    real, tries = routes_mod.raise_operator_alarm, []

    def flaky(*a, **kw):
        tries.append(kw["name"])
        if len(tries) == 1:
            raise AlarmWriteError("injected: the alarm row could not be written")
        return real(*a, **kw)

    monkeypatch.setattr(routes_mod, "raise_operator_alarm", flaky)
    r = routes_for(tenancy, stripe)
    payload = event("checkout.session.completed", session, "checkout.session")
    status, body = send(r, payload)
    assert (status, body["error"]) == (503, "service_unavailable")
    assert account(tenancy, org) is None and "linked" not in outcomes(tenancy)  # nothing kept: Stripe will redeliver
    status, body = send(r, payload)
    assert (status, body["outcome"], body["replayed"]) == (200, "linked", False)
    assert alarm_names(tenancy, org) == ["billing.enterprise_contract_incomplete"]
    status, body = send(r, payload)  # a further redelivery is a replay and writes nothing
    assert body["replayed"] is True and alarm_names(tenancy, org) == ["billing.enterprise_contract_incomplete"]


# the usage job reads the plan of record, and reports the days an incomplete contract held back ---------------------------

def test_the_usage_job_never_reads_a_live_subscription(tenancy, stripe, pg_server):
    backdate_events(tenancy, tenancy.a, YESTERDAY, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    stripe.fail["retrieve_subscription"] = UNAVAILABLE
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    assert stripe.count("retrieve_subscription") == 0
    assert [e["value"] for e in stripe.meter_events if e["customer"] == cus and e["event_name"].endswith("events")] == [2]


def test_days_held_back_by_an_incomplete_contract_are_reported_once_it_completes(tenancy, stripe, pg_server):
    day1, day2 = YESTERDAY - timedelta(days=1), YESTERDAY
    backdate_events(tenancy, tenancy.a, day1, 2, first_seq=1000)
    backdate_events(tenancy, tenancy.a, day2, 3, first_seq=2000)
    cus = stripe.add_customer(str(tenancy.a.org_id))
    sub = stripe.add_subscription(cus, "active", str(tenancy.a.org_id), "price_enterprise_acme")
    start = datetime.combine(day1, datetime.min.time(), timezone.utc) - timedelta(days=3)
    link_plan(tenancy, tenancy.a, cus, sub, "enterprise_contract_incomplete", start=start)
    with worker_conn(tenancy, pg_server) as w:
        with pytest.raises(UsageReportError, match="enterprise contract"):
            run_daily_usage(w, stripe, day1, gate_counter=gates(4), alarm=Alarms(), sleep=lambda s: None)
    assert [e for e in stripe.meter_events if e["customer"] == cus] == []
    link_plan(tenancy, tenancy.a, cus, sub, "enterprise", 250000, 9000000, start=start)
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, day2, gate_counter=gates(5), alarm=Alarms(), sleep=lambda s: None)
    sent = {e["identifier"]: e["value"] for e in stripe.meter_events if e["customer"] == cus}
    assert sent == {idempotency_key(tenancy.a.org_id, day1, "events"): 2,
                    idempotency_key(tenancy.a.org_id, day1, "gate_checks"): 4,
                    idempotency_key(tenancy.a.org_id, day2, "events"): 3,
                    idempotency_key(tenancy.a.org_id, day2, "gate_checks"): 5}
    assert all(r["reported_at"] is not None for r in usage_rows(tenancy, tenancy.a))


def test_held_back_days_before_the_current_period_are_not_reported_into_it(tenancy, stripe, pg_server):
    old = YESTERDAY - timedelta(days=5)
    backdate_events(tenancy, tenancy.a, old, 2, first_seq=1000)
    cus = stripe.add_customer(str(tenancy.a.org_id))
    sub = stripe.add_subscription(cus, "active", str(tenancy.a.org_id), "price_enterprise_acme")
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError):
        link_plan(tenancy, tenancy.a, cus, sub, "enterprise_contract_incomplete")
        run_daily_usage(w, stripe, old, gate_counter=gates(1), alarm=Alarms(), sleep=lambda s: None)
    start = datetime.combine(YESTERDAY, datetime.min.time(), timezone.utc)
    link_plan(tenancy, tenancy.a, cus, sub, "enterprise", 10, 10, start=start)
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="abandoned"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=gates(1), alarm=alarms, sleep=lambda s: None)
    assert not any(e["identifier"].startswith(f"{tenancy.a.org_id}:{old.isoformat()}") for e in stripe.meter_events)
    assert any(n == "usage_day_abandoned" and old.isoformat() in d for n, d in alarms.raised)  # named, never silent


# one Price with bad metadata is dropped by name; the rest of the catalog stands --------------------------------------

def test_a_price_missing_metadata_is_dropped_with_a_named_alarm_and_the_list_still_answers(tenancy, stripe):
    del stripe.prices["price_growth"]["metadata"]["systems"]
    stripe.prices["price_growth_ev"]["metadata"]["meter"] = "minutes"
    alarms = Alarms()
    res = call(routes_for(tenancy, stripe, alarm=alarms), "GET", "/v1/billing/plans", tenancy.a)
    assert res.status == 200
    got = {(p["plan_id"], p["interval"]) for p in res.payload["items"]}
    assert got == {("starter", "month"), ("starter", "year")}  # growth lost its base Price and an overage: off sale
    assert alarms.names.count("billing.plan_price_invalid") == 2
    assert any(n == "billing.plan_off_sale" and "growth" in d for n, d in alarms.raised)
    assert any("price_growth " in d and "systems" in d for _, d in alarms.raised)
    assert any("price_growth_ev" in d for _, d in alarms.raised)


# whole numbers are ASCII digits only ---------------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["1²", "²", "٣", "250000\n", " 5"])
def test_a_contract_volume_that_is_not_ascii_digits_is_incomplete_never_a_crash(tenancy, stripe, value):
    org = tenancy.a
    contract = {"contract_included_events": value, "contract_included_gate_checks": "9000000"}
    cus, sub = subscribed(stripe, org, status="active", price_id="price_enterprise_acme", contract=contract)
    assert webhook.contract_incomplete(stripe.subscriptions[sub]) is True
    session = stripe.add_session(cus, sub, str(org.org_id))
    status, body = send(routes_for(tenancy, stripe), event("checkout.session.completed", session, "checkout.session"))
    assert (status, body["outcome"]) == (200, "linked")
    assert account(tenancy, org)["plan_id"] == "enterprise_contract_incomplete"


# the summary shows the Enterprise plan with a pending flag, never the internal name -----------------------------------

def test_the_summary_names_enterprise_with_a_contract_pending_flag(tenancy, stripe):
    cus, sub = subscribed(stripe, tenancy.a, price_id="price_enterprise_acme")
    link_plan(tenancy, tenancy.a, cus, sub, "enterprise_contract_incomplete")
    res = call(routes_for(tenancy, stripe), "GET", "/v1/billing", tenancy.a)
    assert res.payload["plan"] == {"plan_id": "enterprise", "name": "Enterprise", "contract_pending": True}
    assert "enterprise_contract_incomplete" not in str(res.payload)


# the Enterprise free tier must equal the contract's included volume ---------------------------------------------------

def _enterprise_overage(stripe, meter, free_up_to):
    pid = f"price_ent_{meter}"
    stripe.prices[pid] = {"id": pid, "object": "price", "active": True, "currency": "usd", "unit_amount": None,
                          "billing_scheme": "tiered", "tiers_mode": "graduated",
                          "recurring": {"interval": "month", "usage_type": "metered"},
                          "tiers": [{"up_to": free_up_to, "unit_amount": 0},
                                    {"up_to": None, "unit_amount_decimal": "2"}],
                          "metadata": {"overage_for": "enterprise", "meter": meter},
                          "product": {"id": "prod_enterprise_o", "name": "Enterprise overage"}}
    return pid


def _enterprise_sub(stripe, org, free_events, free_gates):
    contract = {"contract_included_events": "250000", "contract_included_gate_checks": "9000000"}
    cus, sub = subscribed(stripe, org, status="active", price_id="price_enterprise_acme", contract=contract)
    items = [{"price": dict(stripe.prices["price_enterprise_acme"])}]
    for meter, free in (("events", free_events), ("gate_checks", free_gates)):
        if free is not None:
            items.append({"price": dict(stripe.prices[_enterprise_overage(stripe, meter, free)])})
    stripe.subscriptions[sub]["items"]["data"] = items
    return cus, sub


@pytest.mark.parametrize("free_events,free_gates,mismatch", [
    (250000, 9000000, False), (250000, 1000, True), (1, 9000000, True), (250000, None, True)])
def test_an_enterprise_free_tier_that_disagrees_with_the_contract_alarms(tenancy, stripe, free_events, free_gates,
                                                                         mismatch):
    org = tenancy.a
    cus, sub = _enterprise_sub(stripe, org, free_events, free_gates)
    session = stripe.add_session(cus, sub, str(org.org_id))
    status, body = send(routes_for(tenancy, stripe), event("checkout.session.completed", session, "checkout.session"))
    assert (status, body["outcome"]) == (200, "linked")
    assert account(tenancy, org)["plan_id"] == "enterprise"
    assert ("billing.enterprise_contract_mismatch" in alarm_names(tenancy, org)) is mismatch
