"""A Stripe stand-in: Stripe-shaped objects held in memory, and a webhook signer. Nothing here touches the network."""

from __future__ import annotations

import copy
import itertools
import json
import time
from typing import Any

from consentvault.billing.errors import StripeRejectedError, StripeUnavailableError
from consentvault.billing.signature import sign_payload

SECRET = "whsec_test_" + "a" * 32
_ids = itertools.count(1)


def new_id(prefix: str) -> str:
    return f"{prefix}_{next(_ids):06d}"


def price(price_id: str, plan_id: str, name: str, amount: int, *, events: int, gates: int, systems: int = 1,
          legal_holds: bool = False, interval: str = "month") -> dict:
    return {"id": price_id, "object": "price", "active": True, "currency": "usd", "unit_amount": amount,
            "recurring": {"interval": interval, "usage_type": "licensed"},
            "metadata": {"plan_id": plan_id, "included_events": str(events), "included_gate_checks": str(gates),
                         "systems": str(systems), "legal_holds": "true" if legal_holds else "false"},
            "product": {"id": f"prod_{plan_id}", "name": name}}


def overage(price_id: str, plan_id: str, meter: str) -> dict:
    return {"id": price_id, "object": "price", "active": True, "currency": "usd", "unit_amount": None,
            "billing_scheme": "tiered", "recurring": {"interval": "month", "usage_type": "metered"},
            "metadata": {"overage_for": plan_id, "meter": meter}, "product": {"id": f"prod_{plan_id}_o", "name": "x"}}


def contract_price(price_id: str, amount: int) -> dict:
    """An Enterprise contract's own Price: no included-volume metadata, the limits ride on the subscription."""
    return {"id": price_id, "object": "price", "active": True, "currency": "usd", "unit_amount": amount,
            "recurring": {"interval": "month", "usage_type": "licensed"}, "metadata": {"plan_id": "enterprise"},
            "product": {"id": "prod_enterprise", "name": "Enterprise"}}


CATALOG = [
    price("price_growth", "growth", "Growth", 49900, events=15000, gates=500000, systems=5, legal_holds=True),
    price("price_growth_annual", "growth", "Growth", 499000, events=15000, gates=500000, systems=5, legal_holds=True,
          interval="year"),
    price("price_starter", "starter", "Starter", 4900, events=1000, gates=25000),
    price("price_starter_annual", "starter", "Starter", 49000, events=1000, gates=25000, interval="year"),
    contract_price("price_enterprise_acme", 250000),
    overage("price_starter_ev", "starter", "events"), overage("price_starter_gc", "starter", "gate_checks"),
    overage("price_growth_ev", "growth", "events"), overage("price_growth_gc", "growth", "gate_checks"),
]


class FakeStripe:
    """Implements the vault's StripeClient interface over dictionaries. ``fail`` makes a named call raise."""

    def __init__(self) -> None:
        self.prices = {p["id"]: copy.deepcopy(p) for p in CATALOG}
        self.subscriptions: dict[str, dict] = {}
        self.invoices: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.customers: dict[str, dict] = {}
        self.calls: list[tuple[str, tuple]] = []
        self.fail: dict[str, Exception] = {}
        self.fail_times: dict[str, int] = {}
        self.meter_events: list[dict] = []
        self.idempotency_seen: dict[str, dict] = {}
        self.checkout_pages: dict[str, dict] = {}
        self.create_delay = 0.0

    # helpers for tests ---------------------------------------------------------------------------------------------
    def count(self, name: str) -> int:
        return sum(1 for c in self.calls if c[0] == name)

    def _enter(self, name: str, *args: Any) -> None:
        self.calls.append((name, args))
        if name in self.fail_times and self.fail_times[name] > 0:
            self.fail_times[name] -= 1
            raise self.fail[name]
        if name in self.fail and name not in self.fail_times:
            raise self.fail[name]

    def add_customer(self, org_id: str | None) -> str:
        cid = new_id("cus")
        self.customers[cid] = {"id": cid, "object": "customer", "metadata": {"org_id": org_id} if org_id else {}}
        return cid

    def add_subscription(self, customer: str, status: str = "active", org_id: str | None = None,
                         price_id: str = "price_starter", contract: dict | None = None) -> str:
        sid = new_id("sub")
        self.subscriptions[sid] = {
            "id": sid, "object": "subscription", "customer": customer, "status": status,
            "metadata": ({"org_id": org_id} if org_id else {}) | (contract or {}),
            "current_period_start": 1_760_000_000, "current_period_end": 1_762_592_000,
            "items": {"data": [{"price": copy.deepcopy(self.prices[price_id])},
                               {"price": copy.deepcopy(self.prices["price_starter_ev"])}]}}
        return sid

    def add_invoice(self, customer: str, subscription: str | None, status: str = "paid") -> str:
        iid = new_id("in")
        self.invoices[iid] = {"id": iid, "object": "invoice", "customer": customer, "subscription": subscription,
                              "status": status}
        return iid

    def add_session(self, customer: str, subscription: str | None, org_id: str | None, mode: str = "subscription") -> str:
        sid = new_id("cs")
        self.sessions[sid] = {"id": sid, "object": "checkout.session", "mode": mode, "customer": customer,
                              "subscription": subscription, "client_reference_id": org_id,
                              "metadata": {"org_id": org_id} if org_id else {}}
        return sid

    # the StripeClient interface ------------------------------------------------------------------------------------
    def retrieve_checkout_session(self, session_id):
        self._enter("retrieve_checkout_session", session_id)
        return copy.deepcopy(self.sessions[session_id])

    def retrieve_subscription(self, subscription_id):
        self._enter("retrieve_subscription", subscription_id)
        return copy.deepcopy(self.subscriptions[subscription_id])

    def retrieve_invoice(self, invoice_id):
        self._enter("retrieve_invoice", invoice_id)
        return copy.deepcopy(self.invoices[invoice_id])

    def retrieve_customer(self, customer_id):
        self._enter("retrieve_customer", customer_id)
        return copy.deepcopy(self.customers[customer_id])

    def list_subscriptions(self, customer):
        self._enter("list_subscriptions", customer)
        return copy.deepcopy([s for s in self.subscriptions.values()
                              if s["customer"] == customer and s["status"] != "canceled"])

    def retrieve_price(self, price_id):
        self._enter("retrieve_price", price_id)
        return copy.deepcopy(self.prices[price_id])

    def list_prices(self):
        self._enter("list_prices")
        return copy.deepcopy(list(self.prices.values()))

    def create_customer(self, *, org_id, idempotency_key):
        self._enter("create_customer", org_id, idempotency_key)
        if idempotency_key in self.idempotency_seen:
            return self.idempotency_seen[idempotency_key]
        cid = self.add_customer(org_id)
        self.idempotency_seen[idempotency_key] = self.customers[cid]
        return self.customers[cid]

    def create_checkout_session(self, *, customer, line_items, org_id, success_url, cancel_url, idempotency_key):
        self._enter("create_checkout_session", customer, line_items, org_id, success_url, cancel_url)
        if self.create_delay:
            time.sleep(self.create_delay)
        page = {"id": new_id("cs"), "url": f"https://checkout.stripe.test/{customer}", "customer": customer,
                "status": "open"}
        self.checkout_pages[page["id"]] = page
        return {"id": page["id"], "url": page["url"]}

    def list_open_checkout_sessions(self, customer):
        self._enter("list_open_checkout_sessions", customer)
        return copy.deepcopy([p for p in self.checkout_pages.values()
                              if p["customer"] == customer and p["status"] == "open"])

    def expire_checkout_session(self, session_id):
        self._enter("expire_checkout_session", session_id)
        self.checkout_pages[session_id]["status"] = "expired"
        return {"id": session_id, "status": "expired"}

    def open_pages(self, customer):
        return [p["id"] for p in self.checkout_pages.values() if p["customer"] == customer and p["status"] == "open"]

    def create_portal_session(self, *, customer, return_url):
        self._enter("create_portal_session", customer, return_url)
        return {"id": new_id("bps"), "url": f"https://billing.stripe.test/{customer}"}

    def create_meter_event(self, *, event_name, customer, value, identifier, timestamp):
        self._enter("create_meter_event", event_name, customer, value, identifier)
        if identifier in {e["identifier"] for e in self.meter_events}:
            raise StripeRejectedError(f"duplicate meter event identifier {identifier}")
        event = {"event_name": event_name, "customer": customer, "value": value, "identifier": identifier,
                 "timestamp": timestamp}
        self.meter_events.append(event)
        return {"object": "billing.meter_event", "identifier": identifier}


def event(event_type: str, object_id: str, object_type: str | None = None) -> dict:
    return {"id": new_id("evt"), "object": "event", "type": event_type, "livemode": False,
            "data": {"object": {"id": object_id, "object": object_type or event_type.split(".")[0]}}}


def signed(payload: dict | bytes, secret: str = SECRET, timestamp: int | None = None) -> tuple[bytes, dict[str, str]]:
    """A request body and its Stripe-Signature header."""
    body = payload if isinstance(payload, bytes) else json.dumps(payload, sort_keys=True).encode("utf-8")
    ts = int(time.time()) if timestamp is None else timestamp
    return body, {"Stripe-Signature": f"t={ts},v1={sign_payload(secret, body, ts)}"}


UNAVAILABLE = StripeUnavailableError("Stripe answered 503: test")
