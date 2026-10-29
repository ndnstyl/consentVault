"""The Stripe webhook: verify, store once, re-fetch the object by id, apply.

Order of events is not trusted. Whatever the event says, the state that decides is the one Stripe holds *now* for the
object's id (the subscription, the invoice, the checkout session), fetched through the injected client. A late
``invoice.paid`` for a subscription that has since been cancelled therefore cannot reactivate the organisation, and a
late ``invoice.payment_failed`` for an invoice that has since been paid cannot make it past due.

The whole handling runs in one transaction with the event row: if the re-fetch or any write fails, the event is not
recorded and the failure goes back to Stripe as a non-2xx so Stripe retries. A replay (same event id) changes nothing.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import psycopg

from . import store
from .errors import WebhookPayloadError
from .signature import verify_signature
from .stripe_client import StripeClient

DEAD = {"canceled", "incomplete_expired"}
LATE = {"past_due", "unpaid"}
ALIVE = {"active", "trialing"}
HANDLED = ("checkout.session.completed", "customer.subscription.updated", "invoice.paid", "invoice.payment_failed",
           "customer.subscription.deleted")


@dataclass(frozen=True)
class WebhookResult:
    event_id: str
    event_type: str
    outcome: str
    replayed: bool
    org_id: uuid.UUID | None = None


def parse_event(payload: bytes) -> dict[str, Any]:
    try:
        event = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise WebhookPayloadError(f"the webhook body is not JSON: {exc}") from exc
    if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not isinstance(event.get("type"), str):
        raise WebhookPayloadError("the webhook body is not a Stripe event (no id or type)")
    obj = ((event.get("data") or {}).get("object")) if isinstance(event.get("data"), dict) else None
    if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
        raise WebhookPayloadError("the webhook event carries no object id to look up")
    return event


def receive(conn: psycopg.Connection, client: StripeClient, *, payload: bytes, signature_header: str | None,
            secret: str, now: float | None = None) -> WebhookResult:
    """Verify the signature, then handle the event. Raises ``WebhookSignatureError`` before anything is stored."""
    verify_signature(payload, signature_header, secret, now=now)
    return handle_event(conn, client, parse_event(payload))


def handle_event(conn: psycopg.Connection, client: StripeClient, event: dict[str, Any]) -> WebhookResult:
    event_id, event_type = event["id"], event["type"]
    with conn.transaction():
        if not store.record_event(conn, event_id, event_type):
            return WebhookResult(event_id, event_type, "replayed", True)
        handler = _HANDLERS.get(event_type)
        if handler is None:
            outcome, org = "ignored_type", None
        else:
            outcome, org = handler(conn, client, event_id, event["data"]["object"]["id"])
        store.finish_event(conn, event_id, org, outcome)
    return WebhookResult(event_id, event_type, outcome, False, org)


# helpers -----------------------------------------------------------------------------------------------------------

def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


def _utc(unix: Any) -> datetime | None:
    return datetime.fromtimestamp(int(unix), timezone.utc) if unix else None


def _customer_id(obj: dict[str, Any]) -> str | None:
    c = obj.get("customer")
    return c.get("id") if isinstance(c, dict) else c


def _subscription_id(obj: dict[str, Any]) -> str | None:
    s = obj.get("subscription")
    if s is None:
        s = (((obj.get("parent") or {}).get("subscription_details")) or {}).get("subscription")
    return s.get("id") if isinstance(s, dict) else s


def _base_item(sub: dict[str, Any]) -> dict[str, Any] | None:
    for item in ((sub.get("items") or {}).get("data")) or []:
        meta = (item.get("price") or {}).get("metadata") or {}
        if meta.get("plan_id") and not meta.get("overage_for"):
            return item
    return None


def _facts(client: StripeClient, sub: dict[str, Any]) -> tuple[store.PlanFacts, datetime | None, datetime | None]:
    item = _base_item(sub)
    if item is None:
        return store.PlanFacts(), _utc(sub.get("current_period_start")), _utc(sub.get("current_period_end"))
    price = client.retrieve_price(item["price"]["id"])
    meta = price.get("metadata") or {}
    product = price.get("product")
    facts = store.PlanFacts(
        price_id=price["id"], plan_id=meta.get("plan_id"),
        plan_name=product.get("name") if isinstance(product, dict) else None,
        included_events=int(meta["included_events"]) if str(meta.get("included_events", "")).isdigit() else None,
        included_gate_checks=(int(meta["included_gate_checks"])
                              if str(meta.get("included_gate_checks", "")).isdigit() else None))
    start = sub.get("current_period_start") or item.get("current_period_start")
    end = sub.get("current_period_end") or item.get("current_period_end")
    return facts, _utc(start), _utc(end)


def _link(conn: psycopg.Connection, client: StripeClient, org: uuid.UUID, customer: str, sub: dict[str, Any] | None
          ) -> None:
    if sub is None:
        store.link_account(conn, org, customer)
        return
    facts, start, end = _facts(client, sub)
    store.link_account(conn, org, customer, subscription=sub["id"], status=sub.get("status"), facts=facts,
                       period_start=start, period_end=end)


def _org_for(conn: psycopg.Connection, client: StripeClient, customer: str | None, hint: uuid.UUID | None
             ) -> uuid.UUID | None:
    """The organisation a Stripe customer belongs to. An unlinked customer is read back from Stripe (the customer
    carries the org id the vault put there) so an event that beats the checkout confirmation is not lost."""
    if not customer:
        return None
    org = store.resolve_org(conn, customer, hint)
    if org is None:
        org = store.resolve_org(conn, customer, _uuid(((client.retrieve_customer(customer)).get("metadata") or {})
                                                      .get("org_id")))
    if org is not None:
        store.link_account(conn, org, customer)
    return org


def _result(applied: str) -> str:
    return "applied" if applied == "changed" else applied


# handlers: (conn, client, event_id, object_id) -> (outcome, org_id) -----------------------------------------------------

def _checkout_completed(conn, client, event_id, object_id):
    session = client.retrieve_checkout_session(object_id)
    if session.get("mode") != "subscription":
        return "ignored_mode", None
    customer = _customer_id(session)
    hint = _uuid(session.get("client_reference_id") or (session.get("metadata") or {}).get("org_id"))
    org = _org_for(conn, client, customer, hint)
    if org is None:
        return "unmatched", None
    sub_id = _subscription_id(session)
    _link(conn, client, org, customer, client.retrieve_subscription(sub_id) if sub_id else None)
    return "linked", org


def _subscription_updated(conn, client, event_id, object_id):
    sub = client.retrieve_subscription(object_id)
    customer = _customer_id(sub)
    org = _org_for(conn, client, customer, _uuid((sub.get("metadata") or {}).get("org_id")))
    if org is None:
        return "unmatched", None
    _link(conn, client, org, customer, sub)
    status = sub.get("status")
    if status in DEAD:
        result = store.apply_status(conn, org, "suspended", "subscription_deleted", event_id)
    elif status in LATE:
        result = store.apply_status(conn, org, "past_due", "payment_failed", event_id)
    elif status in ALIVE:
        result = store.apply_status(conn, org, "active", "invoice_paid", event_id, ["past_due"])
    else:
        result = "unchanged"
    return ("linked" if result == "unchanged" else _result(result)), org


def _invoice_paid(conn, client, event_id, object_id):
    invoice = client.retrieve_invoice(object_id)
    if invoice.get("status") != "paid":
        return "ignored_stale", None
    customer = _customer_id(invoice)
    org = _org_for(conn, client, customer, None)
    if org is None:
        return "unmatched", None
    sub_id = _subscription_id(invoice)
    sub = client.retrieve_subscription(sub_id) if sub_id else None
    if sub is not None and sub.get("status") in DEAD:
        result = store.apply_status(conn, org, "suspended", "subscription_deleted", event_id)
        return ("applied" if result == "changed" else "ignored_stale" if result == "unchanged" else result), org
    if sub is not None:
        _link(conn, client, org, customer, sub)
    return _result(store.apply_status(conn, org, "active", "invoice_paid", event_id)), org


def _invoice_failed(conn, client, event_id, object_id):
    invoice = client.retrieve_invoice(object_id)
    if invoice.get("status") in ("paid", "void"):
        return "ignored_stale", None
    customer = _customer_id(invoice)
    org = _org_for(conn, client, customer, None)
    if org is None:
        return "unmatched", None
    sub_id = _subscription_id(invoice)
    sub = client.retrieve_subscription(sub_id) if sub_id else None
    if sub is not None and sub.get("status") in DEAD:
        result = store.apply_status(conn, org, "suspended", "subscription_deleted", event_id)
        return ("applied" if result == "changed" else "ignored_stale" if result == "unchanged" else result), org
    return _result(store.apply_status(conn, org, "past_due", "payment_failed", event_id)), org


def _subscription_deleted(conn, client, event_id, object_id):
    sub = client.retrieve_subscription(object_id)
    if sub.get("status") not in DEAD:
        return "ignored_stale", None
    customer = _customer_id(sub)
    org = _org_for(conn, client, customer, _uuid((sub.get("metadata") or {}).get("org_id")))
    if org is None:
        return "unmatched", None
    store.link_account(conn, org, customer, subscription=sub["id"], status=sub["status"])
    return _result(store.apply_status(conn, org, "suspended", "subscription_deleted", event_id)), org


_HANDLERS = {
    "checkout.session.completed": _checkout_completed,
    "customer.subscription.updated": _subscription_updated,
    "invoice.paid": _invoice_paid,
    "invoice.payment_failed": _invoice_failed,
    "customer.subscription.deleted": _subscription_deleted,
}
