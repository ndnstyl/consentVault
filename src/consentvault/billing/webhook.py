"""The Stripe webhook: verify, store once, re-fetch the object by id, apply.

Order of events is not trusted. Whatever the event says, the state that decides is the one Stripe holds *now* for the
object's id (the subscription, the invoice, the checkout session), fetched through the injected client. A late
``invoice.paid`` for a subscription that has since been cancelled therefore cannot reactivate the organisation, and a
late ``invoice.payment_failed`` for an invoice that has since been paid cannot make it past due.

The whole handling runs in one transaction with the event row: if the re-fetch or any write fails, the event is not
recorded and the failure goes back to Stripe as a non-2xx so Stripe retries. A replay (same event id) changes nothing.
"""

from __future__ import annotations

import contextvars
import json
from ..safelog import describe
from .. import safelog
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import psycopg

from . import store
from .errors import WebhookPayloadError
from .plans import (ALARM_ENTERPRISE_MISMATCH, ALARM_SECOND_SUBSCRIPTION, ENTERPRISE, ENTERPRISE_INCOMPLETE,
                    METERS)
from .signature import verify_signature
from .stripe_client import StripeClient

_log = safelog.get(__name__)
DEAD = {"canceled", "incomplete_expired"}
LATE = {"past_due", "unpaid"}
ALIVE = {"active", "trialing"}
IGNORED_SECOND = "ignored_second_subscription"
LIVE = ALIVE | LATE | {"paused"}  # a subscription in force: the same set the checkout route refuses a second one for
HANDLED = ("checkout.session.completed", "customer.subscription.updated", "invoice.paid", "invoice.payment_failed",
           "customer.subscription.deleted")


@dataclass(frozen=True)
class WebhookResult:
    event_id: str
    event_type: str
    outcome: str
    replayed: bool
    org_id: uuid.UUID | None = None
    alarms: tuple[str, ...] = ()  # operator alarms the handling found (also handed to ``after`` inside the transaction)


# Called inside the event's transaction, after the event row is finished: (conn, org_id, alarm names). Whatever it writes
# commits with the event, and if it raises, the event is not recorded and Stripe redelivers it.
After = Callable[[psycopg.Connection, uuid.UUID, tuple[str, ...]], None]
_ALARMS: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar("billing_webhook_alarms", default=None)
_WHOLE = re.compile(r"[0-9]+")


def whole_number(value: Any) -> int | None:
    """A whole number written in ASCII digits only, else None (``str.isdigit`` passes superscripts and other scripts)."""
    text = value if isinstance(value, str) else str(value) if isinstance(value, int) and not isinstance(value, bool) else ""
    return int(text) if _WHOLE.fullmatch(text) else None


def _note_alarm(name: str) -> None:
    held = _ALARMS.get()
    if held is None:
        raise RuntimeError(f"operator alarm {name!r} raised outside handle_event; it would be lost")
    if name not in held:
        held.append(name)


def parse_event(payload: bytes) -> dict[str, Any]:
    try:
        event = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise WebhookPayloadError(f"the webhook body is not JSON: {describe(exc)}") from exc
    if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not isinstance(event.get("type"), str):
        raise WebhookPayloadError("the webhook body is not a Stripe event (no id or type)")
    obj = ((event.get("data") or {}).get("object")) if isinstance(event.get("data"), dict) else None
    if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
        raise WebhookPayloadError("the webhook event carries no object id to look up")
    return event


def receive(conn: psycopg.Connection, client: StripeClient, *, payload: bytes, signature_header: str | None,
            secret: str, now: float | None = None, after: After | None = None) -> WebhookResult:
    """Verify the signature, then handle the event. Raises ``WebhookSignatureError`` before anything is stored."""
    verify_signature(payload, signature_header, secret, now=now)
    return handle_event(conn, client, parse_event(payload), after=after)


def handle_event(conn: psycopg.Connection, client: StripeClient, event: dict[str, Any], *,
                 after: After | None = None) -> WebhookResult:
    event_id, event_type = event["id"], event["type"]
    alarms: list[str] = []
    token = _ALARMS.set(alarms)
    try:
        with conn.transaction():
            if not store.record_event(conn, event_id, event_type):
                return WebhookResult(event_id, event_type, "replayed", True)
            handler = _HANDLERS.get(event_type)
            if handler is None:
                outcome, org = "ignored_type", None
            else:
                outcome, org = handler(conn, client, event_id, event["data"]["object"]["id"])
            store.finish_event(conn, event_id, org, outcome)
            if after is not None and org is not None:
                after(conn, org, tuple(alarms))
    finally:
        _ALARMS.reset(token)
    return WebhookResult(event_id, event_type, outcome, False, org, tuple(alarms))


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


def contract_incomplete(sub: dict[str, Any]) -> bool:
    """True for an Enterprise subscription whose contract metadata lacks a whole-number event or gate-check volume."""
    item = _base_item(sub)
    if item is None or (item["price"].get("metadata") or {}).get("plan_id") != ENTERPRISE:
        return False
    contract = sub.get("metadata") or {}
    return (whole_number(contract.get("contract_included_events")) is None
            or whole_number(contract.get("contract_included_gate_checks")) is None)


def _free_tier(price: dict[str, Any]) -> int | None:
    """The free first tier of a graduated overage Price (``up_to`` with a zero amount), else None."""
    tiers = price.get("tiers") or []
    if price.get("tiers_mode") != "graduated" or not tiers or not isinstance(tiers[0], dict):
        return None
    first = tiers[0]
    if first.get("flat_amount") not in (0, None) or str(first.get("flat_amount_decimal") or "0") not in ("0", "0.0"):
        return None
    if first.get("unit_amount") not in (0, None) or str(first.get("unit_amount_decimal") or "0") not in ("0", "0.0"):
        return None
    return whole_number(first.get("up_to"))


def _check_enterprise_free_tiers(client: StripeClient, sub: dict[str, Any], included: dict[str, int]) -> None:
    """Each meter's overage Price must give exactly the contract's included volume free; otherwise alarm by name."""
    seen: dict[str, int | None] = {}
    for item in ((sub.get("items") or {}).get("data")) or []:
        meta = (item.get("price") or {}).get("metadata") or {}
        if meta.get("overage_for") and meta.get("meter") in METERS:
            seen[meta["meter"]] = _free_tier(client.retrieve_price(item["price"]["id"]))
    if any(seen.get(m) != included[m] for m in METERS):
        _note_alarm(ALARM_ENTERPRISE_MISMATCH)


def _price_set(sub: dict[str, Any]) -> str | None:
    """Every price on the subscription, base and overage, sorted and comma-joined: a swap of any one of them shows."""
    ids = sorted(str((item.get("price") or {}).get("id")) for item in ((sub.get("items") or {}).get("data")) or []
                 if (item.get("price") or {}).get("id"))
    return ",".join(ids) or None


def _facts(client: StripeClient, sub: dict[str, Any]) -> tuple[store.PlanFacts, datetime | None, datetime | None]:
    item = _base_item(sub)
    if item is None:
        return store.PlanFacts(), _utc(sub.get("current_period_start")), _utc(sub.get("current_period_end"))
    price = client.retrieve_price(item["price"]["id"])
    meta = price.get("metadata") or {}
    if meta.get("plan_id") == ENTERPRISE:
        contract = sub.get("metadata") or {}
        events = whole_number(contract.get("contract_included_events"))
        gates = whole_number(contract.get("contract_included_gate_checks"))
        if events is None or gates is None:
            return (store.PlanFacts(price_id=price["id"], plan_id=ENTERPRISE_INCOMPLETE,
                                    plan_name=(price.get("product") or {}).get("name"), price_set=_price_set(sub)),
                    _utc(sub.get("current_period_start") or item.get("current_period_start")),
                    _utc(sub.get("current_period_end") or item.get("current_period_end")))
        _check_enterprise_free_tiers(client, sub, {"events": events, "gate_checks": gates})
        meta = {**meta, "included_events": str(events), "included_gate_checks": str(gates)}
    product = price.get("product")
    facts = store.PlanFacts(
        price_id=price["id"], plan_id=meta.get("plan_id"),
        plan_name=product.get("name") if isinstance(product, dict) else None,
        included_events=whole_number(meta.get("included_events")),
        included_gate_checks=whole_number(meta.get("included_gate_checks")), price_set=_price_set(sub))
    start = sub.get("current_period_start") or item.get("current_period_start")
    end = sub.get("current_period_end") or item.get("current_period_end")
    return facts, _utc(start), _utc(end)


def _ignore_foreign(conn: psycopg.Connection, org: uuid.UUID, sub: dict[str, Any], by: str) -> bool:
    """True when ``sub`` is not the subscription the vault stores while the stored one is in force: the stored one stays
    whatever happens to ``sub``. A second live subscription raises the duplicate alarm; one that has ended (or never
    started) is only logged, and clears the duplicate alarm, since the duplicate is gone."""
    held_id, held_status = store.held_subscription(conn, org)
    if not (held_id and held_id != sub["id"] and held_status in LIVE):
        return False
    status = sub.get("status")
    if status in LIVE:
        _note_alarm(ALARM_SECOND_SUBSCRIPTION)
    else:
        cleared = store.clear_alarm(conn, org, ALARM_SECOND_SUBSCRIPTION, by)
        _log.info("ignored a subscription that is not the stored one for the organisation; duplicate alarms cleared",
                  status=status, subscription_id=sub["id"], org_id=org, cleared=cleared)
    return True


def _link(conn: psycopg.Connection, client: StripeClient, org: uuid.UUID, customer: str, sub: dict[str, Any] | None,
          by: str = "stripe:webhook") -> bool:
    """Link the subscription to the organisation. False when it was left out because it is not the stored one."""
    if sub is None:
        store.link_account(conn, org, customer)
        return True
    if _ignore_foreign(conn, org, sub, by):
        store.link_account(conn, org, customer)
        return False
    held_id, _held_status = store.held_subscription(conn, org)
    facts, start, end = _facts(client, sub)
    store.link_account(conn, org, customer, subscription=sub["id"], status=sub.get("status"), facts=facts,
                       period_start=start, period_end=end)
    if held_id and held_id != sub["id"]:  # the stored one had ended and this one is adopted: no duplicate remains
        store.clear_alarm(conn, org, ALARM_SECOND_SUBSCRIPTION, by)
        _log.info("adopted a subscription for the organisation after the held one ended", subscription_id=sub["id"], org_id=org,
                  held_subscription_id=held_id)
    return True


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
    linked = _link(conn, client, org, customer, client.retrieve_subscription(sub_id) if sub_id else None,
                   f"stripe:{event_id}")
    return ("linked" if linked else IGNORED_SECOND), org


def _subscription_updated(conn, client, event_id, object_id):
    sub = client.retrieve_subscription(object_id)
    customer = _customer_id(sub)
    org = _org_for(conn, client, customer, _uuid((sub.get("metadata") or {}).get("org_id")))
    if org is None:
        return "unmatched", None
    held_id, _held_status = store.held_subscription(conn, org)
    adopted = bool(held_id) and held_id != sub["id"]  # the stored one ended and this one takes its place
    if not _link(conn, client, org, customer, sub, f"stripe:{event_id}"):
        return IGNORED_SECOND, org
    status = sub.get("status")
    if status in DEAD:
        result = store.apply_status(conn, org, "suspended", "subscription_deleted", event_id)
    elif status in LATE:
        result = store.apply_status(conn, org, "past_due", "payment_failed", event_id)
    elif status in ALIVE:
        result = store.apply_status(conn, org, "active", "invoice_paid", event_id, None if adopted else ["past_due"])
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
    if not sub_id:  # a one-off invoice says nothing about the subscription: it never lifts a cancellation
        return "ignored_no_subscription", org
    sub = client.retrieve_subscription(sub_id)
    if sub is not None and _ignore_foreign(conn, org, sub, f"stripe:{event_id}"):
        return IGNORED_SECOND, org
    if sub is not None and sub.get("status") in DEAD:
        result = store.apply_status(conn, org, "suspended", "subscription_deleted", event_id)
        return ("applied" if result == "changed" else "ignored_stale" if result == "unchanged" else result), org
    if sub is not None and not _link(conn, client, org, customer, sub, f"stripe:{event_id}"):
        return IGNORED_SECOND, org
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
    if not sub_id:  # a failed one-off invoice says nothing about the subscription: it never makes the org past due
        return "ignored_no_subscription", org
    sub = client.retrieve_subscription(sub_id)
    if sub is not None and _ignore_foreign(conn, org, sub, f"stripe:{event_id}"):
        return IGNORED_SECOND, org
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
    if _ignore_foreign(conn, org, sub, f"stripe:{event_id}"):
        store.link_account(conn, org, customer)
        return IGNORED_SECOND, org
    store.link_account(conn, org, customer, subscription=sub["id"], status=sub["status"])
    return _result(store.apply_status(conn, org, "suspended", "subscription_deleted", event_id)), org


_HANDLERS = {
    "checkout.session.completed": _checkout_completed,
    "customer.subscription.updated": _subscription_updated,
    "invoice.paid": _invoice_paid,
    "invoice.payment_failed": _invoice_failed,
    "customer.subscription.deleted": _subscription_deleted,
}
