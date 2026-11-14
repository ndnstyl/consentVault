"""Billing routes (contracts/billing.md), written as plain functions so the API router registers them in one line.

``BillingRoutes.handle(method, path, ...)`` answers with a ``Response(status, payload)``; it never writes to a socket
and never reads a header the router did not hand it. The router authenticates the portal session first and passes the
``Caller`` (organisation id and role, never taken from a path or body); the webhook is the one route with no caller:
its authority is the Stripe signature.

Every error is a name from contracts/README.md section 5. Capture is never touched here: nothing in this module can
refuse an event for non-payment.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Callable, Mapping

import psycopg

from ..safelog import caller_detail
from ..alarms import AlarmWriteError, raise_operator_alarm
from ..tenancy.errors import TenantTokenError
from ..tenancy.tokens import org_transaction
from . import store, webhook
from .errors import (AlreadySubscribedError, NotSubscribedError, OrgNotActiveError, PlanCatalogError,
                     PlanNotFoundError, RoleNotAllowedError, StripeRejectedError, StripeUnavailableError,
                     WebhookPayloadError, WebhookSignatureError)
from .plans import ALARM_ENTERPRISE_INCOMPLETE, ALARM_SECOND_SUBSCRIPTION, ENTERPRISE, ENTERPRISE_INCOMPLETE, INTERVALS, catalog, find_plan
from .stripe_client import StripeClient

SUCCESS_URL = "https://app.consentvault.ai/billing/return?result=success"
CANCEL_URL = "https://app.consentvault.ai/billing/return?result=cancel"
PORTAL_RETURN_URL = "https://app.consentvault.ai/billing"
SUBSCRIPTION_IN_FORCE = {"active", "trialing", "past_due", "unpaid", "paused"}
BILLING_SCOPES = ("billing",)
# The checkout lock is held across the Stripe calls so two pages for one customer are made one after the other. Each
# Stripe call carries its own timeout (stripe_client.TIMEOUT_SECONDS), so the hold is bounded by a few of those; a
# second request waits at most this long, then answers 503 so the caller retries instead of queueing without end.
CHECKOUT_LOCK_TIMEOUT_MS = 15000

ROUTES = {("GET", "/v1/billing/plans"), ("GET", "/v1/billing"), ("POST", "/v1/billing/checkout"),
          ("POST", "/v1/billing/portal"), ("POST", "/v1/billing/webhook")}


@dataclass(frozen=True)
class Caller:
    org_id: uuid.UUID
    role: str
    request_id: str = ""
    member_id: str = ""


@dataclass(frozen=True)
class Response:
    status: int
    payload: dict[str, Any]


def error(status: int, name: str, detail: str, request_id: str = "", fields: dict[str, Any] | None = None) -> Response:
    body: dict[str, Any] = {"error": name, "detail": detail, "request_id": request_id}
    if fields:
        body["fields"] = fields
    return Response(status, body)


class BillingRoutes:
    def __init__(self, *, connect: Callable[[], psycopg.Connection], mint_token: Callable[[uuid.UUID, list[str]], str],
                 client: StripeClient, webhook_secret: str, clock: Callable[[], float] = time.time,
                 alarm: Callable[[str, str], None] | None = None):
        from .usage import stderr_alarm

        self._connect = connect
        self._alarm = alarm or stderr_alarm
        self._mint = mint_token
        self._client = client
        self._secret = webhook_secret
        self._clock = clock

    @staticmethod
    def handles(method: str, path: str) -> bool:
        return (method, path) in ROUTES

    def handle(self, method: str, path: str, *, body: bytes = b"", headers: Mapping[str, str] | None = None,
               caller: Caller | None = None) -> Response:
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        rid = headers.get("x-request-id", caller.request_id if caller else "")
        if (method, path) not in ROUTES:
            return error(404, "not_found", "unknown billing path", rid)
        try:
            if path == "/v1/billing/webhook":
                return self._webhook(body, headers.get("stripe-signature"), rid)
            if caller is None:
                return error(401, "unauthenticated", "a portal session is required", rid)
            if caller.role != "admin":
                raise RoleNotAllowedError(caller.role)
            if (method, path) == ("GET", "/v1/billing/plans"):
                return self._plans(rid)
            if (method, path) == ("GET", "/v1/billing"):
                return self._summary(caller, rid)
            if path == "/v1/billing/checkout":
                return self._checkout(caller, body, rid)
            return self._portal(caller, rid)
        except RoleNotAllowedError as exc:
            return error(403, "role_not_allowed", "only an organization admin may use billing", rid,
                         {"role": caller_detail(exc)})
        except OrgNotActiveError as exc:
            return error(403, "org_not_active", caller_detail(exc), rid)
        except AlreadySubscribedError as exc:
            return error(409, "already_subscribed", caller_detail(exc), rid)
        except PlanNotFoundError as exc:
            return error(404, "not_found", caller_detail(exc), rid)
        except NotSubscribedError as exc:
            return error(404, "not_found", caller_detail(exc), rid)
        except (StripeUnavailableError, StripeRejectedError, PlanCatalogError) as exc:
            return error(502, "stripe_unavailable", f"{type(exc).__name__}: {caller_detail(exc)}", rid)
        except TenantTokenError as exc:
            return error(401, "unauthenticated", f"the tenant token was refused: {caller_detail(exc)}", rid)
        except psycopg.errors.LockNotAvailable:
            return error(503, "service_unavailable",
                         "another checkout for this organization is in progress; try again in a moment", rid)

    # webhook -------------------------------------------------------------------------------------------------------
    def _webhook(self, body: bytes, signature: str | None, rid: str) -> Response:
        try:
            with self._connect() as conn:
                result = webhook.receive(conn, self._client, payload=body, signature_header=signature,
                                         secret=self._secret, now=self._clock(), after=self._alarms_in_event)
        except (WebhookSignatureError, WebhookPayloadError) as exc:
            return error(400, "invalid_request", f"{type(exc).__name__}: {caller_detail(exc)}", rid)
        except (AlarmWriteError, TenantTokenError) as exc:
            # the event rolled back with the alarm: nothing was recorded, so Stripe redelivers and the alarm is retried
            return error(503, "service_unavailable", f"{type(exc).__name__}: {caller_detail(exc)}; the event was not recorded", rid)
        return Response(200, {"received": True, "outcome": result.outcome, "replayed": result.replayed})

    def _alarms_in_event(self, conn: psycopg.Connection, org_id: uuid.UUID, found: tuple[str, ...]) -> None:
        """Inside the webhook's transaction: an Enterprise contract with no limits, or a free tier that disagrees with
        it, is an operator alarm (billing never refuses evidence). The alarm commits with the event or neither does."""
        token = self._mint(org_id, list(BILLING_SCOPES))
        prev = conn.execute("SELECT current_setting('consentvault.org_token', true) AS t").fetchone()["t"]
        try:
            try:
                conn.execute("SELECT consentvault.enter_org(%s)", (token,))
            except psycopg.Error as exc:
                raise TenantTokenError(f"could not enter the tenant to write its alarm: {type(exc).__name__}") from exc
            acct = store.read_account(conn)
            names = list(found)
            if acct is not None and acct["plan_id"] == ENTERPRISE_INCOMPLETE:
                names.insert(0, ALARM_ENTERPRISE_INCOMPLETE)
            for name in dict.fromkeys(names):
                if name == ALARM_SECOND_SUBSCRIPTION and conn.execute(
                        "SELECT consentvault.billing_alarm_open(%s, %s) AS open", (org_id, name)).fetchone()["open"]:
                    continue  # one open alarm is enough; an operator acknowledges it
                raise_operator_alarm(conn, name=name, error_class="EnterpriseContract" if "enterprise" in name else "BillingSubscription",
                                     ref_kind="org", ref_id=org_id)
        except BaseException:
            try:
                conn.execute("SELECT set_config('consentvault.org_token', %s, true)", (prev or "",))
            except psycopg.Error:  # loud-failure-exempt: the transaction is aborted and rolls back; the first error is the one named
                pass
            raise
        conn.execute("SELECT set_config('consentvault.org_token', %s, true)", (prev or "",))

    # portal --------------------------------------------------------------------------------------------------------
    def _plans(self, rid: str) -> Response:
        plans = catalog(self._client.list_prices(), on_invalid=self._alarm)
        return Response(200, {"items": [p.public() for p in plans], "next_cursor": None})

    def _summary(self, caller: Caller, rid: str) -> Response:
        with self._connect() as conn, org_transaction(conn, self._mint(caller.org_id, list(BILLING_SCOPES))):
            status = store.read_org_status(conn)
            acct = store.read_account(conn)
            start, end = _period(acct)
            rows = conn.execute("SELECT events, gate_checks, reported_at FROM consentvault.usage_day"
                                " WHERE day >= %s AND day < %s", (start, end)).fetchall()
            failed = None
            if status == "past_due":  # when the payment failure moved the organization to past_due
                failed = conn.execute("SELECT from_at FROM consentvault.org_status_history WHERE status = 'past_due'"
                                      " AND org_id = (SELECT consentvault.current_org()) ORDER BY seq DESC LIMIT 1").fetchone()
        used = None
        if rows:
            gate_unread = any(r["gate_checks"] is None for r in rows)
            used = {"events": sum(r["events"] for r in rows),
                    "gate_checks": None if gate_unread else sum(r["gate_checks"] for r in rows)}
        reported = [r["reported_at"] for r in rows if r["reported_at"] is not None]
        has_plan = acct is not None and acct["plan_id"] is not None
        return Response(200, {
            "status": status,
            "past_due_since": _iso(failed["from_at"]) if failed else None,
            "plan": _public_plan(acct) if has_plan else None,
            "period": ({"start": _iso(acct["period_start"]), "end": _iso(acct["period_end"])}
                       if acct is not None and acct["period_start"] and acct["period_end"] else None),
            "included": ({"events": acct["included_events"], "gate_checks": acct["included_gate_checks"]}
                         if has_plan else None),
            "used": used,
            "last_reported_at": _iso(max(reported)) if reported else None,
        })

    def _checkout(self, caller: Caller, body: bytes, rid: str) -> Response:
        try:
            parsed = json.loads(body.decode("utf-8") or "null")
            plan_id = parsed["plan_id"]
            if not isinstance(plan_id, str) or not plan_id:
                raise ValueError("plan_id must be a non-empty string")
            interval = parsed.get("interval", "month")
            if interval not in INTERVALS:
                raise ValueError("interval must be month or year")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return error(422, "validation_failed", "a plan_id is required and interval, if given, is month or year", rid,
                         {"plan_id": "required"})
        with self._connect() as conn:
            with org_transaction(conn, self._mint(caller.org_id, list(BILLING_SCOPES))):
                org_status = store.read_org_status(conn)
                acct = store.read_account(conn)
            if org_status in ("offboarding", "closed"):
                raise OrgNotActiveError(f"the organization is {org_status}; it cannot start a subscription")
            if acct is not None and acct["stripe_subscription_id"] and acct["status"] in SUBSCRIPTION_IN_FORCE:
                raise AlreadySubscribedError("the organization already has a subscription in force")
            plan = find_plan(catalog(self._client.list_prices(), on_invalid=self._alarm), plan_id, interval)
            customer = acct["stripe_customer_id"] if acct is not None else None
            if customer is None:
                customer = self._client.create_customer(org_id=str(caller.org_id),
                                                        idempotency_key=f"customer:{caller.org_id}")["id"]
                try:
                    store.link_account(conn, caller.org_id, customer)
                except psycopg.errors.UniqueViolation:  # a concurrent checkout linked the same customer first
                    pass
            with org_transaction(conn, self._mint(caller.org_id, list(BILLING_SCOPES))):
                conn.execute(f"SET LOCAL lock_timeout = {int(CHECKOUT_LOCK_TIMEOUT_MS)}")
                store.lock_account(conn, caller.org_id)  # held to the end: one checkout page is made at a time
                acct = store.read_account(conn)
                if acct is not None and acct["stripe_subscription_id"] and acct["status"] in SUBSCRIPTION_IN_FORCE:
                    raise AlreadySubscribedError("the organization already has a subscription in force")
                if any(s.get("status") in SUBSCRIPTION_IN_FORCE for s in self._client.list_subscriptions(customer)):
                    raise AlreadySubscribedError("Stripe already lists a subscription in force for this organization")
                for open_page in self._client.list_open_checkout_sessions(customer):
                    self._client.expire_checkout_session(open_page["id"])
                session = self._client.create_checkout_session(
                    customer=customer, line_items=plan.line_items(), org_id=str(caller.org_id),
                    success_url=SUCCESS_URL, cancel_url=CANCEL_URL,
                    idempotency_key=f"checkout:{caller.org_id}:{plan.plan_id}:{uuid.uuid4()}")
        return Response(201, {"checkout_url": session["url"]})

    def _portal(self, caller: Caller, rid: str) -> Response:
        with self._connect() as conn, org_transaction(conn, self._mint(caller.org_id, list(BILLING_SCOPES))):
            acct = store.read_account(conn)
        if acct is None:
            raise NotSubscribedError("this organization has no Stripe customer yet")
        session = self._client.create_portal_session(customer=acct["stripe_customer_id"],
                                                     return_url=PORTAL_RETURN_URL)
        return Response(201, {"portal_url": session["url"]})


def _public_plan(acct: Mapping[str, Any]) -> dict[str, Any]:
    """The plan as the portal shows it: an Enterprise contract still missing its limits is Enterprise, pending."""
    pending = acct["plan_id"] == ENTERPRISE_INCOMPLETE
    return {"plan_id": ENTERPRISE if pending else acct["plan_id"], "name": acct["plan_name"], "contract_pending": pending}


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _period(acct: Mapping[str, Any] | None) -> tuple[date, date]:
    """The usage window: the subscription period if the vault holds one, else the current UTC calendar month."""
    if acct is not None and acct["period_start"] and acct["period_end"]:
        return acct["period_start"].astimezone(timezone.utc).date(), acct["period_end"].astimezone(timezone.utc).date()
    today = datetime.now(timezone.utc).date()
    first = today.replace(day=1)
    nxt = first.replace(year=first.year + (first.month == 12), month=first.month % 12 + 1)
    return first, nxt
