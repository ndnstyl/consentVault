"""Shared helpers for the billing tests."""

from __future__ import annotations

import uuid

from consentvault import db
from consentvault.billing.routes import BillingRoutes
from consentvault.tenancy.tokens import mint_org_token

from .fakes import SECRET, FakeStripe, event, signed


def routes_for(tenancy, stripe: FakeStripe, **kw) -> BillingRoutes:
    return BillingRoutes(
        connect=lambda: db.connect(tenancy.app_dsn),
        mint_token=lambda org, scopes: mint_org_token(tenancy.key, org, scopes, credential_id=None),
        client=stripe, webhook_secret=SECRET, **kw)


def send(routes: BillingRoutes, payload: dict) -> tuple[int, dict]:
    body, headers = signed(payload)
    r = routes.handle("POST", "/v1/billing/webhook", body=body, headers=headers)
    return r.status, r.payload


def set_status(tenancy, org, status: str) -> None:
    """An operator-side status change (no cause set, so the history records 'operator')."""
    with tenancy.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = %s WHERE org_id = %s", (status, org.org_id))


def status_of(tenancy, org) -> str:
    with tenancy.superuser() as su:
        return su.execute("SELECT status FROM consentvault.organization WHERE org_id = %s",
                          (org.org_id,)).fetchone()["status"]


def history(tenancy, org) -> list[dict]:
    with tenancy.superuser() as su:
        return su.execute("SELECT seq, status, cause, actor FROM consentvault.org_status_history"
                          " WHERE org_id = %s ORDER BY seq", (org.org_id,)).fetchall()


def outcomes(tenancy) -> dict[str, int]:
    with tenancy.superuser() as su:
        return {r["outcome"]: r["n"] for r in su.execute(
            "SELECT coalesce(outcome, 'open') AS outcome, count(*) AS n FROM consentvault.billing_event GROUP BY 1")}


def account(tenancy, org) -> dict | None:
    with tenancy.superuser() as su:
        return su.execute("SELECT * FROM consentvault.billing_account WHERE org_id = %s", (org.org_id,)).fetchone()


def subscribed(stripe: FakeStripe, org, *, status: str = "active", price_id: str = "price_starter",
               contract: dict | None = None) -> tuple[str, str]:
    """A customer and subscription in Stripe for an organisation; returns (customer id, subscription id)."""
    cus = stripe.add_customer(str(org.org_id))
    return cus, stripe.add_subscription(cus, status, str(org.org_id), price_id, contract)


def link(tenancy, org, customer: str, subscription: str | None = None, status: str | None = None) -> None:
    """Link the account the way checkout does, through the function the webhook uses."""
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, %s, %s, NULL, %s, NULL, NULL, NULL, NULL, NULL, NULL)",
                    (org.org_id, customer, subscription, status))


__all__ = ["routes_for", "send", "set_status", "status_of", "history", "outcomes", "account", "subscribed", "link",
           "event", "uuid"]


def retries_age(tenancy, hours: float) -> None:
    """Time passes for the retry queue: the database decides which failed sends are due on its own clock (migration 0065), so
    each send's due time moves back by ``hours`` (seconds, so no zone moves it)."""
    with tenancy.superuser() as su:
        su.execute("UPDATE consentvault.usage_day SET retry_at = retry_at - make_interval(secs => %s) WHERE retry_at IS NOT NULL",
                   (hours * 3600,))
