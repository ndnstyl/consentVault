"""Database access for billing: thin wrappers over the 0007 functions. No business rules live here."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg

from .errors import BillingError


@dataclass(frozen=True)
class PlanFacts:
    """What the vault copies from a Stripe Price when it links a subscription."""

    price_id: str | None = None
    plan_id: str | None = None
    plan_name: str | None = None
    included_events: int | None = None
    included_gate_checks: int | None = None
    price_set: str | None = None  # every price on the subscription (base and overage), sorted, comma-joined


def record_event(conn: psycopg.Connection, event_id: str, event_type: str) -> bool:
    """True the first time this Stripe event id is seen, False on a replay."""
    return bool(conn.execute("SELECT consentvault.billing_record_event(%s, %s) AS first",
                             (event_id, event_type)).fetchone()["first"])


def finish_event(conn: psycopg.Connection, event_id: str, org_id: uuid.UUID | None, outcome: str) -> None:
    conn.execute("SELECT consentvault.billing_finish_event(%s, %s, %s)", (event_id, org_id, outcome))


def event_outcomes(conn: psycopg.Connection) -> dict[str, int]:
    return {r["outcome"]: r["n"] for r in conn.execute("SELECT outcome, n FROM consentvault.billing_event_outcomes()")}


def resolve_org(conn: psycopg.Connection, customer: str | None, hint: uuid.UUID | None) -> uuid.UUID | None:
    if not customer and hint is None:
        return None
    return conn.execute("SELECT consentvault.billing_resolve_org(%s, %s) AS org", (customer, hint)).fetchone()["org"]


def link_account(conn: psycopg.Connection, org_id: uuid.UUID, customer: str, *, subscription: str | None = None,
                 status: str | None = None, facts: PlanFacts = PlanFacts(), period_start: datetime | None = None,
                 period_end: datetime | None = None) -> None:
    conn.execute(
        "SELECT consentvault.billing_link_account(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (org_id, customer, subscription, facts.price_id, status, facts.plan_id, facts.plan_name, facts.included_events,
         facts.included_gate_checks, period_start, period_end, facts.price_set))


def lock_account(conn: psycopg.Connection, org_id: uuid.UUID) -> bool:
    """Lock the entered organisation's billing row until the transaction ends. False when it has no row yet."""
    return bool(conn.execute("SELECT consentvault.billing_lock_account(%s) AS held", (org_id,)).fetchone()["held"])


def held_subscription(conn: psycopg.Connection, org_id: uuid.UUID) -> tuple[str | None, str | None]:
    """The subscription id and status the vault holds for an organisation (None, None when none is held)."""
    row = conn.execute("SELECT stripe_subscription_id, status FROM consentvault.billing_held_subscription(%s)",
                       (org_id,)).fetchone()
    return (row["stripe_subscription_id"], row["status"]) if row else (None, None)


def clear_alarm(conn: psycopg.Connection, org_id: uuid.UUID, name: str, by: str) -> int:
    """Acknowledge the organisation's open alarm of that name; returns how many were open."""
    return conn.execute("SELECT consentvault.billing_clear_alarm(%s, %s, %s) AS n", (org_id, name, by)).fetchone()["n"]


def apply_status(conn: psycopg.Connection, org_id: uuid.UUID, to: str, cause: str, event_id: str,
                 only_from: list[str] | None = None) -> str:
    """changed | unchanged | refused_terminal | refused_transition | refused_operator_suspension (a paid invoice never
    lifts a suspension an operator made; only one whose reason is subscription_canceled)."""
    result = conn.execute("SELECT consentvault.billing_apply_status(%s, %s, %s, %s, %s) AS r",
                          (org_id, to, cause, event_id, only_from)).fetchone()["r"]
    if result not in ("changed", "unchanged", "refused_terminal", "refused_transition", "refused_operator_suspension"):
        raise BillingError(f"the database answered an unknown status result {result!r}")
    return result


def read_account(conn: psycopg.Connection) -> dict[str, Any] | None:
    """The current organisation's billing row (the caller is inside its tenant transaction), or None."""
    return conn.execute("SELECT * FROM consentvault.billing_account").fetchone()


def read_org_status(conn: psycopg.Connection) -> str:
    row = conn.execute("SELECT status FROM consentvault.organization").fetchone()
    if row is None:
        raise BillingError("the current organisation is not visible; the tenant token names none")
    return row["status"]
