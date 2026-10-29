"""Plans as Stripe sells them: every value comes from the Stripe Price and its metadata, never from this code.

A base Price (recurring, flat) carries metadata ``plan_id``, ``included_events``, ``included_gate_checks`` and
``orgs_brands``. Its overage Prices (metered, graduated, one per meter) carry ``overage_for=<plan_id>`` and
``meter=events|gate_checks``; they ride in the same Checkout Session as the base Price.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import PlanCatalogError, PlanNotFoundError

METERS = ("events", "gate_checks")


@dataclass(frozen=True)
class Plan:
    plan_id: str
    name: str
    interval: str
    unit_amount: int
    currency: str
    included_events: int
    included_gate_checks: int
    orgs_brands: str
    price_id: str
    overage_price_ids: dict[str, str] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, "name": self.name, "interval": self.interval, "unit_amount": self.unit_amount,
                "currency": self.currency, "included_events": self.included_events,
                "included_gate_checks": self.included_gate_checks, "orgs_brands": self.orgs_brands}

    def line_items(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = [{"price": self.price_id, "quantity": 1}]
        items.extend({"price": self.overage_price_ids[m]} for m in METERS if m in self.overage_price_ids)
        return items


def _int(meta: dict[str, Any], key: str, price_id: str) -> int:
    raw = meta.get(key)
    try:
        value = int(str(raw))
    except (TypeError, ValueError):
        raise PlanCatalogError(f"Stripe Price {price_id} has metadata {key}={raw!r}, not a whole number") from None
    if value < 0:
        raise PlanCatalogError(f"Stripe Price {price_id} has a negative {key}")
    return value


def plan_from_price(price: dict[str, Any]) -> Plan:
    """One base Price (product expanded) to a Plan. Raises ``PlanCatalogError`` naming the Price and the field."""
    price_id = price.get("id", "")
    meta = price.get("metadata") or {}
    recurring = price.get("recurring") or {}
    product = price.get("product")
    name = product.get("name") if isinstance(product, dict) else None
    if not name:
        raise PlanCatalogError(f"Stripe Price {price_id} has no expanded product name")
    if not recurring.get("interval"):
        raise PlanCatalogError(f"Stripe Price {price_id} is not recurring")
    if price.get("unit_amount") is None or not price.get("currency"):
        raise PlanCatalogError(f"Stripe Price {price_id} has no flat unit_amount or currency")
    orgs_brands = meta.get("orgs_brands")
    if not orgs_brands:
        raise PlanCatalogError(f"Stripe Price {price_id} has no orgs_brands metadata")
    return Plan(plan_id=str(meta["plan_id"]), name=name, interval=recurring["interval"],
                unit_amount=int(price["unit_amount"]), currency=price["currency"],
                included_events=_int(meta, "included_events", price_id),
                included_gate_checks=_int(meta, "included_gate_checks", price_id),
                orgs_brands=str(orgs_brands), price_id=price_id)


def catalog(prices: Iterable[dict[str, Any]]) -> list[Plan]:
    """All active plans from a list of Stripe Prices, sorted by unit_amount, each with its overage Prices attached."""
    bases: list[dict[str, Any]] = []
    overages: dict[str, dict[str, str]] = {}
    for p in prices:
        if p.get("active") is False:
            continue
        meta = p.get("metadata") or {}
        if meta.get("overage_for"):
            meter = meta.get("meter")
            if meter not in METERS:
                raise PlanCatalogError(f"Stripe Price {p.get('id')} is an overage Price with meter={meter!r}")
            overages.setdefault(meta["overage_for"], {})[meter] = p["id"]
        elif meta.get("plan_id"):
            bases.append(p)
    plans = [plan_from_price(p) for p in bases]
    out = [Plan(**{**pl.__dict__, "overage_price_ids": overages.get(pl.plan_id, {})}) for pl in plans]
    return sorted(out, key=lambda pl: (pl.unit_amount, pl.plan_id))


def find_plan(plans: Iterable[Plan], plan_id: str) -> Plan:
    for p in plans:
        if p.plan_id == plan_id:
            return p
    raise PlanNotFoundError(f"no plan {plan_id!r} is on sale")
