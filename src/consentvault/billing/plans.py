"""Plans as Stripe sells them: every value comes from the Stripe Price and its metadata, never from this code.

A base Price (recurring, flat, monthly or annual) carries metadata ``plan_id``, ``included_events``,
``included_gate_checks``, ``systems`` and ``legal_holds``. Enterprise has no list price and is never on sale here. Its overage Prices (metered, graduated, one per meter) carry ``overage_for=<plan_id>`` and
``meter=events|gate_checks``; they ride in the same Checkout Session as the base Price.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable, Iterable

from ..safelog import describe
from .errors import PlanCatalogError, PlanNotFoundError

METERS = ("events", "gate_checks")
INTERVALS = ("month", "year")
ENTERPRISE_INCOMPLETE = "enterprise_contract_incomplete"  # plan of record while a contract lacks its limits
ALARM_ENTERPRISE_INCOMPLETE = "billing.enterprise_contract_incomplete"
ALARM_ENTERPRISE_MISMATCH = "billing.enterprise_contract_mismatch"  # an overage free tier differs from the contract
ALARM_PLAN_PRICE_INVALID = "billing.plan_price_invalid"  # one Price dropped from the plans list, named in the detail
ALARM_PLAN_OFF_SALE = "billing.plan_off_sale"  # a plan lost an overage Price, so it is not sold without overage billing
ALARM_SECOND_SUBSCRIPTION = "billing.second_live_subscription"  # a different live subscription would replace the stored one
ENTERPRISE = "enterprise"  # priced by consultation: no list price, limits ride on the subscription's contract metadata


@dataclass(frozen=True)
class Plan:
    plan_id: str
    name: str
    interval: str
    unit_amount: int
    currency: str
    included_events: int
    included_gate_checks: int
    systems: int
    legal_holds: bool
    price_id: str
    overage_price_ids: dict[str, str] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, "name": self.name, "interval": self.interval, "unit_amount": self.unit_amount,
                "currency": self.currency, "included_events": self.included_events,
                "included_gate_checks": self.included_gate_checks, "systems": self.systems,
                "legal_holds": self.legal_holds}

    def line_items(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = [{"price": self.price_id, "quantity": 1}]
        items.extend({"price": self.overage_price_ids[m]} for m in METERS if m in self.overage_price_ids)
        return items


def _bad_price(price_id: Any, problem: str) -> PlanCatalogError:
    return PlanCatalogError(f"Stripe Price {price_id} {problem}", price_id=str(price_id), problem=problem)


def _int(meta: dict[str, Any], key: str, price_id: str) -> int:
    raw = meta.get(key)
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]+", raw):
        raise _bad_price(price_id, f"has metadata {key}={raw!r}, not a whole number")
    return int(raw)


def plan_from_price(price: dict[str, Any]) -> Plan:
    """One base Price (product expanded) to a Plan. Raises ``PlanCatalogError`` naming the Price and the field."""
    price_id = price.get("id", "")
    meta = price.get("metadata") or {}
    recurring = price.get("recurring") or {}
    product = price.get("product")
    name = product.get("name") if isinstance(product, dict) else None
    if not name:
        raise _bad_price(price_id, "has no expanded product name")
    if not recurring.get("interval"):
        raise _bad_price(price_id, "is not recurring")
    if price.get("unit_amount") is None or not price.get("currency"):
        raise _bad_price(price_id, "has no flat unit_amount or currency")
    holds = str(meta.get("legal_holds", "")).lower()
    if holds not in ("true", "false"):
        raise _bad_price(price_id, f"has metadata legal_holds={meta.get('legal_holds')!r}, not true or false")
    if not meta.get("plan_id"):
        raise _bad_price(price_id, "has no metadata plan_id")
    return Plan(plan_id=str(meta["plan_id"]), name=name, interval=recurring["interval"],
                unit_amount=int(price["unit_amount"]), currency=price["currency"],
                included_events=_int(meta, "included_events", price_id),
                included_gate_checks=_int(meta, "included_gate_checks", price_id),
                systems=_int(meta, "systems", price_id), legal_holds=holds == "true", price_id=price_id)


def catalog(prices: Iterable[dict[str, Any]], on_invalid: Callable[[str, str], None] | None = None) -> list[Plan]:
    """All active plans from a list of Stripe Prices, sorted by unit_amount, each with its overage Prices attached.

    With ``on_invalid`` a Price whose metadata is malformed is dropped and named through ``on_invalid(alarm, detail)``,
    so one bad Price never empties the plans page; without it the first bad Price raises ``PlanCatalogError``.
    """
    def bad(exc: PlanCatalogError) -> None:
        if on_invalid is None:
            raise exc
        on_invalid(ALARM_PLAN_PRICE_INVALID, f"Stripe Price {exc.price_id} {exc.check_problem} ({describe(exc)}); that Price is left "
                                             "off the plans list")

    bases: list[dict[str, Any]] = []
    overages: dict[str, dict[str, str]] = {}
    dropped: set[str] = set()
    for p in prices:
        if p.get("active") is False:
            continue
        meta = p.get("metadata") or {}
        if meta.get("overage_for"):
            meter = meta.get("meter")
            if meter not in METERS:
                bad(_bad_price(p.get("id"), f"is an overage Price with meter={meter!r}"))
                dropped.add(str(meta["overage_for"]))
                continue
            overages.setdefault(meta["overage_for"], {})[meter] = p["id"]
        elif meta.get("plan_id") and meta["plan_id"] != ENTERPRISE:
            bases.append(p)
    plans: list[Plan] = []
    for p in bases:
        try:
            plans.append(plan_from_price(p))
        except PlanCatalogError as exc:
            bad(exc)
    out = []
    for pl in plans:
        held = overages.get(pl.plan_id, {})
        if pl.plan_id in dropped and any(m not in held for m in METERS):
            if on_invalid is not None:
                on_invalid(ALARM_PLAN_OFF_SALE, f"plan {pl.plan_id} lost an overage Price and is taken off sale")
            continue
        out.append(Plan(**{**pl.__dict__, "overage_price_ids": held}))
    monthly = {pl.plan_id: pl.unit_amount for pl in out if pl.interval == "month"}
    return sorted(out, key=lambda pl: (monthly.get(pl.plan_id, pl.unit_amount), pl.plan_id, pl.interval != "month"))


def find_plan(plans: Iterable[Plan], plan_id: str, interval: str = "month") -> Plan:
    for p in plans:
        if p.plan_id == plan_id and p.interval == interval:
            return p
    raise PlanNotFoundError(f"no plan {plan_id!r} is on sale for the {interval} interval")
