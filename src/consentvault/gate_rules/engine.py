"""Validation of the narrowing rules a client's stored policy may carry.

The contact check no longer reads a policy: it returns the recorded facts and history and nothing that turns them into a
decision (``gate.py``). What stays here is the check run when a policy document is written (``check_narrowing``), so the
stored document remains well formed until the policy store itself is retired.

Narrowing rules (``rules.narrowing``, each ``{"kind": ..., ...}``; an optional ``rule_reference_id`` is a citation only):

* ``require_channel_scope`` ``{channels: [...]}``
* ``internal_suppression_list`` ``{contact_fps: [...]}``
* ``time_window`` ``{start: "HH:MM", end: "HH:MM", tz: "<IANA zone>", days?: [0-6, Monday 0]}``
* ``require_verified_contact`` ``{channels: [...]}``
* ``max_age_of_consent`` ``{days: N}``
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..errors import ConsentVaultError

RULE_KINDS = ("require_channel_scope", "internal_suppression_list", "time_window", "require_verified_contact",
              "max_age_of_consent")
VERIFIED = ("otp",)
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_FP = re.compile(r"^[0-9a-f]{64}$")


class PolicyRuleError(ConsentVaultError):
    """A rule in a policy document is malformed."""


@dataclass(frozen=True)
class ApprovedPolicy:
    version: int
    rules: Mapping[str, Any]
    approved_by: str | None
    approved_at: datetime | None
    approval_id: str | None = None


@dataclass(frozen=True)
class Basis:
    """The grant behind a ``consent_record_found`` answer (no personal field)."""

    event_id: str
    channels: tuple[str, ...]
    received_at: datetime
    contact_verification: str
    disclosure_channels: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    """The one grant a rule is evaluated against (a neutral probe when a policy document is validated)."""

    grant: Basis | None = None


def _days(value: Any) -> set[int]:
    if value is None:
        return set(range(7))
    if not isinstance(value, list) or not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6
                                              for d in value):
        raise PolicyRuleError("time_window.days must be a list of weekday numbers 0 (Monday) to 6")
    return set(value)


def _hhmm(value: Any, what: str) -> time:
    m = _HHMM.match(value) if isinstance(value, str) else None
    if not m:
        raise PolicyRuleError(f"time_window.{what} must be HH:MM")
    return time(int(m.group(1)), int(m.group(2)))


def _channels(rule: Mapping[str, Any]) -> set[str]:
    ch = rule.get("channels")
    if not isinstance(ch, list) or not ch or not all(isinstance(c, str) for c in ch):
        raise PolicyRuleError(f"{rule.get('kind')}.channels must be a non-empty list of channel names")
    return set(ch)


def _fires(rule: Mapping[str, Any], *, channel: str, contact_fp: str, evidence: Evidence, now: datetime) -> bool:
    kind = rule.get("kind")
    grant = evidence.grant
    if kind == "require_channel_scope":
        if channel not in _channels(rule):
            return False
        return grant is None or channel not in grant.channels or channel not in grant.disclosure_channels
    if kind == "internal_suppression_list":
        fps = rule.get("contact_fps")
        if not isinstance(fps, list) or not all(isinstance(f, str) and _FP.match(f) for f in fps):
            raise PolicyRuleError("internal_suppression_list.contact_fps must be a list of 64-hex fingerprints")
        return contact_fp in fps
    if kind == "time_window":
        start, end = _hhmm(rule.get("start"), "start"), _hhmm(rule.get("end"), "end")
        try:
            zone = ZoneInfo(str(rule.get("tz")))
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise PolicyRuleError(f"time_window.tz is not a known time zone: {rule.get('tz')!r}") from exc
        local = now.astimezone(zone)
        if local.weekday() not in _days(rule.get("days")):
            return True
        t = local.time().replace(second=0, microsecond=0)
        inside = start <= t < end if start <= end else (t >= start or t < end)
        return not inside
    if kind == "require_verified_contact":
        if channel not in _channels(rule):
            return False
        return grant is None or grant.contact_verification not in VERIFIED
    if kind == "max_age_of_consent":
        days = rule.get("days")
        if not isinstance(days, int) or isinstance(days, bool) or days < 1:
            raise PolicyRuleError("max_age_of_consent.days must be a whole number of days, at least 1")
        return grant is None or now - grant.received_at > timedelta(days=days)
    raise PolicyRuleError(f"unknown narrowing rule kind {kind!r}; known: {list(RULE_KINDS)}")


_RULE_FIELDS = {
    "require_channel_scope": {"channels"},
    "internal_suppression_list": {"contact_fps"},
    "time_window": {"start", "end", "tz", "days"},
    "require_verified_contact": {"channels"},
    "max_age_of_consent": {"days"},
}


def check_narrowing(rules: Any) -> list[dict]:
    """Validate ``rules.narrowing`` when a policy is written (the gate re-checks when it reads). Returns the list.

    Each rule is ``{"kind", <that kind's fields>, "rule_reference_id"?}``; an unknown kind, a missing or malformed
    field, or a field the kind does not take raises ``PolicyRuleError`` naming it.
    """
    if rules is None:
        return []
    if not isinstance(rules, list) or not all(isinstance(r, Mapping) for r in rules):
        raise PolicyRuleError("policy rules.narrowing must be a list of objects")
    probe = Evidence(Basis("probe", (), datetime.now(timezone.utc), "none"))
    for rule in rules:
        kind = rule.get("kind")
        if kind not in _RULE_FIELDS:
            raise PolicyRuleError(f"unknown narrowing rule kind {kind!r}; known: {list(RULE_KINDS)}")
        extra = sorted(set(rule) - _RULE_FIELDS[kind] - {"kind", "rule_reference_id"})
        if extra:
            raise PolicyRuleError(f"{kind} does not take {extra}")
        ref = rule.get("rule_reference_id")
        if ref is not None and (not isinstance(ref, str) or not 1 <= len(ref) <= 200):
            raise PolicyRuleError(f"{kind}.rule_reference_id must be text of 1 to 200 characters")
        if "channels" in _RULE_FIELDS[kind]:
            _channels(rule)
        # every remaining field is checked by evaluating the rule once against a neutral probe
        _fires(rule, channel=next(iter(rule.get("channels") or ["sms"])), contact_fp="0" * 64, evidence=probe,
               now=datetime.now(timezone.utc))
    return [dict(r) for r in rules]
