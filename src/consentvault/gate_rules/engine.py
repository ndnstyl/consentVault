"""Evidence status and the client's approved policy: what the records show, and what the client said to do about it.

Nothing here states a legal conclusion. ``evidence_status`` describes the records (``consent_record_found``,
``stop_on_record``, ``no_record``, ``record_incomplete:<elements>``, ``unavailable:<cause>``). ``policy_action`` is the
cell of the client's approved policy for that status, channel and purpose (``proceed`` or ``hold``), or ``None`` when no
policy is approved. Narrowing rules written into the approved policy run after it and can only turn ``proceed`` into
``hold``; nothing turns a stop into ``proceed``.

Narrowing rules (``rules.narrowing`` of the approved policy, each ``{"kind": ..., ...}``; an optional
``rule_reference_id`` is a citation only and is never read by the engine):

* ``require_channel_scope`` ``{channels: [...]}``: for these channels, the grant behind the record must name the
  channel itself and its wording must name it too.
* ``internal_suppression_list`` ``{contact_fps: [...]}``: the client's own list, by contact fingerprint.
* ``time_window`` ``{start: "HH:MM", end: "HH:MM", tz: "<IANA zone>", days?: [0-6, Monday 0]}``: outside it, hold.
* ``require_verified_contact`` ``{channels: [...]}``: the grant must carry a verified contact point (one-time code or
  inbound keyword).
* ``max_age_of_consent`` ``{days: N}``: a grant older than N days, hold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Any, Iterable, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..errors import ConsentVaultError

NOTICE = ("Evidence status and the outcome of your organization's approved policy. Not a legal determination.")

FOUND = "consent_record_found"
STOP = "stop_on_record"
NONE = "no_record"
INCOMPLETE = "record_incomplete"
UNAVAILABLE = "unavailable"

REASON_FOUND = "consent_record_found"
REASON_NO_CONSENT = "no_consent_on_record"
REASON_NO_POLICY = "no_policy_configured"
REASON_POLICY_CELL_MISSING = "policy_cell_missing"

RULE_KINDS = ("require_channel_scope", "internal_suppression_list", "time_window", "require_verified_contact",
              "max_age_of_consent")
VERIFIED = ("otp", "inbound_keyword")
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_FP = re.compile(r"^[0-9a-f]{64}$")


class PolicyRuleError(ConsentVaultError):
    """A rule in the approved policy is malformed; the gate answers unavailable rather than guess."""


@dataclass(frozen=True)
class ApprovedPolicy:
    version: int
    rules: Mapping[str, Any]
    approved_by: str | None
    approved_at: datetime | None
    approval_id: str | None = None

    def purpose(self, purpose: str) -> Mapping[str, Any] | None:
        purposes = self.rules.get("purposes") if isinstance(self.rules, Mapping) else None
        if not isinstance(purposes, Mapping):
            return None
        p = purposes.get(purpose)
        return p if isinstance(p, Mapping) else None

    def cell(self, status_kind: str, channel: str, purpose: str) -> str | None:
        p = self.purpose(purpose)
        if p is None:
            return None
        for c in p.get("cells") or ():
            if isinstance(c, Mapping) and c.get("evidence_status") == status_kind and c.get("channel") == channel:
                action = c.get("action")
                return action if action in ("proceed", "hold") else None
        return None

    def checklist_version(self, purpose: str) -> int | None:
        p = self.purpose(purpose)
        v = p.get("checklist_version") if p is not None else None
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def narrowing(self) -> list[Mapping[str, Any]]:
        rules = self.rules.get("narrowing") if isinstance(self.rules, Mapping) else None
        if rules is None:
            return []
        if not isinstance(rules, list) or not all(isinstance(r, Mapping) for r in rules):
            raise PolicyRuleError("policy rules.narrowing must be a list of objects")
        return list(rules)


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
    status: str  # one of the five kinds, with ':<detail>' for incomplete and unavailable
    reason: str
    basis_event_ids: tuple[str, ...] = ()
    grant: Basis | None = None

    @property
    def kind(self) -> str:
        return self.status.split(":", 1)[0]


@dataclass(frozen=True)
class Outcome:
    evidence_status: str
    policy_action: str | None
    policy_version: int | None
    approved_by: str | None
    approved_at: datetime | None
    basis_event_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    approval_id: str | None = None
    fired: tuple[str, ...] = field(default=())


def evidence_from_permission(row: Mapping[str, Any] | None, star_stop_reason: str | None) -> Evidence:
    """Map a ``current_permission`` row (or its absence) to an evidence status. Describes the records only."""
    if row is None:
        if star_stop_reason is not None and star_stop_reason.startswith("stopped:"):
            return Evidence(STOP, star_stop_reason)
        return Evidence(NONE, REASON_NO_CONSENT)
    reason = str(row.get("reason") or "")
    if row.get("allowed"):
        return Evidence(FOUND, REASON_FOUND)
    if reason.startswith("stopped:"):
        return Evidence(STOP, reason)
    return Evidence(NONE, REASON_NO_CONSENT)


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
    probe = Evidence(FOUND, REASON_FOUND, (), Basis("probe", (), datetime.now(timezone.utc), "none"))
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


_RULE_REASON = {
    "require_channel_scope": "rule:require_channel_scope",
    "internal_suppression_list": "rule:internal_suppression",
    "time_window": "rule:time_window",
    "require_verified_contact": "rule:require_verified_contact",
    "max_age_of_consent": "rule:max_age_of_consent",
}


def decide(
    evidence: Evidence,
    policy: ApprovedPolicy | None,
    *,
    channel: str,
    purpose: str,
    contact_fp: str,
    now: datetime,
    apply_rules: bool = True,
) -> Outcome:
    """The policy action for one evidence status, judged at ``now``: the caller passes the database's clock, there is no default.
    Raises ``PolicyRuleError`` on a malformed approved rule."""
    reasons = [evidence.reason]
    if policy is None:
        return Outcome(evidence.status, None, None, None, None, evidence.basis_event_ids,
                       tuple(reasons + [REASON_NO_POLICY]))
    action = policy.cell(evidence.kind, channel, purpose)
    if action is None:
        action = "hold"
        reasons.append(REASON_POLICY_CELL_MISSING)
    if evidence.kind == STOP:
        action = "hold"  # a stop is never turned into proceed, whatever a cell says
    fired: list[str] = []
    if apply_rules:
        for rule in policy.narrowing():
            if _fires(rule, channel=channel, contact_fp=contact_fp, evidence=evidence, now=now):
                name = _RULE_REASON[str(rule.get("kind"))]
                if name not in fired:
                    fired.append(name)
    if fired:
        action = "hold"
        reasons.extend(fired)
    return Outcome(evidence.status, action, policy.version, policy.approved_by, policy.approved_at,
                   evidence.basis_event_ids, tuple(reasons), policy.approval_id, tuple(fired))


def unavailable(cause: str, policy: ApprovedPolicy | None, channel: str, purpose: str) -> Outcome:
    """The answer when the records cannot be read: ``hold`` when the policy's ``unavailable`` cell says hold, else no
    action. Never ``proceed`` (contracts/gate.md), whatever a stored cell says."""
    status = f"{UNAVAILABLE}:{cause}"
    if policy is None:
        return Outcome(status, None, None, None, None, (), (status,))
    action = "hold" if policy.cell(UNAVAILABLE, channel, purpose) == "hold" else None
    return Outcome(status, action, policy.version if action else None, policy.approved_by if action else None,
                   policy.approved_at if action else None, (), (status,), policy.approval_id if action else None)


def incomplete(evidence: Evidence, missing: Iterable[str]) -> Evidence:
    """Mark a found record incomplete against the client's checklist (documentation completeness only)."""
    elems = sorted({str(m) for m in missing})
    if evidence.kind != FOUND or not elems:
        return evidence
    return Evidence(f"{INCOMPLETE}:{','.join(elems)}", evidence.reason, evidence.basis_event_ids, evidence.grant)
