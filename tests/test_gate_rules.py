"""The rule engine: evidence status, the approved policy's cell, and narrowing rules that can only hold."""

from datetime import datetime, timedelta, timezone

import pytest

from consentvault.gate_rules import engine as e

NOW = datetime(2026, 10, 29, 15, 0, tzinfo=timezone.utc)  # a Thursday, 11:00 in New York
FP = "a" * 64


def policy(cells=None, narrowing=None, checklist=None):
    cells = cells if cells is not None else [
        {"evidence_status": s, "channel": "sms", "action": "proceed" if s == "consent_record_found" else "hold"}
        for s in ("consent_record_found", "stop_on_record", "no_record", "record_incomplete", "unavailable")]
    rules = {"schema_version": 1, "purposes": {"marketing": {"cells": cells, "checklist_version": checklist}}}
    if narrowing is not None:
        rules["narrowing"] = narrowing
    return e.ApprovedPolicy(3, rules, "m-1", NOW, "ap-1")


def found(**grant):
    g = {"event_id": "g1", "channels": ("sms",), "received_at": NOW - timedelta(days=2),
         "contact_verification": "none", "disclosure_channels": ("sms",), **grant}
    return e.Evidence(e.FOUND, e.REASON_FOUND, ("g1",), e.Basis(**g))


def run(ev, pol, **kw):
    return e.decide(ev, pol, channel="sms", purpose="marketing", contact_fp=FP, now=NOW, **kw)


def test_no_policy_gives_no_action_and_says_so():
    o = run(found(), None)
    assert o.policy_action is None and o.policy_version is None and o.reasons == (e.REASON_FOUND, "no_policy_configured")


def test_the_cell_decides_and_a_stop_never_proceeds_even_if_a_cell_says_so():
    assert run(found(), policy()).policy_action == "proceed"
    bad = policy(cells=[{"evidence_status": "stop_on_record", "channel": "sms", "action": "proceed"}])
    o = run(e.Evidence(e.STOP, "stopped:revoke"), bad)
    assert o.evidence_status == "stop_on_record" and o.policy_action == "hold"


def test_a_missing_cell_holds_and_names_it():
    o = run(found(), policy(cells=[]))
    assert o.policy_action == "hold" and "policy_cell_missing" in o.reasons


@pytest.mark.parametrize("rule,grant,fires", [
    ({"kind": "require_verified_contact", "channels": ["sms"]}, {}, True),
    ({"kind": "require_verified_contact", "channels": ["sms"]}, {"contact_verification": "otp"}, False),
    ({"kind": "require_verified_contact", "channels": ["voice"]}, {}, False),
    ({"kind": "max_age_of_consent", "days": 1}, {}, True),
    ({"kind": "max_age_of_consent", "days": 30}, {}, False),
    ({"kind": "internal_suppression_list", "contact_fps": [FP]}, {}, True),
    ({"kind": "internal_suppression_list", "contact_fps": ["b" * 64]}, {}, False),
    ({"kind": "time_window", "start": "08:00", "end": "21:00", "tz": "America/New_York"}, {}, False),
    ({"kind": "time_window", "start": "12:00", "end": "21:00", "tz": "America/New_York"}, {}, True),
    ({"kind": "time_window", "start": "08:00", "end": "21:00", "tz": "America/New_York", "days": [0, 1, 2]}, {}, True),
    ({"kind": "require_channel_scope", "channels": ["sms"]}, {}, False),
    ({"kind": "require_channel_scope", "channels": ["sms"]}, {"disclosure_channels": ("voice",)}, True),
])
def test_each_narrowing_rule_only_turns_proceed_into_hold(rule, grant, fires):
    o = run(found(**grant), policy(narrowing=[rule]))
    assert o.policy_action == ("hold" if fires else "proceed")
    assert (len(o.fired) == 1) is fires


def test_a_rule_never_lifts_a_hold():
    o = run(e.Evidence(e.NONE, e.REASON_NO_CONSENT), policy(narrowing=[{"kind": "max_age_of_consent", "days": 99}]))
    assert o.policy_action == "hold"


def test_a_rule_reference_is_a_citation_only():
    cited = {"kind": "max_age_of_consent", "days": 30, "rule_reference_id": "any"}
    assert run(found(), policy(narrowing=[cited])).policy_action == "proceed"


@pytest.mark.parametrize("rule", [
    {"kind": "time_window", "start": "8am", "end": "21:00", "tz": "America/New_York"},
    {"kind": "time_window", "start": "08:00", "end": "21:00", "tz": "Mars/Base"},
    {"kind": "max_age_of_consent", "days": 0},
    {"kind": "internal_suppression_list", "contact_fps": ["not-a-fingerprint"]},
    {"kind": "legal_basis_check"},
])
def test_a_malformed_rule_is_a_named_error_never_a_guess(rule):
    with pytest.raises(e.PolicyRuleError):
        run(found(), policy(narrowing=[rule]))


def test_unavailable_applies_the_policys_own_unavailable_cell():
    o = e.unavailable("database", policy(), "sms", "marketing")
    assert o.evidence_status == "unavailable:database" and o.policy_action == "hold"
    assert e.unavailable("database", None, "sms", "marketing").policy_action is None


def test_incomplete_names_the_missing_elements_and_only_marks_a_found_record():
    ev = e.incomplete(found(), ["seller_named", "channels_named"])
    assert ev.status == "record_incomplete:channels_named,seller_named" and ev.kind == "record_incomplete"
    assert run(ev, policy()).policy_action == "hold"
    stop = e.Evidence(e.STOP, "stopped:revoke")
    assert e.incomplete(stop, ["x"]) is stop


def test_evidence_mapping_describes_records_only():
    assert e.evidence_from_permission({"allowed": True, "reason": "granted"}, None).status == "consent_record_found"
    assert e.evidence_from_permission({"allowed": False, "reason": "stopped:suppress"}, None).reason == "stopped:suppress"
    assert e.evidence_from_permission(None, "stopped:revoke").status == "stop_on_record"
    assert e.evidence_from_permission(None, None).status == "no_record"
