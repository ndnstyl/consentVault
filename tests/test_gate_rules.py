"""The contact check reads no policy and returns no verdict. What remains of the rule engine is the validation of a stored
policy document's narrowing rules, and the engine holds no function that turns a record into proceed or hold."""

import pytest

from consentvault.gate_rules import engine as e


@pytest.mark.parametrize("name", ["decide", "unavailable", "incomplete", "evidence_from_permission", "Outcome", "NOTICE",
                                  "STOP", "NONE", "UNAVAILABLE", "INCOMPLETE", "REASON_POLICY_CELL_MISSING"])
def test_the_engine_has_no_verdict_function_and_no_hard_coded_hold_rule(name):
    assert not hasattr(e, name)


def test_an_approved_policy_carries_no_cell_lookup():
    assert not hasattr(e.ApprovedPolicy, "cell") and not hasattr(e.ApprovedPolicy, "checklist_version")


@pytest.mark.parametrize("rule", [
    {"kind": "require_verified_contact", "channels": ["sms"]},
    {"kind": "max_age_of_consent", "days": 30, "rule_reference_id": "any"},
    {"kind": "internal_suppression_list", "contact_fps": ["a" * 64]},
    {"kind": "time_window", "start": "08:00", "end": "21:00", "tz": "America/New_York", "days": [0, 1, 2]},
    {"kind": "require_channel_scope", "channels": ["sms"]},
])
def test_a_well_formed_rule_is_kept_as_written(rule):
    assert e.check_narrowing([rule]) == [rule]


@pytest.mark.parametrize("rule", [
    {"kind": "time_window", "start": "8am", "end": "21:00", "tz": "America/New_York"},
    {"kind": "time_window", "start": "08:00", "end": "21:00", "tz": "Mars/Base"},
    {"kind": "max_age_of_consent", "days": 0},
    {"kind": "internal_suppression_list", "contact_fps": ["not-a-fingerprint"]},
    {"kind": "legal_basis_check"},
])
def test_a_malformed_rule_is_a_named_error_never_a_guess(rule):
    with pytest.raises(e.PolicyRuleError):
        e.check_narrowing([rule])
