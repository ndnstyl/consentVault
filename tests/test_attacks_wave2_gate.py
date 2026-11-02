"""Second-wave adversarial review, ported as permanent regression tests: a failed gate never answers proceed, and a
policy can never be written with an unavailable cell set to proceed (contracts/gate.md)."""

import pytest

from consentvault.gate_rules import engine

CELLS = ("consent_record_found", "stop_on_record", "no_record", "record_incomplete", "unavailable")


def _policy(unavailable_action):
    return engine.ApprovedPolicy(1, {"schema_version": 1, "purposes": {"marketing": {"cells": [
        {"evidence_status": "unavailable", "channel": "sms", "action": unavailable_action}]}}}, "admin", None)


def test_unavailable_answers_proceed_when_cell_says_proceed():
    # reviewer's attack: even a stored policy whose unavailable cell says proceed never yields proceed on failure
    out = engine.unavailable("key", _policy("proceed"), "sms", "marketing")
    assert out.policy_action is None and out.policy_version is None


def test_unavailable_holds_only_when_the_cell_says_hold():
    assert engine.unavailable("database", _policy("hold"), "sms", "marketing").policy_action == "hold"
    assert engine.unavailable("database", None, "sms", "marketing").policy_action is None
    assert engine.unavailable("database", _policy("hold"), "voice", "marketing").policy_action is None  # no cell
