"""Second-wave adversarial review, kept as permanent regression tests under the facts-only contact check: there is no path on
which a failure or a stored policy turns into proceed, because nothing in the check answers proceed or hold at all."""

from consentvault import gate
from consentvault.gate_rules import engine


def test_an_unreadable_record_is_unavailable_with_the_cause_and_no_action():
    out = gate.unavailable("key")
    assert out.status == "unavailable" and out.reason == "key" and out.history == () and out.stops == ()
    assert "policy_action" not in out.as_dict() and "allowed" not in out.as_dict()


def test_no_stored_policy_cell_can_reach_an_answer():
    assert not hasattr(engine.ApprovedPolicy, "cell")
    assert not hasattr(gate, "may_contact") and not hasattr(engine, "unavailable")
