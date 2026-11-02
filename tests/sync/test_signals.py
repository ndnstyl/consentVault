"""Inbound signals: stop wins, no echo, dedupe, arrival order, no loophole around a stop."""

import json
import uuid
from datetime import timezone

import pytest

from consentvault.sync.errors import InvalidContactError, SignalValidationError
from consentvault.sync.signals import Signal, parse_signal, process_signal
from consentvault.tenancy.tokens import org_transaction

from .support import PHONES, of

P1, P2, P3, P4 = PHONES[0], PHONES[1], PHONES[2], PHONES[3]


def signal(env, org, *, contact, claimed_state, ref=None, channel="sms", purpose="marketing", wording=None, claimed_at=None,
           system="crm"):
    """What POST /v1/signals does for the system whose credential signs the call."""
    body = {"contact": contact, "channel": channel, "purpose": purpose, "claimed_state": claimed_state,
            "external_ref": ref or str(uuid.uuid4())}
    if wording:
        body["disclosure_sha256"] = wording
    if claimed_at:
        body["claimed_at"] = claimed_at
    with env.t.app() as app, org_transaction(app, env.t.token(org, scopes=("capture",))):
        return process_signal(app, env.t.crypto, org_id=org.org_id, system_id=env.system(org, system).system_id,
                              signal=parse_signal(body))


def _events(env, org, contact):
    return env.q("SELECT event_type, method, origin, source, recorded_by FROM consentvault.event WHERE org_id = %s"
                 " AND contact_fp = %s ORDER BY seq", (org.org_id, env.fp(org, contact)))


def test_a_stop_for_a_person_the_vault_never_saw_is_recorded_as_a_stop_event(env):
    a = env.t.a
    env.add_system(a, "crm")
    r = signal(env, a, contact=P1, claimed_state="denied")
    assert r.resolution == "applied_as_event" and r.event_id and not r.replay
    assert _events(env, a, P1) == [{"event_type": "suppress", "method": "import", "origin": "import", "source": "signal",
                                    "recorded_by": f"system:{env.system(a, 'crm').system_id}"}]
    # scoped to this contact: the harness's own events advance state through the writer's hook (integration pass)
    assert env.q("SELECT state, version FROM consentvault.state_version WHERE org_id = %s AND contact_fp = %s",
                 (a.org_id, env.fp(a, P1))) == [{"state": "denied", "version": 1}]


def test_a_stop_is_pushed_to_every_other_system_and_never_back_to_the_sender(env):
    a = env.t.a
    env.add_system(a, "crm", signal=True)
    other = env.add_system(a, "dialer")
    third = env.add_system(a, "sms", contact_form="fingerprint")
    r = signal(env, a, contact=P1, claimed_state="denied")
    assert r.resolution == "applied_as_event"
    rows = env.outbox(a)
    assert {x["system_id"] for x in rows} == {other.system_id, third.system_id}  # no echo to the sender
    env.run_worker()
    assert env.transport.to(env.system(a, "crm").endpoint) == []
    assert json.loads(env.transport.to(other.endpoint)[0].body)["state"] == "denied"


def test_the_same_external_reference_again_is_the_first_answer_and_changes_nothing(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.add_system(a, "dialer")
    first = signal(env, a, contact=P1, claimed_state="denied", ref="CRM-42")
    again = signal(env, a, contact=P1, claimed_state="denied", ref="CRM-42")
    assert again.replay and (again.signal_id, again.resolution, again.event_id) == (first.signal_id, first.resolution, first.event_id)
    assert len(_events(env, a, P1)) == 1 and len(env.outbox(a)) == 1
    assert env.q("SELECT count(*) AS n FROM consentvault.inbound_signal WHERE org_id = %s", (a.org_id,))[0]["n"] == 1


def test_a_replay_gets_the_first_answer_even_when_the_second_claim_differs(env):
    a = env.t.a
    env.add_system(a, "crm")
    first = signal(env, a, contact=P1, claimed_state="denied", ref="R1")
    again = signal(env, a, contact=P1, claimed_state="permitted", ref="R1")
    assert again.replay and again.resolution == first.resolution == "applied_as_event"


def test_deduplication_is_per_system(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.add_system(a, "dialer")
    one = signal(env, a, contact=P1, claimed_state="denied", ref="X-1", system="crm")
    two = signal(env, a, contact=P1, claimed_state="denied", ref="X-1", system="dialer")
    assert not two.replay and two.signal_id != one.signal_id and two.resolution == "no_change"  # already denied


def test_a_stop_the_ledger_already_holds_is_no_change_no_event_no_push(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.add_system(a, "dialer")
    env.grant(a, P1)
    env.stop(a, P1)
    before = (len(_events(env, a, P1)), len(env.outbox(a)))
    r = signal(env, a, contact=P1, claimed_state="denied")
    assert r.resolution == "no_change" and r.event_id is None
    assert (len(_events(env, a, P1)), len(env.outbox(a))) == before


def test_a_grant_claim_against_a_stop_is_conflict_stop_wins(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    env.stop(a, P1)
    wording = a.disclosure
    r = signal(env, a, contact=P1, claimed_state="permitted", wording=wording)
    assert r.resolution == "conflict_stop_wins" and r.event_id is None
    assert [e["event_type"] for e in _events(env, a, P1)] == ["grant", "revoke"]
    assert env.q("SELECT allowed FROM consentvault.current_permission WHERE org_id = %s AND contact_fp = %s",
                 (a.org_id, env.fp(a, P1)))[0]["allowed"] is False


def test_a_signal_can_never_lift_a_stop_even_with_the_stop_later_than_its_claim(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    env.stop(a, P1)
    r = signal(env, a, contact=P1, claimed_state="permitted", wording=a.disclosure, claimed_at="2099-01-01T00:00:00Z")
    assert r.resolution == "conflict_stop_wins"  # the claimed time is evidence only; arrival order rules
    r2 = signal(env, a, contact=P1, claimed_state="permitted", wording=a.disclosure, claimed_at="2000-01-01T00:00:00Z")
    assert r2.resolution == "conflict_stop_wins"
    stored = env.q("SELECT claimed_at FROM consentvault.inbound_signal WHERE org_id = %s ORDER BY received_at", (a.org_id,))
    assert [s["claimed_at"].astimezone(timezone.utc).year for s in stored] == [2099, 2000]


def test_a_stop_from_a_signal_is_hard_and_a_later_consumer_checkbox_cannot_lift_it(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    signal(env, a, contact=P1, claimed_state="denied")
    _, res = env.grant(a, P1)
    assert res.changes == ()
    assert env.q("SELECT allowed FROM consentvault.current_permission WHERE org_id = %s AND contact_fp = %s",
                 (a.org_id, env.fp(a, P1)))[0]["allowed"] is False


def test_a_grant_claim_for_permission_the_ledger_holds_is_no_change(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    r = signal(env, a, contact=P1, claimed_state="permitted")
    assert r.resolution == "no_change" and r.event_id is None


def test_a_grant_claim_with_nothing_in_the_ledger_and_no_wording_is_ignored(env):
    a = env.t.a
    env.add_system(a, "crm")
    r = signal(env, a, contact=P1, claimed_state="permitted")
    assert r.resolution == "ignored_stale" and r.event_id is None and _events(env, a, P1) == []
    assert env.q("SELECT count(*) AS n FROM consentvault.inbound_signal WHERE org_id = %s", (a.org_id,))[0]["n"] == 1


def test_a_grant_claim_with_registered_wording_becomes_an_event_pushed_to_the_others(env):
    a = env.t.a
    env.add_system(a, "crm")
    other = env.add_system(a, "dialer")
    r = signal(env, a, contact=P1, claimed_state="permitted", wording=a.disclosure)
    assert r.resolution == "applied_as_event"
    (ev,) = _events(env, a, P1)
    assert ev["event_type"] == "grant" and ev["origin"] == "import"
    rows = env.outbox(a)
    assert [(x["system_id"], x["version"]) for x in rows] == [(other.system_id, 1)]


@pytest.mark.parametrize("wording_kind", ["unregistered", "beyond_scope"])
def test_a_grant_claim_that_fails_the_normal_checks_is_ignored(env, wording_kind):
    a = env.t.a
    env.add_system(a, "crm")
    if wording_kind == "unregistered":
        wording = "f" * 64
        kw = {}
    else:
        wording = env.register_wording(a, "alpha: texts about servicing only.", purposes=["servicing"])
        kw = {}
    r = signal(env, a, contact=P1, claimed_state="permitted", wording=wording, **kw)
    assert r.resolution == "ignored_stale" and _events(env, a, P1) == []


def test_external_references_are_held_as_ciphertext_and_a_keyed_hash(env):
    a = env.t.a
    env.add_system(a, "crm")
    signal(env, a, contact=P1, claimed_state="denied", ref="CRM-RECORD-90210")
    row = env.q("SELECT external_ref_ct, external_ref_mac, contact_fp FROM consentvault.inbound_signal WHERE org_id = %s", (a.org_id,))[0]
    assert b"CRM-RECORD-90210" not in bytes(row["external_ref_ct"]) and "CRM-RECORD-90210" not in row["external_ref_mac"]
    assert len(row["external_ref_mac"]) == 64 and row["contact_fp"] == env.fp(a, P1)


def test_the_stop_wording_all_purposes_is_a_stop_on_every_purpose(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.add_system(a, "dialer")
    env.grant(a, P1)
    r = signal(env, a, contact=P1, claimed_state="denied", purpose="*")
    assert r.resolution == "applied_as_event"
    states = {(x["purpose"], x["state"]) for x in env.q("SELECT purpose, state FROM consentvault.state_version WHERE org_id = %s", (a.org_id,))}
    assert states == {("marketing", "denied"), ("*", "denied")}
    later = signal(env, a, contact=P1, claimed_state="permitted", purpose="servicing", wording=a.disclosure)
    assert later.resolution == "conflict_stop_wins"  # a stop on every purpose counts against any purpose


def test_a_second_stop_through_another_system_is_no_change(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.add_system(a, "dialer")
    signal(env, a, contact=P1, claimed_state="denied", system="crm")
    r = signal(env, a, contact=P1, claimed_state="denied", system="dialer")
    assert r.resolution == "no_change"
    assert len(env.outbox(a)) == 1  # only the first stop pushed, to the other system


def test_two_people_do_not_share_a_resolution(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    env.stop(a, P1)
    assert signal(env, a, contact=P2, claimed_state="permitted", wording=a.disclosure).resolution == "applied_as_event"


def test_a_signal_with_an_invalid_contact_is_refused_by_name(env):
    a = env.t.a
    env.add_system(a, "crm")
    with pytest.raises(InvalidContactError):
        signal(env, a, contact="not a phone", claimed_state="denied")


@pytest.mark.parametrize("bad,field", [
    ({"contact": P1, "channel": "sms", "purpose": "marketing", "claimed_state": "denied"}, "external_ref"),
    ({"contact": P1, "channel": "fax", "purpose": "marketing", "claimed_state": "denied", "external_ref": "r"}, "channel"),
    ({"contact": P1, "channel": "sms", "purpose": "marketing", "claimed_state": "maybe", "external_ref": "r"}, "claimed_state"),
    ({"contact": P1, "channel": "sms", "purpose": "Not A Purpose!", "claimed_state": "denied", "external_ref": "r"}, "purpose"),
    ({"contact": P1, "channel": "sms", "purpose": "*", "claimed_state": "permitted", "external_ref": "r"}, "purpose"),
    ({"contact": P1, "channel": "sms", "purpose": "marketing", "claimed_state": "denied", "external_ref": "r", "claimed_at": "yesterday"}, "claimed_at"),
    ({"contact": P1, "channel": "sms", "purpose": "marketing", "claimed_state": "denied", "external_ref": "r", "disclosure_sha256": "abc"}, "disclosure_sha256"),
    ({"contact": P1, "channel": "sms", "purpose": "marketing", "claimed_state": "denied", "external_ref": "r", "verified": True}, "verified"),
])
def test_a_malformed_signal_names_the_field(bad, field):
    with pytest.raises(SignalValidationError) as info:
        parse_signal(bad)
    assert field in info.value.fields


def test_a_signal_body_that_is_not_an_object_is_refused():
    with pytest.raises(SignalValidationError):
        parse_signal(["not", "an", "object"])


def test_the_two_organisations_resolve_the_same_person_independently(env):
    a, b = env.t.a, env.t.b
    env.add_system(a, "crm")
    env.add_system(b, "crm")
    ra = signal(env, a, contact=P1, claimed_state="denied", ref="same-ref")
    rb = signal(env, b, contact=P1, claimed_state="permitted", ref="same-ref", wording=b.disclosure)
    assert (ra.resolution, rb.resolution) == ("applied_as_event", "applied_as_event")
    assert env.fp(a, P1) != env.fp(b, P1)
    assert env.q("SELECT count(*) AS n FROM consentvault.outbox WHERE org_id = %s", (b.org_id,))[0]["n"] == 0
