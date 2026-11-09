"""Finding C1: a post today's intake refuses must not be confirmed or pushed after the cutover.

Today every refusal reason (door.decide) writes no event, so it writes no confirmation intent and no push. After the cutover the
history row is written whatever the sender's standing is (``standing``), and intents are derived only from rows whose standing is
``counts``. Each negative test sets up a rule and a push target, lets a VALID sibling post derive its intents (so a build that
derives nothing at all cannot pass), then sends the refused post and asserts: its history row, no intent for it, the
organisation's total intent count unchanged by it, and after the sender and the push worker have run, the text, email and push
stand-ins saw no call for its contact. The facts use the names today's intake uses; ``support.door_post`` is the one place to change.
"""

import pytest
from consentvault.rawpost import Fact
from .support import PHONE2 as _P2  # noqa: F401

from .support import (PHONE, PHONE2, RecordingSenders, Transport, add_push_target, door_post, grant_fields, history_row, intents,
                      need_cutover, run_effects, stop_fields, tenant_facts)

spec = pytest.mark.spec_item


def _setup(world, armed):
    need_cutover()
    o = world.a
    add_push_target(o, "crm")
    sibling = door_post(world, o, grant_fields(o, PHONE2))
    assert history_row(world, o, sibling)["standing"] == "counts"
    assert intents(world, o, sibling), "the valid sibling derives its intents (a rule is on and a push target is connected)"
    return o, sibling, len(intents(world, o))


def _nothing_went_out(world, stack, o, post, sibling, total):
    assert intents(world, o, post) == [], "a refused sender must derive no confirmation intent and no push"
    assert len(intents(world, o)) == total, "and the organisation's total intent count did not move"
    transport, senders = Transport(), RecordingSenders()
    stack.run()
    run_effects(world, transport=transport, senders=senders, crypto=world.crypto, custody=world.vault.custody)
    fp = o.fp(PHONE)
    assert all(m["to"] == PHONE2 for m in stack.twilio.sent), "the text stand-in saw only the sibling's contact"
    assert all(PHONE not in m["to"] for m in stack.email.sent)
    assert not any(fp.encode() in bytes(r.body) or PHONE.encode() in bytes(r.body) for r in transport.sent), "the push stand-in saw no call for it"
    assert all(PHONE not in str(c) for c in senders.calls)
    assert transport.sent, "and the sibling's push did go out"


def _refused(world, armed, stack, facts, standing, fields=None, body=None):
    o, sibling, total = _setup(world, armed)
    post = door_post(world, o, fields or grant_fields(o, PHONE), facts=facts, body=body)
    row = history_row(world, o, post)
    assert row is not None, "the post must have its history row whatever the standing is"
    if standing is not None:
        assert row["standing"] == standing
    else:
        assert row["standing"] != "counts"
    _nothing_went_out(world, stack, o, post, sibling, total)
    return row


@spec("C1.invalid_signature")
def test_a_forged_signature_derives_no_intent(world, armed, stack):
    _refused(world, armed, stack, [Fact("vault", "request_signature", "invalid"), Fact("vault", "replay", "fresh")], "not_authenticated:invalid")


@spec("C1.unsigned")
def test_an_unsigned_post_derives_no_intent(world, armed, stack):
    _refused(world, armed, stack, [Fact("vault", "replay", "fresh")], "not_authenticated:unsigned")


@spec("C1.stale_grant")
def test_a_grant_with_a_stale_timestamp_derives_no_intent(world, armed, stack):
    _refused(world, armed, stack, tenant_facts(edge="stale"), "stale_timestamp")


@spec("C1.lookup_failed")
def test_a_post_whose_site_key_lookup_failed_waits_for_the_lookup_and_then_projects(hw, monkeypatch):
    need_cutover()
    from consentvault import api
    from isolation.cloud_harness import attempts_of, raw_posts
    from isolation.test_door_site_key_state import _down, _orgs
    from isolation.test_hardening_wave2 import _edge_body, _edge_post, _envelope, _site_key
    from .support import sql
    a = hw.cloud.a
    assert hw.cloud.grant(a, PHONE2)[0] == 201                        # the valid sibling
    key = _site_key(hw, a)
    total = len(sql(hw, "SELECT 1 FROM consentvault.post_history WHERE org_id = %s", (a.org.org_id,)))
    with monkeypatch.context() as m:
        _down(m)
        _edge_post(hw, _envelope(key, _edge_body(a, key)))
    row = raw_posts(hw.t, a.org.org_id)[-1] if False else [r for r in raw_posts(hw.t, sql(hw, "SELECT consentvault.home_org() AS h")[0]["h"])][-1]
    assert not sql(hw, "SELECT 1 FROM consentvault.post_history WHERE post_id = %s", (row["post_id"],)), "a passing fault is never a final reason: it waits"
    reasons = attempts_of(hw.t, row)
    assert reasons and all("sitekey" in r.lower().replace("_", "") for r in reasons), f"the attempt names the site-key lookup: {reasons}"
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))                   # the lookup answers now
    assert len(sql(hw, "SELECT 1 FROM consentvault.post_history WHERE org_id = %s", (a.org.org_id,))) == total + 1, "once the lookup is answered the post projects"


@spec("C1.no_credential")
def test_a_tenant_post_with_no_credential_derives_no_intent(world, armed, stack):
    _refused(world, armed, stack, tenant_facts(credential=False), "no_credential")


@spec("C1.second_copy")
def test_a_second_copy_of_a_counted_request_derives_no_intent(world, armed, stack):
    need_cutover()
    o = world.a
    add_push_target(o, "crm")
    first = door_post(world, o, grant_fields(o, PHONE2), request_key="req-1")
    total = len(intents(world, o))
    assert history_row(world, o, first)["earliest_copy"] is True and total, "the first copy counts and derives"
    again = door_post(world, o, grant_fields(o, PHONE2), request_key="req-1")
    row = history_row(world, o, again)
    assert row is not None and row["earliest_copy"] is False and row["standing"] == "request_seen_before"
    assert intents(world, o, again) == [] and len(intents(world, o)) == total
    stack.run()
    assert len(stack.twilio.sent) == 1, "the replayed grant is not confirmed a second time"


@pytest.mark.parametrize("name,body,reason", [
    pytest.param("text", None, "a_text_is_not_consent", id="text", marks=spec("C1.text")),
    pytest.param("unreadable", b"\xff\x00{not json", "not_json", id="unreadable", marks=spec("C1.unreadable"))])
def test_a_text_or_an_unreadable_body_derives_no_intent(world, armed, stack, name, body, reason):
    fields = grant_fields(world.a, PHONE, contact_verification="inbound_keyword") if name == "text" else None
    row = _refused(world, armed, stack, None, reason, fields=fields, body=body) if name == "unreadable" else \
        _refused_text(world, armed, stack, fields, reason)
    assert row["standing"] == reason, "the exact reason, not only 'not counted'"


def _refused_text(world, armed, stack, fields, reason):
    from .support import good_facts
    return _refused(world, armed, stack, good_facts(), reason, fields=fields)


@spec("C1.grant_without_source")
def test_a_grant_with_no_source_derives_pushes_as_today_and_no_confirmation(world, armed, stack):
    o, sibling, total = _setup(world, armed)
    fields = grant_fields(o, PHONE)
    fields.pop("source_id")
    post = door_post(world, o, fields)
    row = history_row(world, o, post)
    assert row["source_id_sent"] is None and row["standing"] == "counts"
    derived = intents(world, o, post)
    assert derived and all(i["effect"] != "confirmation" for i in derived), "pushes as today, no confirmation intent"
    stack.run()
    assert all(m["to"] == PHONE2 for m in stack.twilio.sent), "no text for the contact whose grant named no source"


@spec("C1.soft_stop_positive")
def test_a_stop_with_a_stale_timestamp_still_counts_and_derives_its_pushes(world, armed, stack):
    o, sibling, total = _setup(world, armed)
    post = door_post(world, o, stop_fields(o, PHONE), facts=[Fact("vault", "request_signature", "stale_timestamp"), Fact("vault", "replay", "fresh")])
    row = history_row(world, o, post)
    assert row["standing"] == "counts", "a soft stale_timestamp on a stop reads counts, as today"
    got = intents(world, o, post)
    assert got and all(i["effect"] != "confirmation" for i in got), "a stop derives push intents only"
    assert len({i["target"] for i in got}) == 1, "one push target is connected, so one push target is derived"
    transport, senders = Transport(), RecordingSenders()
    run_effects(world, transport=transport, senders=senders, crypto=world.crypto, custody=world.vault.custody)
    assert any(o.fp(PHONE).encode() in bytes(r.body) for r in transport.sent), "and the push went out"
