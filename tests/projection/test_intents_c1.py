"""Finding C1: a post today's intake refuses must not be confirmed or pushed after the cutover.

Today every refusal reason (door.decide) writes no event, so it writes no confirmation intent and no push. After the cutover the
history row is written whatever the sender's standing is (the row records it in ``standing``), so the intents are derived only
from rows whose standing is ``counts``. One negative test per old refusal reason, each a post that arrives after the cutover with
a rule on and a push target connected; and the one positive: a stop with a stale timestamp counts, as today, and derives its pushes.
The facts are written with the names today's intake uses; if the build renames a fact, ``support.door_post`` is the one place to change.
"""

import pytest
from consentvault.rawpost import Fact

from .support import (add_push_target, door_post, grant_fields, history_row, intents, need_cutover, stop_fields, tenant_facts, PHONE)


def _setup(world, armed):
    need_cutover()
    o = world.a
    add_push_target(o, "crm")
    return o


def _post_and_check(world, o, post, *, standing):
    row = history_row(world, o, post)
    assert row is not None, "the post must have its history row whatever the standing is"
    assert row["standing"] == standing
    assert intents(world, o, post) == [], "a refused sender must derive no confirmation intent and no push"


@pytest.mark.spec_item("C1.invalid_signature")
def test_a_forged_signature_derives_no_intent(world, armed):
    o = _setup(world, armed)
    post = door_post(world, o, grant_fields(o, PHONE), facts=[Fact("vault", "request_signature", "invalid"), Fact("vault", "replay", "fresh")])
    _post_and_check(world, o, post, standing="not_authenticated:invalid")


@pytest.mark.spec_item("C1.unsigned")
def test_an_unsigned_post_derives_no_intent(world, armed):
    o = _setup(world, armed)
    post = door_post(world, o, grant_fields(o, PHONE), facts=[Fact("vault", "replay", "fresh")])
    _post_and_check(world, o, post, standing="not_authenticated:unsigned")


@pytest.mark.spec_item("C1.stale_grant")
def test_a_grant_with_a_stale_timestamp_derives_no_intent(world, armed):
    o = _setup(world, armed)
    post = door_post(world, o, grant_fields(o, PHONE), facts=tenant_facts(edge="stale"))
    _post_and_check(world, o, post, standing="stale_timestamp")


@pytest.mark.spec_item("C1.lookup_failed")
def test_a_post_whose_site_key_lookup_failed_waits_and_derives_no_intent_while_it_waits(world, armed):
    o = _setup(world, armed)
    post = door_post(world, o, grant_fields(o, PHONE), facts=tenant_facts(credential=False, lookup="failed:down"))
    assert history_row(world, o, post) is None, "a passing fault is never a final reason: the post waits, it is not recorded as refused"
    assert intents(world, o, post) == []
    attempts = world.sql(o, "SELECT 1 FROM consentvault.projection_attempt WHERE org_id = %s AND post_id = %s", (o.org_id, post))
    assert attempts, "the wait is recorded as an attempt"


@pytest.mark.spec_item("C1.no_credential")
def test_a_tenant_post_with_no_credential_derives_no_intent(world, armed):
    o = _setup(world, armed)
    post = door_post(world, o, grant_fields(o, PHONE), facts=tenant_facts(credential=False))
    _post_and_check(world, o, post, standing="no_credential")


@pytest.mark.spec_item("C1.second_copy")
def test_a_second_copy_of_a_counted_request_derives_no_intent(world, armed):
    o = _setup(world, armed)
    first = door_post(world, o, grant_fields(o, PHONE), request_key="req-1")
    again = door_post(world, o, grant_fields(o, PHONE), request_key="req-1")
    assert history_row(world, o, first)["earliest_copy"] is True and intents(world, o, first), "the first copy counts and derives"
    row = history_row(world, o, again)
    assert row is not None and row["earliest_copy"] is False
    assert intents(world, o, again) == [], "the replayed grant gets no confirmation intent and no push"


@pytest.mark.parametrize("name,body", [pytest.param("text", None, id="text", marks=pytest.mark.spec_item("C1.text")),
                                       pytest.param("unreadable", b"\xff\x00{not json", id="unreadable", marks=pytest.mark.spec_item("C1.unreadable"))])
def test_a_text_or_an_unreadable_body_derives_no_intent(world, armed, name, body):
    o = _setup(world, armed)
    if name == "text":
        fields = grant_fields(o, PHONE, contact_verification="inbound_keyword")
        post = door_post(world, o, fields, intake="signal")
    else:
        post = door_post(world, o, None, body=body)
    row = history_row(world, o, post)
    assert row is not None
    assert row["standing"] != "counts", "a text is a record of a text and an unreadable body is stored: neither is counted"
    assert intents(world, o, post) == []


@pytest.mark.spec_item("C1.grant_without_source")
def test_a_grant_with_no_source_derives_pushes_as_today_and_no_confirmation(world, armed):
    o = _setup(world, armed)
    fields = grant_fields(o, PHONE)
    fields.pop("source_id")
    post = door_post(world, o, fields)
    row = history_row(world, o, post)
    assert row["source_id_sent"] is None and row["standing"] == "counts"
    derived = intents(world, o, post)
    assert derived and all(i["effect"] != "confirmation" for i in derived), "pushes as today, no confirmation intent"


@pytest.mark.spec_item("C1.soft_stop_positive")
def test_a_stop_with_a_stale_timestamp_still_counts_and_derives_its_pushes(world, armed):
    o = _setup(world, armed)
    post = door_post(world, o, stop_fields(o, PHONE), facts=[Fact("vault", "request_signature", "stale_timestamp"), Fact("vault", "replay", "fresh")])
    row = history_row(world, o, post)
    assert row["standing"] == "counts", "a soft stale_timestamp on a stop reads counts, as today"
    got = intents(world, o, post)
    assert got and all(i["effect"] != "confirmation" for i in got), "a stop derives push intents only"
    assert len({i["target"] for i in got}) == 1, "one push target is connected, so one push target is derived"
