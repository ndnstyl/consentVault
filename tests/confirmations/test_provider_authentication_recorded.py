"""The provider's signature is recorded beside every validly signed reply before the seen-message check: a reply that is not a
stop, and the second copy of any reply, are settled by the projection like every other post, never left as awaiting
authentication for ever (and re-read on every rebuild)."""

import uuid

from contract_world.confirm import text_in

SENDER = "+13055550151"


def _facts_by_post(world, o):
    rows = world.sql(o, "SELECT p.post_id, f.name FROM consentvault.raw_post p LEFT JOIN consentvault.raw_post_fact f"
                        " ON f.org_id = p.org_id AND f.post_id = p.post_id WHERE p.org_id = %s AND p.intake = 'sms_reply'", (o.org_id,))
    out: dict = {}
    for r in rows:
        out.setdefault(str(r["post_id"]), set()).add(r["name"])
    return out


def test_every_validly_signed_reply_and_every_second_copy_is_authenticated_and_settled(world, stack, armed):
    o = world.a
    before = set(_facts_by_post(world, o))
    sid_stop, sid_text = "SM" + uuid.uuid4().hex[:30], "SM" + uuid.uuid4().hex[:30]
    assert text_in(armed, "STOP", sender=SENDER, sid=sid_stop).status == 200
    assert text_in(armed, "STOP", sender=SENDER, sid=sid_stop).status == 200      # the provider's retry: a second copy
    assert text_in(armed, "thanks, see you then", sender=SENDER, sid=sid_text).status == 200
    assert text_in(armed, "thanks, see you then", sender=SENDER, sid=sid_text).status == 200
    facts = {p: f for p, f in _facts_by_post(world, o).items() if p not in before}
    assert len(facts) == 4
    for post, names in facts.items():
        assert "request_signature" in names, (post, names)
    stack.service.rebuild_replies(o.org_id)
    for post, names in _facts_by_post(world, o).items():
        if post in facts:
            assert names & {"event_derived", "event_not_derived"}, (post, names)
    assert len(world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke' AND contact_fp IS NOT NULL",
                         (o.org_id,))) >= 1
