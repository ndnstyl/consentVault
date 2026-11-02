"""confirmations.md section 7: erasing a contact deletes what the confirmation service kept about it under the organization's key
(an unkept reply, the connection-test reply), and only a grant queues a confirmation (the database checks it, not only the caller)."""

import uuid

from consentvault.tenancy.tokens import org_transaction

from contract_world.confirm import connect_twilio, set_sender, text_in, verify_inbound

NY = "+13055550150"


def test_an_unkept_reply_from_a_number_later_captured_is_deleted_by_its_erasure(world, stack, armed):
    o = world.a
    text_in(armed, "who is this", sender=NY, sid="SMearly")  # no key yet: kept under the organization's key, number sealed
    fp = o.fp(NY)
    q = "SELECT 1 FROM consentvault.confirmation_reply WHERE org_id = %s AND from_fp = %s AND key_kind = 'org'"
    assert len(world.sql(o, q, (o.org_id, fp))) == 1
    world.capture(o, NY)
    world.erase(o, NY)
    assert world.sql(o, q, (o.org_id, fp)) == []


def test_a_connection_test_reply_from_a_number_later_captured_is_deleted_by_its_erasure(world, stack):
    o = world.a
    set_sender(o.boss)
    acct = connect_twilio(stack, o.boss)
    verify_inbound(stack, acct, from_number=NY)
    fp = o.fp(NY)
    q = "SELECT 1 FROM consentvault.confirmation_connect_test WHERE org_id = %s AND from_fp = %s"
    assert len(world.sql(o, q, (o.org_id, fp))) == 1
    world.capture(o, NY)
    world.erase(o, NY)
    assert world.sql(o, q, (o.org_id, fp)) == []


def test_the_database_queues_a_confirmation_only_for_a_grant(world, stack, armed):
    """Called directly with a stop event the enqueue function answers 0 and queues nothing, whatever rules are on."""
    o = world.a
    world.capture(o, NY)
    stop = world.stop(o, NY)
    before = len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s", (o.org_id,)))
    fp = o.fp(NY)
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        n = c.execute("SELECT consentvault.confirmation_enqueue(%s, %s) AS n", (uuid.UUID(stop.event_id), fp)).fetchone()["n"]
    assert n == 0
    assert len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s", (o.org_id,))) == before
