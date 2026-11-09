"""Migration 0089 and the cutover window: effect intents, the seed from the old queues, the watermark, the retired functions, and the
refusal to run effects on a replay database. The 'copy of today's store' tests build the database at the migrations the store of
record has, fill it as the old workers do, apply this spec's migrations on top, then run the new fold and the effects."""

import pytest

from .store_copy import CONFIRMATION_STATUSES, OUTBOX_STATUSES, finish_migrations, queue_every_status, sql_one, today_store
from .support import (PHONE, add_push_target, confirmation_intents, cut_grant, door_post, grant_fields, history_rows, intents,
                      login_in_group, need_cutover, need_function, need_table, sql)
from .conftest import _loader_role

spec = pytest.mark.spec_item

OUTBOX_TO_STATE = {"pending": "pending", "failed": "pending", "sent": "unknown", "acknowledged": "sent", "dead": "failed:dead",
                   "superseded": "failed:superseded"}
CONFIRMATION_TO_STATE = {"intent": "pending", "sending": "unknown", "sent": "sent", "delivered": "sent", "failed": "failed:failed",
                         "dead": "failed:dead", "skipped": "failed:skipped"}


def _cutover_copy(request):
    need_function("seed_effect_intents")
    need_table("effect_intent")
    _loader_role(request)
    env, _ = today_store(request)
    queued = queue_every_status(env)
    before = {"outbox": sql_one(env, "SELECT count(*) AS n FROM consentvault.outbox")["n"],
              "confirmation": sql_one(env, "SELECT count(*) AS n FROM consentvault.confirmation_send_intent")["n"]}
    due = sql_one(env, "SELECT count(*) AS n FROM consentvault.outbox WHERE status IN ('pending', 'failed')")["n"]
    finish_migrations(request)
    with env.t.superuser() as su:
        su.execute("SELECT consentvault.seed_effect_intents()")
    return env, queued, before, due


@spec("0089.seed_equals_queues")
def test_seeded_intents_equal_the_outbox_rows_plus_the_confirmation_intents_across_every_organisation(request):
    env, queued, before, _ = _cutover_copy(request)
    with env.t.superuser() as su:
        total = su.execute("SELECT count(*) AS n FROM consentvault.effect_intent WHERE legacy_ref IS NOT NULL").fetchone()["n"]
        again = su.execute("SELECT consentvault.seed_effect_intents()")   # a second seed adds nothing (unique legacy_ref)
        total2 = su.execute("SELECT count(*) AS n FROM consentvault.effect_intent WHERE legacy_ref IS NOT NULL").fetchone()["n"]
    assert total == before["outbox"] + before["confirmation"] and total2 == total
    for org in (env.t.a, env.t.b):
        n = sql_one(env, "SELECT count(*) AS n FROM consentvault.effect_intent WHERE org_id = %s AND legacy_ref IS NOT NULL", (org.org_id,))["n"]
        assert n > 0, "every organisation's queues are seeded, not only the home organisation's"


@spec("0089.seed_state_mapping")
def test_every_old_queue_state_maps_to_its_intent_state(request):
    env, queued, _, _ = _cutover_copy(request)
    for org in (env.t.a, env.t.b):
        for status in OUTBOX_STATUSES:
            row = sql_one(env, "SELECT state FROM consentvault.effect_intent WHERE org_id = %s AND legacy_ref = %s",
                          (org.org_id, str(queued[org.name]["outbox:" + status])))
            assert row["state"] == OUTBOX_TO_STATE[status], ("outbox", status)
        for status in CONFIRMATION_STATUSES:
            row = sql_one(env, "SELECT state FROM consentvault.effect_intent WHERE org_id = %s AND legacy_ref = %s",
                          (org.org_id, str(queued[org.name]["confirmation:" + status])))
            assert row["state"] == CONFIRMATION_TO_STATE[status], ("confirmation", status)


@spec("0089.send_set_is_the_queued_rows")
def test_the_new_fold_and_the_effects_together_send_exactly_the_rows_the_old_workers_had_queued(request):
    env, _, _, due = _cutover_copy(request)
    sent = 0
    for _ in range(10):
        before = len(env.transport.sent)
        env.run_worker()
        if len(env.transport.sent) == before:
            break
    sent = len(env.transport.sent)
    assert sent == due, "the effects layer sends the pending and failed outbox rows, and nothing for a row that was sent, acknowledged, dead or superseded"
    with env.t.superuser() as su:
        states = {r["state"] for r in su.execute("SELECT state FROM consentvault.effect_intent WHERE legacy_ref IS NOT NULL")}
    assert "unknown" in states, "an in-flight row is left for a person, never sent automatically"


@spec("0089.queued_stop_push_delivered")
def test_a_queued_stop_push_in_the_outbox_is_delivered_after_cutover(request):
    need_function("seed_effect_intents")
    _loader_role(request)
    env, _ = today_store(request)
    a = env.t.a
    env.stop(a, "+13055550177")
    stop_rows = sql_one(env, "SELECT count(*) AS n FROM consentvault.outbox WHERE org_id = %s AND status = 'pending'", (a.org_id,))["n"]
    assert stop_rows >= 1
    finish_migrations(request)
    with env.t.superuser() as su:
        su.execute("SELECT consentvault.seed_effect_intents()")
    env.run_worker()
    assert any(b"revoke" in bytes(getattr(r, "body", b"")) or b"stop" in bytes(getattr(r, "body", b"")) for r in env.transport.sent), \
        "the queued stop push reached the connected system"


@spec("0089.watermark_below_no_intent")
def test_a_post_at_or_below_the_watermark_with_no_legacy_event_derives_no_intent(request):
    need_function("seed_effect_intents")
    need_table("effect_watermark")
    pytest.fail("ADAPTER TO COMPLETE: store a post the old fold never finished before the stop, record the watermark below it, run the "
                "watermark-fact job; the post projects (a history row) and derives no intent, and a post above it derives its intents", pytrace=False)


@spec("0089.between_old_stop_and_new_intake")
def test_posts_between_the_old_folds_stop_and_the_new_intake_get_their_effects(request):
    need_table("effect_watermark")
    pytest.fail("ADAPTER TO COMPLETE: posts stored after the old fold stopped and before the new intake deployed are above the watermark "
                "and derive intents", pytrace=False)


@spec("0089.intake_writes_above")
def test_from_the_cutover_deploy_on_the_intake_writes_the_watermark_fact_above_at_arrival(world):
    need_cutover()
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    got = sql(world, "SELECT status FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s AND name = 'effect_watermark'", (o.org_id, post))
    assert got, "a post with no watermark fact is missing a fact and waits"
    assert history_rows(world, o, post_id=post), "and this one did not wait"


@spec("0089.one_pending_intent_per_rule_and_target")
def test_one_new_grant_gives_one_pending_intent_per_enabled_rule_and_target_and_projecting_again_gives_none(world, armed):
    need_cutover()
    from consentvault import door
    from consentvault.rawpost import RawPostWriter
    o = world.a
    add_push_target(o, "crm")
    add_push_target(o, "dialer")
    post = cut_grant(world, o, PHONE)
    got = intents(world, o, post)
    assert sorted(i["state"] for i in got) == ["pending"] * 4, "two enabled rules (sms, email) and two push targets"
    assert len({(i["effect"], i["target"]) for i in got}) == 4
    with world.vault.appconn() as c:
        from consentvault.tenancy.tokens import org_transaction
        with org_transaction(c, world.capture_token(o.org_id)):
            door.project_pending(RawPostWriter(crypto=world.crypto), c, lambda cc: cc.transaction(), door.TenantLedgerBackend(world.crypto, region="US"))
    assert len(intents(world, o, post)) == 4, "projecting again derives none"


@spec("0089.replay_database_refuses_effects")
def test_the_effects_layer_started_on_a_marked_database_exits_by_name_and_sends_nothing(world):
    need_function("is_replay_database")
    need_table("replay_target")
    assert sql(world, "SELECT consentvault.is_replay_database() AS r")[0]["r"] is False
    pytest.fail("ADAPTER TO COMPLETE: on an empty, marked database the claim function and the effects layer's start refuse by name "
                "(is_replay_database), exit non-zero, and the sender stand-ins saw zero calls", pytrace=False)


@spec("item21")
def test_confirmation_enqueue_is_refused_by_name_only_after_the_cutover(world):
    need_cutover()
    import psycopg
    o = world.a
    with world.vault.superuser() as su:
        with pytest.raises(psycopg.Error) as exc:
            su.execute("SELECT consentvault.confirmation_enqueue(gen_random_uuid(), %s)", ("0" * 64,))
    assert "retired" in str(exc.value).lower() or "cutover" in str(exc.value).lower()
