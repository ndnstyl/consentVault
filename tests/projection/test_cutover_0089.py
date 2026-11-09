"""Migration 0089 and the cutover window: effect intents, the seed from the old queues, the watermark, the retired functions, and the
refusal to run effects on a replay database. The 'copy of today's store' tests build the database at the migrations the store of
record has, fill it as the old workers do, apply this spec's migrations on top, run the watermark job, then run the NEW fold and
the NEW effects layer (call shapes in support.py). The old outbox worker must be refused after the window."""

import pytest

from .conftest import _loader_role
from .store_copy import (CONFIRMATION_STATUSES, OUTBOX_STATUSES, finish_migrations, project_org, queue_every_status, queue_quiet, sql_one,
                         store_unprojected, today_store, watermark_fact)
from .support import (PHONE, RecordingSenders, Transport, add_push_target, cut_grant, door_post, grant_fields, history_rows, intents,
                      need_cutover, need_function, need_py, need_table, new_database, run_effects, sql)

spec = pytest.mark.spec_item

OUTBOX_TO_STATE = {"pending": "pending", "failed": "pending", "sent": "unknown", "acknowledged": "sent", "dead": "failed:dead",
                   "superseded": "failed:superseded"}
CONFIRMATION_TO_STATE = {"intent": "pending", "sending": "unknown", "sent": "sent", "delivered": "sent", "failed": "failed:failed",
                         "dead": "failed:dead", "skipped": "failed:skipped"}


def _needs():
    need_function("seed_effect_intents")
    need_table("effect_intent")
    need_table("effect_watermark")
    need_py("consentvault.effects", "run_once")
    need_py("consentvault.cutover", "write_watermark_facts")


def _window(request, *, unprojected=False):
    """Today's store, filled; optionally one post stored and never projected (the old fold had stopped); the window's steps in order:
    apply the migrations, seed, run the watermark-fact job. Returns the environment and what was queued."""
    _needs()
    _loader_role(request)
    env, _ = today_store(request)
    queued = queue_every_status(env)
    quiet = queue_quiet(env, env.t.a)
    late = store_unprojected(env, env.t.a, "+13055550188") if unprojected else None
    due = sql_one(env, "SELECT count(*) AS n FROM consentvault.outbox WHERE status IN ('pending', 'failed')")["n"]
    finish_migrations(request)
    write = need_py("consentvault.cutover", "write_watermark_facts")
    v = env.t
    write(v.operator, v.key, env.custody, v.crypto)
    with v.superuser() as su:
        su.execute("SELECT consentvault.seed_effect_intents()")
    return env, queued, quiet, late, due


def _run(env, transport, senders):
    for _ in range(6):
        before = len(transport.sent) + len(senders.calls)
        run_effects(env, transport=transport, senders=senders, crypto=env.t.crypto, custody=env.custody)
        if len(transport.sent) + len(senders.calls) == before:
            break


def _pending_ids(env, confirmation: bool) -> set:
    op = "=" if confirmation else "<>"
    with env.t.superuser() as su:
        return {str(r["intent_id"]) for r in su.execute(
            f"SELECT intent_id FROM consentvault.effect_intent WHERE state = 'pending' AND effect {op} 'confirmation'")}


@spec("0089.seed_equals_queues")
def test_seeded_intents_equal_the_outbox_rows_plus_the_confirmation_intents_across_every_organisation(request):
    env, queued, *_ = _window(request)
    outbox = sql_one(env, "SELECT count(*) AS n FROM consentvault.outbox")["n"]
    conf = sql_one(env, "SELECT count(*) AS n FROM consentvault.confirmation_send_intent")["n"]
    with env.t.superuser() as su:
        total = su.execute("SELECT count(*) AS n FROM consentvault.effect_intent WHERE legacy_ref IS NOT NULL").fetchone()["n"]
        su.execute("SELECT consentvault.seed_effect_intents()")   # a second seed adds nothing (unique legacy_ref)
        total2 = su.execute("SELECT count(*) AS n FROM consentvault.effect_intent WHERE legacy_ref IS NOT NULL").fetchone()["n"]
    assert total == outbox + conf and total2 == total
    for org in (env.t.a, env.t.b):
        assert sql_one(env, "SELECT count(*) AS n FROM consentvault.effect_intent WHERE org_id = %s AND legacy_ref IS NOT NULL", (org.org_id,))["n"] > 0


@spec("0089.seed_state_mapping")
def test_every_old_queue_state_maps_to_its_intent_state(request):
    env, queued, *_ = _window(request)
    for org in (env.t.a, env.t.b):
        for status in OUTBOX_STATUSES:
            row = sql_one(env, "SELECT state FROM consentvault.effect_intent WHERE org_id = %s AND legacy_ref = %s", (org.org_id, str(queued[org.name]["outbox:" + status])))
            assert row["state"] == OUTBOX_TO_STATE[status], ("outbox", status)
        for status in CONFIRMATION_STATUSES:
            row = sql_one(env, "SELECT state FROM consentvault.effect_intent WHERE org_id = %s AND legacy_ref = %s", (org.org_id, str(queued[org.name]["confirmation:" + status])))
            assert row["state"] == CONFIRMATION_TO_STATE[status], ("confirmation", status)


@spec("0089.send_set_is_the_queued_rows")
def test_the_new_fold_watermark_job_and_effects_send_exactly_the_seeded_pending_intents_and_the_old_worker_is_refused(request):
    env, queued, quiet, late, due = _window(request)
    push_ids, conf_ids = _pending_ids(env, False), _pending_ids(env, True)
    assert push_ids and conf_ids and len(push_ids) >= due
    with pytest.raises(Exception) as old:
        env.run_worker()
    assert "effect" in str(old.value).lower() or "retired" in str(old.value).lower(), "the old outbox worker is refused by name"
    transport, senders = Transport(), RecordingSenders()
    _run(env, transport, senders)
    keys = transport.keys()
    assert sorted(keys) == sorted(push_ids), "every pending push intent is sent once, by intent id, and nothing else is"
    assert {c["idempotency_key"] for c in senders.calls} <= conf_ids, "a confirmation goes out only for a seeded pending intent"
    states = {str(r["intent_id"]): r["state"] for r in sql(env.t, "SELECT intent_id, state FROM consentvault.effect_intent")}
    assert all(states[i] == "sent" for i in push_ids), "the intent ends sent"
    assert all(states[i] not in ("pending", "claimed") for i in conf_ids), "every pending confirmation reached its send-time checks and ended"
    assert all(c["idempotency_key"] == str(c["intent_id"]) for c in senders.calls)
    assert intents_for_post(env, env.t.a, quiet["post_id"]) == [], "a post at or below the watermark with no queued row derives nothing"
    assert not any(quiet["fp"].encode() in bytes(r.body) for r in transport.sent), "and nothing was sent for it"
    unknown = [i for i, st in states.items() if st == "unknown"]
    assert unknown and not set(unknown) & set(keys), "an in-flight row is left for a person, never sent automatically"


def intents_for_post(env, org, post_id):
    return sql(env.t, "SELECT * FROM consentvault.effect_intent WHERE org_id = %s AND post_id = %s", (org.org_id, post_id))


@spec("0089.queued_stop_push_delivered")
def test_a_queued_stop_push_in_the_outbox_is_delivered_by_the_effects_layer_after_cutover(request):
    _needs()
    _loader_role(request)
    env, _ = today_store(request)
    a = env.t.a
    env.stop(a, "+13055550177")
    finish_migrations(request)
    v = env.t
    need_py("consentvault.cutover", "write_watermark_facts")(v.operator, v.key, env.custody, v.crypto)
    with v.superuser() as su:
        su.execute("SELECT consentvault.seed_effect_intents()")
    want = _pending_ids(env, False)
    transport, senders = Transport(), RecordingSenders()
    _run(env, transport, senders)
    assert want and sorted(transport.keys()) == sorted(want)
    assert any(b"revoke" in bytes(r.body) or b"stop" in bytes(r.body) for r in transport.sent), "the stop push reached the connected system"
    assert all(r["state"] == "sent" for r in sql(env.t, "SELECT state FROM consentvault.effect_intent WHERE intent_id::text = ANY(%s)", (list(want),)))


@spec("0089.watermark_below_no_intent")
def test_a_post_at_or_below_the_watermark_projects_to_history_and_derives_no_intent_while_a_post_above_it_does(request):
    env, queued, quiet, late, _ = _window(request, unprojected=True)
    a = env.t.a
    assert watermark_fact(env, a, quiet["post_id"]) == "below"
    project_org(env, a)
    assert sql(env.t, "SELECT 1 FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (a.org_id, quiet["post_id"])), "it projects"
    assert intents_for_post(env, a, quiet["post_id"]) == []
    assert watermark_fact(env, a, late) == "above"
    assert intents_for_post(env, a, late), "the post above the watermark derives its intents"


@spec("0089.between_old_stop_and_new_intake")
def test_posts_between_the_old_folds_stop_and_the_new_intake_get_their_effects(request):
    env, queued, quiet, late, _ = _window(request, unprojected=True)
    a = env.t.a
    project_org(env, a)
    assert watermark_fact(env, a, late) == "above"
    got = intents_for_post(env, a, late)
    assert got and {i["state"] for i in got} == {"pending"}
    transport, senders = Transport(), RecordingSenders()
    _run(env, transport, senders)
    assert {i["state"] for i in intents_for_post(env, a, late)} <= {"sent", "failed:skipped"} or all(i["state"] != "pending" for i in intents_for_post(env, a, late))


@spec("0089.intake_writes_above")
def test_from_the_cutover_deploy_on_the_intake_writes_the_watermark_fact_above_at_arrival_through_the_http_door(cloud):
    need_cutover()
    from isolation.cloud_harness import facts_of, raw_posts
    status, answer = cloud.grant(cloud.a, PHONE)
    assert status == 201, answer
    (row,) = [r for r in raw_posts(cloud.t, cloud.a.org.org_id) if str(r["post_id"]) == answer["post_id"]]
    assert facts_of(cloud.t, row).get("effect_watermark") == "above"
    assert sql(cloud, "SELECT 1 FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (cloud.a.org.org_id, answer["post_id"])), "and the post did not wait"


@spec("0089.one_pending_intent_per_rule_and_target")
def test_one_new_grant_gives_one_pending_intent_per_enabled_rule_and_target_and_projecting_again_gives_none(world, armed):
    need_cutover()
    from .support import reproject
    o = world.a
    add_push_target(o, "crm")
    add_push_target(o, "dialer")
    post = cut_grant(world, o, PHONE)
    got = intents(world, o, post)
    assert sorted(i["state"] for i in got) == ["pending"] * 4, "two enabled rules (sms, email) and two push targets"
    assert len({(i["effect"], i["target"]) for i in got}) == 4
    reproject(world, o)
    assert len(intents(world, o, post)) == 4, "projecting again derives none"


@spec("0089.replay_database_refuses_effects")
def test_the_effects_layer_started_on_a_marked_database_exits_by_name_and_sends_nothing(world):
    need_function("is_replay_database")
    need_table("replay_target")
    need_py("consentvault.effects", "run_once")
    import psycopg

    from conftest import _dsn
    from urllib.parse import urlparse
    port = urlparse(world.vault.super_dsn).port
    name = new_database(port)
    dsn = _dsn(port, name, "postgres")
    with psycopg.connect(dsn, autocommit=True) as su:
        assert su.execute("SELECT consentvault.is_replay_database()").fetchone()[0] is False
        su.execute("INSERT INTO consentvault.replay_target DEFAULT VALUES")
        assert su.execute("SELECT consentvault.is_replay_database()").fetchone()[0] is True
    transport, senders = Transport(), RecordingSenders()
    from consentvault import db
    with db.connect(dsn) as conn:
        with pytest.raises(Exception) as exc:
            need_py("consentvault.effects", "run_once")(conn, crypto=world.crypto, custody=world.vault.custody, transport=transport,
                                                       senders=senders, clock=lambda: None)
    assert "replay" in str(exc.value).lower()
    assert transport.sent == [] and senders.calls == []


@spec("item21")
def test_confirmation_enqueue_is_refused_by_name_only_after_the_cutover(world):
    need_cutover()
    import psycopg
    with world.vault.superuser() as su:
        with pytest.raises(psycopg.Error) as exc:
            su.execute("SELECT consentvault.confirmation_enqueue(gen_random_uuid(), %s)", ("0" * 64,))
    assert "retired" in str(exc.value).lower() or "cutover" in str(exc.value).lower()
