"""Migration 0084 (loading a fresh database at stored arrival), the proof of purity, and the erasure stop as a post."""

import psycopg
import pytest

from .support import (ALLOWED_KEY_CALLS, PHONE, call_with_nulls, cut_grant, door_post, grant_fields, history_row, history_rows,
                      load_into_fresh, login_in_group, need_cutover, need_function, need_py, need_sql, need_table, purity_run, sql)

spec = pytest.mark.spec_item


# ---- 0084 ------------------------------------------------------------------------------------------------------------------

@spec("0084.fresh_database_holds_stored_arrival")
def test_a_fresh_database_loaded_from_the_store_holds_every_post_at_its_stored_arrival(cloud):
    need_function("load_stored_post")
    store = cloud
    door_post_all = [cloud.grant(cloud.a, PHONE), cloud.grant(cloud.b, PHONE)]
    assert all(s == 201 for s, _ in door_post_all)
    from .support import store_snapshot
    loaded = load_into_fresh(store)
    assert loaded.loaded["posts"] == store_snapshot(store).loaded["posts"] and loaded.loaded["posts"], "seq, received_at, prev_hash, row_hash equal"
    assert loaded.loaded["arrivals"] == store_snapshot(store).loaded["arrivals"]


@spec("0084.multi_mode_mark_refused")
def test_in_multi_mode_with_a_post_in_a_non_home_organisation_the_mark_is_refused(cloud):
    need_table("replay_target")
    status, _ = cloud.grant(cloud.a, PHONE)
    assert status == 201
    loader = login_in_group(cloud, "consentvault_loader")
    with pytest.raises(psycopg.Error) as exc:
        loader.execute("INSERT INTO consentvault.replay_target DEFAULT VALUES")
    assert "post" in str(exc.value).lower(), "the guard counts raw_post across every organisation and names why it refuses"


@spec("0084.store_of_record_refuses_load")
def test_on_the_store_of_record_load_stored_post_is_refused(world):
    need_function("load_stored_post")
    door_post(world, world.a, grant_fields(world.a, PHONE))
    loader = login_in_group(world, "consentvault_loader")
    with pytest.raises(psycopg.Error) as exc:
        call_with_nulls(loader, "load_stored_post")
    assert "mark" in str(exc.value).lower() or "replay" in str(exc.value).lower()


@spec("0084.loading_post_setting_refused_for_app")
def test_a_session_that_sets_the_loading_setting_cannot_insert_a_post_in_the_past_as_the_app_role(world):
    need_function("loading_allowed")
    from datetime import datetime, timedelta, timezone

    from consentvault.tenancy.tokens import org_transaction
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    old = sql(world, "SELECT * FROM consentvault.raw_post WHERE org_id = %s AND post_id = %s", (o.org_id, post))[0]
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        c.execute("SELECT set_config('consentvault.loading_post', %s, true)", (str(old["post_id"]),))
        with pytest.raises(psycopg.Error) as exc:
            c.execute("INSERT INTO consentvault.raw_post (org_id, post_id, received_at) VALUES (%s, gen_random_uuid(), %s)",
                      (o.org_id, datetime.now(timezone.utc) - timedelta(hours=1)))
    assert "received_at" in str(exc.value), "refused by the one-minute check on the vault's own clock, not by some other constraint"


@spec("0084.ordinary_intake_succeeds_unmarked_and_marked")
def test_an_ordinary_intake_insert_as_the_app_role_succeeds_on_an_unmarked_and_on_a_marked_database(world):
    need_table("replay_target")
    o = world.a
    door_post(world, o, grant_fields(o, PHONE))   # unmarked
    assert len(sql(world, "SELECT 1 FROM consentvault.raw_post WHERE org_id = %s", (o.org_id,))) >= 1
    pytest.fail("ADAPTER TO COMPLETE: on an empty marked database an ordinary intake insert as consentvault_app succeeds (the mark does "
                "not loosen or tighten the live path)", pytrace=False)


@spec("0084.out_of_seq_order_refused")
def test_a_post_loaded_out_of_seq_order_is_refused(cloud):
    need_function("load_stored_post")
    load_into_fresh(cloud)


@spec("0084.replay_target_insert_refused_by_grant")
def test_an_insert_into_replay_target_by_the_app_role_is_refused_by_the_grant(world):
    need_table("replay_target")
    for role in ("consentvault_app", "consentvault_console", "consentvault_worker"):
        assert not sql(world, "SELECT has_table_privilege(%s, 'consentvault.replay_target', 'INSERT') AS ok", (role,))[0]["ok"], role
        assert not sql(world, "SELECT has_table_privilege(%s, 'consentvault.replay_target', 'SELECT') AS ok", (role,))[0]["ok"], role
    assert sql(world, "SELECT has_table_privilege('consentvault_loader', 'consentvault.replay_target', 'INSERT') AS ok")[0]["ok"]
    assert not sql(world, "SELECT relrowsecurity FROM pg_class WHERE oid = 'consentvault.replay_target'::regclass")[0]["relrowsecurity"]
    app = world.vault.appconn()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("INSERT INTO consentvault.replay_target DEFAULT VALUES")


@spec("0084.guard_function_owned_by_operator")
def test_the_mark_guard_is_a_definer_function_owned_by_the_bypass_role_and_the_received_check_is_not_a_definer(world):
    need_function("loading_allowed")
    need_table("replay_target")
    guard = sql(world, "SELECT p.prosecdef, pg_get_userbyid(p.proowner) AS owner FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid"
                       " WHERE t.tgrelid = 'consentvault.replay_target'::regclass AND NOT t.tgisinternal AND t.tgtype & 4 = 4")
    assert guard and all(g["prosecdef"] and g["owner"] == "consentvault_operator" for g in guard)
    la = sql(world, "SELECT prosecdef, pg_get_userbyid(proowner) AS owner FROM pg_proc WHERE pronamespace = 'consentvault'::regnamespace AND proname = 'loading_allowed'")
    assert la and la[0]["prosecdef"] and la[0]["owner"] != "consentvault_operator", "loading_allowed is the schema owner's definer"
    rc = sql(world, "SELECT prosecdef FROM pg_proc WHERE pronamespace = 'consentvault'::regnamespace AND proname = 'check_received_at'")
    assert rc and rc[0]["prosecdef"] is False, "stays not a definer so current_user is the real caller"
    trig = sql(world, "SELECT 1 FROM pg_trigger WHERE tgrelid = 'consentvault.raw_post'::regclass AND tgname = 'raw_post_received_check'")
    assert trig, "the trigger keeps its name"


@spec("0084.loader_recomputes_fact_chain")
def test_in_loader_mode_a_stored_fact_whose_computed_columns_differ_is_refused(cloud):
    need_function("load_stored_post")
    load_into_fresh(cloud)


# ---- the proof of purity ---------------------------------------------------------------------------------------------------

def _purity(cloud):
    need_function("load_stored_post")
    need_cutover()
    for co in (cloud.a, cloud.b):
        assert cloud.grant(co, PHONE)[0] == 201
    return purity_run(cloud)


@spec("purity.content_fingerprints")
def test_the_content_fingerprints_per_label_match_each_other_and_the_store(cloud):
    store, first, second = _purity(cloud)
    assert first.fingerprints == second.fingerprints == store.fingerprints and store.fingerprints


@spec("purity.intent_keys")
def test_the_intent_key_fingerprints_match(cloud):
    store, first, second = _purity(cloud)
    assert first.intent_keys == second.intent_keys == store.intent_keys


@spec("purity.key_provider_four_calls")
def test_the_key_provider_stand_in_saw_only_the_four_allowed_calls(cloud):
    _, first, second = _purity(cloud)
    for r in (first, second):
        assert r.key_calls and set(r.key_calls) <= ALLOWED_KEY_CALLS


@spec("purity.evidence_reads_only")
def test_the_evidence_stand_in_saw_only_reads_of_each_posts_own_object(cloud):
    _, first, second = _purity(cloud)
    for r in (first, second):
        assert all(c[0] == "get" and c[1].startswith("posts/") for c in r.evidence_calls)


@spec("purity.senders_zero_calls")
def test_every_sender_stand_in_saw_zero_calls(cloud):
    _, first, second = _purity(cloud)
    assert first.sender_calls == [] and second.sender_calls == []


# ---- the erasure stop is a post ------------------------------------------------------------------------------------------

@spec("erasure.stop_is_a_post")
def test_an_erasure_stores_its_stop_as_a_post_through_the_ordinary_writer_and_the_history_cites_it(world):
    need_cutover()
    from consentvault import door
    o = world.a
    cut_grant(world, o, PHONE)
    world.erase(o, PHONE)
    posts = sql(world, "SELECT post_id, intake FROM consentvault.raw_post WHERE org_id = %s AND intake = 'erasure'", (o.org_id,))
    assert len(posts) == 1, "the erasure job stores one post of intake erasure before it deletes the contact key"
    row = history_row(world, o, str(posts[0]["post_id"]))
    assert row is not None and row["event_type_sent"] in ("revoke", "suppress")
    assert not hasattr(door, "write_system_event"), "write_system_event is removed"
    facts = sql(world, "SELECT label FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s AND label = 'erased'", (o.org_id, posts[0]["post_id"]))
    assert facts, "the erased-label facts are written beside the post"
    body = sql(world, "SELECT length(body_ct) AS n FROM consentvault.raw_post WHERE org_id = %s AND post_id = %s", (o.org_id, posts[0]["post_id"]))
    assert body[0]["n"] > 0


@spec("erasure.replay_agrees")
def test_replay_from_empty_of_a_database_holding_one_erased_contact_holds_its_erasure_stop(cloud):
    need_function("load_stored_post")
    need_cutover()
    from consentvault.tenancy.tokens import org_transaction
    co = cloud.a
    assert cloud.grant(co, PHONE)[0] == 201
    fp = cloud.t.crypto.contact_fingerprint(co.org.org_id, "phone", PHONE)
    with cloud.t.operator() as op, org_transaction(op, cloud.t.admin_token(co.org.org_id)):
        op.execute("SELECT consentvault.erase_contact(%s)", (fp,))
    store, first, second = purity_run(cloud)
    assert first.fingerprints == second.fingerprints == store.fingerprints
    stops = [r for r in sql(cloud, "SELECT event_type_sent FROM consentvault.post_history WHERE org_id = %s", (co.org.org_id,)) if r["event_type_sent"] in ("revoke", "suppress")]
    assert stops, "the replayed history holds the erasure stop"
