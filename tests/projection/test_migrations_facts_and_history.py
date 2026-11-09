"""Migrations 0080 (fact status, order and chain), 0081 (reroute), 0082 (the history table), 0083 (outcomes): the yes/no tests
the design lists under each. Every test starts with the precondition that names the missing migration piece."""

import threading
import uuid

import psycopg
import pytest

from .support import (EMAIL, PHONE, PHONE2, cut_grant, door_post, fact_chain, grant_fields, history_row, history_rows,
                      in_threads, login_in_group, need_columns, need_cutover, need_function, need_sql, need_table, sql,
                      stop_fields, tenant_facts, write_fact)

spec = pytest.mark.spec_item


# ---- 0080 ------------------------------------------------------------------------------------------------------------------

@spec("0080.columns")
def test_0080_adds_the_status_label_order_and_chain_columns_and_nothing_changes_shape(world):
    need_columns("raw_post_fact", "status", "label", "fact_seq", "observed_at", "fact_sha256", "prev_fact_sha256")
    cols = {r["column_name"]: r for r in sql(world, "SELECT column_name, data_type, is_nullable FROM information_schema.columns"
                                                     " WHERE table_schema = 'consentvault' AND table_name = 'raw_post_fact'")}
    assert {"status", "label", "fact_seq", "observed_at", "fact_sha256", "prev_fact_sha256"} <= set(cols)
    assert cols["value_ct"]["data_type"] == "bytea" and cols["recorded_at"]["data_type"] == "timestamp with time zone"
    assert cols["status"]["is_nullable"] == "YES", "rows written before the migration keep a NULL status"


@spec("0080.app_cannot_supply_computed_columns")
def test_an_app_insert_that_supplies_the_hash_or_the_clock_is_refused_by_the_grant(world):
    need_columns("raw_post_fact", "status", "label", "fact_sha256", "observed_at", "prev_fact_sha256", "fact_seq")
    for role in ("consentvault_app", "consentvault_console"):
        for col in ("status", "label"):
            assert sql(world, "SELECT has_column_privilege(%s, 'consentvault.raw_post_fact', %s, 'INSERT') AS ok", (role, col))[0]["ok"], (role, col)
        for col in ("fact_sha256", "observed_at", "prev_fact_sha256", "fact_seq"):
            assert not sql(world, "SELECT has_column_privilege(%s, 'consentvault.raw_post_fact', %s, 'INSERT') AS ok", (role, col))[0]["ok"], (role, col)
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        write_fact(world, o, post, "late_fact", {"x": 1}, extra={"fact_sha256": "0" * 64})


@spec("0080.database_computes_the_chain")
def test_the_database_stamps_order_time_and_hashes_and_each_fact_chains_from_the_one_before(world):
    need_columns("raw_post_fact", "fact_seq", "observed_at", "fact_sha256", "prev_fact_sha256")
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    a = write_fact(world, o, post, "n1", 1)
    b = write_fact(world, o, post, "n2", 2)
    assert a["fact_seq"] is not None and b["fact_seq"] == a["fact_seq"] + 1
    assert b["prev_fact_sha256"] == a["fact_sha256"] and a["observed_at"] is not None
    first = sql(world, "SELECT facts_sha256 FROM consentvault.raw_post WHERE org_id = %s AND post_id = %s", (o.org_id, post))[0]["facts_sha256"]
    assert a["prev_fact_sha256"] == first, "the first later fact chains from the post row's facts digest"


@spec("0080.second_succeeded_row_is_lost_race")
def test_a_second_succeeded_row_for_one_post_and_name_lands_as_lost_race(world):
    need_columns("raw_post_fact", "status", "label")
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    first = write_fact(world, o, post, "credential", {"state": "verified"}, status="value", label="retry")
    second = write_fact(world, o, post, "credential", {"state": "revoked"}, status="value", label="retry")
    assert first["status"] == "value"
    assert second["status"] == "lost_race", "the retry writer re-inserts a second succeeded row as lost_race"


@spec("0080.concurrent_writers_one_chain")
def test_two_concurrent_fact_writers_on_one_post_leave_one_unbroken_chain(world):
    need_columns("raw_post_fact", "fact_seq", "prev_fact_sha256", "fact_sha256")
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    in_threads(*[lambda i=i: [write_fact(world, o, post, f"w{i}-{n}", n) for n in range(5)] for i in range(2)])
    chain = fact_chain(world, o, post)
    assert len(chain) == 10
    for before, after in zip(chain, chain[1:]):
        assert after["prev_fact_sha256"] == before["fact_sha256"] and after["fact_seq"] == before["fact_seq"] + 1


@spec("0080.two_arrival_facts_of_one_name")
def test_an_arrival_carrying_two_facts_of_one_name_stores_and_the_fold_reads_the_lowest_order(world):
    need_columns("raw_post_fact", "fact_seq", "status")
    from consentvault.rawpost import Fact
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE), facts=[Fact("vault", "request_signature", "valid"), Fact("vault", "request_signature", "invalid"),
                                                              Fact("vault", "replay", "fresh"), Fact("vault", "authenticated_by", "system")])
    rows = [r for r in sql(world, "SELECT * FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s AND name = 'request_signature'"
                                  " ORDER BY fact_seq", (o.org_id, post))]
    assert len(rows) == 2, "both arrival facts store, no store aborts"
    assert history_row(world, o, post)["standing"] == "counts", "the fold reads the lowest fact_seq, which is the valid one"


@spec("0080.pre_0080_arrival_credential")
def test_a_post_stored_before_the_migration_projects_using_the_credential_its_arrival_facts_hold(world, request):
    need_cutover()
    need_columns("raw_post_fact", "status")
    _apply_in_two_stages(request)
    pytest.fail("ADAPTER TO COMPLETE: build a tenant post under today's schema, apply the migrations above it, run the backfill, and "
                "read that the history row's credential is the arrival fact's value", pytrace=False)


@spec("0080.pre_0080_no_legacy_event")
def test_a_post_stored_before_the_migration_with_no_legacy_event_projects_after_the_backfill(world, request):
    need_cutover()
    need_columns("raw_post_fact", "status")
    _apply_in_two_stages(request)
    pytest.fail("ADAPTER TO COMPLETE: a pre-migration post with no event and no lookup answer gets a backfill fact set (not_found) and "
                "projects; it never waits on a fact that will not come", pytrace=False)


def _apply_in_two_stages(request):
    from .support import two_stage_migrate

    two_stage_migrate(request.getfixturevalue("raw_dsn"))


# ---- 0081 ------------------------------------------------------------------------------------------------------------------

@spec("0081.table")
def test_0081_makes_the_append_only_reroute_table_with_a_key_on_the_original(cloud):
    need_table("raw_post_reroute")
    need_columns("raw_post_reroute", "from_org", "from_post", "to_org", "to_post", "recorded_at")
    cons = sql(cloud, "SELECT contype, pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'consentvault.raw_post_reroute'::regclass")
    assert any(c["contype"] == "p" and "from_post" in c["d"] for c in cons)
    assert any(c["contype"] == "u" and "to_post" in c["d"] for c in cons)
    triggers = {r["tgname"] for r in sql(cloud, "SELECT tgname FROM pg_trigger WHERE tgrelid = 'consentvault.raw_post_reroute'::regclass AND NOT tgisinternal")}
    assert len(triggers) >= 2, "append-only (update, delete) and no truncate"


@spec("0081.second_reroute_fails")
def test_a_second_reroute_of_one_original_fails_on_the_primary_key(cloud):
    need_table("raw_post_reroute")
    pytest.fail("ADAPTER TO COMPLETE: store an original in the home organisation, reroute it once through the retry lane, then insert a "
                "second reroute row for the same original and expect a unique violation", pytrace=False)


@spec("0081.replay_stores_no_new_post")
def test_replay_from_empty_of_a_rerouted_post_stores_no_new_post_and_places_the_copy_at_its_original_arrival(cloud):
    need_table("raw_post_reroute")
    need_function("load_stored_post")
    pytest.fail("ADAPTER TO COMPLETE: load a store holding one rerouted post onto a fresh database, project, and expect zero new posts, one "
                "history row per stored post, and the copy's placed_at equal to the original arrival", pytrace=False)


# ---- 0082 ------------------------------------------------------------------------------------------------------------------

@spec("0082.columns")
def test_0082_makes_the_history_table_with_the_as_sent_columns_and_no_value_check(world):
    need_table("post_history")
    need_columns("post_history", "org_id", "history_seq", "post_id", "post_seq", "placed_at", "received_at", "event_id", "label",
                 "event_type_sent", "channels_sent", "purposes_sent", "method_sent", "origin_sent", "contact_kind_sent",
                 "captured_at_sent", "wording_sha256_sent", "contact_verification_sent", "source_id_sent", "brand_ids_sent",
                 "wording_fact_id", "standing", "earliest_copy", "contact_fp", "contact_key_ref", "completeness", "facts_read",
                 "rule_set_version", "intake_code_version", "fold_code_version", "backfill_of_event_id", "prev_hash", "row_hash", "hash_version")
    checks = sql(world, "SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'consentvault.post_history'::regclass AND contype = 'c'")
    assert [c["d"] for c in checks if "hash_version" not in c["d"] and "label" not in c["d"]] == [], "no CHECK on any as-sent value"
    fks = sql(world, "SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'consentvault.post_history'::regclass AND contype = 'f'")
    assert not any("wording_sha256_sent" in f["d"] or "contact_fp" in f["d"] or "contact_key_ref" in f["d"] for f in fks)


ODD = [
    pytest.param("start", dict(event_type="start"), "event_type_sent", "start", id="event_type_start"),
    pytest.param("fax", dict(channels=["fax"]), "channels_sent", ["fax"], id="channel_fax"),
    pytest.param("no_purposes", dict(purposes=[]), "purposes_sent", [], id="empty_purposes"),
    pytest.param("unregistered", dict(disclosure_sha256="f" * 64), "wording_sha256_sent", "f" * 64, id="unregistered_wording"),
    pytest.param("future", dict(captured_at="2099-01-01T00:00:00+00:00"), "captured_at_sent", "2099-01-01T00:00:00+00:00", id="capture_time_a_year_ahead"),
    pytest.param("otp", dict(contact_verification="otp"), "contact_verification_sent", "otp", id="otp_claimed_under_a_site_key"),
    pytest.param("release", dict(event_type="release", release_of_event_id=str(uuid.uuid4())), "event_type_sent", "release", id="names_a_release"),
]


@pytest.mark.parametrize("name,over,column,sent", [pytest.param(n, o, c, s, id=i, marks=spec("0082.as_sent." + i)) for (n, o, c, s), i in
                                                   [(p.values[:4], p.id) for p in ODD]])
def test_a_post_that_today_is_refused_projects_to_one_row_holding_each_value_as_sent(world, name, over, column, sent):
    need_cutover()
    o = world.a
    facts = tenant_facts() if name == "otp" else None
    post = door_post(world, o, grant_fields(o, PHONE, **over), facts=facts)
    rows = history_rows(world, o, post_id=post)
    assert len(rows) == 1, "one row, never a refusal"
    got = rows[0][column]
    assert got == sent or str(got) == str(sent), (column, got)


@spec("0082.invalid_signature_standing")
def test_a_post_with_an_invalid_signature_projects_to_one_row_with_its_standing(world):
    need_cutover()
    from consentvault.rawpost import Fact
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE), facts=[Fact("vault", "request_signature", "invalid")])
    (row,) = history_rows(world, o, post_id=post)
    assert row["standing"] == "not_authenticated:invalid"


@spec("0082.missing_ip_completeness")
def test_a_post_missing_its_ip_projects_with_the_ip_marked_absent(world):
    need_cutover()
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    row = history_row(world, o, post)
    assert row["completeness"]["ip"]["state"] == "absent"


@spec("0082.erased_contact_verifies")
def test_an_erased_contacts_rows_verify_with_no_contact_key_row(world):
    need_cutover()
    need_function("history_chain_breaks")
    o = world.a
    cut_grant(world, o, PHONE)
    world.erase(o, PHONE)
    assert sql(world, "SELECT 1 FROM consentvault.contact_key WHERE org_id = %s", (o.org_id,)) == []
    assert sql(world, "SELECT * FROM consentvault.history_chain_breaks()") == []


@spec("0082.concurrent_history_inserts")
def test_two_concurrent_history_inserts_for_one_organisation_never_share_a_prev_hash(world):
    need_cutover()
    o = world.a
    in_threads(*[lambda i=i: [door_post(world, o, grant_fields(o, f"+1305555{i}{n:03d}")) for n in range(4)] for i in range(2)])
    rows = history_rows(world, o)
    assert len(rows) == 8 and len({r["prev_hash"] for r in rows}) == 8


@spec("0082.placed_at_is_the_stored_post")
def test_a_projected_rows_arrival_and_place_must_equal_the_stored_post(world):
    need_cutover()
    o = world.a
    post = cut_grant(world, o, PHONE)
    row = history_row(world, o, post)
    p = sql(world, "SELECT seq, received_at FROM consentvault.raw_post WHERE org_id = %s AND post_id = %s", (o.org_id, post))[0]
    assert row["post_seq"] == p["seq"] and row["received_at"] == p["received_at"] and row["placed_at"] == p["received_at"]
    with pytest.raises(psycopg.Error):
        with world.vault.superuser() as su:
            su.execute("UPDATE consentvault.post_history SET placed_at = placed_at + interval '1 hour' WHERE org_id = %s AND post_id = %s", (o.org_id, post))


@spec("0082.append_only_no_truncate_hash_version")
def test_the_history_is_append_only_refuses_truncate_and_pins_the_hash_version(world):
    need_cutover()
    o = world.a
    post = cut_grant(world, o, PHONE)
    with world.vault.superuser() as su:
        for stmt in ("UPDATE consentvault.post_history SET label = label", "DELETE FROM consentvault.post_history", "TRUNCATE consentvault.post_history"):
            with pytest.raises(psycopg.Error):
                su.execute(stmt)
    assert history_row(world, o, post)["hash_version"] == 3


@spec("0082.backfill_rows")
def test_backfill_rows_copy_the_legacy_event_and_carry_their_own_versions(world, request):
    need_cutover()
    pytest.fail("ADAPTER TO COMPLETE: backfill one legacy event; its row has label backfill, received_at copied from the event, "
                "fold_code_version backfill-1, rule_set_version as-written-hash-v1 or -v2, standing counts, and is exempt from the arrival trigger", pytrace=False)


# ---- 0083 ------------------------------------------------------------------------------------------------------------------

@spec("0083.no_fact_row")
def test_projecting_a_post_adds_no_row_to_the_fact_table(world):
    need_table("projection_outcome")
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    before = sql(world, "SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s", (o.org_id, post))[0]["n"]
    from consentvault import api  # noqa: F401
    door_post(world, o, grant_fields(o, PHONE2))
    after = sql(world, "SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s", (o.org_id, post))[0]["n"]
    assert before == after
    assert not sql(world, "SELECT 1 FROM consentvault.raw_post_fact WHERE org_id = %s AND name = 'event_derived'", (o.org_id,))
    assert sql(world, "SELECT 1 FROM consentvault.projection_outcome WHERE org_id = %s AND post_id = %s", (o.org_id, post))


@spec("0083.append_only")
def test_projection_outcome_is_append_only_and_refuses_truncate(world):
    need_table("projection_outcome")
    door_post(world, world.a, grant_fields(world.a, PHONE))
    with world.vault.superuser() as su:
        for stmt in ("UPDATE consentvault.projection_outcome SET outcome = outcome", "DELETE FROM consentvault.projection_outcome",
                     "TRUNCATE consentvault.projection_outcome"):
            with pytest.raises(psycopg.Error):
                su.execute(stmt)
