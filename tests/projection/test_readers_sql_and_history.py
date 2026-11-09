"""Reader cutover items 19 to 32, 37 and 40 to 42: the SQL objects that read the event table, the history seals and anchors (gate 7),
the retrieval log (gate 4) and the completeness record (gate 8). SQL objects are proved by what their definition reads and, where
the call shape is fixed by today's functions, by what they return for a post that exists only in history."""

import hashlib
import json

import pytest

from .support import (as_text, call_fn, PHONE, PHONE2, cut_grant, cut_stop, door_post, grant_fields, history_event_id, history_head, history_row, integrity_conn,
                      need_cutover, need_function, need_table, sql)

spec = pytest.mark.spec_item


def _def(env, name):
    rows = sql(env, "SELECT pg_get_functiondef(p.oid) AS d FROM pg_proc p WHERE p.pronamespace = 'consentvault'::regnamespace AND p.proname = %s", (name,))
    assert rows, f"function consentvault.{name} does not exist"
    return "\n".join(r["d"] for r in rows).lower()


def _reads_history_only(env, name):
    text = _def(env, name)
    assert "post_history" in text, f"{name} does not read post_history"
    assert "consentvault.event " not in text and "consentvault.event\n" not in text and "from event" not in text, f"{name} still reads the event table"


@spec("item19")
def test_19_the_permission_view_is_rebuilt_over_history_and_the_contact_check_does_not_need_it(cloud):
    need_cutover()
    need_function("history_stop_on_record")
    view = sql(cloud, "SELECT pg_get_viewdef('consentvault.current_permission'::regclass) AS d")[0]["d"].lower()
    assert "post_history" in view and "consentvault.event" not in view and "rule_set_version" in view
    co = cloud.a
    assert cloud.grant(co, PHONE)[0] == 201
    status, answer = cloud.gate(co, PHONE)
    assert status == 200 and answer["history"], "the contact check answers factual queries from history, with the derived view off"


@spec("item20")
def test_20_a_post_cutover_stop_advances_its_sync_state_and_the_person_state_reads_stopped(world):
    need_cutover()
    o = world.a
    cut_grant(world, o, PHONE)
    v1 = sql(world, "SELECT coalesce(max(version), 0) AS v FROM consentvault.state_version WHERE org_id = %s", (o.org_id,))[0]["v"]
    cut_stop(world, o, PHONE)
    v2 = sql(world, "SELECT coalesce(max(version), 0) AS v FROM consentvault.state_version WHERE org_id = %s", (o.org_id,))[0]["v"]
    assert v2 > v1
    state = as_text(call_fn(world, o, "sync_person_state", contact_fp=o.fp(PHONE), fp=o.fp(PHONE)))
    assert ("stop" in state or "revok" in state or "denied" in state) and "permitted" not in state, state
    for name in ("sync_advance_state", "sync_contact_sealed", "sync_person_state"):
        _reads_history_only(world, name)


@spec("item22")
def test_22_a_post_cutover_grant_updates_its_record_index_without_the_event_table(world):
    need_cutover()
    o = world.a
    cut_grant(world, o, PHONE)
    assert world.record_id(o, PHONE)
    for name in ("record_upsert", "record_index_derive", "record_index_refresh", "record_index_without_default"):
        _reads_history_only(world, name)


@spec("item23")
def test_23_receipt_of_returns_the_receipt_of_a_post_cutover_post(world):
    need_cutover()
    o = world.a
    post = cut_grant(world, o, PHONE)
    _reads_history_only(world, "receipt_of")
    got = sql(world, "SELECT * FROM consentvault.receipt_of(%s)", (history_event_id(world, o, post),))
    assert got


def _vals(world, o, post=None, fp_phone=PHONE):
    from datetime import date
    v = {"org_id": o.org_id, "contact_fp": o.fp(fp_phone), "fp": o.fp(fp_phone), "day": date.today(), "source_id": o.web_id}
    if post:
        v["event_id"] = history_event_id(world, o, post)
        v["post_id"] = post
    return v


@spec("item24")
def test_24_the_record_doc_check_of_a_history_only_post_reads_its_completeness(world):
    need_cutover()
    o = world.a
    post = cut_grant(world, o, PHONE)
    text = _def(world, "record_doc_check")
    assert "completeness" in text and "consentvault.event " not in text
    got = as_text(call_fn(world, o, "record_doc_check", **_vals(world, o, post)))
    assert got and "ip" in got, "the check answers for a post that exists only in history, naming the elements"


@spec("item25")
def test_25_the_health_and_usage_counts_count_a_post_cutover_post(world):
    need_cutover()
    o = world.a
    before = as_text(call_fn(world, o, "health_counts", **_vals(world, o)))
    post = cut_grant(world, o, PHONE)
    assert as_text(call_fn(world, o, "health_counts", **_vals(world, o))) != before, "a history-only post is counted"
    assert str(o.web_id).lower() in as_text(call_fn(world, o, "source_last_events", **_vals(world, o, post)))
    assert call_fn(world, o, "usage_events_for_day", **_vals(world, o, post))
    call_fn(world, o, "customer_alarm_rows", **_vals(world, o, post))   # runs against history without error


@spec("item26")
def test_26_an_erasure_after_cutover_covers_the_contacts_history_rows(world):
    need_cutover()
    o = world.a
    post = cut_grant(world, o, PHONE)
    world.erase(o, PHONE)
    cover = as_text(call_fn(world, o, "erasure_request_cover", **_vals(world, o, post)))
    assert cover and "[]" != cover, "the cover names the history rows of the erased contact"
    call_fn(world, o, "erasure_coverage_backfill", **_vals(world, o, post))


@spec("item27")
def test_27_the_stop_lift_guard_moves_to_the_history_lift_table_with_a_key_to_history(world):
    need_table("history_stop_lift")
    fks = sql(world, "SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'consentvault.history_stop_lift'::regclass AND contype = 'f'")
    assert any("post_history" in f["d"] for f in fks)
    assert "history_stop_lift" in _def(world, "check_stop_lift")


@pytest.mark.parametrize("table,column", [pytest.param("confirmation_send_intent", "basis_history_event_id", id="send_intent", marks=spec("item28.send_intent")),
                                          pytest.param("confirmation_reply", "history_event_id", id="reply", marks=spec("item28.reply")),
                                          pytest.param("event_source_post", "history_event_id", id="source_post", marks=spec("item28.source_post"))])
def test_28_each_table_that_cited_an_event_can_cite_a_history_event_and_loses_no_column(world, table, column):
    need_table("post_history")
    from .support import need_columns
    need_columns(table, column)
    fks = sql(world, "SELECT pg_get_constraintdef(c.oid) AS d FROM pg_constraint c WHERE c.conrelid = %s::regclass AND c.contype = 'f'", (f"consentvault.{table}",))
    assert any("post_history" in f["d"] and column in f["d"] for f in fks)
    cols = {r["column_name"] for r in sql(world, "SELECT column_name FROM information_schema.columns WHERE table_schema = 'consentvault' AND table_name = %s", (table,))}
    assert cols & {"event_id", "basis_event_id", "stop_event_id"}, "no existing column is dropped"


@spec("item29.sealed_row_reverifies")
def test_29_a_sealed_history_row_re_verifies(world, request):
    need_table("post_history_seal")
    from consentvault import integrity
    o = world.a
    cut_grant(world, o, PHONE)
    tsa = request.getfixturevalue("tsa")
    integrity.seal_every_org(integrity_conn(world), tsa.url, 100, backoff=0)
    result = integrity.verify_seals_every_org(integrity_conn(world))
    assert "fail" not in json.dumps(result, default=str).lower()
    assert sql(world, "SELECT columns_digested FROM consentvault.post_history_seal WHERE org_id = %s", (o.org_id,))


@spec("item29.changed_row_fails")
def test_29_a_history_row_changed_after_sealing_fails(world, request):
    need_table("post_history_seal")
    from consentvault import integrity
    o = world.a
    post = cut_grant(world, o, PHONE)
    tsa = request.getfixturevalue("tsa")
    integrity.seal_every_org(integrity_conn(world), tsa.url, 100, backoff=0)
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.post_history SET standing = 'changed' WHERE org_id = %s AND post_id = %s", (o.org_id, post))
    result = integrity.verify_seals_every_org(integrity_conn(world))
    assert post in json.dumps(result, default=str) or history_event_id(world, o, post) in json.dumps(result, default=str)


@spec("item29.new_column_fails_no_seal")
def test_29_adding_a_column_to_the_history_table_fails_no_existing_seal(world, request):
    need_table("post_history_seal")
    from consentvault import integrity
    o = world.a
    cut_grant(world, o, PHONE)
    tsa = request.getfixturevalue("tsa")
    integrity.seal_every_org(integrity_conn(world), tsa.url, 100, backoff=0)
    with world.vault.migrator() as m:
        m.execute("ALTER TABLE consentvault.post_history ADD COLUMN later_added text")
    result = integrity.verify_seals_every_org(integrity_conn(world))
    assert "fail" not in json.dumps(result, default=str).lower()


@spec("item30")
def test_30_the_history_chain_verifies_from_the_newest_anchor_after_an_erasure_with_the_key_gone(world, tmp_path):
    need_table("post_history_chain_head")
    from consentvault import integrity
    o = world.a
    cut_grant(world, o, PHONE)
    cut_grant(world, o, PHONE2)
    integrity.anchor_every_org(integrity_conn(world), str(tmp_path / "anchors.jsonl"))
    world.erase(o, PHONE)
    assert sql(world, "SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s", (o.org_id, o.fp(PHONE))) == []
    assert sql(world, "SELECT * FROM consentvault.history_chain_breaks()") == []


def _bundle(cloud, co):
    from consentvault import evidence
    from consentvault.tenancy.tokens import org_transaction
    fp = cloud.t.crypto.contact_fingerprint(co.org.org_id, "phone", PHONE)
    with cloud.t.app() as app, org_transaction(app, cloud.t.token(co.org, scopes=("capture", "gate_read", "proof_read"))):
        bundle, _ = evidence.gather_tenant(app, cloud.t.crypto, fp)
    return bundle


@spec("item31.same_payload_hash")
def test_31_two_exports_a_minute_apart_log_the_same_payload_hash_and_each_log_row_hash_is_the_payload_sha256(cloud):
    need_table("retrieval_log")
    from consentvault.ledger import canonical_dumps
    co = cloud.a
    assert cloud.grant(co, PHONE)[0] == 201
    first, second = _bundle(cloud, co), _bundle(cloud, co)
    rows = sql(cloud, "SELECT payload_sha256, prev_hash, row_hash FROM consentvault.retrieval_log WHERE org_id = %s ORDER BY at", (co.org.org_id,))
    assert len(rows) >= 2 and rows[-1]["payload_sha256"] == rows[-2]["payload_sha256"]
    strip = lambda b: {k: v for k, v in b.items() if k != "generated_at"}  # noqa: E731
    assert hashlib.sha256(canonical_dumps(strip(first)).encode()).hexdigest() == rows[-2]["payload_sha256"]
    assert rows[-1]["prev_hash"] == rows[-2]["row_hash"], "chained per organisation"


@spec("item31.unloggable_read_returns_nothing")
def test_31_a_read_whose_log_row_cannot_be_written_returns_nothing_and_raises(cloud):
    need_table("retrieval_log")
    co = cloud.a
    assert cloud.grant(co, PHONE)[0] == 201
    with cloud.t.superuser() as su:
        su.execute("REVOKE INSERT ON consentvault.retrieval_log FROM consentvault_app")
    with pytest.raises(Exception):
        _bundle(cloud, co)


@spec("item32")
def test_32_a_capture_post_missing_ip_page_and_form_version_projects_with_those_three_absent_and_the_rest_present(world):
    need_cutover()
    from datetime import datetime, timezone
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE, user_agent="UA/1", captured_at=datetime.now(timezone.utc).isoformat()))
    done = history_row(world, o, post)["completeness"]
    absent = {k for k, v in done.items() if v["state"] == "absent"}
    assert absent == {"ip", "page", "form_version"} and all(v["state"] == "present" for k, v in done.items() if k not in absent)
    assert all(v.get("source") for v in done.values()), "each element names the fact or field it came from"


@spec("item37")
def test_37_after_cutover_the_old_append_path_is_refused_by_name(world):
    need_cutover()
    from consentvault import ledger
    from consentvault.errors import ConsentVaultError
    from consentvault.tenancy.tokens import org_transaction
    o = world.a
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        with pytest.raises(ConsentVaultError) as exc:
            ledger.record_tenant_event(c, world.crypto, contact=PHONE, event_type="grant", channels=["sms"], purposes=["marketing"],
                                       method="checkbox", origin="consumer", disclosure_sha256=o.wording, source_id=o.web_id)
    assert "retired" in str(exc.value).lower() or "history" in str(exc.value).lower()


@spec("item40")
def test_40_history_head_returns_the_newest_history_row(world):
    need_cutover()
    need_function("history_head")
    o = world.a
    cut_grant(world, o, PHONE)
    last = cut_grant(world, o, PHONE2)
    head = history_head(world)
    assert head["row_hash"] == history_row(world, o, last)["row_hash"]


@spec("item41")
def test_41_a_broken_history_link_is_listed(world):
    need_cutover()
    need_function("history_chain_breaks")
    o = world.a
    cut_grant(world, o, PHONE)
    last = cut_grant(world, o, PHONE2)
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.post_history SET prev_hash = repeat('f', 64) WHERE org_id = %s AND post_id = %s", (o.org_id, last))
    assert sql(world, "SELECT * FROM consentvault.history_chain_breaks()")


@spec("item42")
def test_42_a_new_history_row_is_listed_as_unsealed_until_it_is_sealed(world, request):
    need_function("unsealed_history")
    from consentvault import integrity
    o = world.a
    post = cut_grant(world, o, PHONE)
    eid = history_event_id(world, o, post)
    assert eid in {str(r["event_id"]) for r in sql(world, "SELECT * FROM consentvault.unsealed_history()")}
    tsa = request.getfixturevalue("tsa")
    integrity.seal_every_org(integrity_conn(world), tsa.url, 100, backoff=0)
    assert eid not in {str(r["event_id"]) for r in sql(world, "SELECT * FROM consentvault.unsealed_history()")}


@spec("item39.forged_after_stop")
def test_a_valid_grant_a_counted_stop_then_a_forged_grant_the_sender_skips_and_the_forged_row_does_not_count(world, stack, armed):
    need_cutover()
    need_function("history_stop_on_record")
    from consentvault import gate
    from consentvault.rawpost import Fact
    from consentvault.tenancy.tokens import org_transaction
    from contract_world.confirm import sends
    o = world.a
    cut_grant(world, o, "+13055550142")
    cut_stop(world, o, "+13055550142")
    forged = door_post(world, o, grant_fields(o, "+13055550142"), facts=[Fact("vault", "request_signature", "invalid")])
    assert history_row(world, o, forged)["standing"] == "not_authenticated:invalid"
    stack.run()
    assert stack.twilio.sent == [] and "stop_on_record" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}
    assert sql(world, "SELECT consentvault.history_stop_on_record(%s, %s, 'sms') AS s", (o.org_id, o.fp("+13055550142")))[0]["s"] is True
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        facts = gate.tenant_facts(c, "phone", o.fp("+13055550142"))
    forged_id = history_event_id(world, o, forged)
    assert forged_id not in facts.event_ids or "not_authenticated" in json.dumps(facts.as_dict(), default=str), \
        "the contact check ignores or labels a row that did not count"
    state = as_text(call_fn(world, o, "sync_person_state", **_vals(world, o, fp_phone="+13055550142")))
    assert "permitted" not in state, "sync person state ignores the forged grant: the person is still stopped"


@spec("item19.sender_with_view_off")
def test_19_with_the_derived_view_switched_off_the_sender_still_skips_on_the_stop_and_the_contact_check_answers(world, stack, armed):
    need_cutover()
    from consentvault import gate
    from consentvault.tenancy.tokens import org_transaction
    from contract_world.confirm import sends
    o = world.a
    cut_grant(world, o, "+13055550142")
    cut_stop(world, o, "+13055550142")
    with world.vault.superuser() as su:
        su.execute("REVOKE ALL ON consentvault.current_permission FROM PUBLIC, consentvault_app, consentvault_worker, consentvault_console")
    stack.run()
    assert stack.twilio.sent == [] and "stop_on_record" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        assert gate.tenant_facts(c, "phone", o.fp("+13055550142")).event_ids, "the contact check answers with the view off"
