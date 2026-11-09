"""The nine record gates (specs/capture-everything/record-contract.md), each answered yes or no by one test. Each test carries its
own control (a planted fault the check must report, or a forced failure that must return nothing), so a check that cannot fail
cannot pass. The call shapes the build must provide are listed in support.py."""

import hashlib
import json

import pytest

from .support import (PHONE, PHONE2, cut_grant, door_post, grant_fields, history_fingerprint, history_rows, integrity_conn, load_into_fresh,
                      login_in_group, need_cutover, need_function, need_py, need_table, purity_run, sql, store_snapshot)

spec = pytest.mark.spec_item


def _bundle(cloud, co, phone=PHONE):
    from consentvault import evidence
    from consentvault.tenancy.tokens import org_transaction
    fp = cloud.t.crypto.contact_fingerprint(co.org.org_id, "phone", phone)
    with cloud.t.app() as app, org_transaction(app, cloud.t.token(co.org, scopes=("capture", "gate_read", "proof_read"))):
        bundle, _ = evidence.gather_tenant(app, cloud.t.crypto, fp)
    return bundle


@spec("gate1")
def test_gate_1_stored_whole_sent_sha_equals_stored_sha_equals_loaded_sha_with_the_chain_and_arrival_rows(cloud):
    need_cutover()
    need_function("load_stored_post")
    import uuid
    co = cloud.a
    body = {"contact": PHONE, "event_type": "grant", "checked": True, "channels": ["sms"], "purposes": ["marketing"],
            "disclosure_sha256": co.wording, "brand_ids": [str(co.org.brand_id)], "session_ref": "s-1", "client_nonce": str(uuid.uuid4())}
    sent_sha = hashlib.sha256(json.dumps(body).encode("utf-8")).hexdigest()
    status, answer = cloud.call("/v1/events", body, token=cloud.token(co, "capture"))
    assert status == 201
    (stored,) = sql(cloud, "SELECT body_sha256 FROM consentvault.raw_post WHERE post_id = %s", (answer["post_id"],))
    assert stored["body_sha256"] == sent_sha, "the stored bytes equal the received bytes"
    store = store_snapshot(cloud)
    loaded = load_into_fresh(cloud)
    assert sent_sha in {p[-1] for p in loaded.loaded["posts"]}, "the loaded bytes equal the received bytes"
    assert loaded.loaded["posts"] == store.loaded["posts"], "seq, received_at, prev_hash, row_hash and the body sha are equal"
    assert loaded.loaded["arrivals"] == store.loaded["arrivals"], "the original-arrival rows are equal"


@spec("gate2")
def test_gate_2_every_stored_post_is_in_history_and_a_planted_missing_row_is_reported(world):
    need_cutover()
    from consentvault import door, integrity
    from consentvault.rawpost import Fact, RawPostWriter, RawRequest
    from consentvault.tenancy.tokens import org_transaction
    o = world.a
    posts = [door_post(world, o, grant_fields(o, PHONE)),
             door_post(world, o, grant_fields(o, PHONE2), facts=[Fact("vault", "request_signature", "invalid")]),
             door_post(world, o, None, body=b"\xff not json")]
    in_history = {str(r["post_id"]) for r in history_rows(world, o)}
    assert set(posts) <= in_history, "all three, including the forged and the unreadable, are in history"
    clean = integrity.verify_chain_every_org(integrity_conn(world))
    req = RawRequest(intake="staff_marked", method="POST", path="/v1/events", query="", headers=(), body=b"{}", headers_presented_by="t", facts=())
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        planted = str(door.store_raw(RawPostWriter(crypto=world.crypto), c, lambda cc: cc.transaction(), req).post_id)
    report = json.dumps(integrity.verify_chain_every_org(integrity_conn(world)), default=str)
    assert planted in report and planted not in json.dumps(clean, default=str), "the check reports a stored post with no history row and no reason"


@spec("gate3")
def test_gate_3_a_mixed_store_replays_to_the_same_history_per_label(request):
    need_cutover()
    need_function("load_stored_post")
    need_py("consentvault.history_backfill", "shadow_start")
    from .conftest import _loader_role
    from .store_copy import finish_migrations, shadow, today_store
    _loader_role(request)
    env, _ = today_store(request)
    env.grant(env.t.a, "+13055550111")                  # a legacy event: it becomes a backfill row
    finish_migrations(request)
    v = env.t
    shadow(env, v.a)
    from consentvault import door
    from consentvault.tenancy.tokens import org_transaction
    from .store_copy import iso_grant_fields
    with v.app() as c, org_transaction(c, v.token(v.a)):
        door.record_observed(c, v.crypto, intake="staff_marked", enter=lambda cc: cc.transaction(), region="US",
                             fields=iso_grant_fields(v.a, "+13055550112"))
    store = store_snapshot(env)
    assert set(store.fingerprints) == {"backfill", "projected"}, "a mixed store: legacy rows and rows projected after the cutover"
    replay = load_into_fresh(env)
    assert replay.fingerprints == store.fingerprints, "equal, label by label"


@spec("gate4")
def test_gate_4_the_retrieval_log_names_who_and_what_recomputes_to_the_payload_and_a_failed_log_returns_nothing(cloud):
    need_table("retrieval_log")
    from consentvault.ledger import canonical_dumps
    co = cloud.a
    assert cloud.grant(co, PHONE)[0] == 201
    cred = co.clients["proof_read"].credential_id
    before = sql(cloud, "SELECT count(*) AS n FROM consentvault.retrieval_log WHERE org_id = %s", (co.org.org_id,))[0]["n"]
    bundle = _bundle(cloud, co)
    rows = sql(cloud, "SELECT actor_kind, actor_id, at, what, payload_sha256 FROM consentvault.retrieval_log WHERE org_id = %s ORDER BY at", (co.org.org_id,))
    assert len(rows) == before + 1
    new = rows[-1]
    assert new["actor_kind"] and new["actor_id"] and new["at"] and new["what"], "who, when and what"
    strip = {k: v for k, v in bundle.items() if k != "generated_at"}
    assert hashlib.sha256(canonical_dumps(strip).encode()).hexdigest() == new["payload_sha256"], "recomputed from the returned bytes"
    status, answer = cloud.proof(co, PHONE)
    assert status == 200 and any(r["actor_id"] == str(cred) for r in sql(cloud, "SELECT actor_id FROM consentvault.retrieval_log WHERE org_id = %s", (co.org.org_id,))), \
        "the proof read is logged under the credential that made it"
    with cloud.t.superuser() as su:
        su.execute("REVOKE INSERT ON consentvault.retrieval_log FROM consentvault_app")
    status, answer = cloud.proof(co, PHONE)
    assert status != 200 and "timeline" not in json.dumps(answer), "a read whose log row cannot be written returns nothing"
    with pytest.raises(Exception):
        _bundle(cloud, co)


@spec("gate5")
def test_gate_5_every_row_carries_exactly_the_versions_the_running_code_declares(world):
    need_cutover()
    from consentvault import door
    fold = need_py("consentvault.door", "FOLD_CODE_VERSION")
    intake = need_py("consentvault.door", "CODE_VERSION")
    rules = need_py("consentvault.door", "RULE_SET_VERSION")
    o = world.a
    cut_grant(world, o, PHONE)
    cut_grant(world, o, PHONE2)
    for row in history_rows(world, o):
        assert (row["fold_code_version"], row["intake_code_version"], row["rule_set_version"]) == (fold, intake, rules)


@spec("gate6")
def test_gate_6_a_year_of_clock_and_different_lookups_change_no_row_and_the_forged_post_is_recorded_not_refused(cloud):
    need_cutover()
    need_function("load_stored_post")
    for co in (cloud.a, cloud.b):
        assert cloud.grant(co, PHONE)[0] == 201
    status, _ = cloud.call("/v1/events", {"contact": PHONE2, "event_type": "grant"}, token="not-a-token")
    store, first, second = purity_run(cloud)
    assert first.fingerprints and second.fingerprints == first.fingerprints == store.fingerprints, "equal rows, not merely equal counts"


@spec("gate7")
def test_gate_7_the_chain_verifies_from_the_newest_anchor_after_an_erasure_and_a_tamper_is_caught(world, tmp_path):
    need_cutover()
    need_function("history_chain_breaks")
    need_table("post_history_chain_head")
    from consentvault import integrity
    o = world.a
    cut_grant(world, o, PHONE)
    last = cut_grant(world, o, PHONE2)
    integrity.anchor_every_org(integrity_conn(world), str(tmp_path / "anchors.jsonl"))
    world.erase(o, PHONE)
    assert sql(world, "SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s", (o.org_id, o.fp(PHONE))) == []
    assert sql(world, "SELECT * FROM consentvault.history_chain_breaks()") == []
    assert "break" not in json.dumps(integrity.verify_chain_every_org(integrity_conn(world), sink_file=str(tmp_path / "anchors.jsonl")), default=str).lower()
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.post_history SET row_hash = repeat('0', 64) WHERE org_id = %s AND post_id = %s", (o.org_id, last))
    assert sql(world, "SELECT * FROM consentvault.history_chain_breaks()"), "control: the same check fails on a tampered row"


@spec("gate8")
def test_gate_8_completeness_names_the_source_of_every_element_and_a_missing_one_is_a_fact_not_a_refusal(world):
    need_cutover()
    from datetime import datetime, timezone
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE, user_agent="UA/1", captured_at=datetime.now(timezone.utc).isoformat()))
    (row,) = history_rows(world, o, post_id=post)
    elements = row["completeness"]
    assert set(elements) >= {"wording", "act", "timestamp", "contact", "business", "ip", "user_agent", "page", "form_version"}
    assert all(e.get("source") for e in elements.values()), "each element names the fact or field it came from"
    assert {k for k, e in elements.items() if e["state"] == "absent"} == {"ip", "page", "form_version"}
    assert all(e["state"] == "present" for k, e in elements.items() if k not in ("ip", "page", "form_version"))


@spec("gate9")
def test_gate_9_matching_is_exact_on_the_normalised_contact_under_a_versioned_rule(world):
    need_cutover()
    o = world.a
    a = door_post(world, o, grant_fields(o, "+13055550142"))
    b = door_post(world, o, grant_fields(o, "(305) 555-0142"))
    c = door_post(world, o, grant_fields(o, "+13055550143"))
    rows = {r["post_id"]: r for r in history_rows(world, o)}
    assert rows[a]["contact_fp"] == rows[b]["contact_fp"] != rows[c]["contact_fp"]
    assert all(r["rule_set_version"] for r in rows.values()), "the normalisation rule is named by its version"
