"""The nine record gates (specs/capture-everything/record-contract.md), each answered yes or no by one test on the live store (and,
for gates 1 and 3, on a fresh replay). The build is done when all nine answer yes (build order, last step)."""

import json

import pytest

from .support import (PHONE, PHONE2, cut_grant, door_post, grant_fields, history_fingerprint, history_rows, load_into_fresh,
                      need_cutover, need_function, need_table, sql, stop_fields)

spec = pytest.mark.spec_item


@spec("gate1")
def test_gate_1_stored_whole_on_the_live_store_and_on_a_fresh_replay(cloud):
    need_cutover()
    need_function("load_stored_post")
    status, answer = cloud.grant(cloud.a, PHONE)
    assert status == 201
    live = sql(cloud, "SELECT body_sha256 FROM consentvault.raw_post WHERE org_id = %s", (cloud.a.org.org_id,))
    loaded = load_into_fresh(cloud)
    assert loaded.loaded["body_sha256"] == [r["body_sha256"] for r in live], "the stored bytes equal the received bytes after the load"


@spec("gate2")
def test_gate_2_nothing_missing_every_stored_post_is_in_history_or_has_a_final_named_reason(world):
    need_cutover()
    from consentvault.rawpost import Fact
    o = world.a
    posts = [door_post(world, o, grant_fields(o, PHONE)),
             door_post(world, o, grant_fields(o, PHONE2), facts=[Fact("vault", "request_signature", "invalid")]),
             door_post(world, o, None, body=b"\xff not json")]
    stored = {str(r["post_id"]) for r in sql(world, "SELECT post_id FROM consentvault.raw_post WHERE org_id = %s", (o.org_id,))}
    in_history = {str(r["post_id"]) for r in history_rows(world, o)}
    with_reason = {str(r["post_id"]) for r in sql(world, "SELECT post_id FROM consentvault.projection_outcome WHERE org_id = %s", (o.org_id,))}
    assert set(posts) <= stored and stored <= in_history | with_reason, "every stored post is in history or carries a final reason"


@spec("gate3")
def test_gate_3_same_history_from_empty_in_arrival_order_on_every_adapter(cloud):
    need_cutover()
    need_function("load_stored_post")
    assert cloud.grant(cloud.a, PHONE)[0] == 201
    live = history_fingerprint(sql(cloud, "SELECT * FROM consentvault.post_history WHERE org_id = %s", (cloud.a.org.org_id,)))
    replay = load_into_fresh(cloud)
    assert replay.fingerprints["projected"] == live


@spec("gate4")
def test_gate_4_every_retrieval_returns_identical_bytes_and_is_logged_with_who_when_and_what(cloud):
    need_table("retrieval_log")
    assert cloud.grant(cloud.a, PHONE)[0] == 201
    first = cloud.proof(cloud.a, PHONE)
    second = cloud.proof(cloud.a, PHONE)
    assert first[0] == second[0] == 200
    strip = lambda ans: {k: v for k, v in ans.items() if k != "generated_at"}  # noqa: E731
    assert json.dumps(strip(first[1]), sort_keys=True) == json.dumps(strip(second[1]), sort_keys=True)
    rows = sql(cloud, "SELECT actor_kind, actor_id, at, what, payload_sha256 FROM consentvault.retrieval_log WHERE org_id = %s ORDER BY at", (cloud.a.org.org_id,))
    assert len(rows) >= 2 and rows[0]["payload_sha256"] == rows[1]["payload_sha256"]
    assert all(r["actor_kind"] and r["actor_id"] and r["at"] and r["what"] for r in rows)


@spec("gate5")
def test_gate_5_every_derived_value_carries_the_code_version_and_the_rule_set_version(world):
    need_cutover()
    o = world.a
    cut_grant(world, o, PHONE)
    for row in history_rows(world, o):
        assert row["rule_set_version"] and row["fold_code_version"] and row["intake_code_version"]
    assert history_rows(world, o)[0]["fold_code_version"].startswith("door-3")


@spec("gate6")
def test_gate_6_no_judgment_on_the_path_the_clock_and_the_signature_are_recorded_never_used_to_refuse(world, monkeypatch):
    need_cutover()
    import time
    from datetime import datetime, timedelta

    from consentvault.rawpost import Fact
    o = world.a
    ok = door_post(world, o, grant_fields(o, PHONE))
    bad = door_post(world, o, grant_fields(o, PHONE2), facts=[Fact("vault", "request_signature", "invalid")])
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 365 * 86400)    # the host clock a year ahead: the fold must not read it
    again = door_post(world, o, grant_fields(o, PHONE2, session_ref="s-2"), facts=[Fact("vault", "request_signature", "invalid")])
    rows = {r["post_id"]: r for r in history_rows(world, o)}
    assert len(rows) == 3, "every post has its row; none was refused"
    assert rows[bad]["standing"] == rows[again]["standing"] == "not_authenticated:invalid"
    assert rows[ok]["standing"] == "counts"


@spec("gate7")
def test_gate_7_the_chain_verifies_end_to_end_including_after_an_erasure(world):
    need_cutover()
    need_function("history_chain_breaks")
    need_table("post_history_chain_head")
    o = world.a
    cut_grant(world, o, PHONE)
    cut_grant(world, o, PHONE2)
    world.erase(o, PHONE)
    assert sql(world, "SELECT * FROM consentvault.history_chain_breaks()") == []
    assert sql(world, "SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s", (o.org_id, o.fp(PHONE))) == []


@spec("gate8")
def test_gate_8_completeness_is_recorded_per_post_and_a_missing_element_is_a_fact_not_a_refusal(world):
    need_cutover()
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    (row,) = history_rows(world, o, post_id=post)
    elements = row["completeness"]
    assert {"wording", "act", "timestamp", "contact", "business", "ip", "user_agent", "page", "form_version"} <= set(elements)
    assert elements["ip"]["state"] == "absent" and elements["contact"]["state"] == "present"


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
