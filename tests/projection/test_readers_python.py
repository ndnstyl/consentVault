"""Reader cutover items 1 to 18, 33 to 36, 38 and 43: every Python module that read the event table now reads history.

Each test runs where a grant or a stop arrived after the cutover and exists only in history (``cut_grant`` and ``cut_stop`` assert
the history row exists and the frozen event table got nothing), so a reader still answering from the event table cannot pass.
Item 5 (the sender) and item 39 are in test_sender_skips.py."""

from .support import product_erase
import json

import pytest

from .support import (EMAIL, PHONE, PHONE2, cut_grant, cut_stop, door_post, grant_fields, history_event_id, history_head,
                      history_row, history_rows, integrity_conn, login_in_group, need_cutover, need_function, need_table, sql)

spec = pytest.mark.spec_item
PHONE_NY = "+13055550142"


def _cloud_grant_and_stop(cloud, contact=PHONE):
    """A grant over HTTP, then a stop through another door (the stop page), both after the cutover, in organisation A."""
    from consentvault import door
    from consentvault.tenancy.tokens import org_transaction
    need_cutover()
    co, t = cloud.a, cloud.t
    assert cloud.grant(co, contact)[0] == 201
    with t.app() as app, org_transaction(app, t.token(co.org)):
        door.record_observed(app, t.crypto, intake="stop_page", enter=lambda c: c.transaction(), region="US", fields=dict(
            contact=contact, event_type="revoke", channels=["sms"], purposes=["*"], method="checkbox", origin="consumer",
            source_id=co.org.source_id, recorded_by="stop-page"))
    return co


@spec("item1")
def test_1_the_anchor_command_anchors_the_history_head(world, tmp_path):
    need_cutover()
    need_table("post_history_chain_head")
    from consentvault import integrity
    o = world.a
    cut_grant(world, o, PHONE)
    integrity.anchor_every_org(integrity_conn(world), str(tmp_path / "anchors.jsonl"))
    head = history_head(world)
    newest = sql(world, "SELECT * FROM consentvault.post_history_chain_head WHERE org_id = %s ORDER BY history_seq DESC LIMIT 1", (o.org_id,))[0]
    assert newest["row_hash"] == head["row_hash"]


@spec("item2")
def test_2_a_confirmation_for_a_post_cutover_grant_resolves_its_contact(world, stack, armed):
    o = world.a
    post = cut_grant(world, o, PHONE_NY)
    with stack.service.tx(o.org_id) as conn:
        kind, norm, key = stack.service._contact_of_event(conn, o.org_id, history_event_id(world, o, post))
    assert (kind, norm) == ("phone", PHONE_NY) and key


@spec("item3")
def test_3_the_page_of_a_post_cutover_grant_shows_its_channels(world, stack, armed):
    import re
    o = world.a
    cut_grant(world, o, PHONE_NY, channels=["sms", "voice"])
    stack.run()
    token = re.search(r"/c/r/([\w-]+)", stack.twilio.sent[0]["body"]).group(1)
    page = stack.public("GET", f"/c/r/{token}", host="consent.example.com")
    text = (page.raw.decode("utf-8", "replace") if page.raw is not None else json.dumps(page.payload, default=str)).lower()
    assert page.status == 200 and "text" in text and "call" in text


@spec("item4")
def test_4_a_reply_from_a_post_cutover_grants_contact_is_found(world, stack, armed):
    import uuid
    from contract_world.confirm import OUR_NUMBER, replies
    o = world.a
    cut_grant(world, o, PHONE_NY)
    stack.inbound(armed.twilio_key, {"From": PHONE_NY, "To": OUR_NUMBER, "Body": "hello", "MessageSid": "SM" + uuid.uuid4().hex[:30]})
    (reply,) = replies(o.boss)
    assert reply["matched_record_id"] == world.record_id(o, PHONE_NY)


@spec("item6")
def test_6_the_receipt_of_a_post_cutover_post_names_its_history_row_hash(world):
    from consentvault import door
    o = world.a
    post = cut_grant(world, o, PHONE)
    row = history_row(world, o, post)
    with world.vault.superuser() as su:
        got = door.event_by_id(su, str(row["event_id"]))
    assert got.row_hash == row["row_hash"]


@spec("item7")
def test_7_the_evidence_bundle_of_a_post_cutover_contact_holds_its_history_rows(cloud):
    from consentvault import evidence
    co = _cloud_grant_and_stop(cloud)
    fp = cloud.t.crypto.contact_fingerprint(co.org.org_id, "phone", PHONE)
    with cloud.t.app() as app:
        from consentvault.tenancy.tokens import org_transaction
        with org_transaction(app, cloud.t.token(co.org, scopes=("capture", "gate_read", "proof_read"))):
            bundle, _ = evidence.gather_tenant(app, cloud.t.crypto, fp)
    ids = {str(r["event_id"]) for r in sql(cloud, "SELECT event_id FROM consentvault.post_history WHERE org_id = %s", (co.org.org_id,))}
    assert ids and all(i in json.dumps(bundle, default=str) for i in ids)
    assert sql(cloud, "SELECT 1 FROM consentvault.retrieval_log WHERE org_id = %s", (co.org.org_id,)), "the retrieval is logged"


@spec("item8")
def test_8_the_contact_check_finds_a_post_cutover_stop_and_logs_the_retrieval(cloud):
    need_table("retrieval_log")
    co = _cloud_grant_and_stop(cloud)
    status, answer = cloud.gate(co, PHONE)
    assert status == 200 and [h["event_type"] for h in answer["history"]][-1] in ("revoke", "suppress")
    assert sql(cloud, "SELECT 1 FROM consentvault.retrieval_log WHERE org_id = %s", (co.org.org_id,))


@spec("item9")
def test_9_a_stored_post_with_no_history_row_and_no_reason_is_reported(world):
    need_cutover()
    from consentvault import integrity
    from consentvault.rawpost import RawPostWriter, RawRequest
    from consentvault import door
    from consentvault.tenancy.tokens import org_transaction
    o = world.a
    req = RawRequest(intake="staff_marked", method="POST", path="/v1/events", query="", headers=(), body=b"{}", headers_presented_by="test", facts=())
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        stored = door.store_raw(RawPostWriter(crypto=world.crypto), c, lambda cc: cc.transaction(), req)   # stored, never projected
    report = integrity.verify_chain_every_org(integrity_conn(world))
    assert str(stored.post_id) in json.dumps(report, default=str), "gate 2: reported by name"


@spec("item10")
def test_10_a_broken_history_prev_hash_fails_verification(world):
    need_cutover()
    need_function("history_chain_breaks")
    from consentvault import ledger
    o = world.a
    cut_grant(world, o, PHONE)
    cut_grant(world, o, PHONE2)
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.post_history SET prev_hash = repeat('0', 64) WHERE org_id = %s AND history_seq = (SELECT max(history_seq) FROM consentvault.post_history WHERE org_id = %s)", (o.org_id, o.org_id))
    with world.vault.superuser() as su:
        assert ledger.verify_chain(su), "ledger.verify_chain covers the frozen event chain and the history chain"


@spec("item11")
def test_11_a_post_cutover_stop_is_found_and_a_lift_is_written_to_the_history_lift_table(cloud, tmp_path):
    need_table("history_stop_lift")
    need_cutover()
    from consentvault import door, lift, rawpost
    from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
    from consentvault.tenancy.pipeline import ReceiptSigner
    from consentvault.tenancy.tokens import org_transaction
    from test_stop_lift import _lift, _post
    t, org, contact = cloud.t, cloud.t.a, PHONE2
    with t.app() as app, org_transaction(app, t.token(org)):
        door.record_observed(app, t.crypto, intake="stop_page", enter=lambda c: c.transaction(), region="US", fields=dict(
            contact=contact, event_type="revoke", channels=["sms"], purposes=["*"], method="checkbox", origin="consumer",
            source_id=org.source_id, recorded_by="stop-page"))
    writer = rawpost.RawPostWriter(crypto=t.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")), receipts=ReceiptSigner.generate(key_id="k1"))
    stored = _post(t, writer, org, contact=contact)
    before = sql(cloud, "SELECT count(*) AS n FROM consentvault.stop_lift WHERE org_id = %s", (org.org_id,))[0]["n"]
    result = _lift(t, writer, org, stored)
    assert len(result.linked) == 1, result
    assert sql(cloud, "SELECT count(*) AS n FROM consentvault.history_stop_lift WHERE org_id = %s", (org.org_id,))[0]["n"] == 1
    assert sql(cloud, "SELECT count(*) AS n FROM consentvault.stop_lift WHERE org_id = %s", (org.org_id,))[0]["n"] == before, "none in the frozen table"


@spec("item12")
def test_12_the_proof_of_a_post_cutover_contact_lists_its_rows_and_logs_the_retrieval(cloud):
    need_table("retrieval_log")
    co = _cloud_grant_and_stop(cloud)
    status, answer = cloud.proof(co, PHONE)
    assert status == 200
    timeline = answer["timeline"]["items"] if isinstance(answer.get("timeline"), dict) else answer["timeline"]
    assert [i["event_type"] for i in timeline] == ["grant", "revoke"]
    assert sql(cloud, "SELECT 1 FROM consentvault.retrieval_log WHERE org_id = %s", (co.org.org_id,))


@spec("item13")
def test_13_a_post_cutover_contact_gets_a_record(world):
    from consentvault import records_backfill
    o = world.a
    cut_grant(world, o, PHONE_NY)
    v = world.vault
    records_backfill.backfill(v.operator, v.key, v.custody, world.crypto)
    assert world.record_id(o, PHONE_NY)


@spec("item14")
def test_14_a_post_cutover_row_is_sealed_into_the_history_seal_table(world, request):
    need_table("post_history_seal")
    from consentvault import integrity
    tsa = request.getfixturevalue("tsa")
    o = world.a
    post = cut_grant(world, o, PHONE)
    sealed = integrity.seal_every_org(integrity_conn(world), tsa.url, 100, backoff=0)
    assert history_event_id(world, o, post) in {str(e) for ids in sealed.values() for e in ids}
    assert sql(world, "SELECT 1 FROM consentvault.post_history_seal WHERE org_id = %s", (o.org_id,))


@spec("item15")
def test_15_a_second_erasure_request_after_cutover_finds_the_first_stop(world):
    need_cutover()
    o = world.a
    cut_grant(world, o, PHONE)
    product_erase(world, o.org_id, PHONE)
    try:
        product_erase(world, o.org_id, PHONE)
    except Exception:  # noqa: BLE001  (the second request may be refused by name; what matters is that it wrote no second stop)
        pass
    assert len(sql(world, "SELECT 1 FROM consentvault.raw_post WHERE org_id = %s AND intake = 'erasure'", (o.org_id,))) == 1


@spec("item16")
def test_16_a_post_cutover_contact_is_offboarded(cloud):
    need_cutover()
    from datetime import datetime, timezone
    from consentvault.evidence import LocalEcdsaSigner
    from consentvault.tenancy.offboard import build_final_export
    from consentvault.tenancy.tokens import org_transaction
    co, t = cloud.a, cloud.t

    def count():
        with t.app() as app, org_transaction(app, t.admin_token(co.org.org_id)):
            return build_final_export(app, t.crypto, LocalEcdsaSigner.generate("k", 1), now=datetime.now(timezone.utc))[1]["contacts"]
    before = count()
    assert cloud.grant(co, "+13055550166")[0] == 201
    assert count() == before + 1, "a contact whose only rows are in history is in the final export"


@spec("item17")
def test_17_a_post_cutover_contact_shows_in_the_records_admin(world):
    need_cutover()
    o = world.a
    cut_grant(world, o, PHONE_NY)
    from consentvault import records_backfill
    v = world.vault
    records_backfill.backfill(v.operator, v.key, v.custody, world.crypto)
    world.record_id(o, PHONE_NY)
    shown = o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE_NY})
    assert "0142" in json.dumps(shown), "the masked contact comes from the last contact ciphertext in history"


@spec("item18")
def test_18_a_post_cutover_contact_is_found_by_the_restore_job(cloud):
    need_cutover()
    from consentvault.tenancy.restore import _replay_stop
    from consentvault.tenancy.tokens import org_transaction
    co, t = cloud.a, cloud.t
    assert cloud.grant(co, "+13055550167")[0] == 201
    done = product_erase(cloud, co.org.org_id, "+13055550167")
    fp = t.crypto.contact_fingerprint(co.org.org_id, "phone", "+13055550167")
    before = len(sql(cloud, "SELECT 1 FROM consentvault.raw_post WHERE org_id = %s AND intake = 'erasure'", (co.org.org_id,)))
    n = {"stops_present": 0, "stops_replayed": 0, "stops_superseded": [], "failed_checks": []}
    with t.app() as app, org_transaction(app, t.admin_token(co.org.org_id)):
        _replay_stop(app, t.crypto, {"contact_fp": fp, "erasure_id": done["erasure_id"], "seq": 0, "channels": ["sms"]}, n, set())
    assert len(sql(cloud, "SELECT 1 FROM consentvault.raw_post WHERE org_id = %s AND intake = 'erasure'", (co.org.org_id,))) == before, \
        "the restore finds the erasure stop that exists only in history and writes no second one"
    assert n["stops_present"] == 1 and not n["failed_checks"]


@spec("item33")
def test_33_the_anchor_command_reads_history_head(cloud, tmp_path):
    need_function("history_head")
    need_cutover()
    from consentvault.cmd_anchor import anchor_tenants
    from consentvault.evidence import LocalEcdsaSigner
    from consentvault.providers.anchors import FileAnchorSink
    co = cloud.a
    assert cloud.grant(co, PHONE)[0] == 201
    worker = login_in_group(cloud, "consentvault_worker")
    with cloud.t.app() as app:
        results = anchor_tenants(worker, app, LocalEcdsaSigner.generate("k", 1), lambda org: FileAnchorSink(tmp_path / f"{org}.jsonl"))
    (mine,) = [r for r in results if r["org_id"] == str(co.org.org_id)]
    head = sql(cloud, "SELECT row_hash FROM consentvault.post_history WHERE org_id = %s ORDER BY history_seq DESC LIMIT 1", (co.org.org_id,))[0]["row_hash"]
    assert mine["status"] == "published" and mine["row_hash"] == head, "the anchored head is the history head, not the frozen event head"


@spec("item34")
def test_34_the_seal_command_seals_a_post_cutover_row(world, request):
    need_function("unsealed_history")
    from consentvault import integrity
    o = world.a
    post = cut_grant(world, o, PHONE)
    eid = history_event_id(world, o, post)
    done = integrity.seal_every_org(integrity_conn(world), request.getfixturevalue("tsa").url, 100, backoff=0)   # what the seal command runs
    assert eid in {str(e) for ids in done.values() for e in ids}
    assert eid not in {str(r["event_id"]) for r in sql(world, "SELECT * FROM consentvault.unsealed_history()")}


@spec("item35")
def test_35_integrity_reports_an_unsealed_post_cutover_row_and_its_head_equals_the_history_head(world):
    need_function("unsealed_history")
    from consentvault import integrity
    o = world.a
    post = cut_grant(world, o, PHONE)
    report = integrity.verify_seals_every_org(integrity_conn(world))
    assert history_event_id(world, o, post) in json.dumps(report, default=str)
    heads = integrity.verify_chain_every_org(integrity_conn(world))
    assert history_head(world)["row_hash"] in json.dumps(heads, default=str)


@spec("item36")
def test_36_the_bundles_head_equals_the_history_head_and_the_derived_view_is_labelled(cloud):
    need_function("history_head")
    from consentvault import evidence
    from consentvault.tenancy.tokens import org_transaction
    co = _cloud_grant_and_stop(cloud)
    fp = cloud.t.crypto.contact_fingerprint(co.org.org_id, "phone", PHONE)
    with cloud.t.app() as app, org_transaction(app, cloud.t.token(co.org, scopes=("capture", "gate_read", "proof_read"))):
        bundle, _ = evidence.gather_tenant(app, cloud.t.crypto, fp)
    text = json.dumps(bundle, default=str)
    assert sql(cloud, "SELECT row_hash FROM consentvault.history_head()")[0]["row_hash"] in text and "derived" in text.lower()


@spec("item38")
def test_38_the_proof_of_a_post_cutover_stop_shows_it_under_the_derived_label(cloud):
    co = _cloud_grant_and_stop(cloud)
    status, answer = cloud.proof(co, PHONE)
    assert status == 200 and "derived" in json.dumps(answer, default=str).lower()
    assert "stopped" in json.dumps(answer, default=str).lower()


@spec("item43")
def test_43_a_post_naming_a_release_projects_to_one_history_row_and_the_event_table_is_unchanged(world):
    need_cutover()
    import uuid
    o = world.a
    before = sql(world, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", (o.org_id,))[0]["n"]
    post = door_post(world, o, grant_fields(o, PHONE, event_type="release", release_of_event_id=str(uuid.uuid4())))
    assert len(history_rows(world, o, post_id=post)) == 1
    assert sql(world, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", (o.org_id,))[0]["n"] == before
    assert sql(world, "SELECT 1 FROM pg_trigger WHERE tgrelid = 'consentvault.post_history'::regclass AND tgname LIKE '%%release%%'") == []
