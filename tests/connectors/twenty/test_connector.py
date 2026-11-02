"""The Twenty connector against the real core in Postgres and a fake Twenty (twenty.md sections 1 to 6; the model's rules R16 to
R31). Every test names the contract statement or model rule it proves."""

import time
from datetime import timedelta

import psycopg
import pytest

from consentvault.sync.connectors import twenty as tw
from consentvault.sync.errors import CredentialError
from consentvault.tenancy import erasure, holds
from consentvault.tenancy.tokens import org_transaction

from erasure.support import OPERATOR, Env as ErasureEnv
from .support import API_KEY, BASE, WEBHOOK_SECRET, TwentyEnv, signed

PHONE, PHONE2 = "+15555552001", "+15555552002"
EMAIL = "ann@example.com"


@pytest.fixture
def tw_env(env):
    return TwentyEnv(env, env.t.a)


@pytest.fixture
def life(tenancy, tmp_path):
    return ErasureEnv(tenancy, tmp_path)


def grant(env, contact, channel="sms"):
    env.grant(env.t.a, contact, channels=[channel], purposes=["marketing"])


def stop(env, contact, channel="sms"):
    env.stop(env.t.a, contact, channels=[channel], purposes=["marketing"])


def request_and_confirm(life, contact):
    org = life.t.a
    with life.admin(org) as ctx:
        eid = erasure.request_erasure(ctx, {"contact": contact, "reason": "the person asked"}, crypto=life.t.crypto)["erasure_id"]
    with life.operator() as c:
        out = erasure.confirm_erasure(c, token_key=life.t.key, crypto=life.t.crypto, ledger=life.ledger, operator_id=OPERATOR,
                                      request_id="req-op", org_id=org.org_id, erasure_id=eid)
    return eid, out


def resume(life):
    with life.operator() as c:
        return erasure.resume_waiting(c, token_key=life.t.key, ledger=life.ledger, crypto=life.t.crypto, request_id="req-r",
                                      org_id=life.t.a.org_id)


def request_status(env, eid):
    return env.q("SELECT status, wait_reason FROM consentvault.erasure_request WHERE erasure_id = %s", [eid])[0]


# ---- 1. connect, secrets, address, disconnect ---------------------------------------------------------------------------
def test_connect_starts_paused_connecting_plaintext_and_seals_the_key(env):
    org = env.t.a
    with env.t.app() as app, org_transaction(app, env.t.admin_token(org.org_id)):
        made = tw.create_twenty_system(app, env.custody, org.org_id, name="crm", base_url=BASE, api_key=API_KEY)
    row = env.q("SELECT * FROM consentvault.connected_system WHERE system_id = %s", [made["system_id"]])[0]
    assert (row["status"], row["connector_state"], row["contact_form"], row["connector"], row["signature"]) == \
        ("paused", "connecting", "plaintext", "twenty", "none")
    dump = env.q("SELECT wrapped, sealed FROM consentvault.connector_secret WHERE system_id = %s", [made["system_id"]])
    assert dump and all(API_KEY.encode() not in bytes(r["wrapped"]) + bytes(r["sealed"]) for r in dump)
    stored = env.q("SELECT receiver_hash FROM consentvault.connector_receiver WHERE system_id = %s", [made["system_id"]])
    assert stored[0]["receiver_hash"] != made["receiver_id"] and len(stored[0]["receiver_hash"]) == 64
    with env.t.app() as app, org_transaction(app, env.t.admin_token(org.org_id)), pytest.raises(psycopg.errors.CheckViolation):
        app.execute("UPDATE consentvault.connected_system SET contact_form = 'fingerprint' WHERE system_id = %s",
                    (made["system_id"],))


@pytest.mark.parametrize("bad", ["http://crm.example.test", "https://crm.example.test/path", "https://u:p@crm.example.test"])
def test_connect_refuses_an_address_that_is_not_an_https_origin(env, bad):
    with env.t.app() as app, org_transaction(app, env.t.admin_token(env.t.a.org_id)), pytest.raises(CredentialError):
        tw.create_twenty_system(app, env.custody, env.t.a.org_id, name="crm", base_url=bad, api_key=API_KEY)


def test_address_change_needs_the_key_again_and_remints_the_receiver(env, tw_env):
    org, sid = env.t.a, tw_env.sys.system_id
    with env.t.app() as app, org_transaction(app, env.t.admin_token(org.org_id)), pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("UPDATE consentvault.connected_system SET endpoint = 'https://evil.example.test' WHERE system_id = %s", (sid,))
    with env.t.app() as app, org_transaction(app, env.t.admin_token(org.org_id)), pytest.raises(CredentialError):
        tw.set_address(app, env.custody, org.org_id, sid, base_url="https://crm2.example.test", api_key=None)
    with env.t.app() as app, org_transaction(app, env.t.admin_token(org.org_id)):
        new_rid = tw.set_address(app, env.custody, org.org_id, sid, base_url="https://crm2.example.test", api_key=API_KEY)
    raw = tw_env.twenty.event("person.updated", "p1", {"id": "p1", "cvStopFlag": False, "emails": {}, "phones": {}})
    assert tw_env.receiver.handle(tw_env.sys.receiver_id, signed(raw), raw) == (404, {})   # the old address's receiver is dead
    assert tw_env.receiver.handle(new_rid, signed(raw), raw)[0] != 404
    row = env.q("SELECT status, connector_state FROM consentvault.connected_system WHERE system_id = %s", [sid])[0]
    assert (row["status"], row["connector_state"]) == ("paused", "connecting")   # the self-test must pass again


def test_a_developer_token_cannot_change_a_key_or_disconnect(env, tw_env):
    tok = env.t.token(env.t.a, scopes=("developer",))
    with env.t.app() as app, org_transaction(app, tok), pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("SELECT consentvault.sync_twenty_disconnect(%s, 'x')", (tw_env.sys.system_id,))
    with env.t.app() as app, org_transaction(app, tok), pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("SELECT consentvault.connector_secret_put(%s, 'api_key', '\\x00', '\\x00')", (tw_env.sys.system_id,))


def test_disconnect_supersedes_pushes_kills_an_open_clear_retires_the_receiver_and_destroys_secrets(env, tw_env, life):
    tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    eid, out = request_and_confirm(life, PHONE2 if False else PHONE)
    assert out["status"] == "held" and out["held_reason"] == "waiting_for_system_clear"
    with env.t.app() as app, org_transaction(app, env.t.admin_token(env.t.a.org_id)):
        got = tw.disconnect(app, tw_env.sys.system_id, "moving CRM")
    assert got["clears_dead"] == 1
    rows = env.outbox(env.t.a, system_id=tw_env.sys.system_id)
    assert {(r["push_kind"], r["status"], r["superseded_reason"]) for r in rows} >= {("clear", "dead", None)}
    assert all(r["superseded_reason"] in ("system_disconnected", "erased", None) for r in rows)
    assert env.q("SELECT count(*) AS n FROM consentvault.connector_secret WHERE system_id = %s", [tw_env.sys.system_id])[0]["n"] == 0
    raw = tw_env.twenty.event("person.updated", "p")
    assert tw_env.receiver.handle(tw_env.sys.receiver_id, signed(raw), raw) == (404, {})
    resume(life)
    assert request_status(env, eid)["wait_reason"] == "system_clear_dead"   # a dead clear waits for an operator, never passes
    with life.operator() as c, erasure.operator_org(c, life.t.key, env.t.a.org_id):
        tw.waive_clear(c, eid, tw_env.sys.system_id, operator_id=OPERATOR, reason="the CRM is gone")
    resume(life)
    assert request_status(env, eid)["status"] == "completed"


def test_waiver_is_refused_while_the_system_is_reachable(env, tw_env, life):
    tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    eid, _ = request_and_confirm(life, PHONE)
    env.q("UPDATE consentvault.outbox SET status = 'dead', finished_at = now(), next_attempt_at = NULL WHERE erasure_id = %s", [eid])
    with life.operator() as c, erasure.operator_org(c, life.t.key, env.t.a.org_id), pytest.raises(CredentialError):
        tw.waive_clear(c, eid, tw_env.sys.system_id, operator_id=OPERATOR, reason="skip it")


# ---- 2. outbound: the combined state, the sequence, the read-back, the lease ---------------------------------------------
@pytest.mark.parametrize("order", ["grant_first", "stop_first"])
def test_email_granted_plus_phone_stopped_reads_denied_in_both_orders(env, tw_env, order):
    pid = tw_env.twenty.add(email=EMAIL, phone=PHONE)
    steps = [lambda: grant(env, EMAIL), lambda: stop(env, PHONE)]
    for s in steps if order == "grant_first" else reversed(steps):
        s()
        tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"   # R16: a stop on any contact wins
    assert len(tw_env.links()) == 2                                   # R18: one link per Person and contact


def test_no_match_is_acknowledged_not_in_system_and_never_creates_a_person(env, tw_env):
    stop(env, PHONE)
    tw_env.drain()
    rows = env.outbox(env.t.a, system_id=tw_env.sys.system_id)
    assert [(r["status"], r["confirmation"]) for r in rows] == [("acknowledged", "not_in_system")]
    assert tw_env.twenty.count("POST") == 0


def test_a_person_created_later_gets_the_state_by_a_refresh(env, tw_env):
    stop(env, PHONE)
    tw_env.drain()
    pid = tw_env.twenty.add(phone=PHONE)
    assert tw_env.webhook("person.created", pid)[0] == 202
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"


def test_integer_sequence_and_a_larger_typed_sequence_is_overwritten_and_counted(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE, cvStateSeq="99999")
    stop(env, PHONE)
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStateSeq"] != "99999"
    assert tw_env.activity("seq_above_vault") == 1


def test_applying_twice_writes_the_same_fields_and_needs_no_second_patch(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    tw_env.drain()
    first = tw_env.twenty.status_of(pid)
    patches = tw_env.twenty.count("PATCH")
    with env.t.app() as app, org_transaction(app, env.t.token(env.t.a, scopes=("capture",))):
        tw.enqueue_refresh(app, env.t.crypto, env.t.a.org_id, tw_env.sys.system_id, env.fp(env.t.a, PHONE))
    tw_env.drain()
    assert tw_env.twenty.status_of(pid) == first and tw_env.twenty.count("PATCH") == patches


def test_readback_mismatch_retries(env, tw_env):
    tw_env.twenty.add(phone=PHONE)
    tw_env.twenty.overwrite_on_patch = {"cvStatusSms": "permitted"}   # a second writer or a Twenty rule
    stop(env, PHONE)
    tw_env.drain(rounds=1)
    row = env.outbox(env.t.a, system_id=tw_env.sys.system_id)[0]
    assert (row["status"], row["last_error_class"]) == ("failed", "readback_mismatch")


def test_rejected_key_goes_dead_at_once_and_two_in_ten_minutes_need_attention_with_one_alarm(env, tw_env):
    tw_env.twenty.api_key = "rotated"
    stop(env, PHONE)
    stop(env, PHONE2)
    tw_env.drain(rounds=2)
    rows = env.outbox(env.t.a, system_id=tw_env.sys.system_id)
    assert {(r["status"], r["last_error_class"]) for r in rows} == {("dead", "key_rejected")}
    st = env.q("SELECT connector_state FROM consentvault.connected_system WHERE system_id = %s", [tw_env.sys.system_id])[0]
    assert st["connector_state"] == "needs_attention:key_rejected"
    assert len(tw_env.alarms("connector.state")) == 1


def test_a_stalled_send_past_fifteen_seconds_sends_nothing_and_is_not_an_attempt(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)

    def stall(sending):
        if sending:
            tw_env.mono.t += 16          # the worker stalled between the lease extension and the send
    tw_env.delivery.after_extension = stall
    tw_env.drain(rounds=1)
    assert tw_env.twenty.count("PATCH") == 0 and tw_env.twenty.status_of(pid)["cvStatusSms"] is None
    row = env.outbox(env.t.a, system_id=tw_env.sys.system_id)[0]
    assert row["status"] == "pending" and row["attempts"] == 0     # released, not counted
    assert tw_env.activity("refused_late_send") == 1
    tw_env.delivery.after_extension = None
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"


def test_a_person_leased_by_another_delivery_is_not_written(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    with env.t.superuser() as su:
        key = env.q("SELECT wrapped FROM consentvault.connector_secret WHERE org_id = %s AND purpose = 'hash_key'",
                    [env.t.a.org_id])[0]["wrapped"]
    h = tw.person_id_hash(env.custody.unwrap(str(env.t.a.org_id), bytes(key)), pid)
    import uuid as _u

    env.q("INSERT INTO consentvault.connector_person_lease VALUES (%s, %s, %s, %s, 1, now() + interval '30 seconds')",
          [env.t.a.org_id, tw_env.sys.system_id, h, _u.uuid4()])
    tw_env.drain(rounds=1)
    assert tw_env.twenty.count("PATCH") == 0
    assert env.outbox(env.t.a, system_id=tw_env.sys.system_id)[0]["attempts"] == 0


# ---- 3. inbound: stops from Twenty -------------------------------------------------------------------------------------
def test_flag_false_to_true_records_a_stop_on_every_point_and_channel_as_import(env, tw_env):
    pid = tw_env.twenty.add(email=EMAIL, phone=PHONE)
    tw_env.twenty.touch(pid, cvStopFlag=True)
    assert tw_env.webhook("person.updated", pid) == (202, {"ok": True})
    for c in (EMAIL, PHONE):
        for ch in ("sms", "voice", "artificial_voice", "email"):
            assert env.q("SELECT 1 FROM consentvault.current_permission WHERE org_id = %s AND contact_fp = %s AND channel = %s"
                         " AND NOT allowed AND reason LIKE 'stopped:%%'", [env.t.a.org_id, env.fp(env.t.a, c), ch])
    ev = env.q("SELECT method, origin, source, recorded_by FROM consentvault.event WHERE org_id = %s AND event_type = 'suppress'",
               [env.t.a.org_id])
    assert ev and {(e["method"], e["origin"], e["source"]) for e in ev} == {("import", "import", "signal")}
    assert all(e["recorded_by"] == f"system:{tw_env.sys.system_id}" for e in ev)


def test_true_to_true_and_true_to_false_record_nothing_and_a_lift_is_never_restopped(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE, flag=True)
    tw_env.webhook("person.updated", pid)              # first sight with the flag true: a stop
    n = env.q("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", [env.t.a.org_id])[0]["n"]
    tw_env.twenty.touch(pid, cvStatusSms="denied")      # our own write coming back: true to true
    tw_env.webhook("person.updated", pid)
    tw_env.twenty.touch(pid, cvStopFlag=False)          # true to false: not a lift
    tw_env.webhook("person.updated", pid)
    assert env.q("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", [env.t.a.org_id])[0]["n"] == n
    signals = env.q("SELECT count(*) AS n FROM consentvault.inbound_signal WHERE org_id = %s", [env.t.a.org_id])[0]["n"]
    tw_env.twenty.touch(pid, cvStopFlag=True)           # a new false to true: a new stop signal, which is what staff meant
    tw_env.webhook("person.updated", pid)
    assert env.q("SELECT count(*) AS n FROM consentvault.inbound_signal WHERE org_id = %s", [env.t.a.org_id])[0]["n"] > signals


def test_consent_is_never_created_from_twenty(env, tw_env):
    grants = "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = 'grant'"
    before = env.q(grants, [env.t.a.org_id])[0]["n"]
    pid = tw_env.twenty.add(phone=PHONE, cvStatusSms="permitted", cvStatusEmail="permitted")
    tw_env.webhook("person.updated", pid)
    assert env.q(grants, [env.t.a.org_id])[0]["n"] == before


def test_a_repeat_with_the_same_updated_at_is_dropped_once(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE, flag=True)
    rec = dict(tw_env.twenty.people[pid])
    assert tw_env.webhook("person.updated", pid, rec)[0] == 202
    assert tw_env.webhook("person.updated", pid, rec) == (202, {"ok": True, "dedupe": True})


def test_webhook_signature_window_replay_and_unknown_receiver(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE)
    raw = tw_env.twenty.event("person.updated", pid)
    rid, now = tw_env.sys.receiver_id, env.clock()
    assert tw_env.receiver.handle(rid, {**signed(raw), "X-Twenty-Webhook-Signature": "0" * 64}, raw) == (401, {"error": "invalid_client"})
    assert tw_env.receiver.handle(rid, signed(raw, secret="y" * 30), raw)[0] == 401
    assert tw_env.receiver.handle(rid, signed(raw, at=now - timedelta(minutes=5, seconds=1)), raw)[0] == 401
    assert tw_env.receiver.handle(rid, {}, raw)[0] == 401
    ok = signed(raw, at=now - timedelta(minutes=4, seconds=59))
    assert tw_env.receiver.handle(rid, ok, raw)[0] == 202
    assert tw_env.receiver.handle(rid, ok, raw) == (401, {"error": "invalid_client"})   # the same signature again: a replay
    assert tw_env.receiver.handle("not-a-receiver", signed(raw), raw) == (404, {})
    assert tw_env.receiver.handle(rid, signed(raw + b" "), raw)[0] == 401              # signed bytes differ from the body
    assert tw_env.activity("signature_bad") == 3 and tw_env.activity("stale_timestamp") == 1
    assert tw_env.activity("replay") == 1 and tw_env.activity("signature_missing") == 1


def test_five_bad_signatures_in_ten_minutes_raise_webhook_failing_once(env, tw_env):
    raw = tw_env.twenty.event("person.updated", "x")
    for _ in range(6):
        tw_env.receiver.handle(tw_env.sys.receiver_id, {**signed(raw), "X-Twenty-Webhook-Signature": "1" * 64}, raw)
    st = env.q("SELECT connector_state FROM consentvault.connected_system WHERE system_id = %s", [tw_env.sys.system_id])[0]
    assert st["connector_state"] == "needs_attention:webhook_failing"
    assert len(tw_env.alarms("connector.state")) == 1


def test_unknown_events_are_acknowledged_and_ignored(env, tw_env):
    raw = b'{"eventName":"company.updated","record":{"id":"c"}}'
    assert tw_env.receiver.handle(tw_env.sys.receiver_id, signed(raw), raw) == (202, {"ok": True, "ignored": "unsupported_event"})


def test_an_incomplete_payload_requests_a_reconcile(env, tw_env):
    assert tw_env.webhook("person.updated", "p", {"id": "p"})[0] == 202
    assert env.q("SELECT reconcile_requested_at FROM consentvault.connected_system WHERE system_id = %s",
                 [tw_env.sys.system_id])[0]["reconcile_requested_at"] is not None


# ---- 4. merges, restores, soft and hard deletes -------------------------------------------------------------------------
@pytest.mark.parametrize("order", ["flag_then_merge", "merge_then_flag"])
def test_a_point_merged_onto_a_flagged_person_is_stopped_in_either_order(env, tw_env, order):
    pid = tw_env.twenty.add(email=EMAIL)
    grant(env, EMAIL)
    grant(env, PHONE)
    tw_env.drain()
    if order == "flag_then_merge":
        tw_env.twenty.touch(pid, cvStopFlag=True)
        tw_env.webhook("person.updated", pid)
        tw_env.twenty.add_point(pid, phone=PHONE)
        tw_env.webhook("person.updated", pid)
    else:
        tw_env.twenty.add_point(pid, phone=PHONE)
        tw_env.webhook("person.updated", pid)
        tw_env.twenty.touch(pid, cvStopFlag=True)
        tw_env.webhook("person.updated", pid)
    assert tw_env.gate(PHONE) == "denied" and tw_env.gate(EMAIL) == "denied"   # R26
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"


def test_soft_delete_keeps_links_and_a_restore_rewrites_the_person(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    tw_env.drain()
    tw_env.twenty.soft_delete(pid)
    tw_env.webhook("person.deleted", pid)
    assert len(tw_env.links()) == 1
    tw_env.twenty.people[pid]["cvStatusSms"] = "permitted"   # restored with stale fields
    tw_env.twenty.restore(pid)
    tw_env.webhook("person.restored", pid)
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"


def test_a_hard_delete_drops_links_keeps_a_marker_and_a_late_update_is_ignored(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE, flag=True)
    tw_env.webhook("person.updated", pid)          # stop recorded
    stop_count = env.q("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", [env.t.a.org_id])[0]["n"]
    late = dict(tw_env.twenty.people[pid])
    late["updatedAt"] = "2099-01-01T00:00:00.000Z"
    tw_env.twenty.destroy(pid)
    tw_env.webhook("person.destroyed", pid, {"id": pid})
    assert tw_env.links() == []
    assert env.q("SELECT count(*) AS n FROM consentvault.connector_destroyed WHERE system_id = %s", [tw_env.sys.system_id])[0]["n"] == 1
    assert env.q("SELECT count(*) AS n FROM consentvault.connector_flag_seen WHERE system_id = %s", [tw_env.sys.system_id])[0]["n"] == 0
    tw_env.webhook("person.updated", pid, late)    # arrives after the destroy, flag true
    assert env.q("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", [env.t.a.org_id])[0]["n"] == stop_count
    assert tw_env.activity("after_destroyed") == 1


def test_a_person_destroyed_before_it_was_ever_linked_gets_a_marker(env, tw_env):
    tw_env.webhook("person.destroyed", "never-linked", {"id": "never-linked"})
    assert env.q("SELECT count(*) AS n FROM consentvault.connector_destroyed WHERE system_id = %s", [tw_env.sys.system_id])[0]["n"] == 1


# ---- 5. the reconcile ---------------------------------------------------------------------------------------------------
def test_reconcile_finds_a_missed_flag_and_records_the_stop(env, tw_env):
    tw_env.twenty.add(phone=PHONE, flag=True)       # no webhook ever arrived
    rep = tw_env.reconcile()
    assert rep.complete and rep.stops_found >= 1 and tw_env.gate(PHONE) == "denied"


def test_a_hidden_stop_is_corrected_and_alarms_every_time(env, tw_env):
    pid = tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    tw_env.drain()
    for n in (1, 2):
        tw_env.twenty.touch(pid, cvStatusSms="permitted")   # staff type over the stop
        rep = tw_env.reconcile()
        assert rep.stops_hidden == 1
        assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"
        assert len(tw_env.alarms("connector.stop_hidden")) == n   # never folded into the 25-a-day drift threshold


def test_reconcile_watermark_advances_only_on_a_completed_page_and_three_failures_alarm(env, tw_env):
    tw_env.twenty.add(phone=PHONE)
    tw_env.reconcile()
    wm = env.q("SELECT watermark FROM consentvault.connector_reconcile WHERE system_id = %s", [tw_env.sys.system_id])[0]["watermark"]
    assert wm is not None
    from consentvault.sync.errors import SyncError

    for _ in range(3):
        tw_env.twenty.script("GET", 500)
        with pytest.raises(SyncError):
            tw_env.reconcile()
    assert env.q("SELECT watermark FROM consentvault.connector_reconcile WHERE system_id = %s",
                 [tw_env.sys.system_id])[0]["watermark"] == wm
    assert len(tw_env.alarms("connector.reconcile_failing")) == 1


# ---- 6. erasure: the clear -----------------------------------------------------------------------------------------------
def test_erasing_the_email_while_the_phone_is_stopped_writes_denied_never_blank(env, tw_env, life):
    pid = tw_env.twenty.add(email=EMAIL, phone=PHONE)
    grant(env, EMAIL)
    stop(env, PHONE)
    tw_env.drain()
    eid, out = request_and_confirm(life, EMAIL)
    assert out["held_reason"] == "waiting_for_system_clear"
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"   # R17
    assert [c["confirmation"] for c in tw_env.clears()] == ["cleared"]
    resume(life)
    assert request_status(env, eid)["status"] == "completed"
    assert {l["contact_fp"] for l in tw_env.links()} == {env.fp(env.t.a, PHONE)}   # only the erased contact's links went


def test_erasing_the_only_contact_blanks_the_fields_and_completes_after_the_clear(env, tw_env, life):
    pid = tw_env.twenty.add(phone=PHONE)
    grant(env, PHONE)
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "permitted"
    eid, out = request_and_confirm(life, PHONE)
    assert out["status"] == "held" and request_status(env, eid)["wait_reason"] == "waiting_for_system_clear"
    tw_env.drain()
    assert tw_env.twenty.status_of(pid) == {f: None for f in tw_env.twenty.status_of(pid)}
    resume(life)
    assert request_status(env, eid)["status"] == "completed"
    assert tw_env.twenty.people[pid]["cvStopFlag"] is False          # the vault never writes the flag


def test_no_status_write_while_the_erasure_is_mid_flight(env, tw_env, life):
    pid = tw_env.twenty.add(phone=PHONE)
    grant(env, PHONE)
    tw_env.drain()
    eid, _ = request_and_confirm(life, PHONE)
    stop(env, PHONE)                                                 # R1: inserted superseded while the clear is open
    rows = [r for r in env.outbox(env.t.a, system_id=tw_env.sys.system_id) if r["push_kind"] == "state"]
    assert rows[-1]["status"] == "superseded" and rows[-1]["superseded_reason"] == "erased"
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] is None


def test_a_clear_waits_on_a_soft_deleted_person_and_alarms_at_seven_and_thirty_days(env, tw_env, life):
    pid = tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    tw_env.drain()
    tw_env.twenty.soft_delete(pid)
    eid, _ = request_and_confirm(life, PHONE)
    tw_env.drain()
    assert tw_env.clears()[0]["status"] == "pending"               # R25: a 404 from a soft-deleted Person is no acknowledgement
    assert tw_env.alarms("connector.clear_waiting_deleted_record") == []
    prev = 0
    for days, customer, operator in ((7, 1, 0), (8, 2, 0), (30, 3, 1)):
        # the wait's age is the database's clock: its start and the last alarm move back by the days that pass, and the clear
        # is due again; the process clock moves with them for everything that reads it
        secs = (days - prev) * 86400
        env.q("UPDATE consentvault.connector_link SET deleted_since = deleted_since - make_interval(secs => %s),"
              " alarm_raised_at = alarm_raised_at - make_interval(secs => %s) WHERE system_id = %s AND deleted_since IS NOT NULL",
              [secs, secs, tw_env.sys.system_id])
        env.ageing(env.t.a)
        prev = days
        env.clock.offset = timedelta(days=days)
        tw_env.drain(rounds=1)
        assert len(tw_env.alarms("connector.clear_waiting_deleted_record")) == customer
        assert len(tw_env.alarms("erasure.clear_blocked_by_deleted_record")) == operator
    with env.t.app() as app, org_transaction(app, env.t.admin_token(env.t.a.org_id)):
        waits = tw.deleted_record_waits(app, env.t.crypto, env.t.a.org_id)
    assert waits[0]["record_id"] == pid and waits[0]["link"] == f"{BASE}/object/person/{pid}"
    alarm_rows = tw_env.alarms("connector.clear_waiting_deleted_record")
    assert all(pid not in str(r) and PHONE not in str(r) for r in alarm_rows)   # never a contact or a record id in a row
    resume(life)
    assert request_status(env, eid)["status"] == "pending_operator_confirmation"
    env.clock.offset = timedelta(0)                                  # the replay guard keeps the database's own time
    tw_env.twenty.destroy(pid)                                       # a permanent delete acknowledges it
    tw_env.webhook("person.destroyed", pid, {"id": pid})
    tw_env.drain()
    assert tw_env.clears()[0]["confirmation"] == "not_in_system"
    resume(life)
    assert request_status(env, eid)["status"] == "completed"


def test_a_hold_blocks_the_clear_never_a_stop(env, tw_env, life):
    pid = tw_env.twenty.add(phone=PHONE)
    grant(env, PHONE)
    tw_env.drain()
    eid, _ = request_and_confirm(life, PHONE)
    with life.admin(env.t.a) as ctx:
        holds.place_hold_member(ctx, {"scope": "contacts", "contacts": [PHONE], "reason": "litigation"}, ledger=life.ledger,
                                crypto=env.t.crypto)
    assert tw_env.clears()[0]["superseded_reason"] == "held"
    stop(env, PHONE)
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"   # invariant 6: the stop reaches Twenty under the hold


def test_a_stop_on_a_point_merged_in_as_an_additional_phone_reaches_twenty_on_the_event_path(env, tw_env):
    """Twenty's filter reaches only the primary phone, so the receiver links the Person to every point it carries when an event
    names them; the delivery then finds the Person by that link. No reconcile runs here."""
    pid = tw_env.twenty.add(email=EMAIL)
    grant(env, EMAIL)
    grant(env, PHONE)
    tw_env.drain()
    tw_env.twenty.add_point(pid, phone=PHONE)            # an additional phone, never the primary
    assert tw_env.webhook("person.updated", pid)[0] == 202
    tw_env.drain()
    stop(env, PHONE)
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"
    assert env.q("SELECT count(*) AS n FROM consentvault.connector_reconcile WHERE system_id = %s",
                 [tw_env.sys.system_id])[0]["n"] == 0                  # the event path did it, not the reconcile


def test_a_repeated_stop_rewrites_a_twenty_record_whose_stop_staff_typed_over(env, tw_env):
    """A fresh ledger fact that moves no state still queues a Twenty refresh, so the record converges without waiting for the
    reconcile (the model queues a write for every ledger event)."""
    pid = tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    tw_env.drain()
    tw_env.twenty.touch(pid, cvStatusSms="permitted")      # staff type over the stop
    stop(env, PHONE)                                        # the person texts STOP again: no state moves
    tw_env.drain()
    assert tw_env.twenty.status_of(pid)["cvStatusSms"] == "denied"


def test_a_stop_set_in_twenty_is_written_back_to_twenty_echo_to_source(env, tw_env):
    """3.6: the one documented echo exception. The staff stop's own status write goes back to the Twenty that sent it."""
    pid = tw_env.twenty.add(phone=PHONE, flag=True)
    tw_env.webhook("person.updated", pid)
    rows = [r for r in env.outbox(env.t.a, system_id=tw_env.sys.system_id) if r["push_kind"] == "state"]
    assert rows, "the stop recorded from Twenty queued no status write back to Twenty"


def _restore_ctx(life, org):
    from consentvault.tenancy import restore

    return erasure.operator_org(life.operator(), life.t.key, org.org_id, scopes=restore.RESTORE_SCOPES)


def test_a_restore_that_replays_a_committed_erasure_closes_its_twenty_clear_as_erased(env, tw_env, life):
    """5.1 Restore: the key is deleted again, and an open clear is closed as erased (the nightly scan handles the fields)."""
    from datetime import datetime, timezone

    from consentvault.tenancy import restore

    tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    tw_env.drain()
    eid, _ = request_and_confirm(life, PHONE)
    assert tw_env.clears()[0]["status"] == "pending"
    n = {"erasures_present": 0, "erasures_held": [], "erasures_replayed": 0, "keys_deleted": 0}
    with life.operator() as c, erasure.operator_org(c, life.t.key, env.t.a.org_id, scopes=restore.RESTORE_SCOPES):
        restore._replay_erasure(c, env.t.crypto, {"erasure_id": eid, "contact_fp": env.fp(env.t.a, PHONE), "seq": 1,
                                                  "erased_at": datetime.now(timezone.utc)}, {"seq": 2}, n, request_id="r")
    clear = tw_env.clears()[0]
    assert n["erasures_replayed"] == 1 and (clear["status"], clear["superseded_reason"]) == ("superseded", "erased")


def test_a_restore_that_finds_an_uncommitted_intent_holds_the_clear_until_the_operator_confirms_again(env, tw_env, life):
    from consentvault.tenancy import restore

    tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    tw_env.drain()
    eid, _ = request_and_confirm(life, PHONE)
    with life.operator() as c, erasure.operator_org(c, life.t.key, env.t.a.org_id, scopes=restore.RESTORE_SCOPES):
        assert restore._hold_uncommitted(c, {"erasure_id": eid, "seq": 1}, request_id="r")
    clear = tw_env.clears()[0]
    assert (clear["status"], clear["superseded_reason"]) == ("superseded", "held")
    assert request_status(env, eid)["wait_reason"] == "uncommitted_ledger_intent"
    resume(life)                                                   # the resume job never runs a restore-held request
    assert tw_env.clears()[0]["superseded_reason"] == "held"
    with life.operator() as c:                                     # the operator's re-confirm revives its own clear
        erasure.confirm_erasure(c, token_key=life.t.key, crypto=life.t.crypto, ledger=life.ledger, operator_id=OPERATOR,
                                request_id="re", org_id=env.t.a.org_id, erasure_id=eid)
    assert tw_env.clears()[0]["status"] == "pending"


@pytest.mark.parametrize("bad", ["https://169.254.169.254", "https://127.0.0.1", "https://10.0.0.5", "https://[::1]",
                                 "https://[fe80::1]", "http://crm2.example.test", "https://crm2.example.test/path",
                                 "https://u:p@crm2.example.test", "https://localhost"])
def test_create_and_a_new_address_refuse_the_same_non_public_or_non_origin_addresses(env, tw_env, bad):
    """1.1: an https origin, public; one check for creation and for a changed address."""
    with env.t.app() as app, org_transaction(app, env.t.admin_token(env.t.a.org_id)), pytest.raises(CredentialError):
        tw.set_address(app, env.custody, env.t.a.org_id, tw_env.sys.system_id, base_url=bad, api_key=API_KEY)
    with env.t.app() as app, org_transaction(app, env.t.admin_token(env.t.a.org_id)), pytest.raises(CredentialError):
        tw.create_twenty_system(app, env.custody, env.t.a.org_id, name="crm-x", base_url=bad, api_key=API_KEY)


def test_each_group_is_stamped_when_its_own_push_starts_and_its_backoff_counts_from_there(env, tw_env):
    """Two people in one batch, both ending in a retry; the first push takes 0.3 seconds. Each group's attempt time is its own
    push's start on the database's clock (the second is at least 0.3 seconds later), and each waits exactly the backoff from it."""
    tw_env.twenty.add(phone=PHONE)
    tw_env.twenty.add(phone=PHONE2)
    tw_env.twenty.overwrite_on_patch = {"cvStatusSms": "permitted"}   # every write reads back wrong: a retry
    slowed = []

    def slow_first_push(method, path):
        if not slowed:
            slowed.append(path)
            time.sleep(0.3)                     # the push takes real time: the database's clock stamps the start
    tw_env.twenty.hook = slow_first_push
    stop(env, PHONE)
    stop(env, PHONE2)
    tw_env.drain(rounds=1)
    rows = sorted(env.outbox(env.t.a, system_id=tw_env.sys.system_id), key=lambda r: r["last_attempt_at"])
    assert [r["status"] for r in rows] == ["failed", "failed"]
    assert [(r["next_attempt_at"] - r["last_attempt_at"]).total_seconds() for r in rows] == [30, 30]
    assert (rows[1]["last_attempt_at"] - rows[0]["last_attempt_at"]).total_seconds() >= 0.3


def test_a_group_another_worker_took_before_its_push_started_is_counted_stale(env, tw_env):
    """As for the sync worker: the Twenty push-start stamp refused because a second worker took the group is a stale group,
    never a failed run."""
    tw_env.twenty.add(phone=PHONE)
    stop(env, PHONE)
    real_db, taken = tw_env.delivery._db, []

    def take_over_first(conn, token, sql, args=(), **kw):
        if "sync_attempt_started" in sql and not taken:
            taken.append(1)
            # this worker's lease runs out on the database's clock: its claim and its Person lease end now
            env.q("UPDATE consentvault.outbox SET claimed_until = clock_timestamp() - interval '1 second'"
                  " WHERE system_id = %s AND status = 'sent'", [tw_env.sys.system_id])
            env.q("UPDATE consentvault.connector_person_lease SET lease_until = clock_timestamp() - interval '1 minute'"
                  " WHERE system_id = %s", [tw_env.sys.system_id])
            with env.worker_conn() as w2:
                tw_env.worker().run_once(w2, raise_on_error=False)  # a second worker takes the group and pushes it
        return real_db(conn, token, sql, args, **kw)
    tw_env.delivery._db = take_over_first
    reports = tw_env.drain(rounds=1)
    mine = next(o for o in reports[0].orgs if o.org_id == tw_env.org.org_id)
    assert taken and mine.stale >= 1
    rows = env.outbox(env.t.a, system_id=tw_env.sys.system_id)
    assert [r["status"] for r in rows] == ["acknowledged"]
