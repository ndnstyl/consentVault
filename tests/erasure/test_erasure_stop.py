"""Erasure leaves a stop on record: after the contact key is destroyed the gate still refuses every channel and
purpose, the stop survives a later capture of the same person until a verified grant lifts it, and one contact has at
most one open erasure request."""

import pytest

from consentvault.tenancy import erasure
from consentvault.tenancy.admin_base import ApiError

from isolation.cloud_harness import CHANNELS, PURPOSES, Cloud

from .support import OPERATOR
from .test_erasure import _confirm, _request

X = "+15555550177"
ALL = {"channels": list(CHANNELS), "purposes": list(PURPOSES)}


@pytest.fixture
def cloud(env, tmp_path):
    c = Cloud(env.t, str(tmp_path / "evidence"))
    try:
        yield c
    finally:
        c.close()


def _consented(cloud):
    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r


def _every_cell(cloud):
    return [cloud.gate(cloud.a, X, channel=ch, purpose=p) for ch in CHANNELS for p in PURPOSES]


def test_after_erasure_a_consenting_contact_reads_stopped_on_every_channel_and_purpose(env, cloud):
    _consented(cloud)
    assert all(a[1]["evidence_status"] == "consent_record_found" for a in _every_cell(cloud))
    req = _request(env, env.t.a, X)
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "completed"
    assert not env.key_present(env.t.a, X)
    for status, answer in _every_cell(cloud):
        assert status == 200 and answer["evidence_status"] == "stop_on_record", answer
        assert answer["policy_action"] == "hold", answer


def test_after_erasure_the_batch_gate_denies_every_channel_and_purpose(env, cloud):
    _consented(cloud)
    req = _request(env, env.t.a, X)
    _confirm(env, env.t.a, req["erasure_id"])
    items = [{"contact": X, "channel": ch, "purpose": p} for ch in CHANNELS for p in PURPOSES]
    s, r = cloud.call("/v1/permission:batch", {"items": items}, token=cloud.token(cloud.a, "gate_read"))
    assert s == 200 and len(r["items"]) == len(items)
    assert {(i["evidence_status"], i["policy_action"]) for i in r["items"]} == {("stop_on_record", "hold")}


def test_the_erasure_stop_is_one_marked_event_by_fingerprint_with_an_allowed_method(env, cloud):
    _consented(cloud)
    req = _request(env, env.t.a, X)
    _confirm(env, env.t.a, req["erasure_id"])
    with env.t.superuser() as su:
        rows = su.execute("SELECT event_type, channels, purposes, method, origin, source, recorded_by, contact_fp,"
                          " hash_version FROM consentvault.event WHERE org_id = %s AND contact_fp = %s"
                          " AND source = 'erasure'", (env.t.a.org_id, env.fp(env.t.a, X))).fetchall()
    assert len(rows) == 1
    r = rows[0]
    assert (r["event_type"], r["purposes"], r["method"], r["origin"], r["hash_version"]) == \
        ("suppress", ["*"], "written", "consumer", 2)
    assert sorted(r["channels"]) == sorted(CHANNELS)
    assert r["recorded_by"] == f"erasure:{req['erasure_id']}:1"  # the erasure and its ledger entry's sequence number


def test_the_stop_survives_until_the_person_grants_again_on_a_form_and_then_that_grant_takes_effect(env, cloud):
    _consented(cloud)
    req = _request(env, env.t.a, X)
    _confirm(env, env.t.a, req["erasure_id"])
    assert all(a[1]["evidence_status"] == "stop_on_record" for a in _every_cell(cloud))
    s, r = cloud.grant(cloud.a, X, **ALL)  # the same person captured again on a form, key re-made
    assert s == 201, r
    assert all(a[1]["evidence_status"] == "consent_record_found" for a in _every_cell(cloud))


def test_a_second_open_request_for_the_same_contact_is_refused_by_name(env):
    first = _request(env, env.t.a)
    with pytest.raises(ApiError) as e:
        _request(env, env.t.a)
    assert e.value.name == "erasure_already_requested" and e.value.fields == {"erasure_id": first["erasure_id"]}
    with env.t.superuser() as su, pytest.raises(Exception, match="erasure_request_one_open_idx"):
        su.execute("INSERT INTO consentvault.erasure_request (org_id, contact_fp, reason, requested_by)"
                   " VALUES (%s, %s, 'dup', gen_random_uuid())", (env.t.a.org_id, env.fp(env.t.a)))


def test_a_request_for_an_already_erased_contact_is_refused_by_name(env):
    req = _request(env, env.t.a)
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "completed"
    with pytest.raises(ApiError) as e:
        _request(env, env.t.a)
    assert e.value.name == "contact_already_erased"


def test_a_request_for_a_contact_the_organization_never_held_is_refused_by_name(env):
    with pytest.raises(ApiError) as e:
        _request(env, env.t.a, "+15555550199")
    assert e.value.name == "contact_not_held"


def test_a_declined_request_frees_the_contact_for_a_new_one(env):
    req = _request(env, env.t.a)
    with env.operator() as c:
        erasure.decline_erasure(c, token_key=env.t.key, operator_id=OPERATOR, request_id="req-d",
                                org_id=env.t.a.org_id, erasure_id=req["erasure_id"], reason="identity unproven")
    assert _request(env, env.t.a)["status"] == "pending_operator_confirmation"


def test_record_erasure_stop_directly_writes_one_stop_over_every_org_channel_by_fingerprint(env, cloud):
    from consentvault.tenancy.erasure import ERASURE_SOURCE, operator_org, record_erasure_stop

    _consented(cloud)
    t, eid = env.t, "11111111-1111-4111-8111-111111111111"
    with env.operator() as c, operator_org(c, t.key, t.a.org_id):
        first = record_erasure_stop(c, t.crypto, fp=env.fp(t.a, X), erasure_id=eid)
        again = record_erasure_stop(c, t.crypto, fp=env.fp(t.a, X), erasure_id=eid)
    assert first is not None and again == first  # once per request
    with t.superuser() as su:
        row = su.execute("SELECT event_type, channels, purposes, method, origin, source, contact_fp, contact_norm"
                         " FROM consentvault.event WHERE event_id = %s", (first,)).fetchone()
    assert (row["event_type"], row["purposes"], row["method"], row["origin"], row["source"]) == \
        ("suppress", ["*"], "written", "consumer", ERASURE_SOURCE)
    assert sorted(row["channels"]) == sorted(CHANNELS)
    assert row["contact_fp"] == env.fp(t.a, X) and row["contact_norm"] is None  # fingerprint only, no clear contact


def test_the_stop_survives_a_decline_after_the_first_unheld_confirm(env, cloud, monkeypatch):
    _consented(cloud)
    req = _request(env, env.t.a, X)
    monkeypatch.setattr(erasure, "pending_pushes", lambda conn, fp: 1)  # the confirm waits on deliveries
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "held"
    monkeypatch.undo()
    with env.operator() as c:
        erasure.decline_erasure(c, token_key=env.t.key, operator_id=OPERATOR, request_id="req-d",
                                org_id=env.t.a.org_id, erasure_id=req["erasure_id"], reason="withdrawn")
    assert env.key_present(env.t.a, X)
    assert all(a[1]["evidence_status"] == "stop_on_record" for a in _every_cell(cloud))
    items = [{"contact": X, "channel": ch, "purpose": p} for ch in CHANNELS for p in PURPOSES]
    s, r = cloud.call("/v1/permission:batch", {"items": items}, token=cloud.token(cloud.a, "gate_read"))
    assert {i["evidence_status"] for i in r["items"]} == {"stop_on_record"}


def _verified_regrant_and_release(env, cloud, contact, *, commit):
    """A verified grant and its release decision, in one transaction on its own connection. Returns the open connection
    context when ``commit`` is False so the caller decides when it lands."""
    from consentvault.release import release_after_tenant_grant
    from consentvault.ledger import record_tenant_event
    from consentvault.tenancy.tokens import org_transaction

    t = env.t
    conn = t.app()
    tx = org_transaction(conn, t.token(t.a, scopes=("capture", "capture_verified", "gate_read", "proof_read")))
    tx.__enter__()
    ev = record_tenant_event(conn, t.crypto, contact=contact, event_type="grant", channels=list(CHANNELS),
                             purposes=list(PURPOSES), method="checkbox", origin="consumer",
                             disclosure_sha256=cloud.a.wording, contact_verification="otp", session_ref="s-9")
    release_after_tenant_grant(conn, t.crypto, ev.event_id)
    return conn, tx


def test_a_grant_still_uncommitted_when_the_stop_is_written_cannot_land_after_it_under_the_deleted_key(env, cloud,
                                                                                                    monkeypatch):
    import threading
    import time

    from consentvault.tenancy import erasure as er

    _consented(cloud)
    req = _request(env, env.t.a, X)
    monkeypatch.setattr(er, "pending_pushes", lambda conn, fp: 1)
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "held"  # first stop on record
    monkeypatch.undo()

    conn, tx = _verified_regrant_and_release(env, cloud, X, commit=False)  # holds the org's event lock, uncommitted
    result = {}

    def finish():
        try:
            with env.operator() as c:
                result["out"] = er.resume_waiting(c, token_key=env.t.key, crypto=env.t.crypto, ledger=env.ledger,
                                                  request_id="req-w", org_id=env.t.a.org_id)
        except BaseException as exc:  # noqa: BLE001  (surfaced by the assertion below)
            result["err"] = exc

    th = threading.Thread(target=finish, daemon=True)
    th.start()
    try:
        deadline = time.monotonic() + 30
        while True:  # wait until the erasure's connection is blocked on the lock the open grant holds
            with env.t.superuser() as su:
                waiting = su.execute("SELECT count(*) AS n FROM pg_stat_activity WHERE datname = current_database()"
                                     " AND wait_event_type = 'Lock' AND wait_event = 'advisory'").fetchone()["n"]
            if waiting:
                break
            assert th.is_alive() and "err" not in result, f"the erasure ended without waiting on the lock: {result}"
            assert time.monotonic() < deadline, "the erasure never waited on the lock"
            time.sleep(0.05)
    finally:
        tx.__exit__(None, None, None)
        conn.close()
    th.join(timeout=60)
    assert not th.is_alive(), "the erasure did not finish after the grant committed"
    assert "err" not in result, result.get("err")
    assert result["out"]["completed"] == [req["erasure_id"]]
    assert all(a[1]["evidence_status"] == "stop_on_record" for a in _every_cell(cloud))


def test_record_erasure_stop_writes_a_fresh_stop_when_a_grant_or_release_came_after_the_last(env, cloud):
    from consentvault.tenancy.erasure import operator_org, record_erasure_stop

    _consented(cloud)
    t, eid = env.t, "22222222-2222-4222-8222-222222222222"
    fp = env.fp(t.a, X)

    def stop():
        with env.operator() as c, operator_org(c, t.key, t.a.org_id):
            return record_erasure_stop(c, t.crypto, fp=fp, erasure_id=eid)

    first = stop()
    assert stop() == first  # nothing since: the same stop
    conn, tx = _verified_regrant_and_release(env, cloud, X, commit=True)
    tx.__exit__(None, None, None)
    conn.close()
    assert all(a[1]["evidence_status"] == "consent_record_found" for a in _every_cell(cloud))  # the first was lifted
    second = stop()
    assert second != first
    assert all(a[1]["evidence_status"] == "stop_on_record" for a in _every_cell(cloud))
    with t.superuser() as su:
        row = su.execute("SELECT channels, purposes, contact_norm FROM consentvault.event WHERE event_id = %s",
                         (second,)).fetchone()
    assert sorted(row["channels"]) == sorted(CHANNELS) and row["purposes"] == ["*"] and row["contact_norm"] is None


def test_a_confirm_under_a_legal_hold_still_writes_the_stop_and_only_the_key_waits(env, cloud):
    from consentvault.tenancy import holds

    _consented(cloud)
    t = env.t
    req = _request(env, t.a, X)
    with env.admin(t.a) as ctx:
        holds.place_hold_member(ctx, {"scope": "org", "reason": "preserve"}, ledger=env.ledger, crypto=t.crypto)
    with pytest.raises(ApiError) as e:
        _confirm(env, t.a, req["erasure_id"])
    assert e.value.name == "legal_hold_active"
    assert env.key_present(t.a, X)  # the data stays while the hold does
    assert all(a[1]["evidence_status"] == "stop_on_record" for a in _every_cell(cloud))
    items = [{"contact": X, "channel": ch, "purpose": p} for ch in CHANNELS for p in PURPOSES]
    s, r = cloud.call("/v1/permission:batch", {"items": items}, token=cloud.token(cloud.a, "gate_read"))
    assert {i["evidence_status"] for i in r["items"]} == {"stop_on_record"}


def test_a_stale_hold_mark_is_cleared_by_erase_in_org_itself(env, monkeypatch):
    from consentvault.tenancy import erasure as er, holds
    from consentvault.tenancy.erasure import erase_in_org, operator_org

    t = env.t
    req = _request(env, t.a)
    with env.admin(t.a) as ctx:
        hold = holds.place_hold_member(ctx, {"scope": "org", "reason": "keep"}, ledger=env.ledger, crypto=t.crypto)
    with t.superuser() as su:
        su.execute("UPDATE consentvault.erasure_request SET held_by = %s, held_since = now() WHERE erasure_id = %s",
                   (hold["hold_id"], req["erasure_id"]))
    with env.admin(t.a) as ctx:
        holds.release_hold_member(ctx, hold["hold_id"], {"reason": "done"}, ledger=env.ledger, crypto=t.crypto)
    monkeypatch.setattr(er, "pending_pushes", lambda conn, fp: 1)
    with env.operator() as c, operator_org(c, t.key, t.a.org_id):
        out = erase_in_org(c, ledger=env.ledger, crypto=t.crypto, erasure_id=req["erasure_id"], actor_kind="operator",
                           actor_id=OPERATOR, request_id="r")
    assert out["status"] == "held"
    with t.superuser() as su:
        row = su.execute("SELECT held_by, held_since FROM consentvault.erasure_request WHERE erasure_id = %s",
                         (req["erasure_id"],)).fetchone()
    assert row == {"held_by": None, "held_since": None}


def _verify(env):
    from consentvault.ledger import verify_chain
    from consentvault.tenancy.erasure import operator_org
    from consentvault.tenancy.restore import RESTORE_SCOPES

    t = env.t
    with env.operator() as c, operator_org(c, t.key, t.a.org_id, scopes=RESTORE_SCOPES):
        return [(b.reason, b.seq) for b in verify_chain(c, crypto=t.crypto)]


def test_crypto_shredded_rows_verify_as_erased_while_their_links_and_hashes_are_still_checked(env, cloud):
    """Destroying a contact key shreds the person's data; the chain still verifies. After the person returns and gets a
    new key, the rows sealed under the destroyed one read as erased, not as a failure."""
    _consented(cloud)
    assert _verify(env) == []
    req = _request(env, env.t.a, X)
    _confirm(env, env.t.a, req["erasure_id"])
    assert not env.key_present(env.t.a, X) and _verify(env) == []  # key gone: rows skipped, links verified
    conn, tx = _verified_regrant_and_release(env, cloud, X, commit=True)  # the person returns under a new key
    tx.__exit__(None, None, None)
    conn.close()
    assert env.key_present(env.t.a, X)
    assert _verify(env) == []  # the older rows were sealed under the destroyed key: erased, not broken

    with env.t.superuser() as su:  # a real break is still a break: a link of an erased row is cut
        su.execute("ALTER TABLE consentvault.event DISABLE TRIGGER event_append_only")
        try:
            su.execute("UPDATE consentvault.event SET prev_hash = repeat('0', 64) WHERE org_id = %s AND source IS NULL"
                       " AND contact_fp = %s AND event_type = 'grant' AND seq = (SELECT min(seq) FROM consentvault.event"
                       " WHERE org_id = %s AND contact_fp = %s)", (env.t.a.org_id, env.fp(env.t.a, X),
                                                                   env.t.a.org_id, env.fp(env.t.a, X)))
        finally:
            su.execute("ALTER TABLE consentvault.event ENABLE TRIGGER event_append_only")
    reasons = {r for r, _ in _verify(env)}
    assert "prev_hash_mismatch" in reasons


def test_an_erasure_through_the_console_succeeds_and_enqueues_no_confirmation(env, cloud):
    """confirmations.md section 5 (only a grant is confirmed): the erasure's stop is written from the operator console role, which
    holds no right to the confirmation enqueue function, so it must not call it; and it queues no confirmation message."""
    _consented(cloud)
    req = _request(env, env.t.a, X)
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "completed"
    with env.t.superuser() as su:
        n = su.execute("SELECT count(*) AS n FROM consentvault.confirmation_send_intent WHERE org_id = %s",
                       (env.t.a.org_id,)).fetchone()["n"]
        stops = su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = 'suppress'",
                           (env.t.a.org_id,)).fetchone()["n"]
    assert stops >= 1 and n == 0
