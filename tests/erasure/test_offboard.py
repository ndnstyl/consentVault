"""Offboarding: final export first, credentials revoked, key destruction at least 30 days out through the key provider,
admins notified, destruction record; holds queue the destruction and cancel a scheduled one; the jobs let an
organisation go only after its final export."""

import io
import json
import zipfile
from datetime import timedelta

import pytest

from consentvault.tenancy import holds, legal_process, offboard
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.legal_process import AccessNoticeError
from consentvault.tenancy.offboard import OffboardNoticeError
from consentvault.tenancy.tokens import org_transaction

from .support import OPERATOR, RecordingNotifier


def _run(env, org, notifier=None, window_days=7, deliver=True):
    env.delivered = getattr(env, "delivered", [])
    if deliver:  # the operator's read of the final export for delivery needs an open access record
        env.open_access(org)
    with env.operator() as c:
        return offboard.run_offboard(c, token_key=env.t.key, custody=env.custody, crypto=env.t.crypto,
                                     signer=env.signer, store=env.archive, notifier=notifier or env.notifier,
                                     operator_id=OPERATOR, request_id="req-off", org_id=org.org_id,
                                     reason="contract ended", window_days=window_days, clock=env.clock,
                                     deliver=(lambda o, r, pkg, sha: env.delivered.append((pkg, sha))) if deliver
                                     else None)


def _evidence_orgs(env):
    with env.operator() as o:
        return {r["o"] for r in o.execute("SELECT o FROM consentvault.evidence_org_ids() AS o")}


def _db(env, sql, *args):
    with env.t.superuser() as su:
        return su.execute(sql, args).fetchall()


def test_offboard_takes_the_export_first_revokes_schedules_at_least_30_days_and_tells_the_admin(env):
    t = env.t
    out = _run(env, t.a, window_days=7)
    steps = out["steps"]
    assert steps["final_export"]["contacts"] == 1 and steps["final_export"]["erased"] == 0
    assert steps["credentials_revoked"]["count"] >= 1
    assert steps["key_destruction"]["status"] == "scheduled" and steps["key_destruction"]["window_days"] == 30
    assert steps["admin_notified"] == {"status": "done", "at": steps["admin_notified"]["at"], "count": 1}
    st = env.custody.status(str(t.a.org_id))
    assert st.state == "pending" and st.destroy_at - env.clock() >= timedelta(days=30)
    assert _db(env, "SELECT status FROM consentvault.organization WHERE org_id = %s", t.a.org_id)[0]["status"] == "offboarding"
    assert _db(env, "SELECT count(*) AS n FROM consentvault.credential WHERE org_id = %s AND revoked_at IS NULL",
               t.a.org_id)[0]["n"] == 0
    assert _db(env, "SELECT status FROM consentvault.org_key WHERE org_id = %s", t.a.org_id)[0]["status"] == "scheduled_destroy"
    recs = _db(env, "SELECT kind, export_sha256 FROM consentvault.destruction_record WHERE org_id = %s", t.a.org_id)
    assert [r["kind"] for r in recs] == ["scheduled"] and recs[0]["export_sha256"] == steps["final_export"]["sha256"]
    assert [to for _, to, _ in env.notifier.sent] == ["admin@alpha.example.com"]
    [(package, sha)] = env.delivered
    assert sha == steps["final_export"]["sha256"] and steps["final_export_delivered"]["status"] == "done"
    with env.operator() as c, pytest.raises(ApiError) as e:  # once scheduled, the export dies with the key
        offboard.read_final_export(c, token_key=t.key, custody=env.custody, store=env.archive, org_id=t.a.org_id,
                                   operator_id=OPERATOR)
    assert e.value.name == "key_unavailable"
    names = zipfile.ZipFile(io.BytesIO(package)).namelist()
    assert "manifest.json" in names and any(n.startswith(f"contacts/{env.fp(t.a)}/") for n in names)
    assert t.a.org_id not in _evidence_orgs(env) and t.b.org_id in _evidence_orgs(env)


def test_without_a_delivery_the_run_stops_before_any_destruction(env):
    out = _run(env, env.t.a, deliver=False)
    assert out["steps"]["key_destruction"] == {"status": "awaiting_delivery"}
    assert env.custody.status(str(env.t.a.org_id)).state == "active" and env.notifier.sent == []
    out = _run(env, env.t.a)
    assert out["steps"]["key_destruction"]["status"] == "scheduled"


def test_an_offboarding_org_stays_in_the_sync_and_anchor_jobs_until_its_final_export_is_taken(env):
    t = env.t
    from consentvault.tenancy import admin

    with env.operator() as c:
        admin.set_org_status(c, token_key=t.key, operator_id=OPERATOR, request_id="req-s", org_id=t.a.org_id,
                             status="offboarding", reason="begin")
    assert t.a.org_id in _evidence_orgs(env)
    _run(env, t.a)
    assert t.a.org_id not in _evidence_orgs(env)


def test_a_hold_queues_the_destruction_and_the_release_schedules_it(env):
    t = env.t
    with env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                         operator_id=OPERATOR, request_id="req-h", org_id=t.a.org_id, scope="contacts",
                                         contact_fps=[env.fp(t.a)], reason="regulator request")
    out = _run(env, t.a)
    assert out["steps"]["key_destruction"]["status"] == "held"
    assert env.custody.status(str(t.a.org_id)).state == "active"
    with env.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):  # the database refuses it too
        with pytest.raises(Exception, match="legal_hold_active"):
            o.execute("UPDATE consentvault.org_key SET status = 'scheduled_destroy' WHERE org_id = %s", (t.a.org_id,))
    with env.operator() as c:
        rel = holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                          operator_id=OPERATOR, request_id="req-r", org_id=t.a.org_id,
                                          hold_id=hold["hold_id"], reason="request withdrawn")
    assert rel["resumed"]["destruction"]["status"] == "scheduled"
    assert env.custody.status(str(t.a.org_id)).state == "pending"
    kinds = [r["kind"] for r in _db(env, "SELECT kind FROM consentvault.destruction_record WHERE org_id = %s"
                                         " ORDER BY created_at", t.a.org_id)]
    assert kinds == ["held", "scheduled", "resumed"]


def test_a_hold_placed_inside_the_window_cancels_the_provider_and_nothing_is_destroyed_until_release(env):
    t = env.t
    _run(env, t.a)
    with env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                         operator_id=OPERATOR, request_id="req-h", org_id=t.a.org_id, scope="org",
                                         reason="subpoena preservation")
    assert hold["destruction_cancelled"] is True and env.custody.status(str(t.a.org_id)).state == "active"
    env.clock.advance(31)
    with env.operator() as c:
        assert offboard.complete_destructions(c, token_key=t.key, custody=env.custody, request_id="job")["destroyed"] == []
    assert not env.custody.is_destroyed(str(t.a.org_id))
    with env.operator() as c:
        holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto, operator_id=OPERATOR,
                                    request_id="req-r", org_id=t.a.org_id, hold_id=hold["hold_id"], reason="closed")
    env.clock.advance(29)
    with env.operator() as c:
        assert offboard.complete_destructions(c, token_key=t.key, custody=env.custody, request_id="job")["destroyed"] == []
    env.clock.advance(2)
    with env.operator() as c:
        done = offboard.complete_destructions(c, token_key=t.key, custody=env.custody, request_id="job",
                                              notifier=env.notifier)
    assert done["destroyed"] == [str(t.a.org_id)] and env.custody.is_destroyed(str(t.a.org_id))
    assert _db(env, "SELECT state FROM consentvault.offboarding_request WHERE org_id = %s", t.a.org_id)[0]["state"] == "complete"
    assert _db(env, "SELECT status FROM consentvault.org_key WHERE org_id = %s", t.a.org_id)[0]["status"] == "destroyed"
    assert not env.custody.is_destroyed(str(t.b.org_id))


def test_a_notice_that_cannot_be_sent_is_a_named_error_and_a_failed_step(env):
    with pytest.raises(OffboardNoticeError):
        _run(env, env.t.a, notifier=RecordingNotifier(fail=True))
    steps = _db(env, "SELECT steps FROM consentvault.offboarding_request WHERE org_id = %s", env.t.a.org_id)[0]["steps"]
    assert steps["admin_notified"]["status"] == "failed"
    assert env.custody.status(str(env.t.a.org_id)).state == "pending"  # cancellable inside its window


def test_a_client_admin_asks_once_and_must_type_the_name(env):
    with env.admin(env.t.a) as ctx, pytest.raises(ApiError) as e:
        offboard.request_offboarding(ctx, {"reason": "leaving", "org_name": "wrong"})
    assert e.value.name == "org_name_mismatch"
    with env.admin(env.t.a) as ctx:
        assert offboard.request_offboarding(ctx, {"reason": "leaving", "org_name": "alpha"})["state"] == "requested"
    with env.admin(env.t.a) as ctx, pytest.raises(ApiError) as e:
        offboard.request_offboarding(ctx, {"reason": "again", "org_name": "alpha"})
    assert e.value.name == "offboarding_already_requested"
    out = _run(env, env.t.a)  # the operator's run advances the client's request
    assert out["state"] == "in_progress"


def test_legal_process_is_logged_with_a_hold_and_closes_only_after_the_notice_decision(env):
    t = env.t
    from datetime import datetime, timezone

    with env.operator() as c:
        p = legal_process.log_legal_process(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                            operator_id=OPERATOR, request_id="req-lp", org_id=t.a.org_id,
                                            type="subpoena", received_at=datetime.now(timezone.utc),
                                            received_via="certified mail", requester="County court clerk",
                                            scope_summary="records for one account")
    assert p["hold_id"] is not None
    with env.operator() as c, pytest.raises(ApiError):
        legal_process.close_legal_process(c, token_key=t.key, operator_id=OPERATOR, request_id="r", org_id=t.a.org_id,
                                          process_id=p["process_id"], response_ref="produced bundle")
    with env.operator() as c:
        n = legal_process.record_customer_notice(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                                 request_id="r", org_id=t.a.org_id, process_id=p["process_id"])
        closed = legal_process.close_legal_process(c, token_key=t.key, operator_id=OPERATOR, request_id="r",
                                                   org_id=t.a.org_id, process_id=p["process_id"],
                                                   response_ref="produced bundle", produced_sha256=["a" * 64])
    assert n["client_notified_at"] and closed["closed_at"]
    assert len(env.notifier.sent) == 1
    with env.operator() as c:
        q = legal_process.log_legal_process(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                            operator_id=OPERATOR, request_id="r2", org_id=t.a.org_id,
                                            type="court_order", received_at=datetime.now(timezone.utc),
                                            received_via="email", requester="Court", scope_summary="sealed order",
                                            hold_scope=None)
        q = legal_process.record_customer_notice(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                                 request_id="r", org_id=t.a.org_id, process_id=q["process_id"],
                                                 prohibited_basis="the order bars notice for 90 days")
    assert q["notice_prohibited"] is True and len(env.notifier.sent) == 1
    assert "no statement about whether any consent was valid" in legal_process.custodian_declaration("alpha").replace(
        "makes no", "no")


def test_operator_access_needs_an_admin_approval_or_an_emergency_notice(env):
    t = env.t
    kw = dict(token_key=t.key, operator_id=OPERATOR, request_id="req-a", org_id=t.a.org_id, reason="support ticket")
    with env.admin(t.b) as ctx:
        other = legal_process.approve_operator_access(ctx, {"operator_id": OPERATOR, "reason": "B's ticket"})
    with env.operator() as c:
        with pytest.raises(ApiError):
            legal_process.open_operator_access(c, notifier=env.notifier, **kw)
        with pytest.raises(ApiError):  # another organisation's approval opens nothing here
            legal_process.open_operator_access(c, notifier=env.notifier, approval_id=other["approval_id"], **kw)
        with pytest.raises(AccessNoticeError):
            legal_process.open_operator_access(c, notifier=RecordingNotifier(fail=True), emergency=True, **kw)
        with org_transaction(c, t.admin_token(t.a.org_id)), pytest.raises(ApiError):
            legal_process.require_open_access(c, OPERATOR)
    a = env.open_access(t.a)
    with env.operator() as c:
        with org_transaction(c, t.admin_token(t.a.org_id)):
            assert legal_process.require_open_access(c, OPERATOR)["access_id"] == a["access_id"]
        e = legal_process.open_operator_access(c, notifier=env.notifier, emergency=True, **kw)
        assert e["client_notified_at"] and e["expires_at"] and len(env.notifier.sent) == 1
        legal_process.close_operator_access(c, token_key=t.key, operator_id=OPERATOR, request_id="r",
                                            org_id=t.a.org_id, access_id=a["access_id"])
        legal_process.close_operator_access(c, token_key=t.key, operator_id=OPERATOR, request_id="r",
                                            org_id=t.a.org_id, access_id=e["access_id"])
        with org_transaction(c, t.admin_token(t.a.org_id)), pytest.raises(ApiError):
            legal_process.require_open_access(c, OPERATOR)
    rows = _db(env, "SELECT count(*) AS n FROM consentvault.operator_access WHERE org_id = %s", t.a.org_id)
    assert rows[0]["n"] == 2  # the refused emergency left no record
    assert json.dumps(rows)
