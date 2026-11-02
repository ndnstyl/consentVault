"""Third adversarial review, lifecycle: erasure, restore, legal process, operator access and the final export.

- Attacks A, B, C: an erasure is a two-phase ledger entry (intent before the key delete, commit after the transaction
  commits). A restore replays only committed erasures, never under a hold, and an intent with no commit is a visible
  held state on the request (and in the report), never a failure and never a delete.
- Attack G: an erasure waits (held, ``pending_suppression_delivery``) until every push for the person is delivered or
  dead; a push superseded because its contact key is gone raises an alarm row.
- Attack H: legal-process rows go to the platform audit only; a legal-process hold stays out of the customer's audit
  until the customer is notified.
- Operator access: an open, unexpired access record (default 4 hours) for every operator read, including the operator's
  read of the final export; the customer's approval is the approving admin's own action, never a typed member id.
- Restore: every contact key is tried in batches; chains and seals are re-verified before the gate serves; the sync
  worker pauses while a restore is unreconciled.
- Final export link: the download needs a signed-in admin of that organisation with the link; delivery is recorded
  only on the admin's confirmation of the full body's digest; a spent link without a delivery is replaced.
"""

import dataclasses
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone

import psycopg
import pytest

from consentvault import db, dbclock
from consentvault.evidence import ExportService
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy import admin, erasure, holds, legal_process, offboard, restore
from consentvault.tenancy.admin_base import ROLE_SCOPES, ApiError, Ctx
from consentvault.tenancy.erasure import LifecycleError, LifecycleLedger
from consentvault.tenancy.lifecycle_routes import LifecycleApp, LifecycleRoutes
from consentvault.tenancy.restore import RestoreIncompleteError
from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX, actor_from_token
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from isolation.harness import PHONE, build_tenancy

from .support import OPERATOR


# ---- helpers -------------------------------------------------------------------------------------------------------------
def _request(env, org, contact=PHONE):
    with env.admin(org) as ctx:
        return erasure.request_erasure(ctx, {"contact": contact, "reason": "asked"}, crypto=env.t.crypto)["erasure_id"]


def _op_hold(env, org):
    with env.operator() as c:
        return holds.place_hold_operator(c, token_key=env.t.key, ledger=env.ledger, custody=env.custody,
                                         operator_id=OPERATOR, request_id="req-h", org_id=org.org_id,
                                         scope="contacts", reason="subpoena preservation", contacts=[PHONE],
                                         crypto=env.t.crypto)


def _confirm(env, org, eid, ledger=None):
    with env.operator() as c:
        return erasure.confirm_erasure(c, token_key=env.t.key, crypto=env.t.crypto, ledger=ledger or env.ledger, operator_id=OPERATOR,
                                       request_id="req-e", org_id=org.org_id, erasure_id=eid)


def _phantom_erasure(env, org, monkeypatch):
    """The intent entry is written, then the transaction dies (an audit failure standing in for a dropped connection)."""
    eid = _request(env, org)
    real = erasure.audit_org

    def boom(conn, **kw):
        if kw.get("action") == "erasure.completed":
            raise LifecycleError("simulated crash after the intent entry")
        return real(conn, **kw)
    monkeypatch.setattr(erasure, "audit_org", boom)
    with pytest.raises(LifecycleError):
        _confirm(env, org, eid)
    monkeypatch.setattr(erasure, "audit_org", real)
    assert env.key_present(org)
    kinds = [e["kind"] for e in env.ledger.entries(org.org_id)]
    assert kinds == ["erasure_intent"], kinds  # an intent, and no commit: the transaction never committed
    return eid


def _copy(t, port):
    src = t.operator_dsn.rsplit("/", 1)[1]
    dst = src + "_r" + uuid.uuid4().hex[:4]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'CREATE DATABASE "{dst}" TEMPLATE "{src}" OWNER cv_test_owner')
    swap = lambda dsn: dsn.rsplit("/", 1)[0] + "/" + dst  # noqa: E731
    return dataclasses.replace(t, operator_dsn=swap(t.operator_dsn), super_dsn=swap(t.super_dsn), app_dsn=swap(t.app_dsn),
                               migrator_dsn=swap(t.migrator_dsn))


def drop_synthetic_seals(r):
    """The isolation harness writes one fake seal per organisation (it never ran a timestamp authority). A restore
    re-verifies every seal and rightly refuses a fake one; suites that are not about seals remove them first."""
    with psycopg.connect(r.super_dsn) as su:
        su.execute("SET session_replication_role = replica")
        su.execute("DELETE FROM consentvault.seal WHERE token = %s", (b"synthetic-token",))


def _reconcile(env, r, *, keep_seals=False, **extra):
    if not keep_seals:
        drop_synthetic_seals(r)
    kw = dict(token_key=env.t.key, crypto=env.t.crypto, store=None, ledger=env.ledger,
              inventory=lambda o, s: [], operator_id=OPERATOR, request_id="req-rc", region="US")
    kw.update(extra)
    with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
        if restore.pending(o) is None:
            restore.begin_restore(o, operator_id=OPERATOR, request_id="req-rs",
                                  restore_point=datetime.now(timezone.utc))
        return restore.reconcile(o, **kw)


def _su(r, sql, *args):
    with psycopg.connect(r.super_dsn, row_factory=psycopg.rows.dict_row) as su:
        return su.execute(sql, args).fetchall()


def _key_in(r, org, fp):
    return bool(_su(r, "SELECT 1 FROM consentvault.contact_key WHERE org_id=%s AND contact_fp=%s", org.org_id, fp))


def _hold_in(r, org):
    return _su(r, "SELECT count(*) n FROM consentvault.legal_hold WHERE org_id=%s AND released_at IS NULL",
               org.org_id)[0]["n"]


def _erasure_row(r, org, eid):
    return _su(r, "SELECT * FROM consentvault.erasure_request WHERE org_id=%s AND erasure_id=%s", org.org_id, eid)[0]


# ---- two-phase erasure ledger and restore (attacks A, B, C) --------------------------------------------------------------
def test_a_restore_never_replays_an_uncommitted_erasure_or_deletes_a_held_key(env, monkeypatch, pg_server):
    t = env.t
    eid = _phantom_erasure(env, t.a, monkeypatch)
    r = _copy(t, pg_server["port"])          # restore point: after the phantom, before the hold
    _op_hold(env, t.a)                       # a subpoena hold on the live database
    rep = _reconcile(env, r)
    a = rep["orgs"][str(t.a.org_id)]
    assert _hold_in(r, t.a) == 1             # the hold is back after the restore
    assert _key_in(r, t.a, env.fp(t.a))      # and the held person's key is still there
    assert a["erasures_replayed"] == 0 and [u["erasure_id"] for u in a["uncommitted_intents"]] == [eid]
    row = _erasure_row(r, t.a, eid)          # the request reads as held, with the reason, for the operator
    assert row["status"] == "pending_operator_confirmation" and row["wait_reason"] == "uncommitted_ledger_intent"


def test_b_an_uncommitted_intent_under_a_hold_is_a_visible_held_state_and_the_restore_completes(env, monkeypatch,
                                                                                              pg_server):
    t = env.t
    eid = _phantom_erasure(env, t.a, monkeypatch)
    _op_hold(env, t.a)
    r = _copy(t, pg_server["port"])          # restore point after both
    rep = _reconcile(env, r)                 # completes: nothing to delete, the intent is named
    assert rep["orgs"][str(t.a.org_id)]["uncommitted_intents"][0]["erasure_id"] == eid
    with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
        assert restore.pending(o) is None    # the gate serves again
    assert _key_in(r, t.a, env.fp(t.a))
    with env.admin(t.a) as ctx:              # the live request reads held on the tenant's own view after a restore too
        assert erasure.get_erasure(ctx, eid)["status"] == "pending_operator_confirmation"
    with db.connect(r.app_dsn) as app, org_transaction(app, env.portal_token(t.a)):
        view = erasure.get_erasure(Ctx(app, actor_from_token(app), "req-v"), eid)
    assert view["status"] == "held" and view["held_reason"] == "uncommitted_ledger_intent"
    _reconcile(env, r)                       # a second reconciliation is idempotent


def test_c_a_declined_request_is_never_executed_by_a_restore(env, monkeypatch, pg_server):
    t = env.t
    eid = _phantom_erasure(env, t.a, monkeypatch)
    with env.operator() as c:
        erasure.decline_erasure(c, token_key=t.key, operator_id=OPERATOR, request_id="req-d", org_id=t.a.org_id,
                                erasure_id=eid, reason="identity not verified")
    r = _copy(t, pg_server["port"])
    rep = _reconcile(env, r)
    assert _key_in(r, t.a, env.fp(t.a))
    assert rep["orgs"][str(t.a.org_id)]["erasures_replayed"] == 0
    assert _erasure_row(r, t.a, eid)["status"] == "declined"


def test_a_committed_erasure_writes_intent_then_commit_and_survives_a_restore(env, pg_server):
    t = env.t
    eid = _request(env, t.a)
    r = _copy(t, pg_server["port"])          # restore point after the request, before the erasure
    out = _confirm(env, t.a, eid)
    assert out["status"] == "completed" and out["ledger_commit"]["status"] == "written", out
    entries = env.ledger.entries(t.a.org_id)
    assert [e["kind"] for e in entries] == ["erasure_intent", "erasure_commit"]
    assert entries[1]["intent_seq"] == entries[0]["seq"] and entries[1]["erasure_id"] == eid
    rep = _reconcile(env, r)
    assert rep["orgs"][str(t.a.org_id)]["erasures_replayed"] == 1
    assert not _key_in(r, t.a, env.fp(t.a))
    assert _erasure_row(r, t.a, eid)["status"] == "completed"


def test_a_committed_erasure_is_never_replayed_under_a_hold_it_is_reported_held(env, pg_server, tmp_path):
    t = env.t
    eid = _request(env, t.a)
    r = _copy(t, pg_server["port"])          # the copy has the request open
    with db.connect(r.operator_dsn) as o:       # a hold only the restored copy holds
        holds.place_hold_operator(o, token_key=t.key, ledger=LifecycleLedger(LocalAppendOnlyEvidenceStore(
            tmp_path / "other"), clock=dbclock.datetime_clock(lambda: db.connect(t.app_dsn))), custody=None, operator_id=OPERATOR, request_id="req-h2",
            org_id=t.a.org_id, scope="org", reason="preserve", crypto=t.crypto)
    _confirm(env, t.a, eid)                  # erased live
    rep = _reconcile(env, r)
    a = rep["orgs"][str(t.a.org_id)]
    assert a["erasures_replayed"] == 0 and a["erasures_held"][0]["erasure_id"] == eid
    assert _key_in(r, t.a, env.fp(t.a))
    assert _erasure_row(r, t.a, eid)["held_by"] is not None


# ---- an erasure waits for the stop push (attack G) ------------------------------------------------------------------------
@pytest.fixture
def senv(dsn, pg_server):
    from sync.support import SyncEnv
    return SyncEnv(build_tenancy(dsn, pg_server["port"]), pg_server["port"])


def _sync_admin_ctx_erasure(t, org, contact):
    with t.superuser() as su:
        mid = su.execute("SELECT member_id FROM consentvault.member WHERE org_id=%s AND role='admin' LIMIT 1",
                         (org.org_id,)).fetchone()["member_id"]
    tok = mint_org_token(t.key, org.org_id, ROLE_SCOPES["admin"], credential_id=MEMBER_CREDENTIAL_PREFIX + str(mid))
    with t.app() as app, org_transaction(app, tok):
        return erasure.request_erasure(Ctx(app, actor_from_token(app), "req-x"), {"contact": contact, "reason": "asked"},
                                       crypto=t.crypto)["erasure_id"]


def test_g_an_erasure_waits_until_the_stop_push_is_delivered_then_completes(senv, tmp_path):
    from sync.support import PHONES

    env, t = senv, senv.t
    a, P = t.a, PHONES[0]
    s = env.add_system(a, "crm")
    env.grant(a, P)
    env.run_worker()
    env.transport.script(s.endpoint, 503)
    env.stop(a, P)
    env.run_worker()                         # the stop push failed once and waits to retry
    assert (2, "failed") in {(r["version"], r["status"]) for r in env.outbox(a)}
    eid = _sync_admin_ctx_erasure(t, a, P)
    ledger = LifecycleLedger(LocalAppendOnlyEvidenceStore(tmp_path / "arch"), clock=dbclock.datetime_clock(lambda: db.connect(t.app_dsn)))
    with t.operator() as o:
        out = erasure.confirm_erasure(o, token_key=t.key, crypto=t.crypto, ledger=ledger, operator_id=OPERATOR, request_id="req-e",
                                      org_id=a.org_id, erasure_id=eid)
    assert out["status"] == "held" and out["held_reason"] == "pending_suppression_delivery"
    assert ledger.entries(a.org_id) == []    # nothing irreversible ran
    env.clock.advance(seconds=600)
    env.run_worker()
    after = {(r["version"], r["status"]) for r in env.outbox(a)}
    assert (2, "acknowledged") in after and "superseded" not in {st for _, st in after}
    with t.operator() as o:
        done = erasure.resume_waiting(o, token_key=t.key, crypto=t.crypto, ledger=ledger, org_id=a.org_id, request_id="req-w")
    assert done["completed"] == [eid]
    with t.superuser() as su:
        assert su.execute("SELECT status FROM consentvault.erasure_request WHERE erasure_id=%s",
                          (eid,)).fetchone()["status"] == "completed"


def test_a_push_superseded_because_its_contact_key_is_gone_raises_an_alarm_row(senv):
    from sync.support import PHONES

    env, t = senv, senv.t
    a, P = t.a, PHONES[1]
    env.add_system(a, "crm")
    env.stop(a, P)
    with t.superuser() as su:                # a key that vanished outside the erasure path
        su.execute("DELETE FROM consentvault.contact_key WHERE org_id=%s AND contact_fp=%s", (a.org_id, env.fp(a, P)))
    env.run_worker()
    with t.superuser() as su:
        rows = su.execute("SELECT name, ref_kind, error_class FROM consentvault.operator_alarm WHERE org_id=%s"
                          " AND name = 'sync.contact_key_missing'", (a.org_id,)).fetchall()
    assert rows and rows[0]["ref_kind"] == "outbox" and rows[0]["error_class"] == "contact_key_missing"


# ---- legal process stays out of the tenant's audit (attack H) ------------------------------------------------------------
def _tenant_audit(env, org):
    with env.admin(org) as ctx:
        return admin.list_audit(ctx)["items"]


def _log(env, org, **kw):
    with env.operator() as c:
        return legal_process.log_legal_process(
            c, token_key=env.t.key, ledger=env.ledger, custody=env.custody, crypto=env.t.crypto, operator_id=OPERATOR,
            request_id="req-lp", org_id=org.org_id, type=kw.pop("type", "search_warrant"),
            received_at=datetime.now(timezone.utc), received_via="email", requester="FBI field office",
            scope_summary="all records of +1555", **kw)


def test_h_a_gagged_legal_process_never_reaches_a_tenant_readable_surface(env):
    t = env.t
    p = _log(env, t.a)
    with env.operator() as c:
        legal_process.record_customer_notice(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                             request_id="req-lp2", org_id=t.a.org_id, process_id=p["process_id"],
                                             prohibited_basis="18 USC 2705(b) non-disclosure order, case 26-mj-123")
        legal_process.close_legal_process(c, token_key=t.key, operator_id=OPERATOR, request_id="req-lp3",
                                          org_id=t.a.org_id, process_id=p["process_id"], response_ref="produced")
    rows = _tenant_audit(env, t.a)
    leaked = [(r["action"], r["reason"]) for r in rows if r["action"].startswith(("legal", "legal_hold"))
              or p["process_id"] in json.dumps(r) or p["hold_id"] in json.dumps(r)]
    assert leaked == []
    assert "2705(b)" not in json.dumps(rows) and "FBI" not in json.dumps(rows)
    with t.app() as app, org_transaction(app, env.portal_token(t.a)):  # the process table is not the tenant's to read
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT 1 FROM consentvault.legal_process")
    with t.superuser() as su:                # and the platform chain holds the whole record
        acts = [r["action"] for r in su.execute("SELECT action FROM consentvault.audit_event WHERE org_id IS NULL"
                                                " AND target_id = %s ORDER BY seq", (p["process_id"],))]
    assert acts == ["legal_process.logged", "legal_process.notice_prohibited", "legal_process.closed"]
    assert env.notifier.sent == []


def test_a_legal_process_hold_reaches_the_tenant_audit_only_once_the_customer_is_notified(env):
    t = env.t
    p = _log(env, t.a, type="subpoena")
    assert not [r for r in _tenant_audit(env, t.a) if r["action"].startswith("legal")]
    with env.operator() as c:
        legal_process.record_customer_notice(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                             request_id="req-n", org_id=t.a.org_id, process_id=p["process_id"])
    seen = [(r["action"], r["target"]["id"]) for r in _tenant_audit(env, t.a) if r["action"].startswith("legal")]
    assert seen == [("legal_hold.set", p["hold_id"])]
    assert len(env.notifier.sent) == 1


# ---- operator access ----------------------------------------------------------------------------------------------------
def _approve(env, org, operator=OPERATOR, **extra):
    with env.admin(org) as ctx:
        return legal_process.approve_operator_access(ctx, {"operator_id": operator, "reason": "ticket 42", **extra})


def _open(env, org, **kw):
    with env.operator() as c:
        return legal_process.open_operator_access(c, token_key=env.t.key, notifier=env.notifier, operator_id=OPERATOR,
                                                  request_id="req-a", org_id=org.org_id, reason="support ticket", **kw)


def test_operator_access_needs_the_admins_own_approval_never_a_typed_member_id(env):
    t = env.t
    with pytest.raises(ApiError) as e:
        _open(env, t.a, approved_by_member=env.member_id(t.a))
    assert e.value.name == "validation_failed"
    with t.app() as app, org_transaction(app, env.portal_token(t.a)):  # no direct write of an approval row
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("INSERT INTO consentvault.operator_access_approval (org_id, operator_id, reason, approved_by,"
                        " expires_at, access_minutes) VALUES ((SELECT consentvault.current_org()), 'op-1', 'x', %s,"
                        " clock_timestamp() + interval '1 hour', 60)", (env.member_id(t.a),))
    ap = _approve(env, t.a)
    with pytest.raises(ApiError) as e:       # an approval belongs to its organisation
        _open(env, t.b, approval_id=ap["approval_id"])
    assert e.value.name == "not_found"
    with pytest.raises(ApiError) as e:       # and to the operator it names
        with env.operator() as c:
            legal_process.open_operator_access(c, token_key=t.key, notifier=env.notifier, operator_id="op-2",
                                               request_id="r", org_id=t.a.org_id, reason="x",
                                               approval_id=ap["approval_id"])
    assert e.value.name == "validation_failed"
    acc = _open(env, t.a, approval_id=ap["approval_id"])
    assert acc["approved_by_client"] == str(env.member_id(t.a))
    opened, expires = (datetime.fromisoformat(acc[k].replace("Z", "+00:00")) for k in ("opened_at", "expires_at"))
    assert 4 * 3600 - 5 <= (expires - opened).total_seconds() <= 4 * 3600 + 5
    with pytest.raises(ApiError) as e:       # spent once
        _open(env, t.a, approval_id=ap["approval_id"])
    assert e.value.name == "validation_failed"


def test_an_expired_access_is_no_access(env):
    t = env.t
    _open(env, t.a, approval_id=_approve(env, t.a)["approval_id"])
    with env.operator() as c, org_transaction(c, t.admin_token(t.a.org_id)):
        assert legal_process.require_open_access(c, OPERATOR)
    with t.superuser() as su:                # time passes: the record's own expiry, set by the database at open
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.operator_access SET expires_at = clock_timestamp() - interval '1 second'"
                   " WHERE org_id = %s", (t.a.org_id,))
    with env.operator() as c, org_transaction(c, t.admin_token(t.a.org_id)), pytest.raises(ApiError):
        legal_process.require_open_access(c, OPERATOR)


def test_the_operators_delivery_read_of_the_final_export_needs_an_open_access(env):
    t = env.t
    delivered = []
    kw = dict(token_key=t.key, custody=env.custody, crypto=t.crypto, signer=env.signer, store=env.archive,
              notifier=env.notifier, operator_id=OPERATOR, request_id="req-o", org_id=t.a.org_id, reason="x",
              clock=env.clock, deliver=lambda *a: delivered.append(a))
    with env.operator() as c, pytest.raises(ApiError) as e:
        offboard.run_offboard(c, **kw)
    assert e.value.name == "role_not_allowed" and delivered == []
    with env.operator() as c, pytest.raises(ApiError):
        offboard.read_final_export(c, token_key=t.key, custody=env.custody, store=env.archive, org_id=t.a.org_id,
                                   operator_id=OPERATOR)
    _open(env, t.a, approval_id=_approve(env, t.a)["approval_id"])
    with env.operator() as c:
        out = offboard.run_offboard(c, **kw)
    assert len(delivered) == 1 and out["steps"]["key_destruction"]["status"] == "scheduled"


# ---- restore: every key, verified chains, a paused worker ----------------------------------------------------------------
def test_restore_tries_every_contact_key_in_batches(env, tmp_path, pg_server, monkeypatch):
    from isolation.cloud_harness import Cloud

    t = env.t
    X = "+15555550191"
    cloud = Cloud(t, str(tmp_path / "evidence"))
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)  # X's key is the oldest of several
        for n in range(4):
            assert cloud.grant(cloud.a, f"+1555555020{n}")[0] in (200, 201)
        r = _copy(t, pg_server["port"])
        since = datetime.now(timezone.utc)
        body = {"contact": X, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                "method": "keyword"}
        assert cloud.call("/v1/events", body, token=cloud.token(cloud.a, "capture"))[0] in (200, 201)
        monkeypatch.setattr(restore, "KEY_BATCH", 2, raising=False)
        monkeypatch.setattr(restore, "MAX_CANDIDATE_KEYS", 2, raising=False)
        drop_synthetic_seals(r)
        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            restore.begin_restore(o, operator_id=OPERATOR, request_id="req-rs", restore_point=since)
            rep = restore.reconcile(o, token_key=t.key, crypto=t.crypto, store=cloud.store, ledger=env.ledger,
                                    inventory=restore.local_inventory(tmp_path / "evidence"), operator_id=OPERATOR,
                                    request_id="req-rc", region="US")
        a = rep["orgs"][str(t.a.org_id)]
        assert len(a["stops_reingested"]) == 1 and a["unreadable"] == []
    finally:
        cloud.close()


def test_restore_refuses_to_serve_while_a_chain_does_not_verify(env):
    t = env.t
    with t.superuser() as su:                # a restored copy whose ledger row was changed underneath
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.event SET row_hash = repeat('0', 64) WHERE org_id = %s"
                   " AND seq = (SELECT max(seq) FROM consentvault.event WHERE org_id = %s)", (t.a.org_id, t.a.org_id))
    with pytest.raises(RestoreIncompleteError) as e:
        _reconcile(env, t)
    failed = e.value.report["orgs"][str(t.a.org_id)]["failed_checks"]
    assert any(f["key"].startswith("chain:") for f in failed), failed
    assert e.value.report["orgs"][str(t.b.org_id)]["failed_checks"] == []
    with t.operator() as o:
        assert restore.pending(o) is not None  # the gate stays at 503


def test_restore_refuses_to_serve_while_a_seal_does_not_verify(env):
    t = env.t                                # the harness's seals were never made by a timestamp authority
    with pytest.raises(RestoreIncompleteError) as e:
        _reconcile(env, t, keep_seals=True)
    for org in (t.a, t.b):
        assert any(f["key"].startswith("seal:") for f in e.value.report["orgs"][str(org.org_id)]["failed_checks"])
    drop_synthetic_seals(t)
    _reconcile(env, t)                       # the same database, its seals settled, serves again


def test_the_sync_worker_pauses_while_a_restore_is_unreconciled(senv, tmp_path):
    from sync.support import PHONES

    env, t = senv, senv.t
    a, P = t.a, PHONES[2]
    s = env.add_system(a, "crm")
    with t.operator() as o:
        restore.begin_restore(o, operator_id=OPERATOR, request_id="req-rs", restore_point=datetime.now(timezone.utc))
    env.stop(a, P)
    rep = env.run_worker()
    assert rep.paused == "restore_in_progress" and env.transport.to(s.endpoint) == []
    drop_synthetic_seals(t)
    with psycopg.connect(t.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
        restore.reconcile(o, token_key=t.key, crypto=t.crypto, store=None,
                          ledger=LifecycleLedger(LocalAppendOnlyEvidenceStore(tmp_path / "arch"),
                                                clock=dbclock.datetime_clock(lambda: db.connect(t.app_dsn))),
                          inventory=lambda org, since: [], operator_id=OPERATOR, request_id="req-rc")
    rep = env.run_worker()
    assert rep.paused is None and len(env.transport.to(s.endpoint)) == 1


# ---- the final export link ----------------------------------------------------------------------------------------------
def _links(env):
    t = env.t
    return ExportService(connect=lambda: db.connect(t.app_dsn),
                         mint_token=lambda o, s: mint_org_token(t.key, o, s, credential_id=None), crypto=t.crypto,
                         signer=env.signer, store=env.archive, link_secret=os.urandom(32), clock=env.clock)


def _run(env, links, org):
    with env.operator() as c:
        return offboard.run_offboard(c, token_key=env.t.key, custody=env.custody, crypto=env.t.crypto,
                                     signer=env.signer, store=env.archive, notifier=env.notifier, operator_id=OPERATOR,
                                     request_id="req-off", org_id=org.org_id, reason="contract ended", clock=env.clock,
                                     links=links)


def _routes(env, links):
    t = env.t
    app = LifecycleApp(connect=lambda: db.connect(t.app_dsn), owner_connect=lambda: db.connect(t.operator_dsn),
                       token_key=t.key, crypto=t.crypto, custody=env.custody, ledger=env.ledger, store=env.archive,
                       signer=env.signer, notifier=env.notifier, links=links)
    return LifecycleRoutes(app, auth=None)


def _link_of(env, out):
    rid = out["request_id"]
    m = re.match(rf"^/v1/offboarding/{rid}/final-export\?link=(.+)$", env.notifier.sent[-1][2]["review_url"])
    assert m
    return rid, m.group(1)


def _get(routes, rid, link, token=None):
    h = {"X-Request-Id": "req-dl"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return routes.handle("GET", f"/v1/offboarding/{rid}/final-export", headers=h, query={"link": link})


def _confirm_delivery(routes, rid, sha, token):
    return routes.handle("POST", f"/v1/offboarding/{rid}/final-export:confirm", body=json.dumps({"sha256": sha}).encode(),
                         headers={"X-Request-Id": "req-cf", "Authorization": f"Bearer {token}"})


def test_the_final_export_download_needs_a_signed_in_admin_of_that_org(env):
    t, links = env.t, _links(env)
    rid, link = _link_of(env, _run(env, links, t.a))
    routes = _routes(env, links)
    assert _get(routes, rid, link).status == 401                          # the link alone is not enough
    other = _get(routes, rid, link, token=env.portal_token(t.b))
    assert other.status in (403, 404) and other.payload["error"] in ("export_link_invalid", "not_found")
    r = _get(routes, rid, link, token=env.portal_token(t.a))              # neither attempt spent the link
    assert r.status == 200 and r.headers["Content-Type"] == "application/zip"


def test_delivery_is_recorded_only_on_the_admins_confirmation_of_the_full_body(env):
    t, links = env.t, _links(env)
    rid, link = _link_of(env, _run(env, links, t.a))
    routes = _routes(env, links)
    tok = env.portal_token(t.a)
    r = _get(routes, rid, link, token=tok)
    assert r.status == 200
    again = _run(env, links, t.a)
    assert "final_export_delivered" not in again["steps"]                 # a download is not a delivery
    assert again["steps"]["key_destruction"]["status"] == "awaiting_delivery"
    bad = _confirm_delivery(routes, rid, "0" * 64, tok)
    assert bad.status == 422 and bad.payload["error"] == "validation_failed"
    assert _confirm_delivery(routes, rid, hashlib.sha256(r.raw).hexdigest(), env.portal_token(t.b)).status in (403, 404)
    ok = _confirm_delivery(routes, rid, hashlib.sha256(r.raw).hexdigest(), tok)
    assert ok.status == 200 and ok.payload["final_export_delivered"]["status"] == "done"
    done = _run(env, links, t.a)
    assert done["steps"]["key_destruction"]["status"] == "scheduled"


def test_a_spent_link_without_a_delivery_is_replaced(env, monkeypatch):
    t, links = env.t, _links(env)
    rid, link = _link_of(env, _run(env, links, t.a))
    routes = _routes(env, links)
    real = offboard._read_export

    def broken(*a, **kw):
        raise LifecycleError("the archive store dropped the read mid-way")
    monkeypatch.setattr(offboard, "_read_export", broken)
    failed = _get(routes, rid, link, token=env.portal_token(t.a))
    monkeypatch.setattr(offboard, "_read_export", real)
    assert failed.status == 503
    assert _get(routes, rid, link, token=env.portal_token(t.a)).payload["error"] == "export_link_used"
    sent_before = len(env.notifier.sent)
    out = _run(env, links, t.a)
    assert len(env.notifier.sent) == sent_before + 1 and out["steps"]["final_export_link"]["status"] == "sent"
    _, link2 = _link_of(env, out)
    assert link2 != link and _get(routes, rid, link2, token=env.portal_token(t.a)).status == 200
