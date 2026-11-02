"""Gag safety: a legal process under a non-disclosure order, and an operator's hold, never reach a tenant-readable
surface by name.

- A held erasure reads to the customer as a neutral held state: no hold id, no reason, nothing naming legal process.
  That holds for the API read, the answer to the request itself, the tenant audit chain, the notices the customer
  receives, the offboarding records the runtime role reads and the final export.
- An emergency operator access opened under a gagged legal process notifies nobody and leaves nothing in the tenant
  audit; one opened while the notice decision is still open is refused by name.
- An operator hold placed outside legal process reaches the customer only as a neutral hold with no reason text.
- The hold release resume never counts a waiting erasure as completed, and writes the commit entry through the
  two-phase ledger.
- The customer's approval of operator access is an audit row written through ``audit.py``.
"""

import io
import json
import zipfile
from datetime import datetime, timezone

import psycopg
import pytest

from consentvault import dbclock
from consentvault.tenancy import admin, audit, erasure, holds, legal_process, offboard
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import PHONE

from .support import OPERATOR

BASIS = "non-disclosure order 2705b case 26-mj-777"
REQUESTER = "Field Office Seventeen"
SCOPE = "every record of the named subscriber"


# ---- helpers -------------------------------------------------------------------------------------------------------------
def _log_gagged(env, org, *, hold_scope="org", decide=True):
    with env.operator() as c:
        p = legal_process.log_legal_process(
            c, token_key=env.t.key, ledger=env.ledger, custody=env.custody, crypto=env.t.crypto, operator_id=OPERATOR,
            request_id="req-lp", org_id=org.org_id, type="search_warrant", received_at=datetime.now(timezone.utc),
            received_via="email", requester=REQUESTER, scope_summary=SCOPE, hold_scope=hold_scope)
        if decide:
            legal_process.record_customer_notice(c, token_key=env.t.key, notifier=env.notifier, operator_id=OPERATOR,
                                                 request_id="req-lp2", org_id=org.org_id, process_id=p["process_id"],
                                                 prohibited_basis=BASIS)
    return p


def _request(env, org, contact=PHONE):
    with env.admin(org) as ctx:
        return erasure.request_erasure(ctx, {"contact": contact, "reason": "asked"}, crypto=env.t.crypto)


def _get(env, org, eid):
    with env.admin(org) as ctx:
        return erasure.get_erasure(ctx, eid)


def _confirm(env, org, eid):
    with env.operator() as c:
        return erasure.confirm_erasure(c, token_key=env.t.key, crypto=env.t.crypto, ledger=env.ledger, operator_id=OPERATOR,
                                       request_id="req-e", org_id=org.org_id, erasure_id=eid)


def _audit(env, org):
    with env.admin(org) as ctx:
        return admin.list_audit(ctx, limit=200)["items"]


def _runtime_rows(env, org):
    """What the tenant runtime role can read of holds and offboarding, entered as the organisation's admin."""
    out = {}
    with env.t.app() as app, org_transaction(app, env.portal_token(org)):
        out["legal_hold"] = app.execute("SELECT hold_id, scope, set_by_kind, set_at, released_at"
                                        " FROM consentvault.legal_hold").fetchall()
        out["erasure_request"] = app.execute("SELECT " + erasure.ERASURE_COLUMNS
                                             + " FROM consentvault.erasure_request").fetchall()
        with pytest.raises(psycopg.errors.InsufficientPrivilege), app.transaction():   # which hold holds it: never
            app.execute("SELECT held_by FROM consentvault.erasure_request")
        out["offboarding_request"] = app.execute("SELECT steps FROM consentvault.offboarding_request").fetchall()
        out["destruction_record"] = app.execute("SELECT kind, request_id FROM consentvault.destruction_record").fetchall()
    return out


def _surfaces(env, org, *erasure_ids) -> str:
    """Every tenant-readable surface this suite knows, as one string to search."""
    views = [_get(env, org, e) for e in erasure_ids]
    return json.dumps({"api": views, "audit": _audit(env, org), "notices": env.notifier.sent,
                       "runtime": _runtime_rows(env, org)}, default=str)


def _assert_neutral(view):
    assert view["status"] == "held", view
    assert view["held_reason"] is None and view["held_by"] is None, view


def _assert_no_trace(text, *secrets):
    for s in secrets + (BASIS, REQUESTER, SCOPE, "legal process", "legal_process", "search warrant", "search_warrant",
                        "legal hold"):
        assert str(s) not in text, f"{s!r} reached a tenant-readable surface"


# ---- 1a. a held erasure under a gagged legal process ---------------------------------------------------------------------
def test_a_request_under_a_gagged_hold_is_queued_as_a_neutral_hold_never_refused_by_name(env):
    t = env.t
    p = _log_gagged(env, t.a)
    out = _request(env, t.a)
    assert out["status"] == "held" and out["held_reason"] is None and "hold_id" not in json.dumps(out)
    _assert_neutral(_get(env, t.a, out["erasure_id"]))
    _assert_no_trace(_surfaces(env, t.a, out["erasure_id"]), p["hold_id"], p["process_id"])
    assert env.key_present(t.a)


def test_a_confirmed_erasure_held_by_a_gagged_hold_reads_neutral_on_every_tenant_surface(env):
    t = env.t
    eid = _request(env, t.a)["erasure_id"]
    p = _log_gagged(env, t.a)
    with pytest.raises(ApiError) as e:       # the operator is told by name; the operator is not the tenant
        _confirm(env, t.a, eid)
    assert e.value.name == "legal_hold_active"
    _assert_neutral(_get(env, t.a, eid))
    text = _surfaces(env, t.a, eid)
    _assert_no_trace(text, p["hold_id"], p["process_id"])
    assert [r["action"] for r in _audit(env, t.a) if r["action"] == "erasure.held"] == ["erasure.held"]
    assert env.notifier.sent == []
    assert env.key_present(t.a)


def test_the_release_of_a_gagged_hold_never_reaches_the_tenant_and_the_erasure_then_completes(env):
    t = env.t
    eid = _request(env, t.a)["erasure_id"]
    p = _log_gagged(env, t.a)
    with pytest.raises(ApiError):
        _confirm(env, t.a, eid)
    with env.operator() as c:
        rel = holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, operator_id=OPERATOR,
                                          request_id="req-r", org_id=t.a.org_id, hold_id=p["hold_id"],
                                          reason="process withdrawn", crypto=t.crypto)
    assert rel["resumed"]["erasures_completed"] == 1
    assert _get(env, t.a, eid)["status"] == "completed"
    _assert_no_trace(_surfaces(env, t.a, eid), p["hold_id"], p["process_id"])
    assert not [r for r in _audit(env, t.a) if r["action"].startswith("legal_hold")]


def test_an_undecided_legal_process_hold_is_as_quiet_as_a_gagged_one(env):
    t = env.t
    p = _log_gagged(env, t.a, decide=False)
    out = _request(env, t.a)
    _assert_neutral(_get(env, t.a, out["erasure_id"]))
    _assert_no_trace(_surfaces(env, t.a, out["erasure_id"]), p["hold_id"], p["process_id"])


def test_a_gagged_hold_is_not_a_row_the_runtime_role_reads(env):
    t = env.t
    p = _log_gagged(env, t.a)
    assert _runtime_rows(env, t.a)["legal_hold"] == []
    with env.t.app() as app, org_transaction(app, env.portal_token(t.a)):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):   # the process link is never a tenant column
            app.execute("SELECT legal_process_id FROM consentvault.legal_hold")
    with t.superuser() as su:                                     # the hold is there and enforced
        assert su.execute("SELECT 1 FROM consentvault.legal_hold WHERE hold_id = %s", (p["hold_id"],)).fetchone()


def test_offboarding_under_a_gagged_hold_tells_the_customer_only_that_destruction_is_on_hold(env):
    t = env.t
    p = _log_gagged(env, t.a)
    env.open_access(t.a)
    delivered = []
    with env.operator() as c:
        out = offboard.run_offboard(c, token_key=t.key, custody=env.custody, crypto=t.crypto, signer=env.signer,
                                    store=env.archive, notifier=env.notifier, operator_id=OPERATOR, request_id="req-o",
                                    org_id=t.a.org_id, reason="x", clock=env.clock,
                                    deliver=lambda *a: delivered.append(a))
    assert out["steps"]["key_destruction"]["status"] == "held"
    assert env.custody.status(str(t.a.org_id)).state == "active"
    assert env.notifier.sent and any("hold" in m[2]["event"] for m in env.notifier.sent)
    _assert_no_trace(_surfaces(env, t.a), p["hold_id"], p["process_id"])
    package = delivered[0][2]                # the export cover and every file in the package
    with zipfile.ZipFile(io.BytesIO(package)) as z:
        body = " ".join(z.namelist()) + " ".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())
    _assert_no_trace(body, p["hold_id"], p["process_id"])


# ---- 1b. an emergency operator access under a gag ------------------------------------------------------------------------
def _emergency(env, org, process_id, reason="preserve records for the warrant"):
    with env.operator() as c:
        return legal_process.open_operator_access(c, token_key=env.t.key, notifier=env.notifier, operator_id=OPERATOR,
                                                  request_id="req-em", org_id=org.org_id, reason=reason, emergency=True,
                                                  legal_process_id=process_id)


def test_an_emergency_access_under_a_gag_notifies_nobody_and_stays_off_the_tenant_audit(env):
    t = env.t
    p = _log_gagged(env, t.a, hold_scope=None)
    acc = _emergency(env, t.a, p["process_id"])
    assert acc["client_notified_at"] is None and acc["emergency"] is True
    with env.operator() as c, org_transaction(c, t.admin_token(t.a.org_id)):   # the operator's read is allowed
        assert legal_process.require_open_access(c, OPERATOR)["access_id"] == acc["access_id"]
    with env.operator() as c:
        legal_process.close_operator_access(c, token_key=t.key, operator_id=OPERATOR, request_id="req-cl",
                                            org_id=t.a.org_id, access_id=acc["access_id"])
    assert env.notifier.sent == []
    text = _surfaces(env, t.a)
    _assert_no_trace(text, p["process_id"], acc["access_id"], "preserve records for the warrant")
    assert not [r for r in _audit(env, t.a) if r["action"].startswith("operator_access")]
    with t.superuser() as su:                # the platform chain holds the whole record
        acts = [r["action"] for r in su.execute("SELECT action FROM consentvault.audit_event WHERE org_id IS NULL"
                                                " AND target_id = %s ORDER BY seq", (acc["access_id"],))]
    assert acts == ["operator_access.opened", "operator_access.closed"]


def test_an_emergency_access_under_an_undecided_process_is_refused_by_name(env):
    t = env.t
    p = _log_gagged(env, t.a, hold_scope=None, decide=False)
    with pytest.raises(ApiError) as e:
        _emergency(env, t.a, p["process_id"])
    assert e.value.name == "validation_failed" and "notice" in e.value.fields
    assert env.notifier.sent == []
    with t.superuser() as su:
        assert su.execute("SELECT count(*) n FROM consentvault.operator_access WHERE org_id = %s",
                          (t.a.org_id,)).fetchone()["n"] == 0


def test_an_emergency_access_with_no_notice_and_no_gag_is_refused_by_the_database(env):
    t = env.t
    with env.operator() as c, org_transaction(c, t.admin_token(t.a.org_id)):
        with pytest.raises(psycopg.errors.IntegrityError):
            c.execute("INSERT INTO consentvault.operator_access (org_id, operator_id, reason, emergency, opened_at,"
                      " expires_at) VALUES (%s, 'op-1', 'x', true, clock_timestamp(),"
                      " clock_timestamp() + interval '1 hour')", (t.a.org_id,))


def test_an_emergency_access_under_a_notified_process_still_notifies(env):
    t = env.t
    with env.operator() as c:
        p = legal_process.log_legal_process(
            c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto, operator_id=OPERATOR,
            request_id="req-lp", org_id=t.a.org_id, type="subpoena", received_at=datetime.now(timezone.utc),
            received_via="email", requester=REQUESTER, scope_summary=SCOPE, hold_scope=None)
        legal_process.record_customer_notice(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                             request_id="req-n", org_id=t.a.org_id, process_id=p["process_id"])
    before = len(env.notifier.sent)
    acc = _emergency(env, t.a, p["process_id"], reason="records needed tonight")
    assert acc["client_notified_at"] is not None and len(env.notifier.sent) > before


# ---- 1c. an operator hold outside legal process --------------------------------------------------------------------------
def _op_hold(env, org, reason="billing dispute preservation"):
    with env.operator() as c:
        return holds.place_hold_operator(c, token_key=env.t.key, ledger=env.ledger, custody=env.custody,
                                         operator_id=OPERATOR, request_id="req-h", org_id=org.org_id, scope="contacts",
                                         reason=reason, contacts=[PHONE], crypto=env.t.crypto)


def test_an_operator_hold_outside_legal_process_is_a_neutral_hold_with_no_reason_text(env):
    t = env.t
    h = _op_hold(env, t.a)
    out = _request(env, t.a)
    _assert_neutral(_get(env, t.a, out["erasure_id"]))
    sets = [r for r in _audit(env, t.a) if r["action"] == "legal_hold.set"]
    assert len(sets) == 1 and sets[0]["reason"] is None
    held = [r for r in _audit(env, t.a) if r["action"] == "erasure.held"]
    assert held and all(r["reason"] is None for r in held)
    with env.operator() as c:
        holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, operator_id=OPERATOR,
                                    request_id="req-r", org_id=t.a.org_id, hold_id=h["hold_id"], reason="settled",
                                    crypto=t.crypto)
    rel = [r for r in _audit(env, t.a) if r["action"] == "legal_hold.released"]
    assert len(rel) == 1 and rel[0]["reason"] is None
    # the hold itself is visible (its id is an audit target), neutrally: no reason text anywhere
    _assert_no_trace(_surfaces(env, t.a, out["erasure_id"]), "billing dispute", "settled", holds.AUDIT_NOTE)
    with env.t.app() as app, org_transaction(app, env.portal_token(t.a)):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):   # not even the sealed reason
            app.execute("SELECT reason FROM consentvault.legal_hold")


def test_a_clients_own_hold_still_refuses_a_request_by_name(env):
    t = env.t
    with env.admin(t.a) as ctx:
        h = holds.place_hold_member(ctx, {"scope": "contacts", "contacts": [PHONE], "reason": "litigation"},
                                    ledger=env.ledger, crypto=t.crypto)
    _op_hold(env, t.a)
    with pytest.raises(ApiError) as e:
        _request(env, t.a)
    assert e.value.name == "legal_hold_active" and e.value.fields == {"hold_id": h["hold_id"]}


# ---- 2. holds.resume -----------------------------------------------------------------------------------------------------
def _held_by_operator_hold(env, org):
    eid = _request(env, org)["erasure_id"]
    h = _op_hold(env, org)
    with pytest.raises(ApiError):
        _confirm(env, org, eid)
    return eid, h


def _release(env, org, h):
    with env.operator() as c:
        return holds.release_hold_operator(c, token_key=env.t.key, ledger=env.ledger, custody=env.custody,
                                           operator_id=OPERATOR, request_id="req-r", org_id=org.org_id,
                                           hold_id=h["hold_id"], reason="settled", crypto=env.t.crypto)


def test_resume_never_counts_an_erasure_waiting_on_delivery_as_completed(env, monkeypatch):
    t = env.t
    eid, h = _held_by_operator_hold(env, t.a)
    monkeypatch.setattr(erasure, "pending_pushes", lambda conn, fp: 2)   # a stop push still in flight
    rel = _release(env, t.a, h)
    assert rel["resumed"]["erasures_completed"] == 0
    assert rel["resumed"]["erasures_waiting"] == [eid]
    assert rel["resumed"]["export_cache"] == []
    assert env.key_present(t.a)
    with t.superuser() as su:
        row = su.execute("SELECT status, wait_reason FROM consentvault.erasure_request WHERE erasure_id = %s",
                         (eid,)).fetchone()
    assert (row["status"], row["wait_reason"]) == ("pending_operator_confirmation", "pending_suppression_delivery")
    assert [e["kind"] for e in env.ledger.entries(t.a.org_id)] == ["hold_set", "hold_released"]


def test_resume_writes_the_commit_entry_through_the_two_phase_ledger(env):
    t = env.t
    eid, h = _held_by_operator_hold(env, t.a)
    rel = _release(env, t.a, h)
    assert rel["resumed"]["erasures_completed"] == 1 and not env.key_present(t.a)
    assert rel["resumed"]["ledger_commit"]["status"] == "written"
    assert rel["resumed"]["ledger_commit"]["erasures"] == [eid]
    entries = env.ledger.entries(t.a.org_id)
    intent = next(e for e in entries if e["kind"] == "erasure_intent")
    commit = next(e for e in entries if e["kind"] == "erasure_commit")
    assert commit["erasure_id"] == eid and commit["intent_seq"] == intent["seq"] and commit["seq"] > intent["seq"]
    with t.superuser() as su:
        assert su.execute("SELECT commit_seq FROM consentvault.erasure_ledger_commit WHERE erasure_id = %s",
                          (eid,)).fetchone()["commit_seq"] == commit["seq"]


# ---- 3. the approval of operator access is audited -----------------------------------------------------------------------
def test_the_customers_approval_of_operator_access_is_an_audit_row_written_through_audit_py(env, monkeypatch):
    t = env.t
    assert "operator_access.approved" in audit.ACTIONS
    calls = []
    real = audit.append

    def spy(conn, **kw):
        calls.append(kw["action"])
        return real(conn, **kw)
    monkeypatch.setattr(audit, "append", spy)
    with env.admin(t.a) as ctx:
        ap = legal_process.approve_operator_access(ctx, {"operator_id": OPERATOR, "reason": "ticket 42"})
    assert calls == ["operator_access.approved"]
    rows = [r for r in _audit(env, t.a) if r["action"] == "operator_access.approved"]
    assert len(rows) == 1
    assert rows[0]["actor"]["kind"] == "member" and rows[0]["target"]["id"] == ap["approval_id"]


# ---- 1d. a restore that meets a gagged hold ------------------------------------------------------------------------------
def test_a_restore_that_queues_an_erasure_behind_a_gagged_hold_writes_a_neutral_audit_row(env, pg_server, tmp_path):
    from consentvault import db
    from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
    from consentvault.tenancy.erasure import LifecycleLedger

    from .test_attacks_wave3_lifecycle import _copy, _reconcile

    t = env.t
    eid = _request(env, t.a)["erasure_id"]
    r = _copy(t, pg_server["port"])          # the copy has the request open
    with db.connect(r.operator_dsn) as o:       # a gagged process hold only the restored copy holds
        p = legal_process.log_legal_process(
            o, token_key=t.key, ledger=LifecycleLedger(LocalAppendOnlyEvidenceStore(tmp_path / "other"),
                                   clock=dbclock.datetime_clock(lambda: db.connect(t.app_dsn))), custody=None,
            crypto=t.crypto, operator_id=OPERATOR, request_id="req-lp", org_id=t.a.org_id, type="search_warrant",
            received_at=datetime.now(timezone.utc), received_via="email", requester=REQUESTER, scope_summary=SCOPE)
        legal_process.record_customer_notice(o, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                             request_id="req-lp2", org_id=t.a.org_id, process_id=p["process_id"],
                                             prohibited_basis=BASIS)
    _confirm(env, t.a, eid)                  # erased live
    rep = _reconcile(env, r)
    assert rep["orgs"][str(t.a.org_id)]["erasures_held"][0]["erasure_id"] == eid
    with psycopg.connect(r.super_dsn, row_factory=psycopg.rows.dict_row) as su:
        rows = su.execute("SELECT action, target_id, reason FROM consentvault.audit_event WHERE org_id = %s",
                          (t.a.org_id,)).fetchall()
    _assert_no_trace(json.dumps(rows, default=str), p["hold_id"], p["process_id"])
