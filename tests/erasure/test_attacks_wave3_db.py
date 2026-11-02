"""Third adversarial review, database guards.

- The tenant runtime role cannot write a hold's release columns; a release goes only through an owner-rights function
  that takes the actor from the verified tenant token (member) or from the owner's own session (operator).
- The tenant runtime role inserts only the request columns of an erasure or offboarding request, and no role may create
  a request already past its first state (export delivered, destruction scheduled, erasure confirmed or completed).
- The down file of the lifecycle migration refuses while pending or declined erasures, a delivered final export, or a
  restore record exist.
"""

import json
import os
import uuid

import psycopg
import pytest

from consentvault.tenancy import erasure, holds
from consentvault.tenancy.admin_base import ROLE_SCOPES
from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from isolation.harness import PHONE

from .support import OPERATOR

DOWN = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "down", "0014_erasure_holds.sql")
NOW = "clock_timestamp()"


def _op_hold(env, org):
    with env.operator() as c:
        return holds.place_hold_operator(c, token_key=env.t.key, ledger=env.ledger, custody=env.custody,
                                         operator_id=OPERATOR, request_id="req-h", org_id=org.org_id,
                                         scope="contacts", reason="subpoena preservation", contacts=[PHONE],
                                         crypto=env.t.crypto)


def _member_hold(env, org):
    with env.admin(org) as ctx:
        return holds.place_hold_member(ctx, {"scope": "org", "reason": "keep"}, ledger=env.ledger, crypto=env.t.crypto)


def _hold_row(env, org, hold_id):
    with env.t.superuser() as su:
        return su.execute("SELECT * FROM consentvault.legal_hold WHERE org_id = %s AND hold_id = %s",
                          (org.org_id, hold_id)).fetchone()


def _release_fn(app, hold_id, actor_id):
    return app.execute("SELECT consentvault.release_hold_as_member(%s, %s, clock_timestamp(), 1, %s) AS h",
                       (hold_id, "ocv1:x", actor_id)).fetchone()


# Finding: the tenant runtime role released a legal-process hold as the operator ------------------------------------------
def test_app_role_cannot_write_hold_release_columns(env):
    t = env.t
    h = _op_hold(env, t.a)
    with t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, env.portal_token(t.a)):
                app.execute("UPDATE consentvault.legal_hold SET released_by_kind='operator', released_by='op-1',"
                            " released_at=clock_timestamp(), release_reason='x' WHERE hold_id=%s", (h["hold_id"],))
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_member_release_function_refuses_an_operator_hold(env):
    t = env.t
    h = _op_hold(env, t.a)
    with t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="operator"):
            with org_transaction(app, env.portal_token(t.a)):
                _release_fn(app, h["hold_id"], str(env.member_id(t.a)))
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_app_role_cannot_call_the_operator_release(env):
    t = env.t
    h = _op_hold(env, t.a)
    with t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, env.portal_token(t.a)):
                app.execute("SELECT consentvault.release_hold_as_operator(%s, 'ocv1:x', clock_timestamp(), 1, 'op-1')",
                            (h["hold_id"],))
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_member_release_needs_a_member_admin_token(env):
    t = env.t
    h = _member_hold(env, t.a)
    machine = mint_org_token(t.key, t.a.org_id, ["admin"], credential_id=None)
    viewer = mint_org_token(t.key, t.a.org_id, ROLE_SCOPES["compliance_viewer"],
                            credential_id=MEMBER_CREDENTIAL_PREFIX + str(env.member_id(t.a)))
    for tok in (machine, viewer):
        with t.app() as app:
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="release refused"):
                with org_transaction(app, tok):
                    _release_fn(app, h["hold_id"], None)
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_member_release_refuses_a_caller_named_actor(env):
    t = env.t
    h = _member_hold(env, t.a)
    with t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="does not match"):
            with org_transaction(app, env.portal_token(t.a)):
                _release_fn(app, h["hold_id"], str(uuid.uuid4()))
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_member_release_records_the_token_member(env):
    t = env.t
    h = _member_hold(env, t.a)
    with env.admin(t.a) as ctx:
        out = holds.release_hold_member(ctx, h["hold_id"], {"reason": "done"}, ledger=env.ledger, crypto=t.crypto)
    assert out["released_at"] is not None
    row = _hold_row(env, t.a, h["hold_id"])
    assert (row["released_by_kind"], row["released_by"]) == ("member", str(env.member_id(t.a)))


def test_operator_release_records_the_operator(env):
    t = env.t
    h = _op_hold(env, t.a)
    with env.operator() as c:
        out = holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody,
                                          operator_id=OPERATOR, request_id="req-r", org_id=t.a.org_id,
                                          hold_id=h["hold_id"], reason="process closed", crypto=t.crypto)
    assert out["released_at"] is not None
    row = _hold_row(env, t.a, h["hold_id"])
    assert (row["released_by_kind"], row["released_by"]) == ("operator", OPERATOR)


# Finding: the tenant runtime role forged an offboarding row whose export was "delivered" -----------------------------------
def test_app_role_cannot_forge_a_delivered_offboarding(env):
    t = env.t
    with t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, env.portal_token(t.a)):
                app.execute("INSERT INTO consentvault.offboarding_request (org_id, reason, requested_by, state, steps,"
                            " final_export_at, final_export_sha256, final_export_key, final_export_wrapped) VALUES"
                            " ((SELECT consentvault.current_org()), 'x', %s, 'in_progress', %s::jsonb,"
                            " clock_timestamp(), repeat('0',64), 'nothing', '\\x00')",
                            (env.member_id(t.a), json.dumps({"final_export_delivered": {"status": "done"}})))
    with t.superuser() as su:
        assert su.execute("SELECT count(*) n FROM consentvault.offboarding_request WHERE org_id = %s",
                          (t.a.org_id,)).fetchone()["n"] == 0


def test_app_role_cannot_forge_a_completed_erasure(env):
    t = env.t
    with t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, env.portal_token(t.a)):
                app.execute("INSERT INTO consentvault.erasure_request (org_id, contact_fp, reason, requested_by, status,"
                            " confirmed_by, confirmed_at, completed_at, ledger_seq) VALUES"
                            " ((SELECT consentvault.current_org()), %s, 'x', %s, 'completed', 'op-1', clock_timestamp(),"
                            " clock_timestamp(), 1)", (env.fp(t.a), env.member_id(t.a)))


@pytest.mark.parametrize("cols,vals", [
    ("state", "'in_progress'"),
    ("steps", "'{\"final_export_delivered\": {\"status\": \"done\"}}'::jsonb"),
    ("steps", "'{\"key_destruction\": {\"status\": \"scheduled\"}}'::jsonb"),
    ("destroy_after", NOW),
    ("final_export_at, final_export_sha256, final_export_key, final_export_wrapped",
     f"{NOW}, repeat('0',64), 'k', '\\x00'"),
])
def test_no_role_creates_an_offboarding_past_its_first_state(env, cols, vals):
    t = env.t
    with env.operator() as c:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="first state"):
            with org_transaction(c, t.admin_token(t.a.org_id)):
                c.execute(f"INSERT INTO consentvault.offboarding_request (org_id, reason, requested_by_operator, {cols})"
                          f" VALUES ((SELECT consentvault.current_org()), 'x', 'op-1', {vals})")


@pytest.mark.parametrize("cols,vals", [
    ("status, decline_reason", "'declined', 'no'"),
    ("confirmed_by, confirmed_at", f"'op-1', {NOW}"),
    ("status, confirmed_by, confirmed_at, completed_at, ledger_seq", f"'completed', 'op-1', {NOW}, {NOW}, 1"),
])
def test_no_role_creates_an_erasure_past_its_first_state(env, cols, vals):
    t = env.t
    with env.operator() as c:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="first state"):
            with org_transaction(c, t.admin_token(t.a.org_id)):
                c.execute(f"INSERT INTO consentvault.erasure_request (org_id, contact_fp, reason, requested_by, {cols})"
                          f" VALUES ((SELECT consentvault.current_org()), %s, 'x', %s, {vals})",
                          (env.fp(t.a), env.member_id(t.a)))


def test_the_request_paths_still_insert(env):
    t = env.t
    with env.admin(t.a) as ctx:
        out = erasure.request_erasure(ctx, {"contact": PHONE, "reason": "asked"}, crypto=t.crypto)
    assert out["status"] == "pending_operator_confirmation"
    from consentvault.tenancy import offboard
    with env.admin(t.b) as ctx:
        offboard.request_offboarding(ctx, {"reason": "leaving", "org_name": t.b.name})


# Finding: the down file dropped pending and declined erasures, a delivered export and the restore record ---------------
def _down(t):
    with psycopg.connect(t.super_dsn, autocommit=True) as su:
        su.execute(open(DOWN, encoding="utf-8").read())


def _still_applied(t):
    with t.superuser() as su:
        return su.execute("SELECT to_regclass('consentvault.erasure_request') IS NOT NULL AS x").fetchone()["x"]


def test_down_refuses_while_a_pending_erasure_exists(env):
    t = env.t
    with env.admin(t.a) as ctx:
        erasure.request_erasure(ctx, {"contact": PHONE, "reason": "asked"}, crypto=t.crypto)
    with pytest.raises(psycopg.errors.RaiseException, match="pending or declined erasures"):
        _down(t)
    assert _still_applied(t)


def test_down_refuses_while_a_declined_erasure_exists(env):
    t = env.t
    with env.admin(t.a) as ctx:
        eid = erasure.request_erasure(ctx, {"contact": PHONE, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
    with t.superuser() as su:
        su.execute("UPDATE consentvault.erasure_request SET status = 'declined', decline_reason = 'no'"
                   " WHERE org_id = %s AND erasure_id = %s", (t.a.org_id, eid))
    with pytest.raises(psycopg.errors.RaiseException, match="pending or declined erasures"):
        _down(t)
    assert _still_applied(t)


def test_down_refuses_while_a_delivered_export_is_recorded(env):
    t = env.t
    with t.superuser() as su:
        rid = uuid.uuid4()
        su.execute("INSERT INTO consentvault.offboarding_request (org_id, request_id, reason, requested_by_operator)"
                   " VALUES (%s, %s, 'x', 'op-1')", (t.a.org_id, rid))
        su.execute("UPDATE consentvault.offboarding_request SET state = 'complete', steps = %s::jsonb"
                   " WHERE org_id = %s AND request_id = %s",
                   (json.dumps({"final_export_delivered": {"status": "done"}}), t.a.org_id, rid))
    with pytest.raises(psycopg.errors.RaiseException, match="delivered final export"):
        _down(t)
    assert _still_applied(t)


def test_down_refuses_while_a_restore_is_recorded(env):
    t = env.t
    with t.superuser() as su:
        su.execute("INSERT INTO consentvault.restore_run (restore_point, started_by) VALUES (clock_timestamp(), 'op-1')")
    with pytest.raises(psycopg.errors.RaiseException, match="restore"):
        _down(t)
    assert _still_applied(t)
