"""Cross-organisation attacks on erasure, holds, offboarding, legal process and operator access. The same phone number is
a contact of both organisations. Every owner-rights function acts on current_org() only; the Python reads filter on
current_org() themselves (proved on a superuser connection, where row security is off)."""

import uuid

import psycopg
import pytest

from consentvault import db
from consentvault.route_wiring import Authenticator, lifecycle_routes
from consentvault.tenancy import erasure, holds, legal_process, offboard
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.lifecycle_routes import LifecycleApp
from consentvault.tenancy.tokens import org_transaction

from admin.support import ISSUER, FakeIdentity
from erasure.support import OPERATOR, Env
from isolation.harness import PHONE


@pytest.fixture
def env(tenancy, tmp_path):
    return Env(tenancy, tmp_path)


def _request(env, org):
    with env.admin(org) as ctx:
        return erasure.request_erasure(ctx, {"contact": PHONE, "reason": "asked"}, crypto=env.t.crypto)["erasure_id"]


def test_erase_contact_under_one_org_never_touches_the_other(env):
    t = env.t
    with t.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):
        assert o.execute("SELECT consentvault.erase_contact(%s) AS d", (env.fp(t.b),)).fetchone()["d"] is False
    assert env.key_present(t.b) and env.key_present(t.a)


def test_the_runtime_role_can_neither_erase_nor_delete_a_key_nor_read_the_restore_state(env):
    t = env.t
    with t.app() as app, org_transaction(app, t.admin_token(t.a.org_id)):
        for sql in ("SELECT consentvault.erase_contact(repeat('a', 64))",
                    "DELETE FROM consentvault.contact_key",
                    "SELECT * FROM consentvault.restore_run",
                    "INSERT INTO consentvault.operator_access (org_id, operator_id, reason, emergency,"
                    " client_notified_at) VALUES (consentvault.current_org(), 'x', 'y', true, now())",
                    "INSERT INTO consentvault.legal_process (org_id, type, received_at, received_via, requester,"
                    " scope_summary, handled_by) VALUES (consentvault.current_org(), 'other', now(), 'a', 'b', 'c', 'd')"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with app.transaction():
                    app.execute(sql)
    assert env.key_present(t.a)


def test_another_orgs_hold_neither_blocks_nor_shows_and_cannot_be_released_from_here(env):
    t = env.t
    with env.admin(t.b) as ctx:
        hb = holds.place_hold_member(ctx, {"scope": "org", "reason": "b's matter"}, ledger=env.ledger, crypto=t.crypto)
    with t.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):
        assert o.execute("SELECT consentvault.legal_hold_covering(%s) AS h", (env.fp(t.a),)).fetchone()["h"] is None
    for superuser in (False, True):
        with env.admin(t.a, superuser=superuser) as ctx, pytest.raises(ApiError) as e:
            holds.release_hold_member(ctx, hb["hold_id"], {"reason": "x"}, ledger=env.ledger, crypto=env.t.crypto)
        assert e.value.name == "not_found"
    eid = _request(env, t.a)  # B's org-scope hold does not reach A
    with t.operator() as c:
        assert erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, operator_id=OPERATOR, request_id="r",
                                       org_id=t.a.org_id, erasure_id=eid)["status"] == "completed"
    assert env.key_present(t.b)
    assert [e["kind"] for e in env.ledger.entries(t.b.org_id)] == ["hold_set"]
    assert [e["kind"] for e in env.ledger.entries(t.a.org_id)] == ["erasure_intent", "erasure_commit"]


def test_one_orgs_erasure_request_is_invisible_and_unconfirmable_from_the_other(env):
    t = env.t
    eid_b = _request(env, t.b)
    for superuser in (False, True):
        with env.admin(t.a, superuser=superuser) as ctx, pytest.raises(ApiError) as e:
            erasure.get_erasure(ctx, eid_b)
        assert e.value.name == "not_found"
    with t.operator() as c, pytest.raises(ApiError) as e:
        erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, operator_id=OPERATOR, request_id="r",
                                org_id=t.a.org_id, erasure_id=eid_b)
    assert e.value.name == "not_found" and env.key_present(t.b)


def test_offboarding_one_org_leaves_the_other_untouched(env):
    t = env.t
    env.open_access(t.a)  # the operator's delivery read needs an open access record in A
    with t.operator() as c:
        offboard.run_offboard(c, token_key=t.key, custody=env.custody, crypto=t.crypto, signer=env.signer,
                              store=env.archive, notifier=env.notifier, operator_id=OPERATOR, request_id="r",
                              org_id=t.a.org_id, deliver=lambda *a: None)
    assert env.custody.status(str(t.b.org_id)).state == "active"
    with t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.credential WHERE org_id = %s AND revoked_at IS NOT NULL",
                          (t.b.org_id,)).fetchone()["n"] == 0
        assert su.execute("SELECT status FROM consentvault.org_key WHERE org_id = %s", (t.b.org_id,)).fetchone()[
            "status"] == "active"
    assert all(to.endswith("@alpha.example.com") for _, to, _ in env.notifier.sent)


def test_operator_access_and_its_approver_belong_to_one_org(env):
    t = env.t
    with env.admin(t.a) as ctx:
        ap = legal_process.approve_operator_access(ctx, {"operator_id": OPERATOR, "reason": "ticket"})
    with t.operator() as c, pytest.raises(ApiError) as e:  # A's approval opens nothing in B
        legal_process.open_operator_access(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                           request_id="r", org_id=t.b.org_id, reason="ticket",
                                           approval_id=ap["approval_id"])
    assert e.value.name == "not_found"
    with t.operator() as c:
        a = legal_process.open_operator_access(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                               request_id="r", org_id=t.a.org_id, reason="ticket",
                                               approval_id=ap["approval_id"])
        with org_transaction(c, t.admin_token(t.b.org_id)), pytest.raises(ApiError):
            legal_process.require_open_access(c, OPERATOR)  # A's access opens nothing in B
        with pytest.raises(ApiError) as e:
            legal_process.close_operator_access(c, token_key=t.key, operator_id=OPERATOR, request_id="r",
                                                org_id=t.b.org_id, access_id=a["access_id"])
        assert e.value.name == "not_found"


def _routes(env):
    t = env.t
    identity = FakeIdentity()
    auth = Authenticator(connect=lambda: db.connect(t.app_dsn), access_tokens=None, identity=identity,
                         operators={(ISSUER, "op-subject-1"): OPERATOR})
    app = LifecycleApp(connect=lambda: db.connect(t.app_dsn), owner_connect=lambda: db.connect(t.operator_dsn),
                       token_key=t.key, crypto=t.crypto, custody=env.custody, ledger=env.ledger, store=env.archive,
                       signer=env.signer, notifier=env.notifier)
    return lifecycle_routes(app, auth), identity


def _call(routes, method, path, body=None, token=None):
    import json

    h = {"X-Request-Id": "req-route"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    assert routes.handles(method, path), path
    r = routes.handle(method, path, body=json.dumps(body).encode() if body is not None else b"", headers=h)
    return r.status, r.payload


def test_routes_take_the_org_from_the_session_and_operators_from_a_verified_sign_in(env):
    t = env.t
    routes, identity = _routes(env)
    tok_a = env.portal_token(t.a)
    eid_b = _request(env, t.b)
    assert _call(routes, "GET", f"/v1/erasures/{eid_b}", token=tok_a)[1]["error"] == "not_found"
    s, body = _call(routes, "POST", "/v1/legal-holds", {"scope": "org", "reason": "r", "org_id": str(t.b.org_id)},
                    token=tok_a)
    assert s == 422 and body["error"] == "validation_failed"
    s, body = _call(routes, "POST", "/v1/contacts:erase", {"contact": PHONE, "reason": "asked"}, token=tok_a)
    assert s == 202 and body["status"] == "pending_operator_confirmation"
    # an operator route with a portal session, a forged header, or no second factor is no operator
    assert _call(routes, "POST", f"/v1/orgs/{t.a.org_id}/erasures/{body['erasure_id']}:confirm", {},
                 token=tok_a)[0] == 401
    weak = identity.issue("op-subject-1", "op@example.com", mfa=False)
    assert _call(routes, "POST", f"/v1/orgs/{t.a.org_id}/erasures/{body['erasure_id']}:confirm", {},
                 token=weak)[0] == 401
    op = identity.issue("op-subject-1", "op@example.com")
    s, out = _call(routes, "POST", f"/v1/orgs/{t.b.org_id}/erasures/{body['erasure_id']}:confirm", {}, token=op)
    assert s == 404  # the erasure is A's; naming B finds nothing
    s, out = _call(routes, "POST", f"/v1/orgs/{t.a.org_id}/erasures/{body['erasure_id']}:confirm", {}, token=op)
    assert s == 200 and out["status"] == "completed" and env.key_present(t.b) and not env.key_present(t.a)
    s, out = _call(routes, "POST", f"/v1/orgs/{t.a.org_id}/operator-access", {"reason": "ticket",
                                                          "approved_by_member": str(env.member_id(t.a))}, token=op)
    assert s == 422 and out["error"] == "validation_failed"  # a typed member id approves nothing
    s, ap = _call(routes, "POST", "/v1/operator-access-approvals", {"operator_id": OPERATOR, "reason": "ticket"},
                  token=tok_a)
    assert s == 201
    s, out = _call(routes, "POST", f"/v1/orgs/{t.b.org_id}/operator-access", {"reason": "ticket",
                                                          "approval_id": ap["approval_id"]}, token=op)
    assert s == 404  # A's approval names nothing in B
    s, out = _call(routes, "POST", f"/v1/orgs/{t.a.org_id}/operator-access", {"reason": "ticket",
                                                          "approval_id": ap["approval_id"]}, token=op)
    assert s == 201 and out["operator_id"] == OPERATOR
    s, out = _call(routes, "POST", "/v1/legal-holds", {"scope": "org", "reason": "keep"}, token=tok_a)
    assert s == 201
    s, out = _call(routes, "POST", f"/v1/legal-holds/{out['hold_id']}:release", {"reason": "done"}, token=tok_a)
    assert s == 200 and out["resumed"]["erasures_completed"] == 0
    assert _call(routes, "POST", f"/v1/legal-holds/{uuid.uuid4()}:release", {"reason": "x"}, token=tok_a)[0] == 404
