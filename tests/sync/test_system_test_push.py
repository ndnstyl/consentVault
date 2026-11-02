"""POST /v1/systems/{id}:test (systems.md): one signed push marked test, no contact point, the answer reported and recorded."""

import json

import pytest

from consentvault import db
from consentvault.sync.connectors import webhook
from consentvault.sync.routes import Request, SyncRoutes

from .test_routes import call


@pytest.fixture
def routes(env):
    return SyncRoutes(lambda: db.connect(env.t.app_dsn), env.t.crypto, custody=env.custody, transport=env.transport)


def push(env, routes, org, system, *, scopes=("admin",), role="admin", rid="req-t"):
    return call(env, routes, org, "POST", f"/v1/systems/{system.system_id}:test", scopes=list(scopes), role=role, rid=rid)


def test_a_test_push_is_signed_marked_test_carries_no_contact_and_reports_the_answer(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    r = push(env, routes, a, s)
    assert r.status == 200 and r.body["result"] == "accepted" and r.body["http_status"] == 200
    assert isinstance(r.body["latency_ms"], int) and r.body["at"].endswith("Z")
    sent = env.transport.to(s.endpoint)
    assert len(sent) == 1
    body = json.loads(sent[0].body)
    assert body["test"] is True and set(body) == {"org_id", "test", "at"}
    assert webhook.verify_signature("hmac", s.verify_key, sent[0].body, sent[0].headers[webhook.HEADER_SIGNATURE])


@pytest.mark.parametrize("script,result,status", [(500, "server_error", 500), (404, "rejected", 404),
                                                   (webhook.TransportResult("timeout"), "timeout", None),
                                                   (webhook.TransportResult("unreachable"), "unreachable", None)])
def test_a_bad_answer_is_the_answer_not_an_error(env, routes, script, result, status):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, script)
    r = push(env, routes, a, s)
    assert r.status == 200 and r.body["result"] == result and r.body["http_status"] == status


def test_the_answer_is_recorded_on_the_system(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 503)
    push(env, routes, a, s)
    row = env.q("SELECT last_test FROM consentvault.connected_system WHERE system_id = %s", (s.system_id,))[0]
    assert row["last_test"]["result"] == "server_error" and row["last_test"]["http_status"] == 503


def test_roles_and_other_organizations(env, routes):
    a, b = env.t.a, env.t.b
    s = env.add_system(a, "crm")
    assert push(env, routes, a, s, scopes=("developer",), role="developer").status == 200
    r = push(env, routes, a, s, scopes=("proof_read",), role="compliance_viewer")
    assert (r.status, r.body["error"]) == (403, "role_not_allowed")
    r = push(env, routes, b, s)  # another organization's system id
    assert (r.status, r.body["error"]) == (404, "not_found")
    assert len(env.transport.to(s.endpoint)) == 1


def test_six_a_minute_per_system_then_rate_limited(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    other = env.add_system(a, "dialer")
    assert [push(env, routes, a, s).status for _ in range(6)] == [200] * 6
    r = push(env, routes, a, s)
    assert (r.status, r.body["error"]) == (429, "rate_limited")
    assert push(env, routes, a, other).status == 200, "the limit is per system"


def test_a_paused_or_unknown_system_is_not_found(env, routes):
    a = env.t.a
    r = call(env, routes, a, "POST", "/v1/systems/00000000-0000-4000-8000-000000000000:test", scopes=["admin"], role="admin")
    assert (r.status, r.body["error"]) == (404, "not_found")
    r = call(env, routes, a, "POST", "/v1/systems/not-a-uuid:test", scopes=["admin"], role="admin")
    assert (r.status, r.body["error"]) == (404, "not_found")


def test_the_limit_is_counted_in_the_database_so_a_second_server_process_shares_it(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    assert [push(env, routes, a, s).status for _ in range(6)] == [200] * 6
    fresh = SyncRoutes(lambda: db.connect(env.t.app_dsn), env.t.crypto, custody=env.custody, transport=env.transport)
    r = push(env, fresh, a, s)
    assert (r.status, r.body["error"]) == (429, "rate_limited"), "a new process knows the six already made"


def test_the_outbound_call_is_made_with_no_database_transaction_open(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    seen = []

    class Watching:
        def send(self, request):
            seen.append(env.q("SELECT count(*) AS n FROM pg_stat_activity WHERE datname = %s AND state LIKE 'idle in transaction%%'",
                              (env.dbname,))[0]["n"])
            return webhook.TransportResult("response", 200)
    routes = SyncRoutes(lambda: db.connect(env.t.app_dsn), env.t.crypto, custody=env.custody, transport=Watching())
    assert push(env, routes, a, s).status == 200
    assert seen == [0], "a slow receiver must never hold a connection open"


def test_the_runtime_role_cannot_write_the_answer_column_directly(env):
    import psycopg
    from consentvault.tenancy.tokens import org_transaction
    a = env.t.a
    s = env.add_system(a, "crm")
    with env.t.app() as c, org_transaction(c, env.t.token(a, scopes=["admin"])):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE consentvault.connected_system SET last_test = '{}'::jsonb WHERE system_id = %s", (s.system_id,))


def test_the_record_step_uses_a_fresh_token_so_a_slow_receiver_cannot_lose_the_answer(env):
    import time
    from consentvault.tenancy.tokens import mint_org_token
    a = env.t.a
    s = env.add_system(a, "crm")
    minted = []

    # The request token is minted at a controlled instant (now=), so its expiry is known exactly: issued + ttl. The receiver
    # answers only once that instant has passed, so the record step can only succeed on a fresh token. (A one-second token used
    # to expire before the send under the full suite, when the first step outlasted it, and the run answered 401.)
    ttl = 3  # arbitrary test config, not a product timeout: room for the steps before the send
    issued = int(time.time())
    request_token = env.t.token(a, scopes=["admin"], ttl_seconds=ttl, now=issued)
    expires_at = issued + ttl  # exactly the token's exp

    class Slow:
        def send(self, request):
            while time.time() <= expires_at:  # bounded: expires_at is at most ttl seconds away
                time.sleep(min(0.05, max(0.0, expires_at - time.time()) + 0.01))
            return webhook.TransportResult("response", 200)

    def mint(org_id, scopes):
        minted.append((str(org_id), sorted(scopes)))
        return mint_org_token(env.t.key, org_id, scopes, credential_id=None)
    routes = SyncRoutes(lambda: db.connect(env.t.app_dsn), env.t.crypto, custody=env.custody, transport=Slow(), mint_token=mint)
    r = routes.handle(Request(method="POST", path=f"/v1/systems/{s.system_id}:test", org_id=a.org_id, scopes=frozenset(["admin"]),
                              token=request_token, body=None, query={}, request_id="r",
                              credential_id=None, role="admin", actor="x"))
    assert r.status == 200 and r.body["result"] == "accepted"
    assert minted == [(str(a.org_id), ["admin"])]
    assert env.q("SELECT last_test FROM consentvault.connected_system WHERE system_id = %s", (s.system_id,))[0]["last_test"]["result"] == "accepted"
