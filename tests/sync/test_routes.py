"""The five routes, called the way the API lane calls them (framework-free, contracts' error shape)."""

import json
import uuid

import pytest

from consentvault import db
from consentvault.sync.routes import Request, SyncRoutes
from consentvault.tenancy.tokens import org_transaction

from .support import PHONES

P1, P2, P3 = PHONES[0], PHONES[1], PHONES[2]


@pytest.fixture
def routes(env):
    return SyncRoutes(lambda: db.connect(env.t.app_dsn), env.t.crypto)


def call(env, routes, org, method, path, *, scopes, body=None, query=None, credential=True, role=None, rid="req-1"):
    return routes.handle(Request(method=method, path=path, org_id=org.org_id, scopes=frozenset(scopes),
                                 token=env.t.token(org, scopes=scopes), body=body, query=query or {}, request_id=rid,
                                 credential_id=str(org.credential_id) if credential else None, role=role, actor="admin-1"))


def sig(contact, state, ref=None, **kw):
    return {"contact": contact, "channel": "sms", "purpose": "marketing", "claimed_state": state,
            "external_ref": ref or str(uuid.uuid4()), **kw}


# POST /v1/signals --------------------------------------------------------------------------------------------------------

def test_signals_answer_202_with_the_resolution_and_the_event(env, routes):
    a = env.t.a
    env.add_system(a, "crm", signal=True)
    r = call(env, routes, a, "POST", "/v1/signals", scopes=["capture"], body=sig(P1, "denied"))
    assert r.status == 202 and set(r.body) == {"signal_id", "resolution", "event_id"} and r.body["resolution"] == "applied_as_event"
    again = call(env, routes, a, "POST", "/v1/signals", scopes=["capture"], body=sig(P1, "denied", ref="fixed"))
    again2 = call(env, routes, a, "POST", "/v1/signals", scopes=["capture"], body=sig(P1, "denied", ref="fixed"))
    assert again.body["resolution"] == "no_change" and "event_id" not in again.body and again2.body == again.body


def test_signals_are_refused_without_the_capture_scope(env, routes):
    a = env.t.a
    env.add_system(a, "crm", signal=True)
    for scopes in (["proof_read"], ["gate_read"], ["admin"], ["developer"]):
        r = call(env, routes, a, "POST", "/v1/signals", scopes=scopes, body=sig(P1, "denied"), role="x")
        assert r.status == 403 and r.body["error"] == "role_not_allowed" and r.body["request_id"] == "req-1"
    assert env.outbox(a) == [] and env.q("SELECT 1 FROM consentvault.inbound_signal") == []


def test_a_credential_bound_to_no_system_cannot_send_signals(env, routes):
    a = env.t.a
    env.add_system(a, "crm", signal=False)
    r = call(env, routes, a, "POST", "/v1/signals", scopes=["capture"], body=sig(P1, "denied"))
    assert r.status == 403 and r.body["error"] == "role_not_allowed" and "not bound to a connected system" in r.body["detail"]
    none = call(env, routes, a, "POST", "/v1/signals", scopes=["capture"], body=sig(P1, "denied"), credential=False)
    assert none.status == 403


def test_a_credential_of_another_organisation_finds_no_system(env, routes):
    a, b = env.t.a, env.t.b
    env.add_system(a, "crm", signal=True)
    r = routes.handle(Request(method="POST", path="/v1/signals", org_id=b.org_id, scopes=frozenset({"capture"}),
                              token=env.t.token(b, scopes=("capture",)), body=sig(P1, "denied"), request_id="r",
                              credential_id=str(a.credential_id)))
    assert r.status == 403 and env.outbox(a) == [] and env.outbox(b) == []


def test_signals_validate_their_body_and_the_contact(env, routes):
    a = env.t.a
    env.add_system(a, "crm", signal=True)
    bad = call(env, routes, a, "POST", "/v1/signals", scopes=["capture"], body={"contact": P1})
    assert bad.status == 422 and bad.body["error"] == "validation_failed" and "external_ref" in bad.body["fields"]
    contact = call(env, routes, a, "POST", "/v1/signals", scopes=["capture"], body=sig("nope", "denied"))
    assert contact.status == 422 and contact.body["error"] == "invalid_contact"


def test_a_tenant_token_the_database_refuses_is_unauthenticated(env, routes):
    a = env.t.a
    r = routes.handle(Request(method="POST", path="/v1/signals", org_id=a.org_id, scopes=frozenset({"capture"}),
                              token="v1.nokey.00.00", body=sig(P1, "denied"), request_id="r", credential_id=str(a.credential_id)))
    assert r.status == 401 and r.body["error"] == "unauthenticated"


# POST /v1/deliveries:query --------------------------------------------------------------------------------------------------

def _two_pushes(env, a):
    s = env.add_system(a, "crm")
    env.grant(a, P1)
    env.run_worker()
    env.stop(a, P1)
    env.transport.script(s.endpoint, 503)
    env.run_worker()
    return s


def test_the_delivery_query_lists_receipts_for_one_contact_without_naming_it(env, routes):
    a = env.t.a
    s = _two_pushes(env, a)
    env.grant(a, P2)
    env.run_worker()
    r = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["proof_read"],
             body={"contact": P1, "system_id": str(s.system_id)})
    assert r.status == 200 and r.body["next_cursor"] is None
    items = r.body["items"]
    assert [(i["version"], i["status"]) for i in items] == [(2, "failed"), (1, "acknowledged")]  # newest first
    assert set(items[0]) == {"outbox_id", "created_at", "channel", "purpose", "version", "status", "attempts",
                             "last_http_status", "last_error_class"}
    assert items[0]["last_http_status"] == 503 and items[0]["last_error_class"] == "http_5xx"
    assert items[0]["created_at"].endswith("Z")
    assert P1 not in json.dumps(r.body) and env.fp(a, P1) not in json.dumps(r.body)
    other = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["admin"], body={"contact": P3, "system_id": str(s.system_id)})
    assert other.status == 200 and other.body == {"items": [], "next_cursor": None}


def test_the_delivery_query_is_never_open_to_a_developer(env, routes):
    a = env.t.a
    s = _two_pushes(env, a)
    r = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["developer"], body={"contact": P1, "system_id": str(s.system_id)}, role="developer")
    assert r.status == 403 and r.body["error"] == "role_not_allowed" and r.body["fields"] == {"role": "developer"}


def test_the_delivery_query_pages_and_refuses_a_foreign_cursor(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.grant(a, P1)
    env.run_worker()
    env.stop(a, P1)
    env.run_worker()
    body = {"contact": P1, "system_id": str(s.system_id), "limit": 1}
    first = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["admin"], body=body)
    assert len(first.body["items"]) == 1 and first.body["next_cursor"]
    second = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["admin"], body={**body, "cursor": first.body["next_cursor"]})
    assert second.status == 200 and second.body["next_cursor"] is None and len(second.body["items"]) == 1
    got = [i["version"] for i in first.body["items"] + second.body["items"]]
    assert got == sorted(got, reverse=True) and len(set(got)) == len(got)
    bad = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["admin"], body={**body, "cursor": "garbage"})
    assert bad.status == 400 and bad.body["error"] == "invalid_cursor" and bad.body["request_id"] == "req-1"
    sys_cursor = call(env, routes, a, "GET", f"/v1/systems/{s.system_id}/deliveries", scopes=["admin"], query={"limit": "1"})
    foreign = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["admin"], body={**body, "cursor": sys_cursor.body["next_cursor"]})
    assert foreign.status == 400 and foreign.body["error"] == "invalid_cursor"


def test_the_delivery_query_errors(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    sid = str(s.system_id)
    cases = [({"contact": P1}, 422, "validation_failed"), ({"contact": P1, "system_id": "nope"}, 422, "validation_failed"),
             ({"contact": "x", "system_id": sid}, 422, "invalid_contact"),
             ({"contact": P1, "system_id": str(uuid.uuid4())}, 404, "not_found"),
             ({"contact": P1, "system_id": sid, "limit": 500}, 422, "validation_failed"),
             ({"contact": P1, "system_id": sid, "extra": 1}, 422, "validation_failed")]
    for body, status, name in cases:
        r = call(env, routes, a, "POST", "/v1/deliveries:query", scopes=["admin"], body=body)
        assert (r.status, r.body["error"]) == (status, name), body


# GET /v1/systems/{id}/deliveries ------------------------------------------------------------------------------------------

def test_the_system_delivery_list_shows_fingerprint_hints_and_filters(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400)
    env.grant(a, P1)
    env.grant(a, P2)
    env.run_worker()
    path = f"/v1/systems/{s.system_id}/deliveries"
    allrows = call(env, routes, a, "GET", path, scopes=["developer"])
    assert allrows.status == 200 and len(allrows.body["items"]) == 2
    item = allrows.body["items"][0]
    assert set(item) == {"outbox_id", "created_at", "contact_fp_hint", "channel", "purpose", "version", "status", "attempts",
                         "last_attempt_at", "last_http_status", "last_error_class"}
    assert len(item["contact_fp_hint"]) == 8 and env.fp(a, P1).startswith(item["contact_fp_hint"]) or env.fp(a, P2).startswith(item["contact_fp_hint"])
    assert P1 not in json.dumps(allrows.body)
    dead = call(env, routes, a, "GET", path, scopes=["admin"], query={"status": "dead"})
    ack = call(env, routes, a, "GET", path, scopes=["proof_read"], query={"status": "acknowledged"})
    assert [i["status"] for i in dead.body["items"]] == ["dead"] and [i["status"] for i in ack.body["items"]] == ["acknowledged"]
    assert dead.body["items"][0]["last_error_class"] == "http_4xx"
    assert call(env, routes, a, "GET", path, scopes=["admin"], query={"status": "pending"}).body["items"] == []
    ranged = call(env, routes, a, "GET", path, scopes=["admin"], query={"from": "2099-01-01T00:00:00Z"})
    assert ranged.body["items"] == []


def test_the_system_delivery_list_errors_and_scope(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    path = f"/v1/systems/{s.system_id}/deliveries"
    assert call(env, routes, a, "GET", path, scopes=["capture"]).status == 403
    assert call(env, routes, a, "GET", path, scopes=["admin"], query={"status": "weird"}).body["error"] == "validation_failed"
    assert call(env, routes, a, "GET", path, scopes=["admin"], query={"from": "tomorrow"}).status == 422
    assert call(env, routes, a, "GET", path, scopes=["admin"], query={"limit": "0"}).status == 422
    assert call(env, routes, a, "GET", f"/v1/systems/{uuid.uuid4()}/deliveries", scopes=["admin"]).body["error"] == "not_found"
    assert call(env, routes, a, "GET", "/v1/systems/not-a-uuid/deliveries", scopes=["admin"]).status == 404


# redrive ----------------------------------------------------------------------------------------------------------------------

def test_redrive_over_the_routes(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400, 400)
    env.grant(a, P1)
    env.grant(a, P2)
    env.run_worker()
    body = {"system_id": str(s.system_id), "reason": "receiver fixed"}
    r = call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["developer"], body=body)
    assert r.status == 202 and r.body["requeued"] == 2
    busy = call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["admin"], body=body)
    assert busy.status == 409 and busy.body["error"] == "redrive_in_progress"
    st = call(env, routes, a, "GET", f"/v1/redrives/{r.body['redrive_id']}", scopes=["developer"])
    assert st.status == 200 and (st.body["status"], st.body["requeued"], st.body["remaining"]) == ("running", 2, 2)
    env.run_worker()
    done = call(env, routes, a, "GET", f"/v1/redrives/{r.body['redrive_id']}", scopes=["admin"])
    assert (done.body["status"], done.body["acknowledged"], done.body["dead_again"], done.body["remaining"]) == ("done", 2, 0, 0)
    assert set(done.body) == {"redrive_id", "system_id", "status", "requeued", "acknowledged", "dead_again", "remaining",
                              "started_at", "finished_at"} and done.body["finished_at"].endswith("Z")
    empty = call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["admin"], body=body)
    assert empty.status == 202 and empty.body["requeued"] == 0


def test_redrive_errors_and_scope(env, routes):
    a = env.t.a
    s = env.add_system(a, "crm")
    sid = str(s.system_id)
    assert call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["proof_read"], body={"system_id": sid, "reason": "x"}).status == 403
    assert call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["admin"], body={"system_id": sid}).status == 422
    assert call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["admin"], body={"system_id": sid, "reason": ""}).status == 422
    assert call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["admin"], body={"system_id": "x", "reason": "r"}).status == 422
    nf = call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["admin"], body={"system_id": str(uuid.uuid4()), "reason": "r"})
    assert (nf.status, nf.body["error"]) == (404, "not_found")
    assert call(env, routes, a, "GET", f"/v1/redrives/{uuid.uuid4()}", scopes=["admin"]).body["error"] == "not_found"
    assert call(env, routes, a, "GET", "/v1/redrives/zzz", scopes=["admin"]).status == 404
    assert call(env, routes, a, "GET", f"/v1/redrives/{uuid.uuid4()}", scopes=["proof_read"]).status == 403


@pytest.mark.parametrize("status,error", [("suspended", "org_suspended"), ("offboarding", "org_not_active"), ("closed", "org_not_active")])
def test_redrive_refuses_an_organisation_that_is_not_active(env, routes, status, error):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.q("UPDATE consentvault.organization SET status = %s WHERE org_id = %s", (status, a.org_id))
    r = call(env, routes, a, "POST", "/v1/deliveries:redrive", scopes=["admin"], body={"system_id": str(s.system_id), "reason": "r"})
    assert (r.status, r.body["error"]) == (403, error)


def test_the_route_table_matches_exactly_what_it_serves(routes):
    assert routes.matches("POST", "/v1/signals") and routes.matches("POST", "/v1/deliveries:query")
    assert routes.matches("GET", f"/v1/systems/{uuid.uuid4()}/deliveries") and routes.matches("GET", f"/v1/redrives/{uuid.uuid4()}")
    assert routes.matches("POST", "/v1/deliveries:redrive")
    assert not routes.matches("GET", "/v1/signals") and not routes.matches("POST", "/v1/systems") and not routes.matches("DELETE", "/v1/signals")
    assert not routes.matches("GET", "/v1/systems/x/deliveries/extra")


def test_an_unknown_route_is_a_named_404(env, routes):
    r = call(env, routes, env.t.a, "GET", "/v1/nothing", scopes=["admin"])
    assert (r.status, r.body["error"]) == (404, "not_found")
