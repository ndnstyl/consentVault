import pytest

from consentvault.tenancy.admin_routes import ROUTES, Request, Route

TENANT = [r for r in ROUTES if r.kind == "tenant"]
ALL = {"admin", "developer", "compliance_viewer"}


def path_for(r: Route) -> str:
    return (r.pattern.pattern[1:-1].replace("(?P<token>[^/:]+)", "x").replace("(?P<", "").replace(">[^/:]+)", "")
            .replace("source_id", "00000000-0000-0000-0000-000000000001").replace("credential_id", "00000000-0000-0000-0000-000000000002")
            .replace("member_id", "00000000-0000-0000-0000-000000000003").replace("invite_id", "00000000-0000-0000-0000-000000000004")
            .replace("system_id", "00000000-0000-0000-0000-000000000005").replace("sha256", "a" * 64).replace("version", "1"))


@pytest.fixture
def people(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    return {"admin": boss, "developer": vault.add_member(boss, "dev@acme.example", "developer"),
            "compliance_viewer": vault.add_member(boss, "cv@acme.example", "compliance_viewer")}


def test_every_tenant_route_refuses_exactly_the_roles_its_table_does_not_list(people):
    checked = 0
    for r in TENANT:
        path = path_for(r)
        for role, person in people.items():
            resp = person.call(r.method, path, {}, {})
            refused = resp.status == 403 and resp.body.get("error") == "role_not_allowed"
            assert refused == (role not in r.roles), (r.method, path, role, resp.status, resp.body)
            if refused:
                assert resp.body["fields"] == {"role": role}
            checked += 1
    assert checked == len(TENANT) * 3 and len(TENANT) >= 40


def test_every_route_refuses_a_call_with_no_credential(vault):
    for r in ROUTES:
        resp = vault.app.handle(Request(r.method, path_for(r), {}, {}, request_id="r-none"))
        if r.kind == "public":
            assert resp.status == 404  # the invitation read: no such invitation
        else:
            assert resp.status == 401 and resp.body["error"] == "unauthenticated", (r.method, r.pattern.pattern, resp.body)


def test_unknown_paths_and_methods_are_not_found(people):
    boss = people["admin"]
    assert boss.err("GET", "/v1/nope", name="not_found", status=404)
    assert boss.err("DELETE", "/v1/brands", name="not_found")
    assert boss.err("GET", "/v2/brands", name="not_found")


def test_a_retired_route_is_gone(people):
    assert people["admin"].err("DELETE", "/v1/credentials/00000000-0000-0000-0000-000000000002", name="not_found")


def test_errors_carry_the_request_id_and_a_named_error(people):
    r = people["developer"].call("GET", "/v1/members")
    assert set(r.body) == {"error", "detail", "request_id", "fields"} and r.body["request_id"].startswith("req-")


def test_operator_routes_need_an_operator(vault):
    r = vault.app.handle(Request("POST", "/v1/orgs", {}, {"name": "X", "admin_email": "a@x.example"}, request_id="r"))
    assert (r.status, r.body["error"]) == (401, "unauthenticated")


def test_operator_routes_create_suspend_and_issue(vault):
    ok = vault.app.handle(Request("POST", "/v1/orgs", {}, {"name": "Beta", "admin_email": "a@beta.example"}, request_id="r1",
                                  operator_id="op-9"))
    assert ok.status == 201 and ok.body["status"] == "trial"
    oid = ok.body["org_id"]
    st = vault.app.handle(Request("PATCH", f"/v1/orgs/{oid}/status", {}, {"status": "suspended", "reason": "unpaid"},
                                  request_id="r2", operator_id="op-9"))
    assert st.status == 200 and st.body["status"] == "suspended"
    bad = vault.app.handle(Request("PATCH", f"/v1/orgs/{oid}/status", {}, {"status": "closed", "reason": "x"},
                                   request_id="r3", operator_id="op-9"))
    assert bad.status == 422
