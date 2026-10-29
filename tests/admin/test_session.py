import time

import pytest

from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.admin_routes import Request
from consentvault.tenancy.tokens import mint_org_token, org_transaction


def call(vault, method, path, idt, body=None, query=None):
    return vault.app.handle(Request(method, path, query or {}, body, identity_token=idt, request_id="r-sess"))


def test_memberships_lists_every_organisation_sorted_by_name(vault):
    a, boss_a = vault.org_with_admin("Zeta", "same@x.example")
    b = vault.create_org("Alpha", "same@x.example")
    vault.join(b["org_id"], "same@x.example", "admin", invite_token=vault.mailer.token_for("same@x.example"))
    # the same person has two memberships only if the same identity accepted both; use one subject for both
    idt = vault.idp.issue("one-person", "same@x.example", name="Sam")
    with vault.superuser() as su:
        su.execute("UPDATE consentvault.member SET idp_subject = 'one-person', idp_issuer = 'https://idp.example.com'"
                   " WHERE email_norm = 'same@x.example'")
    r = call(vault, "GET", "/v1/session", idt)
    assert r.status == 200 and r.body["user"] == {"display_name": "Sam", "email": "same@x.example"}
    assert [i["name"] for i in r.body["items"]] == ["Alpha", "Zeta"] and r.body["next_cursor"] is None
    page = call(vault, "GET", "/v1/session", idt, query={"limit": "1"})
    assert len(page.body["items"]) == 1 and page.body["next_cursor"]
    nxt = call(vault, "GET", "/v1/session", idt, query={"limit": "1", "cursor": page.body["next_cursor"]})
    assert [i["name"] for i in nxt.body["items"]] == ["Zeta"]


def test_no_organisation_is_an_empty_list_not_an_error(vault):
    idt = vault.idp.issue("nobody", "nobody@x.example")
    r = call(vault, "GET", "/v1/session", idt)
    assert r.status == 200 and r.body["items"] == []


def test_no_token_bad_token_and_no_second_factor(vault):
    assert call(vault, "GET", "/v1/session", None).body["error"] == "unauthenticated"
    assert call(vault, "GET", "/v1/session", "garbage").body["error"] == "unauthenticated"
    weak = vault.idp.issue("weak", "w@x.example", mfa=False)
    r = call(vault, "GET", "/v1/session", weak)
    assert (r.status, r.body["error"]) == (403, "second_factor_required")
    assert call(vault, "POST", "/v1/session/org", weak, {"org_id": "x"}).body["error"] == "second_factor_required"


def test_choosing_an_organisation_mints_a_scoped_short_token_and_audits_it(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    idt = vault.idp.issue(boss.subject, "boss@acme.example")
    r = call(vault, "POST", "/v1/session/org", idt, {"org_id": org["org_id"]})
    assert r.status == 200 and r.body == {"org_id": org["org_id"], "name": "Acme", "role": "admin", "status": "trial"}
    assert "token" not in r.body  # the token goes to the edge, never to the browser
    with vault.appconn() as c:
        s = vault.sessions.choose_org(c, idt, org["org_id"], request_id="r1")
    assert s.expires_in == 300
    with vault.appconn() as c, org_transaction(c, s.token):
        claims = c.execute("SELECT scopes, credential_id FROM consentvault.current_token_claims()").fetchone()
        assert claims["scopes"] == ["admin"] and claims["credential_id"] == "member:" + s.member_id
    rows = boss.ok("GET", "/v1/audit", {"action": "session.opened"})["items"]
    assert len(rows) >= 2 and rows[0]["actor"]["display_name"]


def test_each_role_gets_exactly_its_scopes(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    want = [(boss, ["admin"]), (dev, ["developer"]), (viewer, ["audit_read", "proof_read"])]
    for person, scopes in want:
        with vault.appconn() as c, org_transaction(c, person.token):
            assert sorted(c.execute("SELECT scopes FROM consentvault.current_token_claims()").fetchone()["scopes"]) == scopes


def test_there_is_no_auto_join_by_domain_or_by_anything_else(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    stranger = vault.idp.issue("stranger", "stranger@acme.example")  # same company domain, no invitation
    r = call(vault, "POST", "/v1/session/org", stranger, {"org_id": org["org_id"]})
    assert (r.status, r.body["error"]) == (403, "not_a_member")
    assert call(vault, "GET", "/v1/session", stranger).body["items"] == []
    # an organisation that does not exist answers the same way, so existence is not leaked
    import uuid
    r2 = call(vault, "POST", "/v1/session/org", stranger, {"org_id": str(uuid.uuid4())})
    assert (r2.status, r2.body["error"]) == (403, "not_a_member")
    assert call(vault, "POST", "/v1/session/org", stranger, {"org_id": "not-a-uuid"}).body["error"] == "not_a_member"


def test_a_closed_organisation_cannot_be_entered(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    with vault.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = 'closed' WHERE org_id = %s", (org["org_id"],))
    idt = vault.idp.issue(boss.subject, "boss@acme.example")
    r = call(vault, "POST", "/v1/session/org", idt, {"org_id": org["org_id"]})
    assert (r.status, r.body["error"]) == (403, "org_not_active")


def test_a_tenant_token_for_another_org_or_expired_or_forged_is_unauthenticated(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    for bad in (boss.token[:-2] + "00", "v1.nope", "",
                mint_org_token(vault.key, org["org_id"], ["admin"], credential_id="member:" + boss.member_id,
                               now=time.time() - 4000)):
        r = vault.app.handle(Request("GET", "/v1/org", tenant_token=bad or None, request_id="r"))
        assert (r.status, r.body["error"]) == (401, "unauthenticated")


def test_a_machine_credential_token_is_not_a_portal_session(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    machine = mint_org_token(vault.key, org["org_id"], ["admin"], credential_id="11111111-1111-1111-1111-111111111111")
    r = vault.app.handle(Request("GET", "/v1/org", tenant_token=machine, request_id="r"))
    assert (r.status, r.body["error"]) == (401, "unauthenticated")
    no_cid = mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)
    assert vault.app.handle(Request("GET", "/v1/org", tenant_token=no_cid, request_id="r")).status == 401


def test_removal_and_role_change_take_effect_on_the_next_request(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    assert dev.call("GET", "/v1/org").status == 200
    boss.ok("PATCH", f"/v1/members/{dev.member_id}", body={"role": "compliance_viewer"})
    # the old token carries the developer scope; the database now says viewer, so the session must be re-minted
    dev.err("GET", "/v1/org", name="unauthenticated")
    again = vault.sign_in(org["org_id"], dev.subject, dev.email)
    assert again.role == "compliance_viewer" and again.call("GET", "/v1/org").status == 200
    boss.ok("DELETE", f"/v1/members/{dev.member_id}")
    again.err("GET", "/v1/org", name="unauthenticated")
    with vault.appconn() as c, pytest.raises(ApiError) as e:
        vault.sessions.choose_org(c, vault.idp.issue(dev.subject, dev.email), org["org_id"], request_id="r")
    assert e.value.name == "not_a_member"
