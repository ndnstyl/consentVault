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
    assert r.status == 200 and {k: v for k, v in r.body.items() if k != "expires_at"} == {
        "org_id": org["org_id"], "name": "Acme", "role": "admin", "status": "trial"}
    assert r.body["expires_at"].endswith("Z")
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
    want = [(boss, ["admin"]), (dev, ["developer"]), (viewer, ["audit_read", "proof_read", "records_read"])]
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
    forged = boss.token[:-1] + ("0" if boss.token[-1] != "0" else "1")  # always a different token, never by chance the real one
    for bad in (forged, "v1.nope", "",
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


def test_choosing_an_organisation_hands_the_tenant_token_to_the_edge_in_a_header_only(vault):
    from consentvault.tenancy.tokens import TENANT_TOKEN_HEADER
    org, boss = vault.org_with_admin("Acme Edge", "boss@acme-edge.example")
    idt = vault.idp.issue(boss.subject, "boss@acme-edge.example")
    r = call(vault, "POST", "/v1/session/org", idt, {"org_id": org["org_id"]})
    assert r.status == 200 and "token" not in r.body
    token = r.headers[TENANT_TOKEN_HEADER]
    assert token.startswith("v1.") and token not in str(r.body)
    with vault.appconn() as c, org_transaction(c, token):  # the database accepts it, scoped to the chosen org
        assert c.execute("SELECT scopes FROM consentvault.current_token_claims()").fetchone()["scopes"] == ["admin"]
    for refused in (call(vault, "GET", "/v1/session", idt), call(vault, "POST", "/v1/session/org", idt, {"org_id": "x"})):
        assert TENANT_TOKEN_HEADER not in refused.headers


def _edge(vault, mfa_methods=("hwk", "user")):
    """A vault whose sign-in takes its authentication methods from the portal edge's signed assertion."""
    import base64, hashlib, json
    from datetime import datetime, timezone
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from consentvault.providers.identity import EdgeAssertionVerifier
    from consentvault import db, dbclock
    from consentvault.tenancy.session import SessionMinter

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    vault.sessions = SessionMinter(vault.idp, vault.key, assertions=EdgeAssertionVerifier(
        {"e1": pem}, clock=dbclock.datetime_clock(lambda: db.connect(vault.app_dsn))))
    vault.app._sessions = vault.sessions
    b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()  # noqa: E731

    def make(token, subject, amr=mfa_methods, signer=key, **extra):
        now = int(datetime.now(timezone.utc).timestamp())
        payload = {"iss": EdgeAssertionVerifier.ISSUER, "aud": EdgeAssertionVerifier.AUDIENCE, "sub": subject,
                   "tok": hashlib.sha256(token.encode()).hexdigest(), "amr": list(amr), "iat": now, "exp": now + 60, **extra}
        signing = b(json.dumps({"alg": "ES256", "kid": "e1"}).encode()) + "." + b(json.dumps(payload).encode())
        r, s = utils.decode_dss_signature(signer.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
        return signing + "." + b(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return make


def test_with_assertions_on_the_edge_signed_methods_decide_the_second_factor(vault):
    from consentvault.tenancy.admin_routes import Request
    from cryptography.hazmat.primitives.asymmetric import ec
    org, boss = vault.org_with_admin("Edge Co", "boss@edge-co.example")
    make = _edge(vault)
    idt = vault.idp.issue(boss.subject, "boss@edge-co.example", mfa=False)  # the token itself shows no second factor

    def get(assertion):
        return vault.app.handle(Request("GET", "/v1/session", {}, None, identity_token=idt, edge_assertion=assertion, request_id="r-e"))
    assert get(make(idt, boss.subject)).status == 200
    r = get(None)
    assert (r.status, r.body["error"]) == (403, "second_factor_required")
    r = get(make(idt, boss.subject, amr=("pwd",)))  # password only
    assert (r.status, r.body["error"]) == (403, "second_factor_required")
    r = get(make(idt, boss.subject, signer=ec.generate_private_key(ec.SECP256R1())))  # not the edge's key
    assert (r.status, r.body["error"]) == (401, "unauthenticated")
    r = get(make(idt, "someone-else"))
    assert (r.status, r.body["error"]) == (401, "unauthenticated")
    chosen = vault.app.handle(Request("POST", "/v1/session/org", {}, {"org_id": org["org_id"]}, identity_token=idt,
                                      edge_assertion=make(idt, boss.subject), request_id="r-e2"))
    assert chosen.status == 200 and chosen.headers["X-ConsentVault-Tenant-Token"].startswith("v1.")
    assert vault.app.handle(Request("POST", "/v1/session/org", {}, {"org_id": org["org_id"]}, identity_token=idt,
                                    request_id="r-e3")).status == 403


def test_an_invitation_is_accepted_on_the_address_the_edge_asserts_when_the_token_carries_none(vault):
    import dataclasses
    from consentvault.tenancy.admin_routes import Request
    org = vault.create_org("Invite Co", "boss@invite-co.example")
    token = vault.mailer.token_for("boss@invite-co.example")
    make = _edge(vault)
    idt = vault.idp.issue("workos-user-1", "ignored@x.example")
    vault.idp.known[idt] = dataclasses.replace(vault.idp.known[idt], claims={"sub": "workos-user-1"})  # a token with no address

    def accept(assertion):
        return vault.app.handle(Request("POST", f"/v1/invites/{token}:accept", {}, None, identity_token=idt,
                                        edge_assertion=assertion, request_id="r-inv"))
    r = accept(make(idt, "workos-user-1"))
    assert (r.status, r.body["error"]) == (403, "invite_wrong_account"), "no asserted address, no acceptance"
    r = accept(make(idt, "workos-user-1", email="boss@invite-co.example", email_verified=False))
    assert r.body["error"] == "invite_wrong_account"
    r = accept(make(idt, "workos-user-1", email="someone@else.example", email_verified=True))
    assert r.body["error"] == "invite_wrong_account"
    r = accept(make(idt, "workos-user-1", email="Boss@Invite-Co.example", email_verified=True))
    assert r.status == 200 and r.body["org_id"] == org["org_id"] and r.body["role"] == "admin"
    s = vault.app.handle(Request("GET", "/v1/session", {}, None, identity_token=idt, request_id="r-s",
                                 edge_assertion=make(idt, "workos-user-1", email="boss@invite-co.example", email_verified=True)))
    assert s.status == 200 and s.body["user"]["email"] == "boss@invite-co.example" and len(s.body["items"]) == 1


def test_an_edge_key_the_vault_does_not_hold_is_a_deployment_fault_not_a_bad_sign_in(vault):
    import hashlib, json, base64
    from datetime import datetime, timezone
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from consentvault.tenancy.admin_routes import Request
    org, boss = vault.org_with_admin("Key Co", "boss@key-co.example")
    make = _edge(vault)
    idt = vault.idp.issue(boss.subject, "boss@key-co.example")
    other = ec.generate_private_key(ec.SECP256R1())
    b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()  # noqa: E731
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {"iss": "consentvault-portal-edge", "aud": "consentvault-vault", "sub": boss.subject, "amr": ["hwk", "user"],
               "tok": hashlib.sha256(idt.encode()).hexdigest(), "iat": now, "exp": now + 60}
    signing = b(json.dumps({"alg": "ES256", "kid": "rotated-away"}).encode()) + "." + b(json.dumps(payload).encode())
    r_, s_ = utils.decode_dss_signature(other.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
    unknown = signing + "." + b(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))
    r = vault.app.handle(Request("GET", "/v1/session", {}, None, identity_token=idt, edge_assertion=unknown, request_id="r-k"))
    assert (r.status, r.body["error"]) == (500, "misconfigured")
    assert vault.app.handle(Request("GET", "/v1/session", {}, None, identity_token=idt, edge_assertion=make(idt, boss.subject),
                                    request_id="r-k2")).status == 200


def test_the_token_own_address_is_not_used_when_the_assertion_carries_none(vault):
    import dataclasses
    from consentvault.tenancy.admin_routes import Request
    vault.create_org("Own Addr Co", "boss@own-addr.example")
    make = _edge(vault)
    idt = vault.idp.issue("sub-own", "boss@own-addr.example")  # the token itself claims a verified address
    vault.idp.known[idt] = dataclasses.replace(vault.idp.known[idt], claims={"sub": "sub-own", "email": "boss@own-addr.example", "email_verified": True})
    token = vault.mailer.token_for("boss@own-addr.example")
    r = vault.app.handle(Request("POST", f"/v1/invites/{token}:accept", {}, None, identity_token=idt, edge_assertion=make(idt, "sub-own"), request_id="r-o"))
    assert (r.status, r.body["error"]) == (403, "invite_wrong_account"), "only the edge's assertion can name the address"
    s = vault.app.handle(Request("GET", "/v1/session", {}, None, identity_token=idt, edge_assertion=make(idt, "sub-own"), request_id="r-o2"))
    assert s.body["user"]["email"] is None
