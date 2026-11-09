import uuid

import pytest

from consentvault.tenancy.admin_routes import Request


def accept(vault, token, idt):
    return vault.app.handle(Request("POST", f"/v1/invites/{token}:accept", identity_token=idt, request_id="r-acc"))


def read(vault, token):
    return vault.app.handle(Request("GET", f"/v1/invites/{token}", request_id="r-read"))


@pytest.fixture
def org(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    return org, boss


def test_the_public_read_names_the_org_masks_the_address_and_hides_the_org_id(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "compliance_viewer"})
    r = read(vault, vault.mailer.token_for("ana@acme.example"))
    assert r.status == 200
    assert r.body["org_name"] == "Acme" and r.body["role"] == "compliance_viewer"
    assert r.body["invited_email_hint"] == "a***@acme.example" and r.body["invited_by_name"]
    assert "org_id" not in r.body and o["org_id"] not in str(r.body) and "ana@acme.example" not in str(r.body)


def test_unknown_token_is_invite_not_found(vault, org):
    for t in ("short", "x" * 43, str(uuid.uuid4())):
        r = read(vault, t)
        assert (r.status, r.body["error"]) == (404, "invite_not_found")


def test_single_use(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    tok = vault.mailer.token_for("ana@acme.example")
    first = accept(vault, tok, vault.idp.issue("ana-1", "ana@acme.example"))
    assert first.status == 200 and first.body == {"org_id": o["org_id"], "name": "Acme", "role": "developer", "status": "trial"}
    again = accept(vault, tok, vault.idp.issue("ana-2", "ana@acme.example"))
    assert (again.status, again.body["error"]) == (410, "invite_used")
    assert read(vault, tok).body["error"] == "invite_used"


def test_must_be_accepted_from_the_invited_address(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    tok = vault.mailer.token_for("ana@acme.example")
    r = accept(vault, tok, vault.idp.issue("eve-1", "eve@elsewhere.example"))
    assert (r.status, r.body["error"]) == (403, "invite_wrong_account")
    assert "ana@acme.example" not in r.body["detail"] and "a***@acme.example" in r.body["detail"]
    # case and spacing do not matter, the address does
    ok = accept(vault, tok, vault.idp.issue("ana-1", "  ANA@Acme.Example "))
    assert ok.status == 200


def test_an_unverified_address_is_never_enough(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    r = accept(vault, vault.mailer.token_for("ana@acme.example"),
               vault.idp.issue("ana-1", "ana@acme.example", verified=False))
    assert (r.status, r.body["error"]) == (403, "invite_wrong_account")
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.member WHERE email_norm = 'ana@acme.example'").fetchone()["n"] == 0


def test_a_sign_in_without_a_second_factor_is_refused(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    r = accept(vault, vault.mailer.token_for("ana@acme.example"), vault.idp.issue("ana-1", "ana@acme.example", mfa=False))
    assert (r.status, r.body["error"]) == (403, "second_factor_required")
    r = accept(vault, vault.mailer.token_for("ana@acme.example"), "not-a-token")
    assert (r.status, r.body["error"]) == (401, "unauthenticated")


def test_withdrawn_and_expired(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    boss.ok("POST", "/v1/members", body={"email": "bob@acme.example", "role": "developer"})
    ids = {i["email"]: i["id"] for i in boss.ok("GET", "/v1/members", {"include": "invites"})["items"]}
    assert boss.call("DELETE", f"/v1/invites/{ids['ana@acme.example']}").status == 204
    assert boss.call("DELETE", f"/v1/invites/{ids['ana@acme.example']}").status == 204  # withdrawing twice is a no-op
    tok = vault.mailer.token_for("ana@acme.example")
    assert read(vault, tok).body["error"] == "invite_withdrawn"
    assert accept(vault, tok, vault.idp.issue("ana-1", "ana@acme.example")).body["error"] == "invite_withdrawn"
    # expire bob's invitation out of band (a superuser may disable the guard; the vault itself never can)
    with vault.superuser() as su:
        su.execute("ALTER TABLE consentvault.invite DISABLE TRIGGER invite_guard")
        su.execute("ALTER TABLE consentvault.invite DROP CONSTRAINT invite_life")
        su.execute("UPDATE consentvault.invite SET expires_at = now() - interval '1 minute', created_at = now() - interval '8 days'"
                   " WHERE email_norm = 'bob@acme.example'")
    tok = vault.mailer.token_for("bob@acme.example")
    assert (read(vault, tok).status, read(vault, tok).body["error"]) == (410, "invite_expired")
    assert accept(vault, tok, vault.idp.issue("bob-1", "bob@acme.example")).body["error"] == "invite_expired"
    # an expired invitation no longer holds the address: a new one can be sent
    boss.ok("POST", "/v1/members", body={"email": "bob@acme.example", "role": "developer"})


def test_an_accepted_invitation_cannot_be_withdrawn(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    iid = boss.ok("GET", "/v1/members", {"include": "invites"})["items"][0]["id"]
    vault.join(o["org_id"], "ana@acme.example", "developer", invite_token=vault.mailer.token_for("ana@acme.example"))
    boss.err("DELETE", f"/v1/invites/{iid}", name="invite_used")
    boss.err("DELETE", f"/v1/invites/{uuid.uuid4()}", name="not_found")


def test_inviting_a_member_or_an_open_invite_is_already_member(vault, org):
    o, boss = org
    boss.err("POST", "/v1/members", body={"email": "boss@acme.example", "role": "admin"}, name="already_member")
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "admin"})
    boss.err("POST", "/v1/members", body={"email": "ANA@acme.example", "role": "developer"}, name="already_member")


def test_a_failed_send_creates_no_invitation(vault, org):
    o, boss = org
    vault.mailer.fail = True
    boss.err("POST", "/v1/members", body={"email": "ana@acme.example", "role": "admin"}, name="email_send_failed", status=502)
    vault.mailer.fail = False
    assert [i for i in boss.ok("GET", "/v1/members", {"include": "invites"})["items"] if i["kind"] == "invite"] == []
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "admin"})  # the address was not held


def test_invitation_input_is_validated(vault, org):
    o, boss = org
    boss.err("POST", "/v1/members", body={"email": "nope", "role": "admin"}, name="validation_failed", status=422)
    boss.err("POST", "/v1/members", body={"email": "a@b.example", "role": "owner"}, name="validation_failed")
    boss.err("POST", "/v1/members", body=[1], name="invalid_request")


def test_the_invite_cannot_outlive_seven_days_or_be_forged_by_the_app(vault, org):
    import psycopg
    o, boss = org
    from consentvault.tenancy.tokens import mint_org_token, org_transaction
    tok = mint_org_token(vault.key, o["org_id"], ["admin"], credential_id=None)
    with vault.appconn() as c, pytest.raises(psycopg.errors.CheckViolation):
        with org_transaction(c, tok):
            c.execute("INSERT INTO consentvault.invite (org_id, token_digest, email_norm, role, expires_at)"
                      " VALUES (%s, %s, 'x@y.example', 'admin', now() + interval '30 days')", (o["org_id"], "a" * 64))
    with vault.appconn() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        with org_transaction(c, tok):  # the digest is never readable by the runtime role
            c.execute("SELECT token_digest FROM consentvault.invite")


def test_two_simultaneous_accepts_of_one_link_make_one_member(vault):
    import threading
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    tok = vault.mailer.token_for("ana@acme.example")
    ids = [vault.idp.issue(f"ana-{i}", "ana@acme.example") for i in range(2)]
    gate, out = threading.Barrier(2), []

    def go(idt):
        gate.wait()
        out.append(accept(vault, tok, idt))

    ts = [threading.Thread(target=go, args=(i,)) for i in ids]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(r.status for r in out) == [200, 410] and {r.body.get("error") for r in out} == {None, "invite_used"}
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.member WHERE email_norm = 'ana@acme.example'").fetchone()["n"] == 1


def test_with_no_mailer_the_operator_gets_the_link_token_once(vault):
    from consentvault.tenancy import admin
    with vault.operator() as c:
        out = admin.create_org(c, token_key=vault.key, custody=vault.custody, operator_id="op-1", request_id="r",
                               name="Manual", admin_email="m@manual.example")
    assert len(out["invite_token"]) >= 40 and "invite_token" not in str(vault.mailer.sent)
    person = vault.join(out["org_id"], "m@manual.example", "admin", invite_token=out["invite_token"])
    assert person.ok("GET", "/v1/org")["name"] == "Manual"


def test_accept_itself_refuses_an_identity_with_no_second_factor(vault, org):
    """The check inside invite.accept, called directly: it must hold even if a caller forgets to demand a second factor."""
    from datetime import datetime, timedelta, timezone
    from consentvault.providers.identity import Identity
    from consentvault.tenancy import invite
    from consentvault.tenancy.admin_base import ApiError
    token = vault.mailer.token_for("boss@acme.example")
    weak = Identity("https://idp.example.com", "weak-sub", ("pwd",), False, datetime.now(timezone.utc) + timedelta(hours=1),
                    {"email": "boss@acme.example", "email_verified": True})
    with vault.appconn() as c:
        with pytest.raises(ApiError) as exc:
            invite.accept(c, vault.key, token=token, identity=weak, request_id="r-weak")
    assert exc.value.name == "second_factor_required"


# ---- sign-in joins the person to the organisations that invited their verified address ----

def session(vault, idt):
    return vault.app.handle(Request("GET", "/v1/session", identity_token=idt, request_id="r-sess"))


def _count(vault, sql, *a):
    with vault.superuser() as su:
        return su.execute(sql, a).fetchone()["n"]


def test_sign_in_with_a_pending_invitation_joins_without_the_link(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "admin"})
    audits = "SELECT count(*) AS n FROM consentvault.audit_event WHERE action = 'invite.accepted'"
    before = _count(vault, audits)
    r = session(vault, vault.idp.issue("ana-1", "ana@acme.example"))
    assert r.status == 200 and [(i["org_id"], i["name"], i["role"]) for i in r.body["items"]] == [(o["org_id"], "Acme", "admin")]
    assert _count(vault, "SELECT count(*) AS n FROM consentvault.invite WHERE accepted_at IS NOT NULL AND email_norm = 'ana@acme.example'") == 1
    assert _count(vault, "SELECT count(*) AS n FROM consentvault.member WHERE email_norm = 'ana@acme.example'") == 1
    assert _count(vault, audits) == before + 1
    again = session(vault, vault.idp.issue("ana-1", "ana@acme.example"))
    assert len(again.body["items"]) == 1
    assert _count(vault, audits) == before + 1
    chosen = vault.app.handle(Request("POST", "/v1/session/org", body={"org_id": o["org_id"]},
                                      identity_token=vault.idp.issue("ana-1", "ana@acme.example"), request_id="r-ch"))
    assert chosen.status == 200 and chosen.body["role"] == "admin"


def test_the_emailed_link_still_works_and_a_used_link_is_used(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    tok = vault.mailer.token_for("ana@acme.example")
    session(vault, vault.idp.issue("ana-1", "ana@acme.example"))
    assert accept(vault, tok, vault.idp.issue("ana-1", "ana@acme.example")).body["error"] == "invite_used"
    boss.ok("POST", "/v1/members", body={"email": "bob@acme.example", "role": "developer"})
    assert accept(vault, vault.mailer.token_for("bob@acme.example"), vault.idp.issue("bob-1", "bob@acme.example")).status == 200


def test_an_unverified_address_or_no_second_factor_joins_nothing(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "admin"})
    r = session(vault, vault.idp.issue("ana-1", "ana@acme.example", verified=False))
    assert r.status == 200 and r.body["items"] == []
    r = session(vault, vault.idp.issue("ana-1", "ana@acme.example", mfa=False))
    assert r.status == 403
    assert _count(vault, "SELECT count(*) AS n FROM consentvault.member WHERE email_norm = 'ana@acme.example'") == 0
    assert _count(vault, "SELECT count(*) AS n FROM consentvault.invite WHERE accepted_at IS NOT NULL AND email_norm = 'ana@acme.example'") == 0


def test_withdrawn_and_expired_invitations_join_nothing(vault, org):
    o, boss = org
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    boss.ok("POST", "/v1/members", body={"email": "bob@acme.example", "role": "developer"})
    ids = {i["email"]: i["id"] for i in boss.ok("GET", "/v1/members", {"include": "invites"})["items"]}
    assert boss.call("DELETE", f"/v1/invites/{ids['ana@acme.example']}").status == 204
    with vault.superuser() as su:
        su.execute("ALTER TABLE consentvault.invite DISABLE TRIGGER invite_guard")
        su.execute("ALTER TABLE consentvault.invite DROP CONSTRAINT invite_life")
        su.execute("UPDATE consentvault.invite SET expires_at = now() - interval '1 minute', created_at = now() - interval '8 days'"
                   " WHERE email_norm = 'bob@acme.example'")
    assert session(vault, vault.idp.issue("ana-1", "ana@acme.example")).body["items"] == []
    assert session(vault, vault.idp.issue("bob-1", "bob@acme.example")).body["items"] == []


def test_two_pending_invitations_to_different_organisations_are_both_listed_and_the_person_chooses(vault, org):
    o, boss = org
    o2, boss2 = vault.org_with_admin("Birch", "boss@birch.example")
    boss.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "admin"})
    boss2.ok("POST", "/v1/members", body={"email": "ana@acme.example", "role": "developer"})
    r = session(vault, vault.idp.issue("ana-1", "ana@acme.example"))
    assert sorted(i["name"] for i in r.body["items"]) == ["Acme", "Birch"]
    assert r.body.get("next_cursor") is None
