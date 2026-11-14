"""Company single sign-on: passkey for everyone, SSO only through connections the operator bound to the organization."""

import dataclasses
import threading
import time

import psycopg
import pytest

from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.admin_routes import Request
from consentvault.tenancy.session import check_sso_entry

from .support import Person
from .test_session import _edge

CONN = "conn_01E4ZCR3C56J083X43JQXF3JK5"
CONN2 = "conn_01E4ZCR3C56J083X43JQXF3JK6"
OTHER = "conn_01HZZZZZZZZZZZZZZZZZZZZZZZ"
WOS = "org_01E4ZCR3C56J083X43JQXF3JK5"
WOS_OTHER = "org_01HZZZZZZZZZZZZZZZZZZZZZZZ"


def sso_assertion(make, idt, subject, connection=CONN, org=WOS, **extra):
    return make(idt, subject, amr=("sso",), sso_connection_id=connection, sso_organization_id=org, **extra)


def get(vault, idt, assertion, path="/v1/session"):
    return vault.app.handle(Request("GET", path, {}, None, identity_token=idt, edge_assertion=assertion, request_id="r-sso"))


def choose(vault, idt, assertion, org_id):
    return vault.app.handle(Request("POST", "/v1/session/org", {}, {"org_id": org_id}, identity_token=idt,
                                    edge_assertion=assertion, request_id="r-sso2"))


def operator(vault, method, path, body=None, who="op-1"):
    return vault.app.handle(Request(method, path, {}, body, operator_id=who, request_id="r-op"))


def bind(vault, org, workos=WOS, connections=(CONN,)):
    r = operator(vault, "PUT", f"/v1/orgs/{org['org_id']}/sso-binding",
                 {"workos_organization_id": workos, "connection_ids": list(connections)})
    assert r.status == 200, r.body
    return r


def through_sso(vault, make, org, person: Person, connection=CONN, workos=WOS) -> Person:
    """The person signed in to the organization through the company connection: a session whose token carries it."""
    idt = vault.idp.issue(person.subject, person.email, mfa=False)
    with vault.appconn() as c:
        s = vault.sessions.choose_org(c, idt, org["org_id"], request_id="r-thru",
                                      assertion=sso_assertion(make, idt, person.subject, connection=connection, org=workos))
    return Person(vault, org["org_id"], s.role, person.email, person.subject, s.member_id, s.token)


@pytest.fixture
def acme(vault):
    """An organization the operator has bound to a company connection, and its admin's passkey session."""
    org, boss = vault.org_with_admin("Sso Co", "boss@sso-co.example")
    bind(vault, org)
    return org, boss


@pytest.fixture
def verified(vault, acme):
    """The same organization once its admin has signed in through the bound connection (which proves it)."""
    org, boss = acme
    make = _edge(vault)
    return org, boss, through_sso(vault, make, org, boss), make


# ---- the operator binds; the admin never types a connection id ------------------------------------------------------------

def test_only_an_operator_binds_a_company_connection_and_the_admin_cannot_type_one(vault):
    org, boss = vault.org_with_admin("Bind Co", "boss@bind-co.example")
    assert boss.ok("GET", "/v1/org")["sso"] == {"connected": False, "connection_id": None, "required": False, "verified": False}
    boss.err("PUT", "/v1/org/sso", body={"connection_id": CONN, "require_sso": False}, name="validation_failed")
    path = f"/v1/orgs/{org['org_id']}/sso-binding"
    body = {"workos_organization_id": WOS, "connection_ids": [CONN]}
    assert vault.app.handle(Request("PUT", path, {}, body, request_id="r")).status == 401, "no operator, no binding"
    assert vault.app.handle(Request("PUT", path, {}, body, tenant_token=boss.token, request_id="r")).status == 401
    for bad in ({"workos_organization_id": "nope", "connection_ids": [CONN]}, {"workos_organization_id": WOS, "connection_ids": []},
                {"workos_organization_id": WOS, "connection_ids": ["x"]}, {"workos_organization_id": WOS},
                {"workos_organization_id": WOS, "connection_ids": [CONN], "extra": 1}):
        r = operator(vault, "PUT", path, bad)
        assert (r.status, r.body["error"]) == (422, "validation_failed"), bad
    done = bind(vault, org).body
    assert done["workos_organization_id"] == WOS and done["connection_ids"] == [CONN] and done["version"] == 1
    assert boss.ok("GET", "/v1/org")["sso"] == {"connected": True, "connection_id": None, "required": False, "verified": False}
    rows = [r["action"] for r in boss.ok("GET", "/v1/audit")["items"]]
    assert "sso.bound" in rows


def test_the_admin_turns_the_requirement_on_and_off_only_once_a_bound_connection_is_proved(vault, acme):
    org, boss = acme
    boss.err("PUT", "/v1/org/sso", body={"require_sso": True}, name="validation_failed")
    boss.err("PUT", "/v1/org/sso", body={"require_sso": "yes"}, name="validation_failed")
    sso_boss = through_sso(vault, _edge(vault), org, boss)
    assert boss.ok("GET", "/v1/org")["sso"] == {"connected": True, "connection_id": CONN, "required": False, "verified": True}
    r = boss.call("PUT", "/v1/org/sso", body={"require_sso": True})
    assert (r.status, r.body["error"]) == (422, "validation_failed"), "a passkey session cannot turn it on"
    done = sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    assert done["required"] is True and done["verified"] is True
    assert sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": False})["required"] is False
    actions = [r["action"] for r in sso_boss.ok("GET", "/v1/audit")["items"]]
    assert actions.count("sso.updated") == 2 and "sso.verified" in actions


def test_the_binding_is_proved_only_by_an_admin_signing_in_through_a_bound_connection_of_the_bound_organization(vault, acme):
    org, boss = acme
    make = _edge(vault)
    idt = vault.idp.issue(boss.subject, boss.email, mfa=False)
    for connection, workos in ((OTHER, WOS), (CONN, WOS_OTHER), (OTHER, WOS_OTHER)):
        r = choose(vault, idt, sso_assertion(make, idt, boss.subject, connection=connection, org=workos), org["org_id"])
        assert (r.status, r.body["error"]) == (403, "sso_not_connected"), (connection, workos)
    assert boss.ok("GET", "/v1/org")["sso"]["verified"] is False
    assert choose(vault, idt, sso_assertion(make, idt, boss.subject), org["org_id"]).status == 200
    assert boss.ok("GET", "/v1/org")["sso"]["verified"] is True


def test_a_second_bound_connection_of_the_same_organization_is_admitted_after_proof(vault):
    org, boss = vault.org_with_admin("Two Conn Co", "boss@two-conn.example")
    bind(vault, org, connections=(CONN, CONN2))
    make = _edge(vault)
    through_sso(vault, make, org, boss)
    dev_idt = vault.idp.issue("sub-later", "later@two-conn.example", mfa=False)
    assert get(vault, dev_idt, sso_assertion(make, dev_idt, "sub-later", connection=CONN2)).status == 200


def test_a_pending_binding_admits_only_an_admin(vault, acme):
    org, boss = acme
    dev = vault.add_member(boss, "dev3@sso-co.example", "developer")
    make = _edge(vault)
    idt = vault.idp.issue(dev.subject, dev.email, mfa=False)
    r = choose(vault, idt, sso_assertion(make, idt, dev.subject), org["org_id"])
    assert (r.status, r.body["error"]) == (403, "sso_not_connected"), "nobody can borrow a connection no admin has proved"
    assert get(vault, idt, sso_assertion(make, idt, dev.subject)).body["items"] == []
    through_sso(vault, make, org, boss)
    assert choose(vault, idt, sso_assertion(make, idt, dev.subject), org["org_id"]).status == 200


# ---- the rule is checked on every request ----------------------------------------------------------------------------------

def test_turning_on_require_sso_ends_every_session_that_did_not_come_through_it_on_the_very_next_request(vault, acme):
    org, boss = acme
    dev = vault.add_member(boss, "dev2@sso-co.example", "developer")  # joined before sign-in needs the edge's assertion
    make = _edge(vault)
    sso_boss = through_sso(vault, make, org, boss)
    assert dev.ok("GET", "/v1/org")["name"] == "Sso Co"
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    dev.err("GET", "/v1/org", name="sso_required")
    boss.err("GET", "/v1/org", name="sso_required")
    assert sso_boss.ok("GET", "/v1/org")["sso"]["required"] is True, "the session that came through it carries on"


def test_rebinding_to_another_connection_ends_the_sessions_that_came_through_the_old_one_at_once(vault, verified):
    org, boss, sso_boss, make = verified
    bind(vault, org, connections=(CONN2,))
    sso_boss.err("GET", "/v1/org", name="sso_not_connected")
    assert boss.ok("GET", "/v1/org")["sso"] == {"connected": True, "connection_id": None, "required": False, "verified": False}, \
        "a new binding is unproved until an admin signs in through it"
    assert boss.ok("GET", "/v1/org")["name"] == "Sso Co", "a passkey session is untouched"


def test_removing_the_binding_ends_them_too_and_lifts_the_requirement(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    r = operator(vault, "DELETE", f"/v1/orgs/{org['org_id']}/sso-binding")
    assert r.status == 200, r.body
    sso_boss.err("GET", "/v1/org", name="sso_not_connected")
    assert boss.ok("GET", "/v1/org")["sso"] == {"connected": False, "connection_id": None, "required": False, "verified": False}


# ---- break-glass: the operator lifts the requirement when the provider is down ---------------------------------------------

def test_the_operator_can_lift_the_requirement_when_the_provider_is_down_and_the_admins_are_told(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    boss.err("GET", "/v1/org", name="sso_required")
    path = f"/v1/orgs/{org['org_id']}/sso:break-glass"
    assert operator(vault, "POST", path, {}).status == 422, "a reason is required"
    assert vault.app.handle(Request("POST", path, {}, {"reason": "x"}, request_id="r")).status == 401
    r = operator(vault, "POST", path, {"reason": "Okta outage, customer cannot sign in"})
    assert r.status == 200 and r.body["required"] is False, r.body
    assert boss.ok("GET", "/v1/org")["sso"]["required"] is False, "the passkey works again at once"
    alarms = [a for a in boss.ok("GET", "/v1/health")["alarms"] if a["name"] == "sso.required_lifted"]
    assert len(alarms) == 1 and "operator" in alarms[0]["next_action"].lower()
    rows = [r["action"] for r in boss.ok("GET", "/v1/audit")["items"]]
    assert "sso.break_glass" in rows
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})  # the admin turns it back on: the notice clears
    assert [a for a in sso_boss.ok("GET", "/v1/health")["alarms"] if a["name"] == "sso.required_lifted"] == []


def test_break_glass_does_nothing_to_an_organization_that_does_not_require_it(vault, verified):
    org, boss, sso_boss, make = verified
    r = operator(vault, "POST", f"/v1/orgs/{org['org_id']}/sso:break-glass", {"reason": "checking"})
    assert (r.status, r.body["error"]) == (422, "validation_failed")


def _lifted(person):
    return [a for a in person.ok("GET", "/v1/health")["alarms"] if a["name"] == "sso.required_lifted"]


def test_unbinding_an_active_requirement_tells_the_admins(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    assert operator(vault, "DELETE", f"/v1/orgs/{org['org_id']}/sso-binding").status == 200
    assert len(_lifted(boss)) == 1


def test_rebinding_an_active_requirement_tells_the_admins(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    bind(vault, org, connections=(CONN2,))
    assert len(_lifted(boss)) == 1


def test_unbinding_or_rebinding_when_nothing_is_required_raises_no_alarm(vault, verified):
    org, boss, sso_boss, make = verified
    bind(vault, org, connections=(CONN2,))
    assert _lifted(boss) == []
    assert operator(vault, "DELETE", f"/v1/orgs/{org['org_id']}/sso-binding").status == 200
    assert _lifted(boss) == []


def test_unbinding_after_a_break_glass_clears_the_notice_and_the_admin_can_enable_again(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    assert operator(vault, "POST", f"/v1/orgs/{org['org_id']}/sso:break-glass", {"reason": "Okta outage"}).status == 200
    assert len(_lifted(boss)) == 1
    assert operator(vault, "DELETE", f"/v1/orgs/{org['org_id']}/sso-binding").status == 200
    assert _lifted(boss) == [], "the lifted notice is answered once the binding is gone"
    bind(vault, org)
    again = through_sso(vault, make, org, boss)
    assert again.ok("PUT", "/v1/org/sso", body={"require_sso": True})["required"] is True


def test_a_sign_in_service_organization_bound_to_another_organization_is_refused_with_a_named_conflict(vault):
    org_a, _ = vault.org_with_admin("Own Co", "boss@own-co.example")
    org_b, _ = vault.org_with_admin("Taker Co", "boss@taker-co.example")
    bind(vault, org_a)
    path_b = f"/v1/orgs/{org_b['org_id']}/sso-binding"
    body = {"workos_organization_id": WOS, "connection_ids": [CONN2]}
    r = operator(vault, "PUT", path_b, body)
    assert (r.status, r.body["error"]) == (409, "sso_binding_taken"), r.body
    bind(vault, org_a, connections=(CONN, CONN2))  # the same organization may rebind its own
    assert operator(vault, "DELETE", f"/v1/orgs/{org_a['org_id']}/sso-binding").status == 200
    assert operator(vault, "PUT", path_b, body).status == 200, "freed by the unbind"


def test_a_bind_waits_while_another_transaction_holds_the_lock_on_that_sign_in_service_organization(vault):
    org, _ = vault.org_with_admin("Lock Co", "boss@lock-co.example")
    holder = psycopg.connect(vault.super_dsn, autocommit=False)
    holder.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.sso_wos:' || %s))", (WOS,))
    done = threading.Event()

    def do_bind():
        bind(vault, org)
        done.set()
    t = threading.Thread(target=do_bind, daemon=True)
    t.start()
    time.sleep(0.8)
    assert not done.is_set(), "two organizations binding the same sign-in-service organization must be serialized"
    holder.rollback()
    holder.close()
    t.join(timeout=15)
    assert done.is_set()


def test_a_trailing_newline_or_lowercase_or_short_id_is_refused_at_bind_with_a_named_422(vault):
    org, _ = vault.org_with_admin("Fmt Co", "boss@fmt-co.example")
    path = f"/v1/orgs/{org['org_id']}/sso-binding"
    for wos, conns in ((WOS + "\n", [CONN]), (WOS.lower(), [CONN]), (WOS, [CONN + "\n"]), (WOS, [CONN.lower()]),
                       ("org_" + "0" * 10, [CONN]), (WOS + "A", [CONN]), (WOS, [CONN + "A"])):
        r = operator(vault, "PUT", path, {"workos_organization_id": wos, "connection_ids": conns})
        assert (r.status, r.body["error"]) == (422, "validation_failed"), (wos, conns, r.body)
    assert "workos_organization_id" in operator(vault, "PUT", path, {"workos_organization_id": WOS.lower(), "connection_ids": [CONN]}).body["fields"]


def test_an_unknown_organization_is_not_found_on_every_operator_sso_route(vault):
    ghost = "00000000-0000-4000-8000-000000000001"
    for method, suffix, body in (("PUT", "sso-binding", {"workos_organization_id": WOS, "connection_ids": [CONN]}),
                                 ("DELETE", "sso-binding", None), ("POST", "sso:break-glass", {"reason": "x"})):
        r = operator(vault, method, f"/v1/orgs/{ghost}/{suffix}", body)
        assert (r.status, r.body["error"]) == (404, "not_found"), (method, suffix, r.status, r.body)


# ---- the operator's actions are on both audit chains ----------------------------------------------------------------------

def _platform_rows(vault, org, action):
    with vault.superuser() as su:
        return su.execute("SELECT actor_id, target_kind, target_id, reason FROM consentvault.audit_event"
                          " WHERE org_id IS NULL AND action = %s AND target_id = %s", (action, str(org["org_id"]))).fetchall()


def _org_actions(boss):
    return [r["action"] for r in boss.ok("GET", "/v1/audit", {"limit": "200"})["items"]]


def test_bind_writes_the_platform_log_row(vault):
    org, boss = vault.org_with_admin("Plat Co", "boss@plat-co.example")
    bind(vault, org)
    rows = _platform_rows(vault, org, "sso.bound")
    assert len(rows) == 1 and rows[0]["actor_id"] == "op-1" and rows[0]["target_kind"] == "org" and rows[0]["reason"] == WOS


def test_unbind_writes_the_platform_log_row_and_the_org_log_row(vault, verified):
    org, boss, sso_boss, make = verified
    assert operator(vault, "DELETE", f"/v1/orgs/{org['org_id']}/sso-binding").status == 200
    rows = _platform_rows(vault, org, "sso.unbound")
    assert len(rows) == 1 and rows[0]["actor_id"] == "op-1"
    assert _org_actions(boss).count("sso.unbound") == 1


def test_break_glass_writes_the_platform_log_row(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    assert operator(vault, "POST", f"/v1/orgs/{org['org_id']}/sso:break-glass", {"reason": "Okta outage"}).status == 200
    rows = _platform_rows(vault, org, "sso.break_glass")
    assert len(rows) == 1 and rows[0]["reason"] == "Okta outage" and rows[0]["actor_id"] == "op-1"


# ---- sign-in checks ---------------------------------------------------------------------------------------------------------

def test_an_sso_sign_in_enters_only_the_organization_bound_to_that_connection(vault, acme):
    org, boss = acme
    make = _edge(vault)
    idt = vault.idp.issue(boss.subject, "boss@sso-co.example", mfa=False)
    ok = get(vault, idt, sso_assertion(make, idt, boss.subject))
    assert ok.status == 200 and [i["org_id"] for i in ok.body["items"]] == [org["org_id"]]
    wrong = sso_assertion(make, idt, boss.subject, connection=OTHER)
    assert get(vault, idt, wrong).body["items"] == [], "another company's connection sees none of this organization"
    r = choose(vault, idt, wrong, org["org_id"])
    assert (r.status, r.body["error"]) == (403, "sso_not_connected")


def test_an_sso_sign_in_is_refused_by_an_organization_with_no_binding(vault):
    org, boss = vault.org_with_admin("No Sso Co", "boss@no-sso.example")
    make = _edge(vault)
    idt = vault.idp.issue(boss.subject, "boss@no-sso.example", mfa=False)
    r = choose(vault, idt, sso_assertion(make, idt, boss.subject), org["org_id"])
    assert (r.status, r.body["error"]) == (403, "sso_not_connected")
    assert choose(vault, idt, make(idt, boss.subject), org["org_id"]).status == 200, "a passkey still gets in"


def test_an_sso_assertion_must_name_its_connection_and_its_organization(vault, acme):
    org, boss = acme
    make = _edge(vault)
    idt = vault.idp.issue(boss.subject, "boss@sso-co.example", mfa=False)
    for extra in ({}, {"sso_connection_id": ""}, {"sso_connection_id": 5}, {"sso_connection_id": CONN},
                  {"sso_organization_id": WOS}, {"sso_connection_id": CONN, "sso_organization_id": ""}):
        r = get(vault, idt, make(idt, boss.subject, amr=("sso",), **extra))
        assert (r.status, r.body["error"]) == (403, "second_factor_required"), extra


def test_the_vault_itself_requires_an_sso_sign_in_to_be_exactly_sso(vault, acme):
    org, boss = acme
    make = _edge(vault)
    idt = vault.idp.issue(boss.subject, "boss@sso-co.example", mfa=False)
    for amr in (("hwk", "user"), ("sso", "hwk", "user"), ("mfa",), ("sso", "pwd")):
        r = get(vault, idt, make(idt, boss.subject, amr=amr, sso_connection_id=CONN, sso_organization_id=WOS))
        assert (r.status, r.body["error"]) == (401, "unauthenticated"), amr
        r = choose(vault, idt, make(idt, boss.subject, amr=amr, sso_connection_id=CONN, sso_organization_id=WOS), org["org_id"])
        assert r.status == 401, amr
    assert get(vault, idt, sso_assertion(make, idt, boss.subject)).status == 200


def test_when_sso_is_required_a_passkey_sign_in_is_refused_and_sso_is_not(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    idt = vault.idp.issue(boss.subject, "boss@sso-co.example", mfa=False)
    assert get(vault, idt, make(idt, boss.subject)).body["items"][0]["sso_required"] is True
    r = choose(vault, idt, make(idt, boss.subject), org["org_id"])
    assert (r.status, r.body["error"]) == (403, "sso_required")
    assert choose(vault, idt, sso_assertion(make, idt, boss.subject), org["org_id"]).status == 200


def test_the_audit_row_for_an_sso_sign_in_says_the_provider_vouched_for_the_second_factor(vault, verified):
    org, boss, sso_boss, make = verified
    rows = [r for r in sso_boss.ok("GET", "/v1/audit")["items"] if r["action"] == "session.opened"]
    assert any("sso" in str(r).lower() or "company" in str(r).lower() for r in rows), rows


def test_an_invitation_is_accepted_through_sso_only_by_the_bound_organization(vault, verified):
    org, boss, sso_boss, make = verified
    sso_boss.ok("PUT", "/v1/org/sso", body={"require_sso": True})
    sso_boss.ok("POST", "/v1/members", body={"email": "new@sso-co.example", "role": "developer"})
    token = vault.mailer.token_for("new@sso-co.example")
    idt = vault.idp.issue("sso-newcomer", "x@x.example", mfa=False)
    vault.idp.known[idt] = dataclasses.replace(vault.idp.known[idt], claims={"sub": "sso-newcomer"})

    def accept(assertion):
        return vault.app.handle(Request("POST", f"/v1/invites/{token}:accept", {}, None, identity_token=idt,
                                        edge_assertion=assertion, request_id="r-i"))
    addr = {"email": "new@sso-co.example", "email_verified": True}
    assert accept(make(idt, "sso-newcomer", **addr)).body["error"] == "sso_required", "a passkey cannot join an SSO-only organization"
    assert accept(sso_assertion(make, idt, "sso-newcomer", connection=OTHER, **addr)).body["error"] == "sso_not_connected"
    assert accept(sso_assertion(make, idt, "sso-newcomer", org=WOS_OTHER, **addr)).body["error"] == "sso_not_connected"
    assert accept(sso_assertion(make, idt, "sso-newcomer", **addr)).status == 200


# ---- the database refuses what the rules refuse -----------------------------------------------------------------------------

def _insert(su, org_id, **cols):
    base = {"org_id": org_id, "version": 99, "workos_org_id": WOS, "bound_connections": [CONN], "connection_id": None,
            "require_sso": False, "verified": False}
    base.update(cols)
    names = ", ".join(base)
    su.execute(f"INSERT INTO consentvault.org_sso ({names}) VALUES ({', '.join(['%s'] * len(base))})", list(base.values()))


def test_the_database_refuses_required_without_proved_and_proved_outside_the_binding(vault):
    org, boss = vault.org_with_admin("Db Co", "boss@db-co.example")
    with vault.superuser() as su:
        for cols in ({"require_sso": True},                                             # required, not proved
                     {"require_sso": True, "verified": False, "connection_id": CONN},    # required, a connection but not proved
                     {"verified": True},                                                 # proved with no connection
                     {"verified": True, "connection_id": OTHER},                         # proved through a connection outside the binding
                     {"verified": False, "connection_id": CONN},                         # a proving connection recorded as unproved
                     {"workos_org_id": None},                                            # connections without their organization
                     {"workos_org_id": "bad"}, {"bound_connections": ["bad"]}):
            with pytest.raises(psycopg.errors.CheckViolation):
                with su.transaction():
                    _insert(su, org["org_id"], **cols)
        with su.transaction():
            _insert(su, org["org_id"], verified=True, connection_id=CONN, require_sso=True)  # the one valid shape


# ---- proving cannot undo a concurrent change --------------------------------------------------------------------------------

def test_proving_waits_for_a_concurrent_change_to_the_same_setting(vault, acme):
    org, boss = acme
    make = _edge(vault)
    holder = psycopg.connect(vault.super_dsn, autocommit=False)
    holder.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.sso:' || %s))", (org["org_id"],))
    done = threading.Event()

    def sign_in():
        through_sso(vault, make, org, boss)
        done.set()
    t = threading.Thread(target=sign_in, daemon=True)
    t.start()
    time.sleep(0.8)
    assert not done.is_set(), "the sign-in that proves the binding must wait while the setting is being changed"
    holder.rollback()
    holder.close()
    t.join(timeout=15)
    assert done.is_set()


# ---- the rule itself, branch by branch --------------------------------------------------------------------------------------

def S(bound=(CONN,), workos=WOS, required=False, verified=True):
    return {"workos_org_id": workos if bound else None, "bound_connections": list(bound), "connection_id": CONN if verified else None,
            "required": required, "verified": verified}


@pytest.mark.parametrize("setting,signed_in,role,workos,expected", [
    (S(), CONN, "developer", None, None),
    (S(), OTHER, "admin", None, "sso_not_connected"),
    (S(bound=()), CONN, "admin", None, "sso_not_connected"),
    (S(verified=False), CONN, "developer", None, "sso_not_connected"),
    (S(verified=False), CONN, "admin", None, None),
    (S(required=True), None, "admin", None, "sso_required"),
    (S(), None, "developer", None, None),
    (S(bound=(), verified=False), None, "admin", None, None),
    (S(), CONN, "developer", WOS, None),
    (S(), CONN, "developer", WOS_OTHER, "sso_not_connected"),
])
def test_check_sso_entry_branches(setting, signed_in, role, workos, expected):
    if expected is None:
        check_sso_entry(setting, signed_in, role, workos)
    else:
        with pytest.raises(ApiError) as exc:
            check_sso_entry(setting, signed_in, role, workos)
        assert exc.value.name == expected
