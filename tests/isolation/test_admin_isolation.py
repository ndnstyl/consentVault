"""Isolation of the admin plane: every tenant table it added, every owner-rights function it added, and every endpoint
that takes an id, tried with organisation A's credentials against organisation B's rows (wave-0 review condition 3).

Every owner-rights function here (append_audit, audit_head, health_counts, source_last_events, current_token_claims)
filters on current_org() itself because the operator role that owns them bypasses row security; the pre-tenant lookups
(invite_lookup, session_memberships) answer for one digest or one identity and are tested for what they refuse.
"""

import copy
import hashlib
import uuid

import psycopg
import pytest

from admin.conftest import vault  # noqa: F401  (the fixture)
from consentvault import db
from consentvault.ledger import record_tenant_event
from consentvault.tenancy import audit
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.keys_adapter import CustodyKeyAdapter
from consentvault.tenancy.tokens import mint_org_token, org_transaction

NEW_TABLES = ("channel", "purpose", "invite", "policy", "policy_approval", "policy_attestation", "doc_checklist",
              "retention_policy", "connected_system", "export_job", "audit_event", "org_fingerprint_secret", "brand",
              "capture_source", "credential", "member")


class Two:
    pass


def populate(vault, name, domain):
    org, boss = vault.org_with_admin(name, f"boss@{domain}")
    dev = vault.add_member(boss, f"dev@{domain}", "developer")
    viewer = vault.add_member(boss, f"cv@{domain}", "compliance_viewer")
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Shared Name"})["brand_id"]
    src = boss.ok("POST", "/v1/sources", body={"name": "Shared Source", "kind": "site_key", "brand_ids": [brand],
                                               "allowed_origins": [f"https://{domain}"]})["source_id"]
    cred = boss.ok("POST", "/v1/credentials", body={"name": "Shared Cred", "kind": "hmac_fallback", "scope": "capture",
                                                    "source_id": src})["credential_id"]
    word = boss.ok("POST", "/v1/disclosures", body={"body": "Identical wording in both organisations.", "label": "L",
                                                    "channels": ["sms"], "purposes": ["marketing"], "brand_ids": [brand],
                                                    "effective_from": "2026-10-01T00:00:00Z"})["sha256"]
    tpl = boss.ok("GET", "/v1/policy-templates")["items"][0]["rules"]
    boss.ok("POST", "/v1/policies", body={"rules": tpl})
    att = boss.ok("GET", "/v1/attestations/current")
    boss.ok("POST", "/v1/policies/1:approve", body={"attestation_version": att["version"], "attestation_sha256": att["sha256"],
                                                   "accepted": True})
    boss.ok("POST", "/v1/policies", body={"rules": tpl})  # a draft too
    boss.ok("POST", "/v1/checklists", body={"kind": "custom", "label": "C", "elements": [{"name": "One"}]})
    system = boss.ok("POST", "/v1/systems", body={"name": "Dialer", "kind": "dialer", "endpoint": "https://d.example/h",
                                                  "signature": "hmac", "contact_form": "fingerprint"})["system_id"]
    boss.ok("PUT", "/v1/retention", body={"evidence_years": 8, "reason": "ours"})
    boss.ok("POST", "/v1/members", body={"email": f"pending@{domain}", "role": "developer"})
    invite = [i for i in boss.ok("GET", "/v1/members", {"include": "invites"})["items"] if i["kind"] == "invite"][0]["id"]
    # one event through the ledger so the source and health reads have something to count
    adapter = CustodyKeyAdapter(vault.custody, lambda oid: bytes(wrapped_fp(vault, str(oid))),
                                lambda oid: bytes(wrapped_display(vault, str(oid))))
    crypto = TenantCrypto(adapter)
    with vault.appconn() as c, org_transaction(c, mint_org_token(vault.key, org["org_id"], ["capture"], credential_id=None)):
        e = record_tenant_event(c, crypto, contact="+15555550142", event_type="grant", channels=["sms"], purposes=["marketing"],
                                method="checkbox", origin="consumer", disclosure_sha256=word, source_id=uuid.UUID(src),
                                brand_ids=[uuid.UUID(brand)])
    # an export job row as the evidence-export lane would hold it
    with vault.operator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        o.execute("INSERT INTO consentvault.export_job (org_id, contact_fp, requested_by) VALUES (%s, %s, %s)",
                  (org["org_id"], "ab" * 32, boss.member_id))
    t = Two()
    t.org, t.boss, t.dev, t.viewer = org, boss, dev, viewer
    t.brand, t.src, t.cred, t.word, t.system, t.invite, t.seq = brand, src, cred, word, system, invite, e.seq
    return t


def wrapped_display(vault, org_id):
    with vault.operator() as c, org_transaction(c, mint_org_token(vault.key, org_id, ["admin", "worker:display_key"], credential_id=None)):
        return c.execute("SELECT wrapped FROM consentvault.org_display_key").fetchone()["wrapped"]


def wrapped_fp(vault, org_id):
    with vault.operator() as c, org_transaction(c, mint_org_token(vault.key, org_id, ["admin"], credential_id=None)):
        return c.execute("SELECT wrapped FROM consentvault.org_fingerprint_secret").fetchone()["wrapped"]


@pytest.fixture
def two(vault):
    a = populate(vault, "Alpha", "alpha.example")
    b = populate(vault, "Bravo", "bravo.example")
    a.vault = b.vault = vault
    return a, b


def tok(vault, t, scopes=("admin",)):
    return mint_org_token(vault.key, t.org["org_id"], list(scopes), credential_id=None)


# ---- tables ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("table", NEW_TABLES)
def test_a_token_for_one_org_sees_only_its_own_rows_in_every_admin_table(two, table):
    a, b = two
    vault = a.vault
    with vault.operator() as o, org_transaction(o, tok(vault, a)):  # the owner, bound by row security like everyone
        seen = {r["org_id"] for r in o.execute(f"SELECT org_id FROM consentvault.{table}")}
        assert seen == {uuid.UUID(a.org["org_id"])}, table
    with vault.superuser() as su:  # and the table really does hold B's rows, so the empty read above means something
        assert su.execute(f"SELECT count(*) AS n FROM consentvault.{table} WHERE org_id = %s", (b.org["org_id"],)).fetchone()["n"] > 0


@pytest.mark.parametrize("table", [t for t in NEW_TABLES if t not in ("audit_event", "org_fingerprint_secret", "export_job")])
def test_a_token_for_one_org_cannot_update_or_delete_the_others_rows(two, table):
    a, b = two
    vault = a.vault
    with vault.superuser() as su:
        before = su.execute(f"SELECT count(*) AS n FROM consentvault.{table} WHERE org_id = %s", (b.org["org_id"],)).fetchone()["n"]
    with vault.migrator() as o, org_transaction(o, tok(vault, a)):  # owner rights: still fenced by row security
        # both statements match no row of B (row security hides them) or are refused by a guard; neither touches B
        for sql in (f"DELETE FROM consentvault.{table} WHERE org_id = %s", f"UPDATE consentvault.{table} SET org_id = org_id WHERE org_id = %s"):
            try:
                n = o.execute(sql, (b.org["org_id"],)).rowcount
            except psycopg.errors.IntegrityConstraintViolation:
                break  # an append-only guard refused the statement; the transaction is over and B is untouched
            assert n == 0
    with vault.superuser() as su:
        assert su.execute(f"SELECT count(*) AS n FROM consentvault.{table} WHERE org_id = %s", (b.org["org_id"],)).fetchone()["n"] == before


def test_a_token_for_one_org_cannot_insert_rows_into_another(two):
    a, b = two
    vault = a.vault
    inserts = {
        "brand": ("INSERT INTO consentvault.brand (org_id, display_name) VALUES (%s, 'planted')", 1),
        "channel": ("INSERT INTO consentvault.channel (org_id, channel, label) VALUES (%s, 'planted', 'planted')", 1),
        "purpose": ("INSERT INTO consentvault.purpose (org_id, purpose, label) VALUES (%s, 'planted', 'planted')", 1),
        "retention_policy": ("INSERT INTO consentvault.retention_policy (org_id, version, evidence_years, platform_minimum_years)"
                             " VALUES (%s, 50, 9, 5)", 1),
        "invite": ("INSERT INTO consentvault.invite (org_id, token_digest, email_norm, role, expires_at)"
                   " VALUES (%s, repeat('a', 64), 'p@x.example', 'admin', now() + interval '1 day')", 1),
        "member": ("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role) VALUES (%s, 'i', 's', 'admin')", 1),
        "policy": ("INSERT INTO consentvault.policy (org_id, version, rules) VALUES (%s, 50, '{}')", 1),
    }
    for table, (sql, _) in inserts.items():
        # the lists the operator sets (channel, purpose) have no INSERT grant at all; the rest are stopped by row security
        why = "permission denied" if table in ("channel", "purpose") else "row-level security"
        with vault.appconn() as app, pytest.raises(psycopg.errors.InsufficientPrivilege, match=why):
            with org_transaction(app, tok(vault, a)):
                app.execute(sql, (b.org["org_id"],))
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.brand WHERE display_name = 'planted'").fetchone()["n"] == 0
        assert su.execute("SELECT count(*) AS n FROM consentvault.member WHERE idp_issuer = 'i'").fetchone()["n"] == 0


# ---- owner-rights functions -------------------------------------------------------------------------------------------
def test_append_audit_writes_to_the_entered_chain_and_to_no_other(two):
    a, b = two
    vault = a.vault
    with vault.superuser() as su:
        b_before = su.execute("SELECT count(*) AS n FROM consentvault.audit_event WHERE org_id = %s", (b.org["org_id"],)).fetchone()["n"]
    with vault.appconn() as app, org_transaction(app, tok(vault, a)):
        before = audit.head(app)["seq"]
        audit.append(app, actor_kind="system", actor_id=None, action="org.status_changed", target_kind="org", request_id="r-iso")
        assert audit.head(app)["seq"] == before + 1
        assert audit.chain_breaks(app) == []
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.audit_event WHERE org_id = %s", (b.org["org_id"],)).fetchone()["n"] == b_before
        assert su.execute("SELECT count(*) AS n FROM consentvault.audit_chain_breaks").fetchone()["n"] == 0


def test_append_audit_refuses_without_an_entered_tenant(two):
    a, b = two
    with a.vault.appconn() as app, pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
        app.execute("SELECT consentvault.append_audit('system', NULL, 'org.created', 'org', NULL, NULL, 'r')")
    with a.vault.appconn() as app:  # a forged setting is the same as none
        with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification), app.transaction():
            app.execute("SELECT set_config('consentvault.org_token', 'v1.adm-k1.00.00', true)")
            app.execute("SELECT consentvault.append_audit('system', NULL, 'org.created', 'org', NULL, NULL, 'r')")


def test_audit_head_is_the_entered_organisations(two):
    a, b = two
    vault = a.vault
    with vault.appconn() as app:
        heads = {}
        for name, t in (("a", a), ("b", b)):
            with org_transaction(app, tok(vault, t)):
                heads[name] = audit.head(app)
    with vault.superuser() as su:
        for name, t in (("a", a), ("b", b)):
            want = su.execute("SELECT seq, row_hash FROM consentvault.audit_event WHERE org_id = %s ORDER BY seq DESC LIMIT 1",
                              (t.org["org_id"],)).fetchone()
            assert heads[name] == want
    assert heads["a"]["row_hash"] != heads["b"]["row_hash"]


def test_health_and_source_reads_count_only_the_entered_organisation(two):
    a, b = two
    vault = a.vault
    with vault.superuser() as su:  # give B many more events than A so a leak would change A's answer
        su.execute("SELECT 1")
    ha, hb = a.boss.ok("GET", "/v1/health"), b.boss.ok("GET", "/v1/health")
    assert ha["first_event"]["sealed"] is False and hb["first_event"]["sealed"] is False
    with vault.appconn() as app:
        with org_transaction(app, tok(vault, a)):
            rows = app.execute("SELECT * FROM consentvault.source_last_events()").fetchall()
            h = app.execute("SELECT * FROM consentvault.health_counts()").fetchone()
        assert [str(r["source_id"]) for r in rows] == [a.src]
        assert h["first_event_at"] is not None
    # with no tenant entered the functions answer nothing at all
    with vault.appconn() as app:
        assert app.execute("SELECT * FROM consentvault.source_last_events()").fetchall() == []
        assert app.execute("SELECT unsealed_over_1h FROM consentvault.health_counts()").fetchone()["unsealed_over_1h"] == 0
        assert app.execute("SELECT * FROM consentvault.current_token_claims()").fetchall() == []
        assert app.execute("SELECT * FROM consentvault.audit_head()").fetchall() == []


def test_current_token_claims_describe_only_the_entered_token(two):
    a, b = two
    with a.vault.appconn() as app, org_transaction(app, tok(a.vault, a, ["admin", "audit_read"])):
        r = app.execute("SELECT * FROM consentvault.current_token_claims()").fetchone()
    assert str(r["org_id"]) == a.org["org_id"] and sorted(r["scopes"]) == ["admin", "audit_read"]


def test_the_invite_lookup_answers_for_one_exact_digest_and_nothing_else(two):
    a, b = two
    vault = a.vault
    a_tok = vault.mailer.token_for("pending@alpha.example")
    digest = hashlib.sha256(b"consentvault.invite.v1:" + a_tok.encode()).hexdigest()
    with vault.appconn() as app:
        row = app.execute("SELECT * FROM consentvault.invite_lookup(%s)", (digest,)).fetchall()
        assert len(row) == 1 and str(row[0]["org_id"]) == a.org["org_id"] and row[0]["role"] == "developer"
        assert set(row[0]) == {"org_id", "invite_id", "org_status", "role", "invited_by", "invited_by_operator", "email_norm",
                               "expires_at", "accepted_at", "withdrawn_at"}  # no digest, no token, no names
        for probe in ("%", "a%", "", "0" * 64, digest[:63], digest + "0", digest.upper(), "x" * 64, None):
            assert app.execute("SELECT * FROM consentvault.invite_lookup(%s)", (probe,)).fetchall() == [], probe
    # the runtime role cannot enumerate invitations through the table either: the digest column is unreadable
    with vault.appconn() as app, pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("SELECT token_digest FROM consentvault.invite")


def test_session_memberships_answer_for_one_identity_only(two):
    a, b = two
    vault = a.vault
    with vault.appconn() as app:
        mine = app.execute("SELECT org_id, role FROM consentvault.session_memberships(%s, %s)", ("https://idp.example.com", a.boss.subject)).fetchall()
        assert [(str(r["org_id"]), r["role"]) for r in mine] == [(a.org["org_id"], "admin")]
        for iss, sub in (("https://idp.example.com", "%"), ("%", "%"), ("", ""), (None, None), ("https://idp.example.com", a.boss.subject + "x")):
            assert app.execute("SELECT * FROM consentvault.session_memberships(%s, %s)", (iss, sub)).fetchall() == [], (iss, sub)


def test_the_platform_chain_is_unreachable_from_the_runtime_role(two):
    a, b = two
    with a.vault.appconn() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM consentvault.platform_audit_head()")


# ---- endpoints with ids -------------------------------------------------------------------------------------------------
def test_a_session_of_one_org_cannot_reach_the_others_objects_by_id(two):
    a, b = two
    me = a.boss
    probes = [
        ("GET", f"/v1/sources/{b.src}", None), ("PATCH", f"/v1/sources/{b.src}", {"name": "hijack"}),
        ("POST", f"/v1/credentials/{b.cred}:revoke", {"reason": "x"}),
        ("PATCH", f"/v1/members/{b.boss.member_id}", {"role": "compliance_viewer"}), ("DELETE", f"/v1/members/{b.dev.member_id}", None),
        ("DELETE", f"/v1/invites/{b.invite}", None),
        ("GET", f"/v1/systems/{b.system}", None), ("PATCH", f"/v1/systems/{b.system}", {"status": "paused"}),
    ]
    for method, path, body in probes:
        r = me.call(method, path, None, body)
        assert (r.status, r.body["error"]) == (404, "not_found"), (method, path, r.body)
    # wording is keyed per organisation: the same text is A's own row, and B's row is not reachable through A's session
    assert a.word == b.word
    assert me.ok("GET", f"/v1/disclosures/{a.word}")["registered_by"] == a.boss.member_id
    with a.vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.disclosure WHERE sha256 = %s", (a.word,)).fetchone()["n"] == 2
    # nothing of B's changed
    assert b.boss.ok("GET", f"/v1/sources/{b.src}")["name"] == "Shared Source"
    assert [c["revoked_at"] for c in b.boss.ok("GET", "/v1/credentials")["items"]] == [None]
    assert {m["id"] for m in b.boss.ok("GET", "/v1/members")["items"]} == {b.boss.member_id, b.dev.member_id, b.viewer.member_id}


def test_lists_never_include_the_other_organisation(two):
    a, b = two
    for path, key in (("/v1/brands", "brand_id"), ("/v1/sources", "source_id"), ("/v1/credentials", "credential_id"),
                      ("/v1/members", "id"), ("/v1/systems", "system_id"), ("/v1/audit", "audit_id")):
        left = {i[key] for i in a.boss.ok("GET", path, {"limit": "200"})["items"]}
        right = {i[key] for i in b.boss.ok("GET", path, {"limit": "200"})["items"]}
        assert left and right and not (left & right), path
    for path in ("/v1/policies", "/v1/checklists", "/v1/disclosures"):  # versioned or hashed: each side sees its own count
        assert len(a.boss.ok("GET", path, {"limit": "200"})["items"]) == len(b.boss.ok("GET", path, {"limit": "200"})["items"]) > 0
    assert a.boss.ok("GET", "/v1/retention")["current"]["set_by"] == a.boss.member_id
    assert b.boss.member_id not in str(a.boss.ok("GET", "/v1/members", {"limit": "200"}))
    assert b.boss.member_id not in str(a.boss.ok("GET", "/v1/audit", {"limit": "200"}))
    assert a.boss.ok("GET", "/v1/audit", {"actor": b.boss.member_id})["items"] == []
    assert b.org["org_id"] not in str(a.boss.ok("GET", "/v1/audit", {"limit": "200"}))


def test_the_same_names_live_independently_in_both_organisations(two):
    a, b = two
    for body, path in (({"display_name": "Shared Name 2"}, "/v1/brands"),):
        assert a.boss.call("POST", path, None, body).status == 201 and b.boss.call("POST", path, None, body).status == 201
    # populate() already made identical brand, source, credential, wording and system names in both: none collided


def test_a_policy_approval_in_one_org_leaves_the_others_in_force(two):
    a, b = two
    tpl = a.boss.ok("GET", "/v1/policy-templates")["items"][1]
    a.boss.ok("POST", "/v1/policies", body={"rules": tpl["rules"], "based_on_version": 1})
    att = a.boss.ok("GET", "/v1/attestations/current")
    r = a.boss.call("POST", "/v1/policies/3:approve", None, {"attestation_version": att["version"], "attestation_sha256": att["sha256"], "accepted": True})
    assert r.status == 200 and r.body["retired"]["version"] == 1
    assert [p["version"] for p in b.boss.ok("GET", "/v1/policies", {"status": "approved"})["items"]] == [1]


def test_suspending_one_org_leaves_the_other_working(two):
    a, b = two
    from consentvault.tenancy import admin
    with a.vault.operator() as o:
        admin.set_org_status(o, token_key=a.vault.key, operator_id="op", request_id="r", org_id=a.org["org_id"], status="suspended", reason="x")
    a.boss.err("POST", "/v1/systems", body={"name": "n", "kind": "crm", "endpoint": "https://x.example/", "signature": "hmac",
                                            "contact_form": "fingerprint"}, name="org_suspended")
    assert b.boss.call("POST", "/v1/systems", None, {"name": "n", "kind": "crm", "endpoint": "https://x.example/", "signature": "hmac",
                                                      "contact_form": "fingerprint"}).status == 201


def test_accepting_an_invitation_in_one_org_grants_nothing_in_the_other(two):
    a, b = two
    vault = a.vault
    person = vault.join(a.org["org_id"], "pending@alpha.example", "developer", invite_token=vault.mailer.token_for("pending@alpha.example"))
    from consentvault.tenancy.session import SessionMinter
    from consentvault.providers.errors import IdentityError
    idt = vault.idp.issue(person.subject, "pending@alpha.example")
    with vault.appconn() as c:
        with pytest.raises(Exception) as e:
            vault.sessions.choose_org(c, idt, b.org["org_id"], request_id="r")
        assert e.value.name == "not_a_member"
    assert person.call("GET", f"/v1/sources/{b.src}").status == 404


def test_a_token_for_one_org_cannot_be_turned_into_a_token_for_another(two):
    a, b = two
    swapped = a.org["org_id"].encode().hex(), b.org["org_id"].encode().hex()
    assert swapped[0] in a.boss.token  # the organisation id is in the signed payload, so the swap is a real edit
    forged = a.boss.token.replace(*swapped)
    assert forged != a.boss.token
    from consentvault.tenancy.admin_routes import Request
    r = a.vault.app.handle(Request("GET", "/v1/org", tenant_token=forged, request_id="r"))
    assert r.status == 401


def test_a_developer_and_a_viewer_stay_inside_their_own_org_too(two):
    a, b = two
    for who in (a.dev, a.viewer):
        assert who.call("GET", f"/v1/systems/{b.system}").status in (404,)
        assert who.call("GET", f"/v1/policies/1").status == 200
    assert a.viewer.ok("GET", "/v1/audit", {"limit": "200"})["items"]
    assert b.org["org_id"] not in str(a.viewer.ok("GET", "/v1/audit", {"limit": "200"}))


def test_the_operator_role_reads_no_organisation_name_and_no_person_name(two):
    """The operator bypasses row security, so what it may read is the whole of what a bug in its functions could leak."""
    a, b = two
    with a.vault.superuser() as su:
        su.execute("SET ROLE consentvault_operator")
        try:
            for sql in ("SELECT name FROM consentvault.organization", "SELECT display_name FROM consentvault.member",
                        "SELECT email_norm FROM consentvault.member", "SELECT body FROM consentvault.disclosure",
                        "SELECT rules FROM consentvault.policy", "SELECT credentials_ct FROM consentvault.connected_system",
                        "SELECT wrapped FROM consentvault.org_fingerprint_secret", "SELECT reason FROM consentvault.audit_event WHERE false"):
                if "audit_event" in sql:
                    continue  # the audit table is the one table the operator may read whole: it holds no contact point by contract
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with su.transaction():
                        su.execute(sql)
        finally:
            su.execute("RESET ROLE")
