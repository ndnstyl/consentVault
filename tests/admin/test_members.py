import threading
import uuid

import psycopg

from consentvault import db


def test_last_admin_cannot_be_demoted_or_removed(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    boss.err("PATCH", f"/v1/members/{boss.member_id}", body={"role": "developer"}, name="last_admin", status=409)
    boss.err("DELETE", f"/v1/members/{boss.member_id}", name="last_admin", status=409)
    second = vault.add_member(boss, "two@acme.example", "admin")
    boss.ok("PATCH", f"/v1/members/{boss.member_id}", body={"role": "developer"})  # now there is another admin
    second.err("DELETE", f"/v1/members/{second.member_id}", name="last_admin")
    second.ok("DELETE", f"/v1/members/{boss.member_id}")


def test_two_admins_cannot_demote_each_other_at_once(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    two = vault.add_member(boss, "two@acme.example", "admin")
    results = []
    gate = threading.Barrier(2)

    def demote(actor, target):
        gate.wait()
        results.append(actor.call("PATCH", f"/v1/members/{target.member_id}", body={"role": "compliance_viewer"}).status)

    threads = [threading.Thread(target=demote, args=(boss, two)), threading.Thread(target=demote, args=(two, boss))]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) in ([200, 403], [200, 409], [200, 401]), results  # exactly one change lands
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.member WHERE org_id = %s AND role = 'admin'",
                          (org["org_id"],)).fetchone()["n"] == 1


def test_member_list_pages_members_and_invites_newest_first(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    vault.add_member(boss, "dev@acme.example", "developer")
    boss.ok("POST", "/v1/members", body={"email": "open@acme.example", "role": "compliance_viewer"})
    only_members = boss.ok("GET", "/v1/members")
    assert {i["kind"] for i in only_members["items"]} == {"member"}
    both = boss.ok("GET", "/v1/members", {"include": "invites"})
    assert [i["kind"] for i in both["items"]].count("invite") == 1
    assert [i["created_at"] for i in both["items"]] == sorted((i["created_at"] for i in both["items"]), reverse=True)
    invited = boss.ok("GET", "/v1/members", {"status": "invited"})["items"]
    assert [(i["kind"], i["email"], i["status"]) for i in invited] == [("invite", "open@acme.example", "invited")]
    assert invited[0]["expires_at"] and invited[0]["invited_by_name"]
    assert [i["email"] for i in boss.ok("GET", "/v1/members", {"role": "developer"})["items"]] == ["dev@acme.example"]
    seen, cursor = [], None
    for _ in range(5):
        page = boss.ok("GET", "/v1/members", {"include": "invites", "limit": "1", **({"cursor": cursor} if cursor else {})})
        seen += [i["id"] for i in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 3 == len(set(seen))
    boss.err("GET", "/v1/members", {"cursor": "garbage"}, name="invalid_cursor", status=400)
    boss.err("GET", "/v1/members", {"limit": "0"}, name="validation_failed")
    boss.err("GET", "/v1/members", {"limit": "201"}, name="validation_failed")
    boss.err("GET", "/v1/members", {"role": "owner"}, name="validation_failed")


def test_a_cursor_belongs_to_its_endpoint_and_expires(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    vault.add_member(boss, "dev@acme.example", "developer")
    cur = boss.ok("GET", "/v1/members", {"limit": "1"})["next_cursor"]
    boss.err("GET", "/v1/brands", {"cursor": cur}, name="invalid_cursor")
    from consentvault.tenancy import admin_base
    stale = admin_base.encode_cursor(vault.key.secret, "GET /v1/members", ["2026-01-01 00:00:00+00", str(uuid.uuid4())], 1.0)
    boss.err("GET", "/v1/members", {"cursor": stale}, name="invalid_cursor")


def test_only_an_admin_manages_members(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    for p in (dev, viewer):
        p.err("GET", "/v1/members", name="role_not_allowed", status=403)
        p.err("POST", "/v1/members", body={"email": "x@y.example", "role": "admin"}, name="role_not_allowed")
        p.err("PATCH", f"/v1/members/{boss.member_id}", body={"role": "developer"}, name="role_not_allowed")
        p.err("DELETE", f"/v1/members/{boss.member_id}", name="role_not_allowed")


def test_unknown_member_and_bad_role(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    boss.err("PATCH", f"/v1/members/{uuid.uuid4()}", body={"role": "admin"}, name="not_found", status=404)
    boss.err("DELETE", f"/v1/members/{uuid.uuid4()}", name="not_found")
    boss.err("PATCH", f"/v1/members/{boss.member_id}", body={"role": "root"}, name="validation_failed")


def test_audit_rows_for_member_changes_name_the_target_not_the_email(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    boss.ok("PATCH", f"/v1/members/{dev.member_id}", body={"role": "compliance_viewer"})
    boss.ok("DELETE", f"/v1/members/{dev.member_id}")
    log = boss.ok("GET", "/v1/audit", {"limit": "50"})["items"]
    assert "dev@acme.example" not in str(log)
    kinds = [r["action"] for r in log]
    assert {"member.invited", "invite.accepted", "member.role_changed", "member.removed"} <= set(kinds)
