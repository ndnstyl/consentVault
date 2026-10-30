import uuid

import pytest

from consentvault.tenancy import admin, audit
from consentvault.tenancy.tokens import mint_org_token, org_transaction


@pytest.fixture
def world(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    return vault, org, boss, dev, viewer


# ---- retention ---------------------------------------------------------------------------------------------------------
def test_retention_starts_at_the_platform_minimum_and_only_rises_with_history(world):
    vault, org, boss, dev, viewer = world
    first = viewer.ok("GET", "/v1/retention")
    assert first["platform_minimum_years"] == 5 and first["current"]["evidence_years"] == 5 and first["current"]["set_by"] is None
    set7 = boss.ok("PUT", "/v1/retention", body={"evidence_years": 7, "reason": "contract says seven"})
    assert set7["version"] == 2 and set7["evidence_years"] == 7 and set7["applies_from"]
    got = boss.ok("GET", "/v1/retention")
    assert got["current"] == {"version": 2, "evidence_years": 7, "applies_from": set7["applies_from"], "set_by": boss.member_id}
    assert [i["version"] for i in got["items"]] == [2, 1]  # history, newest first, nothing rewritten
    boss.ok("PUT", "/v1/retention", body={"evidence_years": 5, "reason": "back to the minimum"})  # lowering to the floor is allowed
    page = boss.ok("GET", "/v1/retention", {"limit": "1"})
    assert len(page["items"]) == 1 and page["next_cursor"] and page["current"]["version"] == 3


def test_retention_refusals(world):
    vault, org, boss, dev, viewer = world
    boss.err("PUT", "/v1/retention", body={"evidence_years": 4, "reason": "less"}, name="below_platform_minimum", status=422)
    for bad in ({"evidence_years": "7", "reason": "x"}, {"evidence_years": True, "reason": "x"}, {"evidence_years": 7},
                {"evidence_years": 101, "reason": "x"}):
        boss.err("PUT", "/v1/retention", body=bad, name="validation_failed")
    for who in (dev, viewer):
        who.err("PUT", "/v1/retention", body={"evidence_years": 8, "reason": "x"}, name="role_not_allowed")
    dev.err("GET", "/v1/retention", name="role_not_allowed")
    import psycopg
    with vault.migrator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):  # append-only, even for the owner's rights
            o.execute("UPDATE consentvault.retention_policy SET evidence_years = 99")


# ---- connected systems -------------------------------------------------------------------------------------------------
SYS = {"name": "Dialer", "kind": "dialer", "endpoint": "https://dialer.example/hook", "signature": "ed25519",
       "contact_form": "fingerprint"}


def test_systems_register_with_a_one_time_secret_or_a_readable_public_key(world):
    vault, org, boss, dev, viewer = world
    ed = dev.ok("POST", "/v1/systems", body=SYS)
    assert ed["public_key"].startswith("-----BEGIN PUBLIC KEY-----") and "hmac_secret" not in ed
    assert ed["retry_window_hours"] == 24 and ed["status"] == "active" and ed["counts"] is None and ed["partial"] == ["counts"]
    hm = boss.ok("POST", "/v1/systems", body={**SYS, "name": "CRM", "kind": "crm", "signature": "hmac"})
    assert len(hm["hmac_secret"]) == 64 and hm["public_key"] is None
    listed = viewer.ok("GET", "/v1/systems")["items"]
    assert [s["name"] for s in listed] == ["CRM", "Dialer"] and "hmac_secret" not in str(listed) and "PRIVATE" not in str(listed)
    assert viewer.ok("GET", f"/v1/systems/{ed['system_id']}")["public_key"] == ed["public_key"]
    # the private half and the HMAC secret exist only wrapped under the organisation key
    with vault.operator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        rows = {r["name"]: bytes(r["credentials_ct"]) for r in o.execute("SELECT name, credentials_ct FROM consentvault.connected_system")}
    assert vault.custody.unwrap(org["org_id"], rows["CRM"]) == bytes.fromhex(hm["hmac_secret"])
    assert len(vault.custody.unwrap(org["org_id"], rows["Dialer"])) == 32
    import psycopg
    with vault.appconn() as a, pytest.raises(psycopg.errors.InsufficientPrivilege):
        with org_transaction(a, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
            a.execute("SELECT credentials_ct FROM consentvault.connected_system")


def test_system_input_rules(world):
    vault, org, boss, dev, viewer = world
    boss.ok("POST", "/v1/systems", body=SYS)
    boss.err("POST", "/v1/systems", body={**SYS, "name": "dialer"}, name="system_exists", status=409)
    for url in ("http://dialer.example/hook", "ftp://x.example", "dialer.example"):
        boss.err("POST", "/v1/systems", body={**SYS, "name": url, "endpoint": url}, name="endpoint_not_https", status=422)
    for url in ("https://user:pw@dialer.example/", "https:///nohost", "https://a b.example"):
        boss.err("POST", "/v1/systems", body={**SYS, "name": url, "endpoint": url}, name="validation_failed")
    boss.err("POST", "/v1/systems", body={**SYS, "name": "k", "kind": "fax"}, name="validation_failed")
    boss.err("POST", "/v1/systems", body={**SYS, "name": "k", "signature": "rsa"}, name="validation_failed")
    boss.err("POST", "/v1/systems", body={**SYS, "name": "k", "retry_window_hours": 0}, name="validation_failed")
    viewer.err("POST", "/v1/systems", body={**SYS, "name": "v"}, name="role_not_allowed")


def test_system_edit_pause_and_the_plaintext_choice_is_audited(world):
    vault, org, boss, dev, viewer = world
    s = dev.ok("POST", "/v1/systems", body=SYS)
    p = dev.ok("PATCH", f"/v1/systems/{s['system_id']}", body={"status": "paused", "retry_window_hours": 48,
                                                              "endpoint": "https://dialer2.example/h"})
    assert (p["status"], p["retry_window_hours"], p["endpoint"]) == ("paused", 48, "https://dialer2.example/h")
    dev.err("PATCH", f"/v1/systems/{s['system_id']}", body={"signature": "hmac"}, name="validation_failed")
    dev.err("PATCH", f"/v1/systems/{s['system_id']}", body={"endpoint": "http://x.example"}, name="endpoint_not_https")
    dev.err("PATCH", f"/v1/systems/{uuid.uuid4()}", body={"status": "active"}, name="not_found")
    dev.ok("PATCH", f"/v1/systems/{s['system_id']}", body={"contact_form": "plaintext"})
    log = boss.ok("GET", "/v1/audit", {"action": "system.updated"})["items"]
    assert [r["reason"] for r in log][0] == "contact point sent in plaintext"
    assert boss.ok("GET", "/v1/systems", {"status": "paused"})["items"][0]["name"] == "Dialer"
    assert boss.ok("GET", "/v1/systems", {"kind": "crm"})["items"] == []


def test_suspended_organisations_register_no_new_systems(world):
    vault, org, boss, dev, viewer = world
    with vault.operator() as o:
        admin.set_org_status(o, token_key=vault.key, operator_id="op", request_id="r", org_id=org["org_id"], status="suspended", reason="x")
    boss.err("POST", "/v1/systems", body=SYS, name="org_suspended", status=403)


# ---- audit -------------------------------------------------------------------------------------------------------------
def test_the_audit_log_lists_filters_and_pages_newest_first(world):
    vault, org, boss, dev, viewer = world
    boss.ok("POST", "/v1/brands", body={"display_name": "A"})
    boss.ok("POST", "/v1/brands", body={"display_name": "B"})
    log = boss.ok("GET", "/v1/audit", {"limit": "200"})["items"]
    ats = [r["at"] for r in log]
    assert ats == sorted(ats, reverse=True) and log[0]["action"] == "brand.created"
    row = log[0]
    assert set(row) == {"audit_id", "at", "action", "actor", "target", "reason", "request_id"}
    assert row["actor"] == {"kind": "member", "id": boss.member_id, "display_name": row["actor"]["display_name"]} and row["actor"]["display_name"]
    assert row["target"]["kind"] == "brand" and row["request_id"].startswith("req-")
    assert [r["action"] for r in boss.ok("GET", "/v1/audit", {"action": "brand.created"})["items"]] == ["brand.created"] * 2
    assert {r["actor"]["id"] for r in boss.ok("GET", "/v1/audit", {"actor": boss.member_id, "limit": "200"})["items"]} == {boss.member_id}
    assert boss.ok("GET", "/v1/audit", {"target_kind": "brand"})["items"][0]["target"]["kind"] == "brand"
    seen, cur = [], None
    while True:
        p = viewer.ok("GET", "/v1/audit", {"limit": "3", **({"cursor": cur} if cur else {})})
        seen += [r["audit_id"] for r in p["items"]]
        cur = p["next_cursor"]
        if not cur:
            break
    assert len(seen) == len(set(seen)) == len(log)
    assert boss.ok("GET", "/v1/audit", {"from": "2999-01-01T00:00:00Z"})["items"] == []
    assert boss.ok("GET", "/v1/audit", {"to": "2000-01-01T00:00:00Z"})["items"] == []
    boss.err("GET", "/v1/audit", {"from": "2026-12-01T00:00:00Z", "to": "2026-01-01T00:00:00Z"}, name="validation_failed")
    boss.err("GET", "/v1/audit", {"action": "made.up"}, name="validation_failed")
    boss.err("GET", "/v1/audit", {"from": "yesterday"}, name="validation_failed")
    dev.err("GET", "/v1/audit", name="role_not_allowed")


def test_the_action_list_covers_every_action_the_log_uses(world):
    vault, org, boss, dev, viewer = world
    p = boss.ok("GET", "/v1/audit/actions", {"limit": "200"})
    labels = [i["label"] for i in p["items"]]
    assert labels == sorted(labels) and {i["action"] for i in p["items"]} == set(audit.ACTIONS)
    first = boss.ok("GET", "/v1/audit/actions", {"limit": "5"})
    assert len(first["items"]) == 5 and boss.ok("GET", "/v1/audit/actions", {"limit": "5", "cursor": first["next_cursor"]})["items"]
    dev.err("GET", "/v1/audit/actions", name="role_not_allowed")


def test_the_chain_verifies_and_tampering_is_detected(world):
    vault, org, boss, dev, viewer = world
    boss.ok("POST", "/v1/brands", body={"display_name": "A"})
    with vault.operator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        assert audit.chain_breaks(o) == []
        head = audit.head(o)
        assert head["seq"] >= 4
    with vault.superuser() as su:  # a database administrator can rewrite a row; the chain says so
        su.execute("ALTER TABLE consentvault.audit_event DISABLE TRIGGER audit_event_append_only")
        su.execute("UPDATE consentvault.audit_event SET reason = 'edited later' WHERE org_id = %s AND seq = 2", (org["org_id"],))
        su.execute("ALTER TABLE consentvault.audit_event ENABLE TRIGGER audit_event_append_only")
    with vault.operator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        broken = audit.chain_breaks(o)
        assert [(b["seq"], b["reason"]) for b in broken] == [(2, "row_hash_mismatch")]


def test_no_fork_no_gap_no_edit_no_delete(world):
    vault, org, boss, dev, viewer = world
    import psycopg
    tok = mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)
    with vault.migrator() as o, org_transaction(o, tok):  # the owner's rights: the guard, not a missing grant, refuses
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            o.execute("UPDATE consentvault.audit_event SET action = 'x.yy'")
    with vault.migrator() as o, org_transaction(o, tok):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            o.execute("DELETE FROM consentvault.audit_event")
    with vault.superuser() as su:  # even the owner path cannot insert a row that skips ahead or forks
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="fork or gap"):
            su.execute("INSERT INTO consentvault.audit_event (org_id, seq, actor_kind, action, target_kind, request_id, at,"
                       " prev_hash, row_hash) VALUES (%s, 99, 'system', 'a.bc', 'org', 'r', now(), %s, %s)",
                       (org["org_id"], "0" * 64, "1" * 64))
    with vault.appconn() as a, org_transaction(a, tok):  # the runtime role has no INSERT on the table
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            a.execute("INSERT INTO consentvault.audit_event (org_id, seq, actor_kind, action, target_kind, request_id, at,"
                      " prev_hash, row_hash) VALUES (%s, 99, 'system', 'a.bc', 'org', 'r', now(), %s, %s)",
                      (org["org_id"], "0" * 64, "1" * 64))


def test_concurrent_writers_never_fork_a_chain(world):
    import threading
    vault, org, boss, dev, viewer = world
    errs = []

    def work(i):
        try:
            for j in range(5):
                r = boss.call("POST", "/v1/brands", None, {"display_name": f"B{i}-{j}"})
                assert r.status == 201, r.body
        except Exception as exc:  # collected and asserted below
            errs.append(exc)

    ts = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs
    with vault.operator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        assert audit.chain_breaks(o) == []
        n = o.execute("SELECT count(*) AS n FROM consentvault.audit_event WHERE action = 'brand.created'").fetchone()["n"]
    assert n == 20


def test_the_platform_chain_is_separate_and_hidden_from_tenants(world):
    vault, org, boss, dev, viewer = world
    with vault.operator() as o:
        a = audit.platform_head(o)
        audit.append_platform(o, operator_id="op-1", action="org.status_changed", target_kind="org", target_id="x", request_id="r1")
        b = audit.platform_head(o)
        assert b["seq"] == a["seq"] + 1
    assert not any(r["actor"]["kind"] == "operator" and r["target"]["id"] == "x" for r in boss.ok("GET", "/v1/audit", {"limit": "200"})["items"])
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.audit_chain_breaks").fetchone()["n"] == 0
    import psycopg
    with vault.appconn() as a, pytest.raises(psycopg.errors.InsufficientPrivilege):
        a.execute("SELECT consentvault.append_platform_audit('x', 'a.bc', 'org', NULL, NULL, 'r')")


def test_a_contact_point_never_reaches_a_reason_by_construction_of_the_endpoints(world):
    vault, org, boss, dev, viewer = world
    s = boss.ok("POST", "/v1/brands", body={"display_name": "A"})
    assert "@" not in str([r for r in boss.ok("GET", "/v1/audit", {"limit": "200"})["items"]
                           if r["action"] not in ("member.invited",)])
