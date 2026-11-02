"""setup.md: the eight steps derived from facts, skip and un-skip, roles, audit, isolation, the table."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consentvault.tenancy.admin_routes import Request

from contract_world.world import PENDING, PHONE, need

ORDER = ["brand", "source", "wording", "credential", "first_event", "policy", "system", "confirmations"]
STEP_KEYS = {"step", "status", "required", "evidence", "blocked_reason", "skipped_by", "skipped_at", "skip_reason", "roles"}
REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def fresh(vault):
    """A brand-new organization: nothing configured yet."""
    org, boss = vault.org_with_admin("Fresh", "boss@fresh.example")
    dev = vault.add_member(boss, "dev@fresh.example", "developer")
    viewer = vault.add_member(boss, "cv@fresh.example", "compliance_viewer")
    return vault, org, boss, dev, viewer


def steps(p):
    body = p.ok("GET", "/v1/setup")
    return body, {s["step"]: s for s in body["steps"]}


def test_get_setup_lists_the_eight_steps_in_order_with_the_contract_fields(fresh):
    """setup.md GET /v1/setup (shape, order, required flags, roles)."""
    vault, org, boss, dev, viewer = fresh
    body, by = steps(boss)
    assert [s["step"] for s in body["steps"]] == ORDER and set(body) >= {"steps", "current_step", "complete", "partial"}
    assert all(set(s) == STEP_KEYS for s in body["steps"])
    assert {k: by[k]["required"] for k in ORDER} == {**{k: True for k in ORDER[:6]}, "system": False, "confirmations": False}
    assert by["brand"]["roles"] == ["admin"] and by["wording"]["roles"] == ["admin"] and by["policy"]["roles"] == ["admin"]
    assert "developer" in by["system"]["roles"] and "developer" in by["source"]["roles"] and "developer" in by["credential"]["roles"]
    assert body["current_step"] == "brand" and body["complete"] is False and body["partial"] == []
    assert by["brand"]["status"] == "to_do" and by["brand"]["evidence"] is None


def test_done_is_derived_from_the_facts_on_every_read(fresh):
    """setup.md (done is derived on every read from facts, never stored): brand, source, wording, credential, policy."""
    vault, org, boss, dev, viewer = fresh
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Fresh"})["brand_id"]
    _, by = steps(boss)
    assert by["brand"]["status"] == "done" and set(by["brand"]["evidence"]) == {"kind", "id", "at"}
    boss.ok("POST", "/v1/sources", body={"name": "Web", "kind": "server", "brand_ids": [brand]})
    assert steps(boss)[1]["source"]["status"] == "done"
    cred = boss.ok("POST", "/v1/credentials", body={"source_id": steps(boss)[1]["source"]["evidence"]["id"], "kind": "jwt_public_key",
                                                      "name": "Server key", "algorithm": "ES256", "scope": "capture", "public_key": _pem()})
    assert steps(boss)[1]["credential"]["status"] == "done"
    boss.ok("POST", f"/v1/credentials/{cred['credential_id']}:revoke", body={"reason": "test"})
    assert steps(boss)[1]["credential"]["status"] == "to_do"  # nothing stored: the fact went away, so did done


def _pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def test_first_event_and_wording_and_blocking(fresh, vault):
    """setup.md (first event done from GET /v1/health first_event; blocked needs:wording until a wording version exists)."""
    vault, org, boss, dev, viewer = fresh
    _, by = steps(boss)
    assert by["first_event"]["status"] == "blocked" and by["first_event"]["blocked_reason"] == "needs:wording"
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Fresh"})["brand_id"]
    w = boss.ok("POST", "/v1/disclosures", body={"brand_ids": [brand], "effective_from": "2026-01-01T00:00:00Z", "body": "We may text you. Reply STOP to end.", "label": "f", "locale": "en",
                                                   "channels": ["sms"], "purposes": ["marketing"]})
    _, by = steps(boss)
    assert by["wording"]["status"] == "done" and by["first_event"]["status"] == "to_do" and by["first_event"]["blocked_reason"] is None


def test_first_event_is_done_by_a_recorded_event(world):
    """setup.md (a first event is recorded: GET /v1/health first_event)."""
    o = world.a
    assert steps(o.boss)[1]["first_event"]["status"] == "to_do"
    world.capture(o, PHONE)
    got = steps(o.boss)[1]["first_event"]
    assert got["status"] == "done" and got["evidence"]["at"]


def test_policy_step_is_done_by_an_approved_policy(world):
    """setup.md (a policy is approved: GET /v1/policies?status=approved)."""
    o = world.a
    assert steps(o.boss)[1]["policy"]["status"] == "to_do"
    from isolation.cloud_harness import policy_rules
    made = o.boss.ok("POST", "/v1/policies", body={"rules": policy_rules()})
    att = o.boss.ok("GET", "/v1/attestations/current")
    o.boss.ok("POST", f"/v1/policies/{made['version']}:approve",
              body={"accepted": True, "attestation_version": att["version"], "attestation_sha256": att["sha256"]})
    assert steps(o.boss)[1]["policy"]["status"] == "done"


def test_system_step_is_done_by_a_test_push_answered_2xx_and_confirmations_by_a_rule_that_is_on(world):
    """setup.md (system: GET /v1/systems last_test answered 2xx; confirmations: a rule is on)."""
    o = world.a
    s = o.boss.ok("POST", "/v1/systems", body={"name": "Dialer", "kind": "dialer", "endpoint": "https://dialer.example/hook",
                                                 "signature": "ed25519", "contact_form": "fingerprint"})
    assert steps(o.boss)[1]["system"]["status"] == "to_do"
    with world.vault.superuser() as su:
        su.execute("UPDATE consentvault.connected_system SET last_test = %s WHERE system_id = %s",
                   (json.dumps({"at": datetime.now(timezone.utc).isoformat(), "http_status": 204, "ok": True}), s["system_id"]))
    assert steps(o.boss)[1]["system"]["status"] == "done"
    assert steps(o.boss)[1]["confirmations"]["status"] == "to_do"


def test_confirmations_step_is_done_by_a_rule_that_is_on_with_the_rule_as_evidence(world):
    """setup.md (done when a confirmation rule is on: GET /v1/confirmations/rules; evidence {kind, id, at} names the rule)."""
    from contract_world.confirm import arm, build_stack
    o = world.a
    assert steps(o.boss)[1]["confirmations"]["status"] == "to_do"
    arm(build_stack(world), o, text=False)
    got = steps(o.boss)[1]["confirmations"]
    assert got["status"] == "done" and set(got["evidence"]) == {"kind", "id", "at"} and got["evidence"]["at"]
    assert got["required"] is False and steps(o.boss)[0]["complete"] is False


def test_current_step_is_the_first_neither_done_nor_skipped_and_complete_needs_only_the_required_six(world):
    """setup.md (current_step; complete: every required step done, optional ones may stay to_do)."""
    o = world.a
    body, by = steps(o.boss)
    assert body["current_step"] == next(k for k in ORDER if by[k]["status"] not in ("done", "skipped"))
    assert by["system"]["required"] is False
    o.boss.ok("POST", "/v1/setup/steps/system:skip", body={})
    body, by = steps(o.boss)
    assert by["system"]["status"] == "skipped" and body["current_step"] != "system"


def test_skip_records_who_and_when_is_audited_and_unskip_returns_to_do(world):
    """setup.md (skip stored with who and when, audited setup.step_skipped; unskip audited setup.step_unskipped)."""
    o = world.a
    got = o.boss.ok("POST", "/v1/setup/steps/confirmations:skip", body={"reason": "later"})
    assert got["step"] == "confirmations" and got["status"] == "skipped" and got["skip_reason"] == "later"
    assert got["skipped_by"] == o.boss.member_id and got["skipped_at"]
    (row,) = world.audit(o.boss, "setup.step_skipped")
    assert row["target"]["id"] == "confirmations"
    assert row["reason"] == "later"
    back = o.boss.ok("POST", "/v1/setup/steps/confirmations:unskip", body={})
    assert back["status"] == "to_do" and back["skipped_by"] is None and back["skip_reason"] is None
    assert len(world.audit(o.boss, "setup.step_unskipped")) == 1


def test_only_system_and_confirmations_can_be_skipped_and_a_done_step_cannot(world):
    """setup.md (step_not_skippable 422; a done step cannot be skipped: validation_failed; reason at most 200)."""
    o = world.a
    for step in ("brand", "source", "wording", "credential", "first_event", "policy"):
        o.boss.err("POST", f"/v1/setup/steps/{step}:skip", body={}, name="step_not_skippable", status=422)
    world.capture(o, PHONE)
    o.boss.err("POST", "/v1/setup/steps/first_event:skip", body={}, name="step_not_skippable")
    o.boss.err("POST", "/v1/setup/steps/system:skip", body={"reason": "x" * 201}, name="validation_failed")
    assert o.boss.ok("POST", "/v1/setup/steps/system:skip", body={"reason": "x" * 200})["status"] == "skipped"


def test_a_done_optional_step_cannot_be_skipped(world):
    """setup.md (a done step cannot be skipped: validation_failed)."""
    o = world.a
    s = o.boss.ok("POST", "/v1/systems", body={"name": "Dialer", "kind": "dialer", "endpoint": "https://dialer.example/hook",
                                                 "signature": "ed25519", "contact_form": "fingerprint"})
    with world.vault.superuser() as su:
        su.execute("UPDATE consentvault.connected_system SET last_test = %s WHERE system_id = %s",
                   (json.dumps({"at": datetime.now(timezone.utc).isoformat(), "http_status": 200, "ok": True}), s["system_id"]))
    o.boss.err("POST", "/v1/setup/steps/system:skip", body={}, name="validation_failed")


def test_roles_on_setup(world):
    """setup.md and auth.md (A, D, V read; A skips both; D skips system only; V never skips)."""
    o = world.a
    for who in o.people.values():
        assert [s["step"] for s in who.ok("GET", "/v1/setup")["steps"]] == ORDER
    assert o.dev.ok("POST", "/v1/setup/steps/system:skip", body={})["status"] == "skipped"
    o.dev.err("POST", "/v1/setup/steps/confirmations:skip", body={}, name="role_not_allowed")
    o.dev.ok("POST", "/v1/setup/steps/system:unskip", body={})
    o.dev.err("POST", "/v1/setup/steps/confirmations:unskip", body={}, name="role_not_allowed")
    for path in ("system:skip", "confirmations:skip", "system:unskip"):
        o.viewer.err("POST", f"/v1/setup/steps/{path}", body={}, name="role_not_allowed")
    r = world.vault.app.handle(Request("GET", "/v1/setup", {}, None, request_id="r"))
    assert (r.status, r.body["error"]) == (401, "unauthenticated")


def test_a_suspended_organization_blocks_the_credential_and_system_steps(world):
    """setup.md (blocked: org_suspended for credential and system steps while suspended)."""
    o = world.a
    world.set_status(o, "suspended")
    _, by = steps(o.boss)
    assert by["credential"]["blocked_reason"] == "org_suspended" and by["system"]["blocked_reason"] == "org_suspended"
    assert by["credential"]["status"] == "blocked" and by["system"]["status"] == "blocked"


def test_skips_belong_to_their_organization(world):
    """setup.md (setup_step_skip row-secured by org_id; a second organization sees nothing)."""
    world.a.boss.ok("POST", "/v1/setup/steps/system:skip", body={})
    assert steps(world.b.boss)[1]["system"]["status"] != "skipped"
    assert steps(world.a.boss)[1]["system"]["status"] == "skipped"


def test_setup_actions_are_listed_for_the_audit_filter(world):
    """members.md amendment and setup.md (setup.step_skipped and setup.step_unskipped join GET /v1/audit/actions)."""
    got = {i["action"] for i in world.a.boss.ok("GET", "/v1/audit/actions", {"limit": "200"})["items"]}
    assert {"setup.step_skipped", "setup.step_unskipped"} <= got


def test_the_skip_table_stores_only_skips(world):
    """setup.md migration (setup_step_skip (org_id, step) primary key, skipped_by, skipped_at, reason; done is never stored)."""
    cols = {r["column_name"] for r in world.sql(world.a, "SELECT column_name FROM information_schema.columns WHERE table_schema = 'consentvault'"
                                                        " AND table_name = 'setup_step_skip'")}
    assert {"org_id", "step", "skipped_by", "skipped_at", "reason"} <= cols and not ({"done", "status", "completed"} & cols)
    (r,) = world.sql(world.a, "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'setup_step_skip' AND relnamespace = 'consentvault'::regnamespace")
    assert r["relrowsecurity"] and r["relforcerowsecurity"]
    up = [p for p in (REPO / "migrations").glob("*.sql") if "setup_step_skip" in p.read_text() and "CREATE TABLE" in p.read_text()]
    assert len(up) == 1 and (REPO / "migrations" / "down" / up[0].name).exists()


@pytest.mark.parametrize("step", ORDER)
def test_a_fact_that_cannot_be_read_is_null_and_named_in_partial(world, step):
    """setup.md (partial: steps whose fact could not be read; status null, never to_do or done; failed-reads switch
    setup.fact.<step>, one step at a time)."""
    with world.fail_reads("setup.fact." + step):
        body = world.a.boss.ok("GET", "/v1/setup")
    by = {s["step"]: s for s in body["steps"]}
    assert body["partial"] == [step] and by[step]["status"] is None
    assert all(by[k]["status"] is not None for k in ORDER if k != step)


def test_done_beats_skipped_and_turning_the_rule_off_returns_to_skipped(world):
    """setup.md status precedence (done over skipped over blocked over to_do; the skip row stays and skipped_by is still
    returned; the latest fact wins)."""
    from contract_world.confirm import arm, build_stack
    o = world.a
    o.boss.ok("POST", "/v1/setup/steps/confirmations:skip", body={"reason": "later"})
    assert steps(o.boss)[1]["confirmations"]["status"] == "skipped"
    stack = build_stack(world)
    arm(stack, o, text=False)
    got = steps(o.boss)[1]["confirmations"]
    assert got["status"] == "done" and got["skipped_by"] == o.boss.member_id
    o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/email", body={"enabled": False, "sending_brand_id": o.brand_id})
    assert steps(o.boss)[1]["confirmations"]["status"] == "skipped"


def test_a_skipped_step_that_turns_blocked_reads_skipped_and_a_blocked_to_do_reads_blocked(world):
    """setup.md status precedence (skipped over blocked over to_do)."""
    o = world.a
    world.set_status(o, "suspended")
    o.boss.ok("POST", "/v1/setup/steps/system:skip", body={})
    _, by = steps(o.boss)
    assert by["system"]["status"] == "skipped" and by["credential"]["status"] == "blocked"


def test_a_step_cannot_be_marked_done_by_the_caller(fresh):
    """setup.md (done is derived from facts, never stored or set; LC-E4: no route marks a step done, and the two skip routes
    refuse a required step)."""
    vault, org, boss, dev, viewer = fresh
    o = type("P", (), {"boss": boss})()
    for suffix in (":done", ":complete", ":mark_done"):
        r = o.boss.call("POST", f"/v1/setup/steps/brand{suffix}", body={})
        assert (r.status, r.body["error"]) == (404, "not_found"), suffix
    r = o.boss.call("PUT", "/v1/setup/steps/brand", body={"status": "done"})
    assert r.status in (404, 405) or r.body["error"] == "not_found"
    o.boss.err("POST", "/v1/setup/steps/brand:skip", body={}, name="step_not_skippable", status=422)
    assert steps(o.boss)[1]["brand"]["status"] == "to_do"


def test_a_paused_connected_system_does_not_count_as_done(world):
    """setup.md (a connected system with a test push answered 2xx is done; a paused one is not)."""
    o = world.a
    s = o.boss.ok("POST", "/v1/systems", body={"name": "Dialer", "kind": "dialer", "endpoint": "https://dialer.example/hook",
                                                 "signature": "ed25519", "contact_form": "fingerprint"})
    with world.vault.superuser() as su:
        su.execute("UPDATE consentvault.connected_system SET last_test = %s WHERE system_id = %s",
                   (json.dumps({"at": datetime.now(timezone.utc).isoformat(), "http_status": 204, "ok": True}), s["system_id"]))
    assert steps(o.boss)[1]["system"]["status"] == "done"
    o.boss.ok("PATCH", f"/v1/systems/{s['system_id']}", body={"status": "paused"})
    assert steps(o.boss)[1]["system"]["status"] == "to_do"


def test_a_fresh_organization_reads_to_do_while_another_is_fully_set_up(world):
    """setup.md (isolation: one organization's facts never make another's step done)."""
    from contract_world.confirm import arm, build_stack
    o = world.a
    world.capture(o, PHONE)
    s = o.boss.ok("POST", "/v1/systems", body={"name": "Dialer", "kind": "dialer", "endpoint": "https://dialer.example/hook",
                                                 "signature": "ed25519", "contact_form": "fingerprint"})
    with world.vault.superuser() as su:
        su.execute("UPDATE consentvault.connected_system SET last_test = %s WHERE system_id = %s",
                   (json.dumps({"at": datetime.now(timezone.utc).isoformat(), "http_status": 204, "ok": True}), s["system_id"]))
    arm(build_stack(world), o, text=False)
    done = {k for k, v in steps(o.boss)[1].items() if v["status"] == "done"}
    assert {"brand", "source", "first_event", "system", "confirmations"} <= done
    _, other_boss = world.vault.org_with_admin("Other", "boss@other.example")
    got = steps(other_boss)[1]
    assert all(v["status"] in ("to_do", "blocked") for v in got.values()), {k: v["status"] for k, v in got.items()}
    assert all(v["evidence"] is None and v["skipped_by"] is None for v in got.values())
