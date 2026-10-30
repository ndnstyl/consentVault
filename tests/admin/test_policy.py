import copy
import uuid

import pytest

from .test_credentials import approve_a_policy


@pytest.fixture
def world(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    return vault, org, boss, dev, viewer


def tpl(boss, ref="proceed_on_consent_record"):
    return [t for t in boss.ok("GET", "/v1/policy-templates")["items"] if t["template_ref"] == ref][0]


def approve(boss, v, **over):
    att = boss.ok("GET", "/v1/attestations/current")
    body = {"attestation_version": att["version"], "attestation_sha256": att["sha256"], "accepted": True, **over}
    return boss.call("POST", f"/v1/policies/{v}:approve", None, body)


def test_the_template_is_complete_and_is_never_in_force_by_itself(world):
    vault, org, boss, dev, viewer = world
    t = tpl(boss)
    cells = t["rules"]["purposes"]["marketing"]["cells"]
    assert len(cells) == 4 * 5 and {c["action"] for c in cells if c["evidence_status"] == "stop_on_record"} == {"hold"}
    assert boss.ok("GET", "/v1/policies", {"status": "approved"})["items"] == []
    for who in (dev, viewer):  # everyone may read the starting points
        assert who.ok("GET", "/v1/policy-templates")["items"]


def test_draft_edit_and_incomplete_policies(world):
    vault, org, boss, dev, viewer = world
    rules = copy.deepcopy(tpl(boss)["rules"])
    v = boss.ok("POST", "/v1/policies", body={"rules": rules, "template_ref": "proceed_on_consent_record"})
    assert v == {"version": 1, "status": "draft"}
    short = copy.deepcopy(rules)
    dropped = short["purposes"]["marketing"]["cells"].pop(0)
    r = boss.err("POST", "/v1/policies", body={"rules": short}, name="policy_incomplete", status=422)
    assert f"marketing/{dropped['channel']}/{dropped['evidence_status']}" in r["fields"]["missing"]
    boss.err("POST", "/v1/policies", body={"rules": {"schema_version": 1, "purposes": {}}}, name="policy_incomplete")
    boss.err("PUT", "/v1/policies/1", body={"rules": short}, name="policy_incomplete")
    assert boss.ok("PUT", "/v1/policies/1", body={"rules": rules})["status"] == "draft"
    boss.err("PUT", "/v1/policies/9", body={"rules": rules}, name="not_found", status=404)


def test_a_stop_can_only_hold(world):
    vault, org, boss, dev, viewer = world
    bad = copy.deepcopy(tpl(boss)["rules"])
    for c in bad["purposes"]["marketing"]["cells"]:
        if c["evidence_status"] == "stop_on_record" and c["channel"] == "sms":
            c["action"] = "proceed"
    r = boss.err("POST", "/v1/policies", body={"rules": bad}, name="stop_cannot_proceed", status=422)
    assert r["fields"]["cells"] == ["marketing/sms"]


def test_rules_are_checked_against_the_organisations_own_lists(world):
    vault, org, boss, dev, viewer = world
    r = copy.deepcopy(tpl(boss)["rules"])
    r["purposes"]["surveys"] = {"cells": [], "checklist_version": None}
    boss.err("POST", "/v1/policies", body={"rules": r}, name="UnknownPurposeError", status=422)
    r = copy.deepcopy(tpl(boss)["rules"])
    r["purposes"]["marketing"]["cells"][0]["channel"] = "carrier_pigeon"
    boss.err("POST", "/v1/policies", body={"rules": r}, name="invalid_channel")
    r = copy.deepcopy(tpl(boss)["rules"])
    r["purposes"]["marketing"]["cells"][0]["action"] = "maybe"
    boss.err("POST", "/v1/policies", body={"rules": r}, name="validation_failed")
    r = copy.deepcopy(tpl(boss)["rules"])
    r["purposes"]["marketing"]["cells"].append(dict(r["purposes"]["marketing"]["cells"][0]))
    boss.err("POST", "/v1/policies", body={"rules": r}, name="validation_failed")
    boss.err("POST", "/v1/policies", body={"rules": "nope"}, name="validation_failed")
    boss.err("POST", "/v1/policies", body={"rules": tpl(boss)["rules"], "template_ref": "made_up"}, name="validation_failed")
    boss.err("POST", "/v1/policies", body={"rules": tpl(boss)["rules"], "based_on_version": 7}, name="not_found")


def test_a_checklist_in_a_policy_must_exist_and_be_approved(world):
    vault, org, boss, dev, viewer = world
    cl = boss.ok("POST", "/v1/checklists", body={"kind": "custom", "label": "Mine", "elements": [{"name": "Seller named"}]})["version"]
    rules = copy.deepcopy(tpl(boss)["rules"])
    rules["purposes"]["marketing"]["checklist_version"] = cl
    boss.err("POST", "/v1/policies", body={"rules": rules}, name="validation_failed")  # still a draft
    boss.ok("POST", f"/v1/checklists/{cl}:approve", body={"acknowledged_documentation_only": True})
    boss.ok("POST", "/v1/policies", body={"rules": rules})
    rules["purposes"]["marketing"]["checklist_version"] = 99
    boss.err("POST", "/v1/policies", body={"rules": rules}, name="validation_failed")


def test_approval_needs_the_attestation_exactly_and_an_admin(world):
    vault, org, boss, dev, viewer = world
    boss.ok("POST", "/v1/policies", body={"rules": tpl(boss)["rules"]})
    att = boss.ok("GET", "/v1/attestations/current")
    assert "legal sufficiency" in att["text"] and "recommended and is not required" in att["text"]
    assert att["sha256"] and att["version"] == 1
    for who in (dev, viewer):
        who.err("POST", "/v1/policies/1:approve", body={"attestation_version": 1, "attestation_sha256": att["sha256"],
                                                        "accepted": True}, name="role_not_allowed", status=403)
    assert approve(boss, 1, accepted=False).body["error"] == "acknowledgement_required"
    assert approve(boss, 1, accepted="yes").body["error"] == "acknowledgement_required"
    wrong = approve(boss, 1, attestation_sha256="0" * 64)
    assert (wrong.status, wrong.body["error"]) == (409, "attestation_mismatch")
    assert approve(boss, 1, attestation_version=2).body["error"] == "attestation_mismatch"
    assert boss.ok("GET", "/v1/policies", {"status": "approved"})["items"] == []  # nothing changed
    done = approve(boss, 1)
    assert done.status == 200 and done.body["status"] == "approved" and done.body["approved_by"] == boss.member_id
    assert done.body["retired"] is None
    one = boss.ok("GET", "/v1/policies/1")
    assert one["attestation"] == {"version": 1, "sha256": att["sha256"]} and one["rules"]


def test_the_attestation_text_is_kept_word_for_word(world):
    vault, org, boss, dev, viewer = world
    v = approve_a_policy(boss)
    att = boss.ok("GET", "/v1/attestations/current")
    from consentvault.tenancy.tokens import mint_org_token, org_transaction
    with vault.operator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        row = o.execute("SELECT attestation_text, attestation_sha256, approved_by FROM consentvault.policy_attestation"
                        " WHERE version = %s", (v,)).fetchone()
        ap = o.execute("SELECT approval_id, approved_by, attestation_sha256 FROM consentvault.policy_approval WHERE version = %s",
                       (v,)).fetchone()
    assert row["attestation_text"] == att["text"] and row["attestation_sha256"] == att["sha256"]
    assert str(row["approved_by"]) == boss.member_id == str(ap["approved_by"])
    import psycopg
    from consentvault import db
    with vault.migrator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):  # the guard refuses even the owner's rights
            o.execute("UPDATE consentvault.policy_attestation SET attestation_text = 'x'")


def test_one_policy_in_force_and_approval_retires_the_previous(world):
    vault, org, boss, dev, viewer = world
    boss.ok("POST", "/v1/policies", body={"rules": tpl(boss)["rules"]})
    boss.ok("POST", "/v1/policies", body={"rules": tpl(boss, "hold_everything")["rules"], "based_on_version": None})
    assert approve(boss, 1).status == 200
    second = approve(boss, 2)
    assert second.status == 200 and second.body["retired"]["version"] == 1
    inforce = boss.ok("GET", "/v1/policies", {"status": "approved"})["items"]
    assert [p["version"] for p in inforce] == [2]
    old = boss.ok("GET", "/v1/policies/1")
    assert old["status"] == "retired" and old["retired_by_version"] == 2 and old["retired_at"]
    boss.err("PUT", "/v1/policies/1", body={"rules": old["rules"]}, name="version_not_draft", status=409)
    assert approve(boss, 2).body["error"] == "version_not_draft"
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.policy WHERE status = 'approved'").fetchone()["n"] == 1


def test_a_draft_based_on_an_older_policy_is_superseded_by_a_newer_approval(world):
    vault, org, boss, dev, viewer = world
    boss.ok("POST", "/v1/policies", body={"rules": tpl(boss)["rules"]})  # v1
    approve(boss, 1)
    boss.ok("POST", "/v1/policies", body={"rules": tpl(boss)["rules"], "based_on_version": 1})  # v2 draft from v1
    boss.ok("POST", "/v1/policies", body={"rules": tpl(boss, "hold_everything")["rules"], "based_on_version": 1})  # v3
    assert approve(boss, 2).status == 200
    late = approve(boss, 3)
    assert (late.status, late.body["error"], late.body["fields"]) == (409, "policy_superseded", {"newer_version": 2})
    assert boss.ok("GET", "/v1/policies/3")["status"] == "draft"


def test_policy_lists_filter_and_page_and_roles_read(world):
    vault, org, boss, dev, viewer = world
    for _ in range(3):
        boss.ok("POST", "/v1/policies", body={"rules": tpl(boss)["rules"]})
    approve(boss, 2)
    assert [p["version"] for p in boss.ok("GET", "/v1/policies", {"status": "draft"})["items"]] == [3, 1]
    page = viewer.ok("GET", "/v1/policies", {"limit": "2"})
    assert len(page["items"]) == 2 and page["next_cursor"]
    assert dev.ok("GET", "/v1/policies/2")["status"] == "approved"
    for who in (dev, viewer):
        who.err("POST", "/v1/policies", body={"rules": tpl(boss)["rules"]}, name="role_not_allowed")
    boss.err("GET", "/v1/policies/abc", name="not_found")
    boss.err("GET", "/v1/policies", {"status": "live"}, name="validation_failed")


def test_policy_changes_are_audited(world):
    vault, org, boss, dev, viewer = world
    boss.ok("POST", "/v1/policies", body={"rules": tpl(boss)["rules"]})
    approve(boss, 1)
    acts = {r["action"] for r in viewer.ok("GET", "/v1/audit")["items"]}  # a compliance viewer reads the log
    assert {"policy.drafted", "policy.approved"} <= acts
    dev.err("GET", "/v1/audit", name="role_not_allowed")


# ---- integration pass: rules.narrowing is validated and kept by the admin lane, never dropped ---------------------------
def test_narrowing_rules_are_kept_and_checked_when_a_policy_is_written(world):
    vault, org, boss = world[0], world[1], world[2]
    tpl = boss.ok("GET", "/v1/policy-templates")["items"][0]["rules"]
    narrowing = [{"kind": "time_window", "start": "08:00", "end": "21:00", "tz": "America/New_York",
                  "rule_reference_id": "ref-1"},
                 {"kind": "require_verified_contact", "channels": ["sms"]}]
    v = boss.ok("POST", "/v1/policies", body={"rules": {**tpl, "narrowing": narrowing}})["version"]
    assert boss.ok("GET", f"/v1/policies/{v}")["rules"]["narrowing"] == narrowing
    for bad in ([{"kind": "make_it_proceed"}], [{"kind": "time_window", "start": "8am", "end": "21:00", "tz": "UTC"}],
                [{"kind": "max_age_of_consent", "days": 30, "extra": 1}], {"kind": "max_age_of_consent"}):
        r = boss.err("POST", "/v1/policies", body={"rules": {**tpl, "narrowing": bad}}, name="validation_failed")
        assert "rules.narrowing" in str(r)
    boss.err("POST", "/v1/policies", body={"rules": {**tpl, "narrowing": [
        {"kind": "require_channel_scope", "channels": ["fax"]}]}}, name="invalid_channel")
    boss.err("POST", "/v1/policies", body={"rules": {**tpl, "surprise": True}}, name="validation_failed")


def test_a_policy_with_an_unavailable_cell_set_to_proceed_is_refused(world):
    """Second-wave review: a failed read never proceeds, so no policy may say it does."""
    boss = world[2]
    tpl = boss.ok("GET", "/v1/policy-templates")["items"][0]["rules"]
    bad = {**tpl, "purposes": {p: {**spec, "cells": [{**c, "action": "proceed"} if c["evidence_status"] == "unavailable"
                                                      else c for c in spec["cells"]]}
                               for p, spec in tpl["purposes"].items()}}
    r = boss.err("POST", "/v1/policies", body={"rules": bad}, name="unavailable_cannot_proceed", status=422)
    assert r["fields"]["cells"]
