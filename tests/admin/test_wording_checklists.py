import hashlib
import uuid

import pytest


@pytest.fixture
def world(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme"})["brand_id"]
    return vault, org, boss, dev, brand


def wording(brand, body="We may text you about your account.  Reply STOP to end.\n", **over):
    return {"body": body, "label": "Signup form", "channels": ["sms"], "purposes": ["marketing"], "brand_ids": [brand],
            "effective_from": "2026-10-01T00:00:00Z", **over}


def test_wording_is_stored_and_digested_exactly_as_sent(world):
    vault, org, boss, dev, brand = world
    text = " “Curly” quotes, two  spaces, trailing newline\n"
    w = boss.ok("POST", "/v1/disclosures", body=wording(brand, text))
    assert w["sha256"] == hashlib.sha256(text.encode()).hexdigest() and w["body"] == text
    assert w["superseded_by_sha256"] is None and w["supersedes_sha256"] is None and w["registered_by"] == boss.member_id
    assert dev.ok("GET", f"/v1/disclosures/{w['sha256']}")["body"] == text
    assert "body" not in dev.ok("GET", "/v1/disclosures")["items"][0]
    boss.err("POST", "/v1/disclosures", body=wording(brand, text), name="disclosure_exists", status=409)
    again = boss.call("POST", "/v1/disclosures", None, wording(brand, text))
    assert again.body["fields"] == {"sha256": w["sha256"]}


def test_a_new_version_supersedes_the_old_one_both_ways_and_only_once(world):
    vault, org, boss, dev, brand = world
    v1 = boss.ok("POST", "/v1/disclosures", body=wording(brand, "Version one wording."))
    v2 = boss.ok("POST", "/v1/disclosures", body=wording(brand, "Version two wording.", supersedes_sha256=v1["sha256"],
                                                          version_label="v2", effective_from="2026-11-01T00:00:00Z"))
    assert v2["supersedes_sha256"] == v1["sha256"] and v2["version_label"] == "v2"
    assert boss.ok("GET", f"/v1/disclosures/{v1['sha256']}")["superseded_by_sha256"] == v2["sha256"]
    boss.err("POST", "/v1/disclosures", body=wording(brand, "Fork.", supersedes_sha256=v1["sha256"], effective_from="2026-12-01T00:00:00Z"), name="validation_failed")
    boss.err("POST", "/v1/disclosures", body=wording(brand, "Orphan.", supersedes_sha256="0" * 64), name="not_found")
    assert [w["sha256"] for w in boss.ok("GET", "/v1/disclosures", {"state": "current"})["items"]] == [v2["sha256"]]
    assert [w["sha256"] for w in boss.ok("GET", "/v1/disclosures", {"state": "superseded"})["items"]] == [v1["sha256"]]
    # nothing edits or deletes wording
    import psycopg
    with vault.migrator() as o:  # the owner's rights: the guard, not a missing grant, refuses
        from consentvault.tenancy.tokens import mint_org_token, org_transaction
        with org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                o.execute("UPDATE consentvault.disclosure SET body = 'x'")


def test_wording_input_checks(world):
    vault, org, boss, dev, brand = world
    boss.err("POST", "/v1/disclosures", body=wording(brand, channels=["fax"]), name="invalid_channel", status=422)
    boss.err("POST", "/v1/disclosures", body=wording(brand, purposes=["surveys"]), name="UnknownPurposeError", status=422)
    boss.err("POST", "/v1/disclosures", body=wording(str(uuid.uuid4())), name="unknown_brand")
    boss.err("POST", "/v1/disclosures", body=wording(brand, body="   "), name="validation_failed")
    boss.err("POST", "/v1/disclosures", body=wording(brand, effective_from="soon"), name="validation_failed")
    boss.err("POST", "/v1/disclosures", body=wording(brand, channels=[]), name="validation_failed")
    dev.err("POST", "/v1/disclosures", body=wording(brand), name="role_not_allowed")
    boss.err("GET", "/v1/disclosures/not-a-hash", name="not_found")
    boss.err("GET", f"/v1/disclosures/{'a' * 64}", name="not_found")


def test_wording_registered_here_is_usable_by_the_ledger(world):
    vault, org, boss, dev, brand = world
    w = boss.ok("POST", "/v1/disclosures", body=wording(brand, "Texts about your account. Reply STOP to end."))
    from consentvault import disclosure as d
    from consentvault.tenancy.tokens import mint_org_token, org_transaction
    with vault.appconn() as c, org_transaction(c, mint_org_token(vault.key, org["org_id"], ["capture"], credential_id=None)):
        held = d.get(c, w["sha256"])
    assert held["channels"] == ["sms"] and held["purposes"] == ["marketing"]


def test_pewc_example_points_at_a_rule_reference_and_quotes_nothing(world):
    vault, org, boss, dev, brand = world
    t = boss.ok("GET", "/v1/checklist-templates")["items"][0]
    assert t["template_ref"] == "pewc_example" and t["kind"] == "pewc" and len(t["elements"]) == 5
    refs = boss.ok("GET", "/v1/rule-references")["items"]
    assert refs[0]["citation"] == "47 CFR 64.1200" and refs[0]["source_url"].startswith("https://")
    assert refs[0]["last_reviewed_on"] is None and set(refs[0]) == {"ref_id", "version", "jurisdiction", "citation", "source_url", "last_reviewed_on"}
    assert {e["rule_reference_id"] for e in t["elements"]} == {refs[0]["ref_id"]}
    made = boss.ok("POST", "/v1/checklists", body={"kind": "pewc", "label": "Our PEWC", "elements": t["elements"]})
    got = dev.ok("GET", f"/v1/checklists/{made['version']}")
    assert got["status"] == "draft" and got["element_count"] == 5 and all(e["element_id"] for e in got["elements"])
    assert boss.ok("GET", "/v1/rule-references", {"jurisdiction": "Mars"})["items"] == []


def test_checklist_lifecycle(world):
    vault, org, boss, dev, brand = world
    c = boss.ok("POST", "/v1/checklists", body={"kind": "custom", "label": "C", "elements": [{"name": "One"}, {"name": "Two", "required": False}]})
    assert c == {"version": 1, "status": "draft"}
    boss.ok("PUT", "/v1/checklists/1", body={"label": "C2", "elements": [{"name": "Only"}]})
    boss.err("POST", "/v1/checklists/1:approve", body={}, name="acknowledgement_required", status=422)
    boss.err("POST", "/v1/checklists/1:approve", body={"acknowledged_documentation_only": "yes"}, name="acknowledgement_required")
    done = boss.ok("POST", "/v1/checklists/1:approve", body={"acknowledged_documentation_only": True})
    assert done["status"] == "approved" and done["approved_by"] == boss.member_id
    boss.err("PUT", "/v1/checklists/1", body={"elements": [{"name": "x"}]}, name="version_not_draft", status=409)
    boss.err("POST", "/v1/checklists/1:approve", body={"acknowledged_documentation_only": True}, name="version_not_draft")
    boss.err("GET", "/v1/checklists/5", name="not_found")
    assert [i["status"] for i in boss.ok("GET", "/v1/checklists", {"status": "approved"})["items"]] == ["approved"]
    assert boss.ok("GET", "/v1/checklists", {"kind": "pewc"})["items"] == []
    dev.err("POST", "/v1/checklists", body={"kind": "custom", "label": "x", "elements": [{"name": "a"}]}, name="role_not_allowed")


def test_checklist_input_checks(world):
    vault, org, boss, dev, brand = world
    for bad in ([], "nope", [{"name": ""}], [{"description": "no name"}], [{"name": "a", "required": "yes"}],
                [{"name": "a", "rule_reference_id": str(uuid.uuid4())}], [{"name": "a", "description": "x" * 501}],
                [{"name": "a", "element_id": "zzz"}]):
        boss.err("POST", "/v1/checklists", body={"kind": "custom", "label": "x", "elements": bad}, name="validation_failed", status=422)
    boss.err("POST", "/v1/checklists", body={"kind": "legal", "label": "x", "elements": [{"name": "a"}]}, name="validation_failed")
    same = str(uuid.uuid4())
    boss.err("POST", "/v1/checklists", body={"kind": "custom", "label": "x", "elements": [{"name": "a", "element_id": same},
                                                                                         {"name": "b", "element_id": same}]},
             name="validation_failed")


def _owner_tx(vault, org_id):
    from consentvault.tenancy.tokens import mint_org_token, org_transaction
    return org_transaction, mint_org_token(vault.key, org_id, ["admin"], credential_id=None)


def test_the_replaces_link_cannot_be_edited_and_both_ways_show_on_the_version_pair(world):
    import psycopg
    vault, org, boss, dev, brand = world
    v1 = boss.ok("POST", "/v1/disclosures", body=wording(brand, "Link one.", effective_from="2026-01-01T00:00:00Z"))
    v2 = boss.ok("POST", "/v1/disclosures", body=wording(brand, "Link two.", effective_from="2026-02-01T00:00:00Z",
                                                          supersedes_sha256=v1["sha256"]))
    assert dev.ok("GET", f"/v1/disclosures/{v2['sha256']}")["supersedes_sha256"] == v1["sha256"]
    assert dev.ok("GET", f"/v1/disclosures/{v1['sha256']}")["superseded_by_sha256"] == v2["sha256"]
    listed = {w["sha256"]: w for w in dev.ok("GET", "/v1/disclosures")["items"]}
    assert listed[v2["sha256"]]["supersedes_sha256"] == v1["sha256"] and listed[v1["sha256"]]["superseded_by_sha256"] == v2["sha256"]
    org_transaction, token = _owner_tx(vault, org["org_id"])
    for sql in ("UPDATE consentvault.disclosure SET supersedes_sha256 = NULL WHERE sha256 = %s",
                "DELETE FROM consentvault.disclosure WHERE sha256 = %s"):
        with vault.migrator() as o, org_transaction(o, token):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                o.execute(sql, (v2["sha256"],))


def test_a_replaces_link_must_stay_inside_the_organisation_and_come_later(world):
    vault, org, boss, dev, brand = world
    other_org, other_boss = vault.org_with_admin("Other", "boss@other.example")
    other_brand = other_boss.ok("POST", "/v1/brands", body={"display_name": "Other"})["brand_id"]
    theirs = other_boss.ok("POST", "/v1/disclosures", body=wording(other_brand, "Their wording."))
    boss.err("POST", "/v1/disclosures", body=wording(brand, "Mine.", supersedes_sha256=theirs["sha256"]), name="not_found")
    v1 = boss.ok("POST", "/v1/disclosures", body=wording(brand, "Dated one.", effective_from="2026-05-01T00:00:00Z"))
    boss.err("POST", "/v1/disclosures", body=wording(brand, "Same day.", effective_from="2026-05-01T00:00:00Z",
                                                      supersedes_sha256=v1["sha256"]), name="validation_failed")
    boss.err("POST", "/v1/disclosures", body=wording(brand, "Earlier.", effective_from="2026-04-01T00:00:00Z",
                                                      supersedes_sha256=v1["sha256"]), name="validation_failed")
    ok = boss.ok("POST", "/v1/disclosures", body=wording(brand, "Later.", effective_from="2026-06-01T00:00:00Z",
                                                          supersedes_sha256=v1["sha256"]))
    assert ok["supersedes_sha256"] == v1["sha256"]


def test_the_database_refuses_a_self_cross_organisation_or_earlier_link(world):
    import psycopg
    vault, org, boss, dev, brand = world
    other_org, other_boss = vault.org_with_admin("Other", "boss@other.example")
    other_brand = other_boss.ok("POST", "/v1/brands", body={"display_name": "Other"})["brand_id"]
    theirs = other_boss.ok("POST", "/v1/disclosures", body=wording(other_brand, "Their wording."))
    v1 = boss.ok("POST", "/v1/disclosures", body=wording(brand, "DB one.", effective_from="2026-05-01T00:00:00Z"))
    org_transaction, token = _owner_tx(vault, org["org_id"])
    ins = ("INSERT INTO consentvault.disclosure (org_id, sha256, body, label, locale, channels, purposes, supersedes_sha256,"
           " effective_from) VALUES (%s, %s, 'x', 'x', 'en', '{sms}', '{marketing}', %s, %s)")
    sha = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731
    cases = [(sha("self"), sha("self"), "2026-06-01T00:00:00Z"), (sha("cross"), theirs["sha256"], "2026-06-01T00:00:00Z"),
             (sha("early"), v1["sha256"], "2026-04-01T00:00:00Z"), (sha("ghost"), "0" * 64, "2026-06-01T00:00:00Z")]
    for new, target, when in cases:
        with vault.migrator() as o, org_transaction(o, token):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                o.execute(ins, (org["org_id"], new, target, when))
