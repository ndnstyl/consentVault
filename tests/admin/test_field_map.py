"""The field map admin API: a map is a new version, a version is never edited, each version records who set it, and the
widget's built-in map is shown (tasks T062, data-model.md section 3)."""

import uuid

import pytest


@pytest.fixture
def world(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme"})["brand_id"]
    src = boss.ok("POST", "/v1/sources", body={"name": "Site", "kind": "site_key", "brand_ids": [brand],
                                               "allowed_origins": ["https://acme.example"]})["source_id"]
    return vault, org, boss, dev, viewer, src


BODY = {"body_format": "form_urlencoded", "consent_paths": ["tcpa_box"], "consent_ticked_value": "on",
        "decision_time_path": "submitted_at", "wording_path": "tcpa_text",
        "contact_paths": [{"path": "phone", "kind": "phone"}, {"path": "email", "kind": "email"}]}


def test_a_source_with_no_version_lists_none_and_shows_the_widget_map(world):
    vault, org, boss, dev, viewer, src = world
    r = boss.ok("GET", f"/v1/sources/{src}/field-maps")
    assert r["items"] == []
    w = r["built_in"]
    assert w["label"] == "built_in:widget" and w["body_format"] == "json" and w["consent_paths"] == ["/checked"]
    assert w["decision_time_path"] == "/decided_at" and w["wording_path"] == "/disclosure_text"
    assert w["wording_hash_path"] == "/disclosure_sha256" and w["contact_paths"] == [{"path": "/contact", "kind": "detect"}]


def test_adding_a_version_returns_it_with_who_set_it_and_the_next_number(world):
    vault, org, boss, dev, viewer, src = world
    a = boss.ok("POST", f"/v1/sources/{src}/field-maps", body=BODY)
    assert a["map_version"] == 1 and a["set_by"] == boss.member_id and a["set_at"].endswith("Z")
    assert a["consent_paths"] == ["tcpa_box"] and a["consent_ticked_value"] == "on" and a["source_id"] == src
    assert a["contact_paths"] == BODY["contact_paths"] and a["seller_paths"] is None
    b = dev.ok("POST", f"/v1/sources/{src}/field-maps", body={**BODY, "consent_paths": ["box2"], "seller_paths": ["seller"]})
    assert b["map_version"] == 2 and b["set_by"] == dev.member_id and b["seller_paths"] == ["seller"]
    items = boss.ok("GET", f"/v1/sources/{src}/field-maps")["items"]
    assert [i["map_version"] for i in items] == [2, 1]
    assert items[1]["consent_paths"] == ["tcpa_box"] and items[1]["set_by"] == boss.member_id


def test_an_old_version_is_never_edited_and_there_is_no_edit_route(world):
    vault, org, boss, dev, viewer, src = world
    boss.ok("POST", f"/v1/sources/{src}/field-maps", body=BODY)
    boss.ok("POST", f"/v1/sources/{src}/field-maps", body={**BODY, "consent_paths": ["other"]})
    first = [i for i in boss.ok("GET", f"/v1/sources/{src}/field-maps")["items"] if i["map_version"] == 1][0]
    assert first["consent_paths"] == ["tcpa_box"]
    for method in ("PUT", "PATCH", "DELETE"):
        assert boss.call(method, f"/v1/sources/{src}/field-maps/1", body=BODY).status in (404, 405)
    with vault.superuser() as su:
        from psycopg import errors
        with pytest.raises(errors.Error):
            su.execute("UPDATE consentvault.form_field_map SET consent_paths = ARRAY['x'] WHERE map_version = 1")


def test_versions_count_per_source_and_stay_inside_the_organization(world):
    vault, org, boss, dev, viewer, src = world
    brand = boss.ok("GET", "/v1/brands")["items"][0]["brand_id"]
    other = boss.ok("POST", "/v1/sources", body={"name": "Other", "kind": "server", "brand_ids": [brand]})["source_id"]
    boss.ok("POST", f"/v1/sources/{src}/field-maps", body=BODY)
    assert boss.ok("POST", f"/v1/sources/{other}/field-maps", body=BODY)["map_version"] == 1
    assert boss.ok("GET", f"/v1/sources/{other}/field-maps")["items"][0]["source_id"] == other
    org2, boss2 = vault.org_with_admin("Beta", "boss@beta.example")
    boss2.err("GET", f"/v1/sources/{src}/field-maps", name="not_found")
    boss2.err("POST", f"/v1/sources/{src}/field-maps", body=BODY, name="not_found")
    boss.err("GET", f"/v1/sources/{uuid.uuid4()}/field-maps", name="not_found")


def test_the_viewer_role_may_not_read_or_add(world):
    vault, org, boss, dev, viewer, src = world
    viewer.err("GET", f"/v1/sources/{src}/field-maps", name="role_not_allowed")
    viewer.err("POST", f"/v1/sources/{src}/field-maps", body=BODY, name="role_not_allowed")


@pytest.mark.parametrize("patch", [
    {"body_format": "xml"}, {"body_format": None}, {"consent_paths": []}, {"consent_paths": "box"}, {"consent_paths": [1]},
    {"consent_paths": [""]}, {"contact_paths": [{"path": "p", "kind": "fax"}]}, {"contact_paths": [{"kind": "phone"}]},
    {"contact_paths": "x"}, {"decision_time_path": 5}, {"seller_paths": "x"}, {"consent_ticked_value": 5},
    {"set_by": "someone else"}, {"map_version": 9}, {"unknown_setting": "x"},
])
def test_a_malformed_map_is_refused_and_nothing_is_stored(world, patch):
    vault, org, boss, dev, viewer, src = world
    boss.err("POST", f"/v1/sources/{src}/field-maps", body={**BODY, **patch}, name="validation_failed", status=422)
    assert boss.ok("GET", f"/v1/sources/{src}/field-maps")["items"] == []


def test_a_retired_source_still_lists_but_takes_no_new_version(world):
    vault, org, boss, dev, viewer, src = world
    boss.ok("POST", f"/v1/sources/{src}/field-maps", body=BODY)
    boss.ok("PATCH", f"/v1/sources/{src}", body={"status": "retired"})
    assert len(boss.ok("GET", f"/v1/sources/{src}/field-maps")["items"]) == 1
    boss.err("POST", f"/v1/sources/{src}/field-maps", body=BODY, name="validation_failed")


def test_the_stored_version_is_what_extraction_reads_and_the_audit_names_who_added_it(world):
    vault, org, boss, dev, viewer, src = world
    boss.ok("POST", f"/v1/sources/{src}/field-maps", body=BODY)
    acts = [a["action"] for a in boss.ok("GET", "/v1/audit")["items"]]
    assert "field_map.added" in acts
    with vault.superuser() as su:
        row = su.execute("SELECT set_by, consent_paths, contact_paths FROM consentvault.form_field_map").fetchone()
    assert row["set_by"] == boss.member_id and row["consent_paths"] == ["tcpa_box"]
    assert row["contact_paths"] == BODY["contact_paths"]
