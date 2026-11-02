"""admin.md sections 2 and 3, amended after the portal build: the compliance viewer reads brand and source names and ids only,
never credentials or settings."""

import uuid



def mk(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    return org, boss, dev


def test_a_compliance_viewer_reads_brand_and_source_names_with_ids_and_nothing_else(vault):
    org, boss, dev = mk(vault)
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme Roofing"})["brand_id"]
    site = boss.ok("POST", "/v1/sources", body={"name": "Web form", "kind": "site_key", "brand_ids": [brand],
                                                "allowed_origins": ["https://acme.example"]})
    assert viewer.ok("GET", "/v1/brand-names")["items"] == [{"brand_id": brand, "display_name": "Acme Roofing"}]
    assert viewer.ok("GET", "/v1/source-names")["items"] == [{"source_id": site["source_id"], "name": "Web form"}]
    text = str(viewer.ok("GET", "/v1/source-names")) + str(viewer.ok("GET", "/v1/brand-names"))
    assert "acme.example" not in text and "site_key" not in text  # no origins, kind, brand links or status


def test_a_compliance_viewer_is_refused_every_read_that_carries_settings_or_credentials(vault):
    org, boss, dev = mk(vault)
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme Roofing"})["brand_id"]
    src = boss.ok("POST", "/v1/sources", body={"name": "CRM push", "kind": "server", "brand_ids": [brand]})["source_id"]
    for path in ("/v1/brands", "/v1/sources", f"/v1/sources/{src}", "/v1/credentials"):
        viewer.err("GET", path, name="role_not_allowed")
    for path in ("/v1/brand-names", "/v1/source-names"):
        viewer.ok("GET", path)
        for write in ("POST", "PATCH", "DELETE", "PUT"):
            assert viewer.call(write, path).status in (403, 404, 405)


def test_the_name_reads_page_and_stay_inside_the_organization(vault):
    org, boss, dev = mk(vault)
    other, other_boss = vault.org_with_admin("Other", "boss@other.example")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    for n in ("Charlie", "alpha", "Bravo"):
        boss.ok("POST", "/v1/brands", body={"display_name": n})
    other_boss.ok("POST", "/v1/brands", body={"display_name": "Theirs"})
    first = viewer.ok("GET", "/v1/brand-names", {"limit": "2"})
    assert [i["display_name"] for i in first["items"]] == ["alpha", "Bravo"] and first["next_cursor"]
    rest = viewer.ok("GET", "/v1/brand-names", {"limit": "2", "cursor": first["next_cursor"]})
    assert [i["display_name"] for i in rest["items"]] == ["Charlie"]
    viewer.err("GET", "/v1/brand-names", {"limit": "2", "cursor": "not-a-cursor"}, name="invalid_cursor")
