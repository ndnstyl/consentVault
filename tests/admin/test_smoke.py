def test_org_admin_brand_roundtrip(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    assert org["status"] == "trial"
    b = boss.ok("POST", "/v1/brands", body={"display_name": "Acme Roofing"})
    page = boss.ok("GET", "/v1/brands")
    assert [i["brand_id"] for i in page["items"]] == [b["brand_id"]]
