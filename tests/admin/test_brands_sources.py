import uuid


def mk(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    return org, boss, dev


def test_brands_are_admin_to_add_and_admin_or_developer_to_read(vault):
    org, boss, dev = mk(vault)
    b = boss.ok("POST", "/v1/brands", body={"display_name": "  Acme Roofing "})
    assert b["display_name"] == "Acme Roofing"
    boss.err("POST", "/v1/brands", body={"display_name": "acme roofing"}, name="brand_exists", status=409)
    dev.err("POST", "/v1/brands", body={"display_name": "Sneaky"}, name="role_not_allowed")
    boss.err("POST", "/v1/brands", body={"display_name": ""}, name="validation_failed", status=422)
    boss.err("POST", "/v1/brands", body={}, name="validation_failed")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    viewer.err("GET", "/v1/brands", name="role_not_allowed")
    got = dev.ok("GET", "/v1/brands")["items"]
    assert got == [{"brand_id": b["brand_id"], "display_name": "Acme Roofing", "created_at": b["created_at"],
                    "source_count": 0, "disclosure_count": 0}]


def test_brands_sort_by_name_and_page(vault):
    org, boss, dev = mk(vault)
    for n in ("Charlie", "alpha", "Bravo"):
        boss.ok("POST", "/v1/brands", body={"display_name": n})
    names, cur = [], None
    while True:
        p = boss.ok("GET", "/v1/brands", {"limit": "2", **({"cursor": cur} if cur else {})})
        names += [i["display_name"] for i in p["items"]]
        cur = p["next_cursor"]
        if not cur:
            break
    assert names == ["alpha", "Bravo", "Charlie"]


def test_site_key_source_rules(vault):
    org, boss, dev = mk(vault)
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme"})["brand_id"]
    body = {"name": "Landing", "kind": "site_key", "brand_ids": [brand], "allowed_origins": ["https://acme.example"]}
    s = dev.ok("POST", "/v1/sources", body=body)  # a developer manages sources
    assert s["status"] == "active" and s["allowed_origins"] == ["https://acme.example"] and s["last_event_at"] is None
    boss.err("POST", "/v1/sources", body=body, name="source_exists", status=409)
    for bad in ("https://acme.example/path", "acme.example", "ftp://x.example", "https://", "https://a b.example"):
        boss.err("POST", "/v1/sources", body={**body, "name": "X" + bad, "allowed_origins": [bad]},
                 name="invalid_origin", status=422)
    boss.err("POST", "/v1/sources", body={**body, "name": "NoOrigin", "allowed_origins": []}, name="validation_failed")
    boss.err("POST", "/v1/sources", body={**body, "name": "BadBrand", "brand_ids": [str(uuid.uuid4())]}, name="unknown_brand")
    boss.err("POST", "/v1/sources", body={**body, "name": "NoBrand", "brand_ids": []}, name="validation_failed")
    boss.err("POST", "/v1/sources", body={**body, "name": "Kind", "kind": "pigeon"}, name="validation_failed")


def test_server_source_takes_no_origins(vault):
    org, boss, dev = mk(vault)
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme"})["brand_id"]
    ok = boss.ok("POST", "/v1/sources", body={"name": "CRM push", "kind": "server", "brand_ids": [brand]})
    assert ok["kind"] == "server" and ok["allowed_origins"] == []
    boss.err("POST", "/v1/sources", body={"name": "CRM 2", "kind": "server", "brand_ids": [brand],
                                          "allowed_origins": ["https://x.example"]}, name="validation_failed")


def test_source_edit_retire_filters_and_list(vault):
    org, boss, dev = mk(vault)
    b1 = boss.ok("POST", "/v1/brands", body={"display_name": "One"})["brand_id"]
    b2 = boss.ok("POST", "/v1/brands", body={"display_name": "Two"})["brand_id"]
    s1 = boss.ok("POST", "/v1/sources", body={"name": "S1", "kind": "site_key", "brand_ids": [b1],
                                              "allowed_origins": ["https://one.example"]})
    s2 = boss.ok("POST", "/v1/sources", body={"name": "S2", "kind": "server", "brand_ids": [b2]})
    edited = dev.ok("PATCH", f"/v1/sources/{s1['source_id']}", body={"name": "S1b", "brand_ids": [b1, b2],
                                                                    "allowed_origins": ["https://one.example:8443"]})
    assert edited["name"] == "S1b" and sorted(edited["brand_ids"]) == sorted([b1, b2])
    boss.err("PATCH", f"/v1/sources/{s1['source_id']}", body={"name": "S2"}, name="source_exists")
    boss.err("PATCH", f"/v1/sources/{uuid.uuid4()}", body={"name": "Z"}, name="not_found", status=404)
    boss.err("PATCH", f"/v1/sources/{s2['source_id']}", body={"allowed_origins": ["https://x.example"]}, name="validation_failed")
    boss.err("PATCH", f"/v1/sources/{s2['source_id']}", body={"status": "active"}, name="validation_failed")
    assert boss.ok("PATCH", f"/v1/sources/{s2['source_id']}", body={"status": "retired"})["status"] == "retired"
    boss.err("PATCH", f"/v1/sources/{s2['source_id']}", body={"name": "again"}, name="validation_failed")
    assert [i["name"] for i in boss.ok("GET", "/v1/sources", {"status": "retired"})["items"]] == ["S2"]
    assert [i["name"] for i in boss.ok("GET", "/v1/sources", {"kind": "site_key"})["items"]] == ["S1b"]
    assert [i["name"] for i in boss.ok("GET", "/v1/sources", {"brand_id": b2})["items"]] == ["S2", "S1b"]
    assert boss.ok("GET", f"/v1/sources/{s1['source_id']}")["name"] == "S1b"
    # brand counts follow
    counts = {i["display_name"]: i["source_count"] for i in boss.ok("GET", "/v1/brands")["items"]}
    assert counts == {"One": 1, "Two": 2}


def test_last_event_fields_come_from_the_ledger_and_carry_no_personal_field(vault):
    org, boss, dev = mk(vault)
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme"})["brand_id"]
    s = boss.ok("POST", "/v1/sources", body={"name": "S", "kind": "server", "brand_ids": [brand]})
    quiet = dev.ok("GET", f"/v1/sources/{s['source_id']}")
    assert (quiet["last_event_at"], quiet["last_event_seq"], quiet["last_event_sealed"]) == (None, None, None)
    from consentvault.tenancy.tokens import mint_org_token, org_transaction
    # one event written the way the capture lane would: through the tenant crypto, under a capture token
    from consentvault.ledger import record_tenant_event
    from consentvault.tenancy.crypto import TenantCrypto
    from consentvault.tenancy.keys_adapter import CustodyKeyAdapter
    adapter = CustodyKeyAdapter(vault.custody, lambda oid: bytes(_fp(vault, str(oid))), lambda oid: bytes(_display(vault, str(oid))))
    crypto = TenantCrypto(adapter)
    with vault.appconn() as c, org_transaction(c, mint_org_token(vault.key, org["org_id"], ["capture", "gate_read"], credential_id=None)):
        from consentvault import disclosure as disc
        sha = disc.register(c, "We may text you about your account. Reply STOP to end.", "f", "en", ["sms"], ["marketing"])
        e = record_tenant_event(c, crypto, contact="+15555550142", event_type="grant", channels=["sms"], purposes=["marketing"],
                                method="checkbox", origin="consumer", disclosure_sha256=sha, source_id=uuid.UUID(s["source_id"]),
                                brand_ids=[uuid.UUID(brand)])
    got = dev.ok("GET", f"/v1/sources/{s['source_id']}")  # a developer cannot read events, yet sees the counts
    assert got["last_event_seq"] == e.seq and got["last_event_sealed"] is False and got["last_event_at"]
    assert "5555550142" not in str(got)
    h = dev.ok("GET", "/v1/health")
    assert h["first_event"]["sealed"] is False


def _display(vault, org_id):
    from consentvault.tenancy.tokens import mint_org_token, org_transaction
    with vault.operator() as c, org_transaction(c, mint_org_token(vault.key, org_id, ["admin", "worker:display_key"], credential_id=None)):
        return c.execute("SELECT wrapped FROM consentvault.org_display_key").fetchone()["wrapped"]


def _fp(vault, org_id):
    from consentvault.tenancy.tokens import mint_org_token, org_transaction
    with vault.operator() as c, org_transaction(c, mint_org_token(vault.key, org_id, ["admin"], credential_id=None)):
        return c.execute("SELECT wrapped FROM consentvault.org_fingerprint_secret").fetchone()["wrapped"]
