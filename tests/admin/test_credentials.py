import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from consentvault.tenancy import admin
from consentvault.tenancy.tokens import mint_org_token, org_transaction


def pem_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def pem_priv(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


@pytest.fixture
def world(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    viewer = vault.add_member(boss, "cv@acme.example", "compliance_viewer")
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme"})["brand_id"]
    src = boss.ok("POST", "/v1/sources", body={"name": "Site", "kind": "site_key", "brand_ids": [brand],
                                               "allowed_origins": ["https://acme.example"]})["source_id"]
    return vault, org, boss, dev, viewer, src


def server_source(boss, name="Back end"):
    """A source that sends from a server: the only kind a public-key capture credential may belong to."""
    brand = boss.ok("POST", "/v1/brands", body={"display_name": f"{name} brand"})["brand_id"]
    return boss.ok("POST", "/v1/sources", body={"name": name, "kind": "server", "brand_ids": [brand]})["source_id"]


def approve_a_policy(boss):
    chans = [c["channel"] for c in boss.ok("GET", "/v1/channels")["items"]]
    tpl = boss.ok("GET", "/v1/policy-templates")["items"][0]
    v = boss.ok("POST", "/v1/policies", body={"rules": tpl["rules"], "template_ref": tpl["template_ref"]})["version"]
    att = boss.ok("GET", "/v1/attestations/current")
    boss.ok("POST", f"/v1/policies/{v}:approve", body={"attestation_version": att["version"],
                                                       "attestation_sha256": att["sha256"], "accepted": True})
    return v


def test_edge_site_key_has_an_identifier_and_no_secret(world):
    vault, org, boss, dev, viewer, src = world
    c = dev.ok("POST", "/v1/credentials", body={"name": "Site key", "kind": "edge_site_key", "scope": "capture", "source_id": src})
    assert c["site_key_id"].startswith("cv_site_") and "secret" not in c and c["shown_once"] is False and "client_id" not in c
    assert c["scope"] == "capture" and c["source_id"] == src
    listed = boss.ok("GET", "/v1/credentials")["items"][0]
    assert listed["credential_id"] == c["credential_id"] and "site_key_id" not in listed and "secret" not in str(listed)
    dev.err("POST", "/v1/credentials", body={"name": "x", "kind": "edge_site_key", "scope": "capture"}, name="validation_failed")
    dev.err("POST", "/v1/credentials", body={"name": "x", "kind": "edge_site_key", "scope": "capture",
                                             "source_id": str(uuid.uuid4())}, name="not_found")


def test_a_site_key_is_refused_for_a_server_source_and_nothing_is_written(world):
    vault, org, boss, dev, viewer, src = world
    brand = boss.ok("POST", "/v1/brands", body={"display_name": "Acme Two"})["brand_id"]
    server = boss.ok("POST", "/v1/sources", body={"name": "CRM push", "kind": "server", "brand_ids": [brand]})["source_id"]
    before = len(boss.ok("GET", "/v1/credentials")["items"])
    dev.err("POST", "/v1/credentials", body={"name": "wrong", "kind": "edge_site_key", "scope": "capture", "source_id": server},
                name="validation_failed")
    assert len(boss.ok("GET", "/v1/credentials")["items"]) == before
    ok = dev.ok("POST", "/v1/credentials", body={"name": "right", "kind": "edge_site_key", "scope": "capture", "source_id": src})
    assert ok["site_key_id"].startswith("cv_site_")


def test_a_public_key_capture_credential_is_refused_for_a_website_source_and_nothing_is_written(world):
    """A server holding a public-key credential asserts the visitor address, arrival time and bot check itself, so it can never
    be filed under a website form source, whose edge facts only the ConsentVault edge may observe."""
    vault, org, boss, dev, viewer, src = world
    key = ec.generate_private_key(ec.SECP256R1())
    body = {"name": "Server", "kind": "jwt_public_key", "scope": "capture", "source_id": src,
            "public_key": pem_pub(key), "algorithm": "ES256"}
    dev.err("POST", "/v1/credentials", body=body, name="validation_failed")
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.credential WHERE name = 'Server'").fetchone()["n"] == 0
        assert su.execute("SELECT count(*) AS n FROM consentvault.audit_event WHERE action = 'credential.issued'").fetchone()["n"] == 0
    ok = dev.ok("POST", "/v1/credentials", body={**body, "source_id": server_source(boss)})
    assert ok["client_id"] == ok["credential_id"]


@pytest.mark.parametrize("make,alg", [(lambda: ec.generate_private_key(ec.SECP256R1()), "ES256"),
                                      (lambda: ed25519.Ed25519PrivateKey.generate(), "EdDSA")])
def test_public_key_credentials(world, make, alg):
    vault, org, boss, dev, viewer, src = world
    src = server_source(boss)
    key = make()
    c = dev.ok("POST", "/v1/credentials", body={"name": "Server", "kind": "jwt_public_key", "scope": "capture",
                                                "source_id": src, "public_key": pem_pub(key), "algorithm": alg})
    assert c["client_id"] == c["credential_id"] and c["algorithm"] == alg and "secret" not in c


def test_a_pasted_private_key_is_refused_and_never_stored(world):
    vault, org, boss, dev, viewer, src = world
    for key in (ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate()):
        body = {"name": "oops", "kind": "jwt_public_key", "scope": "capture", "source_id": src,
                "public_key": pem_priv(key) + "\n" + pem_pub(key), "algorithm": "ES256"}
        r = dev.err("POST", "/v1/credentials", body=body, name="private_key_refused", status=422)
        assert "BEGIN" not in str(r)
    rsa_priv = rsa.generate_private_key(65537, 2048).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                                 serialization.NoEncryption()).decode()
    dev.err("POST", "/v1/credentials", body={"name": "o", "kind": "jwt_public_key", "scope": "capture", "source_id": src,
                                             "public_key": rsa_priv, "algorithm": "ES256"}, name="private_key_refused")
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.credential WHERE name IN ('oops', 'o')").fetchone()["n"] == 0
        assert su.execute("SELECT count(*) AS n FROM consentvault.audit_event WHERE action = 'credential.issued'").fetchone()["n"] == 0


def test_public_key_must_match_its_algorithm_and_be_a_key(world):
    vault, org, boss, dev, viewer, src = world
    edkey = pem_pub(ed25519.Ed25519PrivateKey.generate())
    base = {"name": "k", "kind": "jwt_public_key", "scope": "capture", "source_id": src}
    dev.err("POST", "/v1/credentials", body={**base, "public_key": edkey, "algorithm": "ES256"}, name="validation_failed")
    dev.err("POST", "/v1/credentials", body={**base, "public_key": "hello", "algorithm": "ES256"}, name="validation_failed")
    dev.err("POST", "/v1/credentials", body={**base, "public_key": edkey, "algorithm": "RS256"}, name="validation_failed")
    p384 = pem_pub(ec.generate_private_key(ec.SECP384R1()))
    dev.err("POST", "/v1/credentials", body={**base, "public_key": p384, "algorithm": "ES256"}, name="validation_failed")


def test_hmac_secret_is_shown_once_and_stored_only_encrypted(world):
    vault, org, boss, dev, viewer, src = world
    c = dev.ok("POST", "/v1/credentials", body={"name": "Webhook", "kind": "hmac_fallback", "scope": "capture", "source_id": src})
    assert c["shown_once"] is True and len(c["secret"]) == 64
    raw = bytes.fromhex(c["secret"])
    with vault.operator() as o, org_transaction(o, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
        ct = bytes(o.execute("SELECT secret_ct FROM consentvault.credential WHERE credential_id = %s",
                             (c["credential_id"],)).fetchone()["secret_ct"])
    assert raw not in ct and vault.custody.unwrap(org["org_id"], ct) == raw
    assert "secret" not in str(boss.ok("GET", "/v1/credentials")["items"]) and c["secret"] not in str(boss.ok("GET", "/v1/credentials"))
    # the runtime role cannot read the ciphertext column
    import psycopg
    with vault.appconn() as a, pytest.raises(psycopg.errors.InsufficientPrivilege):
        with org_transaction(a, mint_org_token(vault.key, org["org_id"], ["admin"], credential_id=None)):
            a.execute("SELECT secret_ct FROM consentvault.credential")
    dev.err("POST", "/v1/credentials", body={"name": "n", "kind": "hmac_fallback", "scope": "capture"}, name="validation_failed")


def test_role_limits_on_scopes(world):
    vault, org, boss, dev, viewer, src = world
    for scope in ("gate_read", "proof_read"):
        dev.err("POST", "/v1/credentials", body={"name": "r", "kind": "hmac_fallback", "scope": scope, "source_id": src},
                name="role_not_allowed", status=403)
    for who in (dev, boss):  # nobody gets capture_verified from the portal
        who.err("POST", "/v1/credentials", body={"name": "v", "kind": "hmac_fallback", "scope": "capture_verified",
                                                 "source_id": src}, name="role_not_allowed")
    viewer.err("POST", "/v1/credentials", body={"name": "v", "kind": "hmac_fallback", "scope": "capture", "source_id": src},
               name="role_not_allowed")
    boss.err("POST", "/v1/credentials", body={"name": "v", "kind": "hmac_fallback", "scope": "admin", "source_id": src},
             name="validation_failed")
    boss.ok("POST", "/v1/credentials", body={"name": "proof", "kind": "hmac_fallback", "scope": "proof_read", "source_id": src})


def test_contact_check_credential_is_issued_with_no_policy(world):
    vault, org, boss, dev, viewer, src = world
    body = {"name": "gate", "kind": "hmac_fallback", "scope": "gate_read", "source_id": src}
    assert boss.ok("POST", "/v1/credentials", body=body)["scope"] == "gate_read"


def test_the_operator_alone_issues_capture_verified_and_never_to_a_site_key(world):
    vault, org, boss, dev, viewer, src = world
    with vault.operator() as o:
        c = admin.issue_verified_credential(o, token_key=vault.key, custody=vault.custody, operator_id="op-1", request_id="r",
                                            org_id=org["org_id"], name="verified", kind="hmac_fallback", source_id=src)
        assert c["scope"] == "capture_verified" and c["shown_once"]
        with pytest.raises(Exception) as e:
            admin.issue_verified_credential(o, token_key=vault.key, custody=vault.custody, operator_id="op-1", request_id="r",
                                            org_id=org["org_id"], name="sk", kind="edge_site_key", source_id=src)
        assert e.value.name == "validation_failed"
    listed = [i for i in boss.ok("GET", "/v1/credentials")["items"] if i["scope"] == "capture_verified"]
    assert len(listed) == 1
    assert [i["scope"] for i in dev.ok("GET", "/v1/credentials")["items"]] == []  # a developer lists capture credentials only


def test_revoke(world):
    vault, org, boss, dev, viewer, src = world
    mine = dev.ok("POST", "/v1/credentials", body={"name": "m", "kind": "hmac_fallback", "scope": "capture", "source_id": src})
    theirs = boss.ok("POST", "/v1/credentials", body={"name": "t", "kind": "hmac_fallback", "scope": "capture", "source_id": src})
    proof = boss.ok("POST", "/v1/credentials", body={"name": "p", "kind": "hmac_fallback", "scope": "proof_read", "source_id": src})
    dev.err("POST", f"/v1/credentials/{theirs['credential_id']}:revoke", body={"reason": "x"}, name="role_not_allowed")
    dev.err("POST", f"/v1/credentials/{proof['credential_id']}:revoke", body={"reason": "x"}, name="role_not_allowed")
    dev.err("POST", f"/v1/credentials/{mine['credential_id']}:revoke", body={}, name="validation_failed")
    r = dev.ok("POST", f"/v1/credentials/{mine['credential_id']}:revoke", body={"reason": "rotated"})
    assert r["revoked_at"]
    dev.err("POST", f"/v1/credentials/{mine['credential_id']}:revoke", body={"reason": "again"}, name="already_revoked", status=409)
    boss.ok("POST", f"/v1/credentials/{proof['credential_id']}:revoke", body={"reason": "any"})
    boss.err("POST", f"/v1/credentials/{uuid.uuid4()}:revoke", body={"reason": "x"}, name="not_found")
    assert {i["credential_id"] for i in boss.ok("GET", "/v1/credentials", {"status": "revoked"})["items"]} == \
        {mine["credential_id"], proof["credential_id"]}
    assert [i["credential_id"] for i in boss.ok("GET", "/v1/credentials", {"status": "active"})["items"]] == [theirs["credential_id"]]
    # the vault's own resolver, which the token endpoint uses, now says revoked
    with vault.appconn() as a:
        assert a.execute("SELECT status FROM consentvault.resolve_credential(%s)", (mine["credential_id"],)).fetchone()["status"] == "revoked"
    log = boss.ok("GET", "/v1/audit", {"action": "credential.revoked"})["items"]
    assert {r["reason"] for r in log} == {"rotated", "any"}


def test_suspended_and_offboarding_organisations_issue_nothing_new(world):
    vault, org, boss, dev, viewer, src = world
    body = {"name": "late", "kind": "hmac_fallback", "scope": "capture", "source_id": src}
    with vault.operator() as o:
        admin.set_org_status(o, token_key=vault.key, operator_id="op", request_id="r", org_id=org["org_id"], status="suspended", reason="x")
    boss.err("POST", "/v1/credentials", body=body, name="org_suspended", status=403)
    existing = boss.ok("GET", "/v1/credentials")  # reads continue
    assert existing["items"] == []
    with vault.operator() as o:
        admin.set_org_status(o, token_key=vault.key, operator_id="op", request_id="r", org_id=org["org_id"], status="offboarding", reason="x")
    boss.err("POST", "/v1/credentials", body=body, name="org_not_active", status=403)


def test_a_credential_resolves_for_the_token_endpoint_with_its_source_and_scope(world):
    vault, org, boss, dev, viewer, src = world
    src = server_source(boss)
    key = ec.generate_private_key(ec.SECP256R1())
    c = dev.ok("POST", "/v1/credentials", body={"name": "s", "kind": "jwt_public_key", "scope": "capture", "source_id": src,
                                               "public_key": pem_pub(key), "algorithm": "ES256"})
    with vault.appconn() as a:
        r = a.execute("SELECT * FROM consentvault.resolve_credential(%s)", (c["credential_id"],)).fetchone()
    assert r["scopes"] == ["capture"] and r["kind"] == "jwt_public_key" and not r["allowed_origins"]  # a server source has no origins


# ---- integration pass: a connected system's signal credential is bound through the sync lane's door ------------------
SIGNAL_SYS = {"name": "CRM", "kind": "crm", "endpoint": "https://crm.example/hook", "signature": "hmac",
              "contact_form": "fingerprint"}


def _signal_credential_of(vault, org_id, system_id):
    with vault.superuser() as su:
        return su.execute("SELECT signal_credential_id FROM consentvault.connected_system WHERE org_id = %s"
                          " AND system_id = %s", (org_id, system_id)).fetchone()["signal_credential_id"]


def test_system_create_and_edit_bind_the_signal_credential(world):
    vault, org, boss, dev, viewer, src = world
    src = server_source(boss)
    key = ec.generate_private_key(ec.SECP256R1())
    first = dev.ok("POST", "/v1/credentials", body={"name": "CRM in", "kind": "jwt_public_key", "scope": "capture",
                                                    "source_id": src, "public_key": pem_pub(key), "algorithm": "ES256"})
    second = dev.ok("POST", "/v1/credentials", body={"name": "CRM in 2", "kind": "jwt_public_key", "scope": "capture",
                                                     "source_id": src, "public_key": pem_pub(ec.generate_private_key(
                                                         ec.SECP256R1())), "algorithm": "ES256"})
    s = dev.ok("POST", "/v1/systems", body={**SIGNAL_SYS, "signal_credential_id": first["credential_id"]})
    assert str(_signal_credential_of(vault, org["org_id"], s["system_id"])) == first["credential_id"]
    dev.ok("PATCH", f"/v1/systems/{s['system_id']}", body={"signal_credential_id": second["credential_id"]})
    assert str(_signal_credential_of(vault, org["org_id"], s["system_id"])) == second["credential_id"]
    # a second system cannot carry a credential already bound, and a made-up id binds nothing (named refusal)
    dev.err("POST", "/v1/systems", body={**SIGNAL_SYS, "name": "Dialer", "signal_credential_id": second["credential_id"]},
            name="validation_failed")
    dev.err("POST", "/v1/systems", body={**SIGNAL_SYS, "name": "Dialer", "signal_credential_id": str(uuid.uuid4())},
            name="validation_failed")
    dev.err("PATCH", f"/v1/systems/{s['system_id']}", body={"signal_credential_id": "nope"}, name="validation_failed")
    assert [x["name"] for x in boss.ok("GET", "/v1/systems")["items"]] == ["CRM"]  # the refused creates rolled back
    assert str(_signal_credential_of(vault, org["org_id"], s["system_id"])) == second["credential_id"]


def test_a_signal_credential_is_unbound_back_to_none_and_audited(world):
    vault, org, boss, dev, viewer, src = world
    src = server_source(boss)
    cred = dev.ok("POST", "/v1/credentials", body={"name": "CRM in", "kind": "jwt_public_key", "scope": "capture",
                                                   "source_id": src, "public_key": pem_pub(ec.generate_private_key(
                                                       ec.SECP256R1())), "algorithm": "ES256"})
    s = dev.ok("POST", "/v1/systems", body={**SIGNAL_SYS, "signal_credential_id": cred["credential_id"]})
    dev.ok("PATCH", f"/v1/systems/{s['system_id']}", body={"signal_credential_id": None})
    assert _signal_credential_of(vault, org["org_id"], s["system_id"]) is None
    dev.ok("PATCH", f"/v1/systems/{s['system_id']}", body={"signal_credential_id": cred["credential_id"]})  # rebind
    assert str(_signal_credential_of(vault, org["org_id"], s["system_id"])) == cred["credential_id"]
    log = boss.ok("GET", "/v1/audit", {"action": "system.signal_unbound"})["items"]
    assert len(log) == 1 and cred["credential_id"] in log[0]["reason"]
    assert boss.ok("GET", "/v1/audit", {"action": "system.signal_bound"})["items"]
    dev.err("POST", "/v1/systems", body={**SIGNAL_SYS, "name": "X", "signal_credential_id": None},
            name="validation_failed")
    dev.err("PATCH", f"/v1/systems/{uuid.uuid4()}", body={"signal_credential_id": None}, name="not_found")
