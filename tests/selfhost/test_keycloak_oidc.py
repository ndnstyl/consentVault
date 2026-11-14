"""OIDCIdentityProvider against the stack's Keycloak (production mode, imported realm, own Postgres database)."""

import uuid
from datetime import datetime, timezone

import pytest

from consentvault.providers.errors import AudienceMismatchError, IssuerMismatchError, MfaRequiredError, SignatureInvalidError
from consentvault.providers.identity import HttpJwksFetcher, OIDCIdentityProvider

from .conftest import http_json

REALM = "consentvault"
TEST_CLIENT = "selfhost-test"


@pytest.fixture(scope="module")
def kc(settings):
    port = settings["KEYCLOAK_PORT"]
    base = f"http://127.0.0.1:{port}"
    status, doc, _ = http_json("POST", f"{base}/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli",
        "username": settings["KEYCLOAK_ADMIN"], "password": settings["KEYCLOAK_ADMIN_PASSWORD"]})
    assert status == 200, doc
    admin = {"Authorization": f"Bearer {doc['access_token']}"}
    # The imported realm ships the portal client only (no password grant). The test adds its own client and user.
    status, _, _ = http_json("POST", f"{base}/admin/realms/{REALM}/clients", headers=admin, data={
        "clientId": TEST_CLIENT, "publicClient": True, "directAccessGrantsEnabled": True, "standardFlowEnabled": False})
    assert status in (201, 409)
    user, pw = "u" + uuid.uuid4().hex[:8], uuid.uuid4().hex
    status, _, _ = http_json("POST", f"{base}/admin/realms/{REALM}/users", headers=admin, data={
        "username": user, "enabled": True, "email": f"{user}@example.test", "emailVerified": True,
        "firstName": "Self", "lastName": "Host",
        "credentials": [{"type": "password", "value": pw, "temporary": False}]})
    assert status == 201
    return {"base": base, "user": user, "pw": pw, "admin": admin, "port": port}


def _id_token(kc):
    status, doc, _ = http_json("POST", f"{kc['base']}/realms/{REALM}/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": TEST_CLIENT, "username": kc["user"], "password": kc["pw"], "scope": "openid"})
    assert status == 200, doc
    return doc["id_token"]


def _provider(kc, *, issuer=None, audience=TEST_CLIENT):
    return OIDCIdentityProvider(
        issuer=issuer or f"http://localhost:{kc['port']}/realms/{REALM}", audience=audience,
        jwks_fetcher=HttpJwksFetcher(f"{kc['base']}/realms/{REALM}/protocol/openid-connect/certs"),
        clock=lambda: datetime.now(timezone.utc))


def test_a_real_keycloak_token_verifies(kc):
    ident = _provider(kc).verify(_id_token(kc))
    assert ident.subject and ident.claims["preferred_username"] == kc["user"]
    assert ident.multi_factor is False  # password only


def test_issuer_is_the_configured_public_url_not_the_address_it_was_fetched_from(kc):
    claims = _provider(kc).verify(_id_token(kc)).claims
    assert claims["iss"] == f"http://localhost:{kc['port']}/realms/{REALM}"


def test_wrong_audience_and_wrong_issuer_are_refused(kc):
    tok = _id_token(kc)
    with pytest.raises(AudienceMismatchError):
        _provider(kc, audience="someone-else").verify(tok)
    with pytest.raises(IssuerMismatchError):
        _provider(kc, issuer="http://localhost:1/realms/other").verify(tok)


def test_a_tampered_token_is_refused(kc):
    h, p, s = _id_token(kc).split(".")
    flipped = ("A" if s[0] != "A" else "B") + s[1:]
    with pytest.raises(SignatureInvalidError):
        _provider(kc).verify(f"{h}.{p}.{flipped}")


def test_a_password_only_login_is_refused_where_mfa_is_required(kc):
    with pytest.raises(MfaRequiredError):
        _provider(kc).verify(_id_token(kc), require_mfa=True)


def test_the_imported_realm_is_in_force(kc):
    status, doc, _ = http_json("GET", f"{kc['base']}/admin/realms/{REALM}/clients?clientId=consentvault-portal", headers=kc["admin"])
    assert status == 200 and doc and doc[0]["directAccessGrantsEnabled"] is False
    status, doc, _ = http_json("GET", f"{kc['base']}/admin/realms/{REALM}", headers=kc["admin"])
    assert doc["bruteForceProtected"] is True and doc["registrationAllowed"] is False
