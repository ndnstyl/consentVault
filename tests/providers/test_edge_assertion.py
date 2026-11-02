"""WorkOS access tokens carry no aud and no amr. Two narrow, configured accommodations keep the vault strict:
the audience may be read from the client_id claim (still required to equal the configured client id), and the
authentication method arrives in a short-lived assertion the portal edge signs with a key the vault trusts."""

import base64
import hashlib
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from consentvault.providers.errors import (
    AudienceMismatchError, EdgeKeyUnknownError, IssuerMismatchError, MfaRequiredError, ProviderConfigError, SignatureInvalidError,
    SigningKeyNotFoundError, TokenExpiredError, TokenMalformedError)
from consentvault.providers.identity import EdgeAssertionVerifier, Identity, OIDCIdentityProvider

from .test_identity import AUD, ISS, JWKS, NOW, RSA_KEY, b64, claims, sign

EDGE_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_KEY = ec.generate_private_key(ec.SECP256R1())
PEM = EDGE_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def workos_token(**over):
    """The claims a real WorkOS access token carried on the staging run: client_id, no aud, no amr."""
    c = claims(aud=None, amr=None, client_id=AUD, sid="session_1", jti="j1", auth_time=int(NOW.timestamp()))
    c.update(over)
    return sign({k: v for k, v in c.items() if v is not None})


def client_id_provider(**kw):
    return OIDCIdentityProvider(issuer=ISS, audience=AUD, jwks_fetcher=lambda: JWKS, clock=lambda: NOW,
                                audience_claim="client_id", **kw)


def test_the_client_id_claim_stands_in_for_aud_only_when_configured_and_only_if_it_matches():
    assert client_id_provider().verify(workos_token()).subject == "user-1"
    with pytest.raises(AudienceMismatchError):  # a different client's token
        client_id_provider().verify(workos_token(client_id="someone-else"))
    with pytest.raises(AudienceMismatchError):  # neither claim
        client_id_provider().verify(workos_token(client_id=None))
    # the default provider is unchanged: a token with only client_id is refused, and client_id never satisfies aud
    strict = OIDCIdentityProvider(issuer=ISS, audience=AUD, jwks_fetcher=lambda: JWKS, clock=lambda: NOW)
    with pytest.raises(AudienceMismatchError):
        strict.verify(workos_token())
    with pytest.raises(ProviderConfigError):
        OIDCIdentityProvider(issuer=ISS, audience=AUD, jwks_fetcher=lambda: JWKS, audience_claim="sub")


def test_a_client_id_provider_still_checks_the_aud_it_is_given_is_not_a_different_client():
    # a token that names another client in aud must not pass just because client_id matches
    with pytest.raises(AudienceMismatchError):
        client_id_provider().verify(workos_token(aud="another-client"))


def assertion(token, *, key=EDGE_KEY, kid="edge1", amr=("hwk", "user"), sub="user-1", iss=EdgeAssertionVerifier.ISSUER,
              aud=EdgeAssertionVerifier.AUDIENCE, iat=None, ttl=60, tok=None, alg="ES256", extra=None):
    iat = int((iat or NOW).timestamp())
    payload = {"iss": iss, "aud": aud, "sub": sub, "tok": tok or hashlib.sha256(token.encode()).hexdigest(),
               "amr": list(amr), "method": "Passkey", "iat": iat, "exp": iat + ttl, **(extra or {})}
    head = {"alg": alg, "typ": "JWT", "kid": kid}
    signing = f"{b64(json.dumps(head).encode())}.{b64(json.dumps(payload).encode())}"
    r, s = utils.decode_dss_signature(key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signing}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def who(token):
    return client_id_provider().verify(token)


def verifier(**kw):
    return EdgeAssertionVerifier({"edge1": PEM}, clock=lambda: NOW, **kw)


def test_a_signed_assertion_supplies_the_authentication_methods():
    tok = workos_token()
    assert verifier().amr_for(who(tok), tok, assertion(tok)) == ("hwk", "user")


def test_no_assertion_is_no_second_factor_and_a_bad_one_is_a_named_refusal():
    tok = workos_token()
    i = who(tok)
    with pytest.raises(MfaRequiredError):
        verifier().amr_for(i, tok, None)
    cases = [
        (assertion(tok, key=OTHER_KEY), SignatureInvalidError),
        (assertion(tok, kid="unknown"), EdgeKeyUnknownError),  # a deployment fault, not a bad caller
        (assertion(tok, iss="someone"), IssuerMismatchError),
        (assertion(tok, aud="another-service"), AudienceMismatchError),
        (assertion(tok, iat=NOW - timedelta(minutes=10)), TokenExpiredError),   # stale: a captured one does not live on
        (assertion(tok, ttl=3600), TokenExpiredError),                           # an edge never signs a long-lived one
        (assertion(tok, sub="someone-else"), IssuerMismatchError),               # for a different person
        (assertion(tok, tok="0" * 64), IssuerMismatchError),                     # for a different token
        ("not.a.jwt", TokenMalformedError),
        (assertion(tok, alg="none"), TokenMalformedError),
    ]
    for bad, exc in cases:
        with pytest.raises(exc):
            verifier().amr_for(i, tok, bad)


def test_the_token_alone_never_supplies_an_amr_when_assertions_are_on():
    # a browser cannot add an amr: even a token claiming hwk is judged by the assertion, never by itself
    tok = workos_token(amr=["hwk", "user"])
    with pytest.raises(MfaRequiredError):
        verifier().amr_for(who(tok), tok, None)


def test_verifier_needs_a_key():
    with pytest.raises(ProviderConfigError):
        EdgeAssertionVerifier({})
    assert isinstance(Identity, type)


def test_a_key_id_that_is_not_text_is_a_named_refusal_never_a_crash():
    tok = workos_token()
    i = who(tok)
    head = {"alg": "ES256", "typ": "JWT", "kid": ["edge1"]}
    good = assertion(tok).split(".")
    bad = f"{b64(json.dumps(head).encode())}.{good[1]}.{good[2]}"
    with pytest.raises(SigningKeyNotFoundError):
        verifier().amr_for(i, tok, bad)
    p = OIDCIdentityProvider(issuer=ISS, audience=AUD, jwks_fetcher=lambda: JWKS, clock=lambda: NOW)
    parts = sign(claims()).split(".")
    listed = f"{b64(json.dumps({'alg': 'RS256', 'kid': ['rsa1']}).encode())}.{parts[1]}.{parts[2]}"
    with pytest.raises(SigningKeyNotFoundError):
        p.verify(listed)


def test_the_verified_address_comes_only_from_the_signed_assertion():
    tok = workos_token()
    i = who(tok)
    v = verifier()
    a = assertion(tok, extra={"email": "Dana@Acme.example", "email_verified": True})
    got = v.check(i, tok, a)
    assert got.amr == ("hwk", "user") and got.email == "Dana@Acme.example" and got.email_verified is True
    none = v.check(i, tok, assertion(tok))
    assert none.email is None and none.email_verified is False
    odd = v.check(i, tok, assertion(tok, extra={"email": ["x"], "email_verified": "yes"}))
    assert odd.email is None and odd.email_verified is False
