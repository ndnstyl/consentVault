import base64
import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from consentvault.providers.errors import (
    AudienceMismatchError, IssuerMismatchError, MfaRequiredError, ProviderConfigError, ProviderTransportError,
    SignatureInvalidError, SigningKeyNotFoundError, TokenExpiredError, TokenMalformedError, UnsupportedAlgorithmError)
from consentvault.providers.identity import (
    HttpJwksFetcher, IdentityProvider, OIDCIdentityProvider, amr_is_multi_factor)

ISS, AUD = "https://idp.example.com", "consentvault-portal"
NOW = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jint(n: int) -> str:
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_jwk(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "n": jint(n.n), "e": jint(n.e), "alg": "RS256", "use": "sig"}


def ec_jwk(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": kid, "x": jint(n.x).rjust(43, "A"), "y": jint(n.y).rjust(43, "A")}


JWKS = {"keys": [rsa_jwk(RSA_KEY, "rsa1"), ec_jwk(EC_KEY, "ec1")]}


def claims(**over):
    c = {"iss": ISS, "aud": AUD, "sub": "user-1", "exp": int((NOW + timedelta(minutes=5)).timestamp()),
         "iat": int(NOW.timestamp()), "amr": ["hwk", "user"]}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def sign(payload, *, key=RSA_KEY, kid="rsa1", alg="RS256", header_extra=None):
    header = {"alg": alg, "typ": "JWT", **({"kid": kid} if kid else {}), **(header_extra or {})}
    signing = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(payload).encode())}"
    if alg == "RS256":
        sig = key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        r, s = utils.decode_dss_signature(key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = b"x"
    return f"{signing}.{b64(sig)}"


def provider(jwks=JWKS, **kw):
    fetches = []

    def fetch():
        fetches.append(1)
        return jwks

    p = OIDCIdentityProvider(issuer=ISS, audience=AUD, jwks_fetcher=fetch, clock=lambda: NOW, **kw)
    p.fetches = fetches
    return p


def test_rs256_and_es256_tokens_verify():
    p = provider()
    assert isinstance(p, IdentityProvider)
    ident = p.verify(sign(claims()))
    assert ident.subject == "user-1" and ident.issuer == ISS and ident.multi_factor and ident.amr == ("hwk", "user")
    assert p.verify(sign(claims(), key=EC_KEY, kid="ec1", alg="ES256")).subject == "user-1"


def test_audience_list_with_matching_azp_is_accepted():
    assert provider().verify(sign(claims(aud=["other", AUD], azp=AUD))).subject == "user-1"


def test_multiple_audiences_without_azp_refused():
    with pytest.raises(AudienceMismatchError):
        provider().verify(sign(claims(aud=["other", AUD])))


def test_wrong_azp_refused():
    with pytest.raises(AudienceMismatchError):
        provider().verify(sign(claims(aud=AUD, azp="someone-else")))
    with pytest.raises(AudienceMismatchError):
        provider().verify(sign(claims(aud=["other", AUD], azp="other")))


def test_single_correct_audience_needs_no_azp():
    assert provider().verify(sign(claims(aud=AUD))).subject == "user-1"
    assert provider().verify(sign(claims(aud=[AUD]))).subject == "user-1"


def test_wrong_signature_key_refused():
    with pytest.raises(SignatureInvalidError):
        provider().verify(sign(claims(), key=OTHER_RSA))


def test_tampered_payload_refused():
    h, p, s = sign(claims()).split(".")
    forged = b64(json.dumps(claims(sub="admin")).encode())
    with pytest.raises(SignatureInvalidError):
        provider().verify(f"{h}.{forged}.{s}")


@pytest.mark.parametrize("alg", ["none", "HS256", "RS512", "PS256", None])
def test_disallowed_algorithms_refused_before_any_key_lookup(alg):
    p = provider()
    header = {"typ": "JWT", "kid": "rsa1", **({"alg": alg} if alg else {})}
    tok = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims()).encode())}.{b64(b'sig')}"
    with pytest.raises(UnsupportedAlgorithmError):
        p.verify(tok)
    assert p.fetches == []


def test_alg_confusion_rs256_header_with_ec_key_refused():
    with pytest.raises(SignatureInvalidError):
        provider().verify(sign(claims(), key=RSA_KEY, kid="ec1", alg="RS256"))


def test_unknown_kid_refused_and_refetch_is_rate_limited():
    p = provider()
    for _ in range(5):
        with pytest.raises(SigningKeyNotFoundError):
            p.verify(sign(claims(), kid="ghost"))
    assert len(p.fetches) == 1


def test_key_rotation_is_picked_up_after_the_cooldown():
    now = {"t": NOW}
    store = {"jwks": JWKS}
    q = OIDCIdentityProvider(issuer=ISS, audience=AUD, jwks_fetcher=lambda: store["jwks"], clock=lambda: now["t"])
    q.verify(sign(claims()))
    store["jwks"] = {"keys": [rsa_jwk(OTHER_RSA, "rsa2")]}
    tok = sign(claims(), key=OTHER_RSA, kid="rsa2")
    with pytest.raises(SigningKeyNotFoundError):
        q.verify(tok)
    now["t"] = NOW + timedelta(seconds=31)
    assert q.verify(sign(claims(exp=int((NOW + timedelta(minutes=9)).timestamp())), key=OTHER_RSA, kid="rsa2")).subject == "user-1"


def test_missing_kid_refused():
    with pytest.raises(SigningKeyNotFoundError):
        provider().verify(sign(claims(), kid=None))


def test_issuer_and_audience_mismatch():
    with pytest.raises(IssuerMismatchError):
        provider().verify(sign(claims(iss="https://evil.example.com")))
    with pytest.raises(AudienceMismatchError):
        provider().verify(sign(claims(aud="someone-else")))
    with pytest.raises(AudienceMismatchError):
        provider().verify(sign(claims(aud=None)))


def test_expiry_leeway_and_not_before():
    p = provider()
    past = lambda s: int((NOW - timedelta(seconds=s)).timestamp())  # noqa: E731
    assert p.verify(sign(claims(exp=past(10)))).subject == "user-1"  # inside the 30 s leeway
    with pytest.raises(TokenExpiredError):
        p.verify(sign(claims(exp=past(31))))
    with pytest.raises(TokenExpiredError):
        p.verify(sign(claims(exp=None)))
    with pytest.raises(TokenExpiredError):
        p.verify(sign(claims(exp="soon")))
    with pytest.raises(TokenExpiredError, match="not valid yet"):
        p.verify(sign(claims(nbf=int((NOW + timedelta(minutes=5)).timestamp()))))


def test_missing_subject_and_bad_amr_shape():
    with pytest.raises(TokenMalformedError):
        provider().verify(sign(claims(sub=None)))
    with pytest.raises(TokenMalformedError):
        provider().verify(sign(claims(amr="mfa")))


@pytest.mark.parametrize("amr,ok", [
    (["mfa"], True), (["pwd", "otp"], True), (["hwk", "user"], True), (["swk", "pin"], True),
    (["pwd"], False), (["otp"], False), (["hwk"], False), ([], False), (["pwd", "pin"], False)])
def test_amr_multi_factor_reading(amr, ok):
    assert amr_is_multi_factor(amr) is ok


def test_require_mfa():
    p = provider()
    with pytest.raises(MfaRequiredError):
        p.verify(sign(claims(amr=["pwd"])), require_mfa=True)
    with pytest.raises(MfaRequiredError):
        p.verify(sign(claims(amr=None)), require_mfa=True)
    assert p.verify(sign(claims(amr=["pwd"]))).multi_factor is False  # not required: single factor is reported, not refused
    assert p.verify(sign(claims(amr=["pwd", "otp"])), require_mfa=True).multi_factor is True


@pytest.mark.parametrize("tok", ["", "a.b", "a.b.c.d", None, 5, "!!!.!!!.!!!"])
def test_malformed_tokens(tok):
    with pytest.raises(TokenMalformedError):
        provider().verify(tok)


def test_header_not_json_object():
    tok = f"{b64(b'[1]')}.{b64(b'{}')}.{b64(b'x')}"
    with pytest.raises(TokenMalformedError):
        provider().verify(tok)


def test_jwks_without_keys_is_loud():
    with pytest.raises(SigningKeyNotFoundError, match="no 'keys'"):
        provider(jwks={"oops": 1}).verify(sign(claims()))


def test_broken_jwks_entry_is_named_error():
    bad = {"keys": [{"kty": "oct", "kid": "rsa1", "k": "x"}]}
    with pytest.raises(SigningKeyNotFoundError, match="unsupported key type"):
        provider(jwks=bad).verify(sign(claims()))
    bad = {"keys": [{"kty": "RSA", "kid": "rsa1"}]}
    with pytest.raises(SigningKeyNotFoundError, match="not a usable public key"):
        provider(jwks=bad).verify(sign(claims()))


def test_config_validation():
    for kw in ({"issuer": "", "audience": "a"}, {"issuer": "i", "audience": ""},
               {"issuer": "i", "audience": "a", "algorithms": ["HS256"]},
               {"issuer": "i", "audience": "a", "algorithms": []},
               {"issuer": "i", "audience": "a", "leeway_s": 9999}):
        with pytest.raises(ProviderConfigError):
            OIDCIdentityProvider(jwks_fetcher=lambda: JWKS, **kw)


def test_algorithm_allow_list_can_be_narrowed():
    p = provider(algorithms=["ES256"])
    with pytest.raises(UnsupportedAlgorithmError):
        p.verify(sign(claims()))
    assert p.verify(sign(claims(), key=EC_KEY, kid="ec1", alg="ES256")).subject == "user-1"


# HttpJwksFetcher
class FakeResp(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, result):
        self.result, self.urls = result, []

    def open(self, url, timeout):
        self.urls.append(url)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_http_jwks_fetcher_ok_and_failures():
    assert HttpJwksFetcher("https://idp.example.com/jwks", opener=FakeOpener(FakeResp(json.dumps(JWKS).encode())))() == JWKS
    with pytest.raises(ProviderTransportError):
        HttpJwksFetcher("https://idp.example.com/jwks", opener=FakeOpener(FakeResp(b"{}", status=500)))()
    with pytest.raises(ProviderTransportError):
        HttpJwksFetcher("https://idp.example.com/jwks", opener=FakeOpener(FakeResp(b"<html>")))()
    with pytest.raises(ProviderTransportError):
        HttpJwksFetcher("https://idp.example.com/jwks", opener=FakeOpener(ConnectionRefusedError("no")))()
    with pytest.raises(ProviderConfigError):
        HttpJwksFetcher("http://idp.example.com/jwks")
