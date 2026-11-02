"""IdentityProvider: verify a person's OIDC ID or access token.

``OIDCIdentityProvider`` works with any OIDC issuer (Keycloak, Authentik, Google, WorkOS). It checks, in order:
the token's shape, the signing algorithm against an allow list (``none`` and HMAC are never accepted, so the
token cannot pick its own verification key), the signature against the issuer's JWKS, issuer, audience, expiry
and not-before, a subject, and, when asked, a multi-factor login read from the ``amr`` claim.

Multi-factor reading (RFC 8176 values): ``mfa`` alone is enough; otherwise at least one possession factor
(``hwk``, ``swk``, ``otp``, ``sc``, ``sms``, ``tel``) together with one knowledge, inherence or user-verification
factor (``pwd``, ``pin``, ``kba``, ``bio``, ``fpt``, ``face``, ``iris``, ``retina``, ``vbm``, ``user``). A passkey
with user verification (``hwk`` + ``user``) passes; a password alone, or a one-time code alone, does not.

Keys come from an injected ``jwks_fetcher`` (so tests never touch the network); ``HttpJwksFetcher`` is the real
one. Time comes from an injected clock, which is the database's (``dbclock.datetime_clock``); there is no default.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from ..safelog import describe
from ..urlguard import open_no_redirect
from .errors import (
    AudienceMismatchError,
    EdgeKeyUnknownError,
    IssuerMismatchError,
    MfaRequiredError,
    ProviderConfigError,
    ProviderTransportError,
    SignatureInvalidError,
    SigningKeyNotFoundError,
    TokenExpiredError,
    TokenMalformedError,
    UnsupportedAlgorithmError,
)

Clock = Callable[[], datetime]
JwksFetcher = Callable[[], Mapping]

ALLOWED_ALGORITHMS = ("RS256", "ES256")
AUDIENCE_CLAIMS = ("aud", "client_id")
REFETCH_COOLDOWN_S = 30
_POSSESSION = frozenset({"hwk", "swk", "otp", "sc", "sms", "tel"})
_SECOND = frozenset({"pwd", "pin", "kba", "bio", "fpt", "face", "iris", "retina", "vbm", "user"})


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    amr: tuple[str, ...]
    multi_factor: bool
    expires_at: datetime
    claims: Mapping
    auth_time: Optional[datetime] = None  # when the person last proved who they are (OIDC ``auth_time``), if the issuer says


def amr_is_multi_factor(amr: Sequence[str]) -> bool:
    s = set(amr)
    return "mfa" in s or (bool(s & _POSSESSION) and bool(s & _SECOND))


def _b64url(part: str, what: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError) as exc:
        raise TokenMalformedError(f"token {what} is not base64url") from exc


def _json_part(part: str, what: str) -> dict:
    try:
        obj = json.loads(_b64url(part, what))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TokenMalformedError(f"token {what} is not JSON") from exc
    if not isinstance(obj, dict):
        raise TokenMalformedError(f"token {what} must be a JSON object")
    return obj


def _uint(b64: str) -> int:
    return int.from_bytes(_b64url(b64, "key parameter"), "big")


def _public_key(jwk: Mapping):
    try:
        if jwk["kty"] == "RSA":
            return rsa.RSAPublicNumbers(_uint(jwk["e"]), _uint(jwk["n"])).public_key()
        if jwk["kty"] == "EC" and jwk["crv"] == "P-256":
            return ec.EllipticCurvePublicNumbers(_uint(jwk["x"]), _uint(jwk["y"]), ec.SECP256R1()).public_key()
    except (KeyError, ValueError, TokenMalformedError) as exc:
        raise SigningKeyNotFoundError(f"the JWKS entry {jwk.get('kid')!r} is not a usable public key: {describe(exc)}") from exc
    raise SigningKeyNotFoundError(f"the JWKS entry {jwk.get('kid')!r} has an unsupported key type")


class IdentityProvider(ABC):
    @abstractmethod
    def verify(self, token: str, *, require_mfa: bool = False) -> Identity:
        """Return the verified identity or raise a named IdentityError."""


class OIDCIdentityProvider(IdentityProvider):
    def __init__(self, *, issuer: str, audience: str, jwks_fetcher: JwksFetcher,
                 algorithms: Sequence[str] = ALLOWED_ALGORITHMS, clock: Optional[Clock] = None, leeway_s: int = 30,
                 audience_claim: str = "aud"):
        if not issuer or not audience:
            raise ProviderConfigError("issuer and audience are required")
        if audience_claim not in AUDIENCE_CLAIMS:
            raise ProviderConfigError(f"audience_claim must be one of {AUDIENCE_CLAIMS}, got {audience_claim!r}")
        # "client_id" is for an issuer (WorkOS) whose access tokens carry no aud: the token must then name the configured
        # client in client_id. It stands in only when aud is absent; an aud that is present is still judged as always.
        self._aud_claim = audience_claim
        bad = [a for a in algorithms if a not in ALLOWED_ALGORITHMS]
        if bad or not algorithms:
            raise ProviderConfigError(f"algorithms must be a non-empty subset of {ALLOWED_ALGORITHMS}, got {list(algorithms)}")
        if not 0 <= leeway_s <= 300:
            raise ProviderConfigError("leeway_s must be between 0 and 300")
        if clock is None:
            raise ProviderConfigError("a clock is required: the database's (dbclock.datetime_clock); there is no host-clock default")
        self._iss, self._aud, self._fetch = issuer, audience, jwks_fetcher
        self._algs, self._clock, self._leeway = tuple(algorithms), clock, leeway_s
        self._keys: dict[str, Mapping] = {}
        self._loaded_at: Optional[datetime] = None

    def _load(self) -> None:
        self._loaded_at = self._clock()
        doc = self._fetch()
        keys = doc.get("keys") if isinstance(doc, Mapping) else None
        if not isinstance(keys, list):
            raise SigningKeyNotFoundError("the issuer's JWKS has no 'keys' list")
        self._keys = {k["kid"]: k for k in keys if isinstance(k, Mapping) and k.get("kid")}

    def _key_for(self, kid: Optional[str]):
        if not kid:
            raise SigningKeyNotFoundError("the token header has no key id (kid)")
        if not isinstance(kid, str):
            raise SigningKeyNotFoundError("the token header key id (kid) must be text")
        if kid not in self._keys and (
                self._loaded_at is None or (self._clock() - self._loaded_at).total_seconds() >= REFETCH_COOLDOWN_S):
            self._load()  # covers issuer key rotation; the cooldown stops random kids from driving fetches
        if kid not in self._keys:
            raise SigningKeyNotFoundError(f"no key {kid!r} in the issuer's JWKS")
        return _public_key(self._keys[kid])

    def verify(self, token: str, *, require_mfa: bool = False) -> Identity:
        if not isinstance(token, str) or token.count(".") != 2:
            raise TokenMalformedError("a token is three dot-separated parts")
        h64, p64, s64 = token.split(".")
        header, claims, sig = _json_part(h64, "header"), _json_part(p64, "payload"), _b64url(s64, "signature")
        alg = header.get("alg")
        if alg not in self._algs:
            raise UnsupportedAlgorithmError(f"token algorithm {alg!r} is not allowed (allowed: {list(self._algs)})")
        pub = self._key_for(header.get("kid"))
        signed = f"{h64}.{p64}".encode("ascii")
        try:
            if alg == "RS256":
                if not isinstance(pub, rsa.RSAPublicKey):
                    raise SignatureInvalidError("token says RS256 but the issuer's key is not an RSA key")
                pub.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
            else:
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    raise SignatureInvalidError("token says ES256 but the issuer's key is not an EC key")
                if len(sig) != 64:
                    raise SignatureInvalidError("ES256 signature must be 64 bytes")
                der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
                pub.verify(der, signed, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise SignatureInvalidError("the token signature does not verify against the issuer's key") from exc

        if claims.get("iss") != self._iss:
            raise IssuerMismatchError(f"token issuer {claims.get('iss')!r} is not {self._iss!r}")
        aud = claims.get("aud")
        if aud is None and self._aud_claim == "client_id":
            if claims.get("client_id") != self._aud:
                raise AudienceMismatchError(f"token client_id {claims.get('client_id')!r} is not {self._aud!r}")
        else:
            auds = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
            if self._aud not in auds:
                raise AudienceMismatchError(f"token audience {aud!r} does not include {self._aud!r}")
            azp = claims.get("azp")
            if len(auds) > 1 and azp is None:
                raise AudienceMismatchError(f"token audience {aud!r} lists several audiences and has no authorized party (azp)")
            if azp is not None and azp != self._aud:
                raise AudienceMismatchError(f"token authorized party {azp!r} is not {self._aud!r}")
        now = self._clock().timestamp()
        exp, nbf = claims.get("exp"), claims.get("nbf")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise TokenExpiredError("token has no numeric exp claim")
        if now > exp + self._leeway:
            raise TokenExpiredError(f"token expired at {datetime.fromtimestamp(exp, timezone.utc).isoformat()}")
        if nbf is not None and (isinstance(nbf, bool) or not isinstance(nbf, (int, float)) or now < nbf - self._leeway):
            raise TokenExpiredError("token is not valid yet (nbf)")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise TokenMalformedError("token has no subject")
        raw_amr = claims.get("amr", [])
        amr = tuple(raw_amr) if isinstance(raw_amr, list) and all(isinstance(a, str) for a in raw_amr) else None
        if amr is None:
            raise TokenMalformedError("the amr claim must be a list of strings")
        mfa = amr_is_multi_factor(amr)
        if require_mfa and not mfa:
            raise MfaRequiredError(f"the token's amr {list(amr)} does not show a multi-factor login")
        at = claims.get("auth_time")
        auth_time = (datetime.fromtimestamp(at, timezone.utc)
                     if isinstance(at, (int, float)) and not isinstance(at, bool) and 0 < at < 4e9 else None)
        return Identity(self._iss, sub, amr, mfa, datetime.fromtimestamp(exp, timezone.utc), claims, auth_time)


class EdgeAssertionVerifier:
    """The authentication methods of a sign-in, from the portal edge Worker rather than from the token.

    Some issuers (WorkOS) put no ``amr`` in their tokens; the edge learns the method from the issuer's own server-to-server
    answer and signs a short assertion (ES256, a key only the edge holds) for each call that carries the identity token. The
    vault trusts the public keys it is configured with. An assertion names this vault as audience, the person (``sub``) and
    the exact token (``tok``, its SHA-256), so it cannot be replayed for another person or another token, and it is refused
    once older than ``max_age_s`` (default two minutes). No assertion means no second factor; the token's own ``amr`` is
    never read when assertions are in use, so nothing the browser holds can claim one.
    """

    ISSUER = "consentvault-portal-edge"
    AUDIENCE = "consentvault-vault"

    def __init__(self, keys: Mapping[str, "str | bytes"], *, clock: Optional[Clock] = None, max_age_s: int = 120, leeway_s: int = 30):
        from cryptography.hazmat.primitives import serialization

        if not keys:
            raise ProviderConfigError("at least one trusted edge public key is required")
        if not 10 <= max_age_s <= 600:
            raise ProviderConfigError("max_age_s must be between 10 and 600")
        if clock is None:
            raise ProviderConfigError("a clock is required: the database's (dbclock.datetime_clock); there is no host-clock default")
        self._keys = {}
        for kid, pem in keys.items():
            key = serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
                raise ProviderConfigError(f"edge key {kid!r} must be an ES256 (P-256) public key")
            self._keys[kid] = key
        self._clock, self._max_age, self._leeway = clock, max_age_s, leeway_s

    def amr_for(self, identity: Identity, id_token: str, assertion: Optional[str]) -> tuple[str, ...]:
        return self.check(identity, id_token, assertion).amr

    def check(self, identity: Identity, id_token: str, assertion: Optional[str]) -> "EdgeFacts":
        """Verify the assertion for this person and token; return how they signed in and the address the provider verified."""
        import hashlib

        if not assertion:
            raise MfaRequiredError("no edge assertion: the sign-in shows no second factor")
        if not isinstance(assertion, str) or assertion.count(".") != 2:
            raise TokenMalformedError("an assertion is three dot-separated parts")
        h64, p64, s64 = assertion.split(".")
        header, claims, sig = _json_part(h64, "header"), _json_part(p64, "payload"), _b64url(s64, "signature")
        if header.get("alg") != "ES256":
            raise TokenMalformedError(f"assertion algorithm {header.get('alg')!r} is not ES256")
        kid = header.get("kid")
        key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None and isinstance(kid, str) and kid:
            raise EdgeKeyUnknownError(f"the portal edge signed with key {kid!r}, which this vault does not hold: key rotation "
                                      "is out of step (add the key to CONSENTVAULT_EDGE_ASSERTION_KEYS)")
        if key is None:
            raise SigningKeyNotFoundError("the assertion header names no usable edge key id")
        if len(sig) != 64:
            raise SignatureInvalidError("ES256 signature must be 64 bytes")
        try:
            key.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                       f"{h64}.{p64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise SignatureInvalidError("the assertion signature does not verify against a trusted edge key") from exc
        if claims.get("iss") != self.ISSUER:
            raise IssuerMismatchError(f"assertion issuer {claims.get('iss')!r} is not the portal edge")
        if claims.get("aud") != self.AUDIENCE:
            raise AudienceMismatchError("the assertion is not for this vault")
        iat, exp = claims.get("iat"), claims.get("exp")
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in (iat, exp)):
            raise TokenMalformedError("assertion iat and exp must be numbers")
        now = self._clock().timestamp()
        if exp - iat > self._max_age or now > exp + self._leeway or now < iat - self._leeway:
            raise TokenExpiredError("the assertion is outside its short validity window")
        if claims.get("sub") != identity.subject:
            raise IssuerMismatchError("the assertion is for a different person")
        if claims.get("tok") != hashlib.sha256(id_token.encode()).hexdigest():
            raise IssuerMismatchError("the assertion is for a different token")
        amr = claims.get("amr")
        if not isinstance(amr, list) or not all(isinstance(a, str) for a in amr):
            raise TokenMalformedError("the assertion amr must be a list of strings")
        email = claims.get("email")
        email = email if isinstance(email, str) and email else None
        conn, wos = claims.get("sso_connection_id"), claims.get("sso_organization_id")
        conn = conn if isinstance(conn, str) and conn else None
        wos = wos if isinstance(wos, str) and wos else None
        return EdgeFacts(tuple(amr), email, email is not None and claims.get("email_verified") is True,
                         sso_connection_id=conn, sso_organization_id=wos)


@dataclass(frozen=True)
class EdgeFacts:
    amr: tuple
    email: Optional[str]
    email_verified: bool
    sso_organization_id: Optional[str] = None  # the sign-in service's organization the connection belongs to
    sso_connection_id: Optional[str] = None  # set for a company single sign-on: the identity provider answers for the second factor


class HttpJwksFetcher:
    """Fetch the issuer's JWKS over https (plain http only for loopback). ``opener`` is injectable for tests."""

    def __init__(self, url: str, *, timeout_s: float = 10.0, opener=None):
        if not (url.startswith("https://") or url.startswith(("http://127.0.0.1", "http://localhost"))):
            raise ProviderConfigError("the JWKS URL must be https (plain http only for loopback)")
        self._url, self._timeout = url, timeout_s
        self._opener = opener

    def __call__(self) -> Mapping:
        try:
            with (self._opener.open(self._url, timeout=self._timeout) if self._opener is not None
                  else open_no_redirect(urllib.request.Request(self._url), timeout=self._timeout)) as resp:
                if resp.status != 200:
                    raise ProviderTransportError(f"JWKS fetch answered HTTP {resp.status}")
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise ProviderTransportError(f"JWKS fetch answered HTTP {exc.code}") from exc
        except OSError as exc:
            raise ProviderTransportError(f"JWKS fetch unreachable: {describe(exc)}") from exc
        except json.JSONDecodeError as exc:
            raise ProviderTransportError("JWKS fetch answered with a non-JSON body") from exc
