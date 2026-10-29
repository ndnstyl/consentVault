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
one. Time comes from an injected clock.
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

from .errors import (
    AudienceMismatchError,
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
REFETCH_COOLDOWN_S = 30
_POSSESSION = frozenset({"hwk", "swk", "otp", "sc", "sms", "tel"})
_SECOND = frozenset({"pwd", "pin", "kba", "bio", "fpt", "face", "iris", "retina", "vbm", "user"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    amr: tuple[str, ...]
    multi_factor: bool
    expires_at: datetime
    claims: Mapping


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
        raise SigningKeyNotFoundError(f"the JWKS entry {jwk.get('kid')!r} is not a usable public key: {exc}") from exc
    raise SigningKeyNotFoundError(f"the JWKS entry {jwk.get('kid')!r} has an unsupported key type")


class IdentityProvider(ABC):
    @abstractmethod
    def verify(self, token: str, *, require_mfa: bool = False) -> Identity:
        """Return the verified identity or raise a named IdentityError."""


class OIDCIdentityProvider(IdentityProvider):
    def __init__(self, *, issuer: str, audience: str, jwks_fetcher: JwksFetcher,
                 algorithms: Sequence[str] = ALLOWED_ALGORITHMS, clock: Clock = _utcnow, leeway_s: int = 30):
        if not issuer or not audience:
            raise ProviderConfigError("issuer and audience are required")
        bad = [a for a in algorithms if a not in ALLOWED_ALGORITHMS]
        if bad or not algorithms:
            raise ProviderConfigError(f"algorithms must be a non-empty subset of {ALLOWED_ALGORITHMS}, got {list(algorithms)}")
        if not 0 <= leeway_s <= 300:
            raise ProviderConfigError("leeway_s must be between 0 and 300")
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
        auds = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if self._aud not in auds:
            raise AudienceMismatchError(f"token audience {aud!r} does not include {self._aud!r}")
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
        return Identity(self._iss, sub, amr, mfa, datetime.fromtimestamp(exp, timezone.utc), claims)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[override]
        return None


class HttpJwksFetcher:
    """Fetch the issuer's JWKS over https (plain http only for loopback). ``opener`` is injectable for tests."""

    def __init__(self, url: str, *, timeout_s: float = 10.0, opener=None):
        if not (url.startswith("https://") or url.startswith(("http://127.0.0.1", "http://localhost"))):
            raise ProviderConfigError("the JWKS URL must be https (plain http only for loopback)")
        self._url, self._timeout = url, timeout_s
        self._opener = opener or urllib.request.build_opener(_NoRedirect)

    def __call__(self) -> Mapping:
        try:
            with self._opener.open(self._url, timeout=self._timeout) as resp:
                if resp.status != 200:
                    raise ProviderTransportError(f"JWKS fetch answered HTTP {resp.status}")
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise ProviderTransportError(f"JWKS fetch answered HTTP {exc.code}") from exc
        except OSError as exc:
            raise ProviderTransportError(f"JWKS fetch unreachable: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProviderTransportError("JWKS fetch answered with a non-JSON body") from exc
