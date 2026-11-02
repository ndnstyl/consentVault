"""Machine authentication: the token endpoint (private_key_jwt) and the access tokens it issues.

POST /v1/oauth/token takes a client assertion: a JWT the client signs with its own private key, the algorithm pinned
per credential (ES256 or EdDSA; anything else is refused), claims iss = sub = client_id (the credential id), aud = the
token endpoint URL, exp at most five minutes ahead, and a jti never seen before for that organisation (replay guard).
The answer is a five-minute access token, a JWT signed with the platform's access-token key (separate from the key that
signs capture receipts, and from the key that signs tenant tokens inside the database), carrying exactly one
organisation and the scopes asked for, each of which the credential holds. ``admin``, ``developer``, ``audit_read`` and
``operator`` are never issued here.

Every refusal is one of three names (contracts/README.md): ``invalid_request``, ``invalid_client``, ``org_not_active``.
An unknown client, a wrong signature, a replayed jti and an expired assertion all answer ``invalid_client`` with the
same detail, and an unknown client runs one signature check against a fixed key so its timing matches a known one.
"""

from __future__ import annotations

import base64
import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping

import psycopg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from ..lengths import is_bytes_of_len
from .errors import ReplayError, TenancyError
from .replay import claim_nonce

ACCESS_TOKEN_TTL = 300
MAX_ASSERTION_LIFETIME = 300
CLOCK_LEEWAY = 30
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
MACHINE_SCOPES = ("capture", "capture_verified", "gate_read", "proof_read")
NEVER_ISSUED = ("admin", "developer", "audit_read", "records_read", "operator")
PINNED_ALGS = ("ES256", "EdDSA")
# a credential's organisation may still use its credentials in these statuses (contracts/billing.md)
ORG_STATUSES_SERVED = ("active", "trial", "past_due", "suspended", "offboarding")
_JTI = re.compile(r"^[A-Za-z0-9._:-]{8,200}$")
_B64 = re.compile(r"^[A-Za-z0-9_-]*$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NIL = "00000000-0000-0000-0000-000000000000"


class OAuthError(TenancyError):
    """A token request or an access token was refused. ``name`` is the contract's error name."""

    status = 400
    name = "invalid_request"

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class InvalidRequestError(OAuthError):
    status, name = 400, "invalid_request"


class InvalidClientError(OAuthError):
    status, name = 401, "invalid_client"


class OrgNotActiveError(OAuthError):
    status, name = 403, "org_not_active"


class UnauthenticatedError(OAuthError):
    """No access token, or it is malformed, forged or expired."""

    status, name = 401, "unauthenticated"


# JWT plumbing -------------------------------------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not _B64.match(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _split(jwt: str) -> tuple[dict, dict, bytes, bytes]:
    if not isinstance(jwt, str) or len(jwt) > 8192 or jwt.count(".") != 2:
        raise ValueError("a JWT has three dot-separated parts")
    h, p, s = jwt.split(".")
    header = json.loads(b64url_decode(h))
    payload = json.loads(b64url_decode(p))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header and payload must be JSON objects")
    return header, payload, f"{h}.{p}".encode("ascii"), b64url_decode(s)


def _signature_ok(alg: str, public_key, signing_input: bytes, signature: bytes) -> bool:
    """True only when the signature verifies under ``alg`` with a key of the matching type."""
    try:
        if alg == "ES256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
                return False
            if not is_bytes_of_len(signature, 64):
                return False
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        if alg == "EdDSA":
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False
            public_key.verify(signature, signing_input)
            return True
    except (InvalidSignature, ValueError):
        return False  # loud-failure-exempt: a bad signature is the answer "no"; every caller refuses on False
    return False


# a fixed key used only to spend the same time on an unknown client as on a known one
_DECOY_KEY = ec.derive_private_key(0x1F2E3D4C5B6A79881726354453627180, ec.SECP256R1()).public_key()


def _load_public_key(pem: str | None):
    """The credential's public key, or None when the stored text is not a public key (the caller refuses)."""
    if not isinstance(pem, str) or "BEGIN PUBLIC KEY" not in pem:
        return None
    try:
        return serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return None  # loud-failure-exempt: an unreadable stored key refuses the client (invalid_client) at the caller


# The platform's access-token key ---------------------------------------------------------------------------------------

class AccessTokenSigner:
    """Signs and verifies access tokens (EdDSA). The managed service keeps the private key in KMS; this local form
    holds an Ed25519 private key in memory (self-host and tests)."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey, *, key_id: str, issuer: str):
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TenancyError("the access-token key must be an Ed25519 private key")
        if not key_id or not re.match(r"^[A-Za-z0-9_-]{1,64}$", key_id):
            raise TenancyError("access-token key id must be 1-64 letters, digits, '_' or '-'")
        if not issuer:
            raise TenancyError("access-token issuer is required")
        self._key = private_key
        self.key_id = key_id
        self.issuer = issuer
        self.public_key = private_key.public_key()

    def __repr__(self) -> str:
        return f"AccessTokenSigner(key_id={self.key_id!r}, private_key=<redacted>)"

    @classmethod
    def generate(cls, *, key_id: str, issuer: str) -> "AccessTokenSigner":
        return cls(ed25519.Ed25519PrivateKey.generate(), key_id=key_id, issuer=issuer)

    def issue(self, claims: Mapping) -> str:
        header = {"alg": "EdDSA", "typ": "at+jwt", "kid": self.key_id}
        signing_input = (b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()) + "." +
                         b64url(json.dumps(dict(claims), separators=(",", ":"), sort_keys=True).encode()))
        return signing_input + "." + b64url(self._key.sign(signing_input.encode("ascii")))

    def verify(self, token: str, *, now: float | None = None) -> "AccessClaims":
        refused = UnauthenticatedError("the access token is missing, malformed, forged or expired")
        try:
            header, payload, signing_input, signature = _split(token)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            raise refused from None
        if header.get("alg") != "EdDSA" or header.get("typ") != "at+jwt" or header.get("kid") != self.key_id \
                or not _signature_ok("EdDSA", self.public_key, signing_input, signature):
            raise refused
        now = time.time() if now is None else now
        exp = payload.get("exp")
        if payload.get("iss") != self.issuer or not isinstance(exp, int) or exp <= now \
                or exp > now + ACCESS_TOKEN_TTL + CLOCK_LEEWAY:
            raise refused
        org, cred = str(payload.get("org_id")), str(payload.get("credential_id"))
        if not _UUID.match(org) or not _UUID.match(cred):
            raise refused
        scopes = tuple(str(payload.get("scope") or "").split())
        if not scopes or any(s not in MACHINE_SCOPES for s in scopes):
            raise refused
        return AccessClaims(uuid.UUID(org), uuid.UUID(cred), scopes, str(payload.get("jti")), exp)


@dataclass(frozen=True)
class AccessClaims:
    org_id: uuid.UUID
    credential_id: uuid.UUID
    scopes: tuple[str, ...]
    jti: str
    exp: int

    def seconds_left(self, now: float | None = None) -> int:
        return int(self.exp - (time.time() if now is None else now))


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    expires_in: int
    scope: str

    def answer(self) -> dict:
        return {"access_token": self.access_token, "token_type": "Bearer", "expires_in": self.expires_in,
                "scope": self.scope}


def _parse_scope(requested: str | None, held: Iterable[str]) -> list[str]:
    held_set = set(held)
    if requested is None or requested == "":
        wanted = sorted(s for s in held_set if s in MACHINE_SCOPES)
    else:
        if not isinstance(requested, str) or len(requested) > 200:
            raise InvalidRequestError("scope must be a space-separated list of scopes")
        wanted = sorted(set(requested.split()))
    refused = [s for s in wanted if s in NEVER_ISSUED or s not in MACHINE_SCOPES]
    if refused:
        raise InvalidRequestError(f"scope(s) {refused} are never issued by the token endpoint")
    missing = [s for s in wanted if s not in held_set]
    if missing:
        raise InvalidRequestError(f"the credential does not hold scope(s) {missing}")
    if not wanted:
        raise InvalidRequestError("the credential holds no machine scope")
    return wanted


def issue_token(
    conn: psycopg.Connection,
    form: Mapping[str, str],
    *,
    token_endpoint_url: str,
    signer: AccessTokenSigner,
    now: Callable[[], float] = time.time,
) -> IssuedToken:
    """Verify one client-credentials request and issue an access token. Raises an ``OAuthError`` subclass."""
    bad_client = InvalidClientError("client authentication failed")
    if form.get("grant_type") != "client_credentials":
        raise InvalidRequestError("grant_type must be client_credentials")
    if form.get("client_assertion_type") != ASSERTION_TYPE:
        raise InvalidRequestError(f"client_assertion_type must be {ASSERTION_TYPE}")
    try:
        header, payload, signing_input, signature = _split(form.get("client_assertion") or "")
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise InvalidRequestError("client_assertion is not a JWT") from None
    iss = str(payload.get("iss"))
    client_id = iss.lower() if _UUID.match(iss) else None
    try:  # an id that is not a UUID is looked up as the nil id, so it takes the same path as an unknown one
        row = conn.execute("SELECT * FROM consentvault.resolve_credential(%s)", (client_id or _NIL,)).fetchone()
    except psycopg.Error as exc:
        raise TenancyError(f"credential lookup failed: {type(exc).__name__}") from exc

    alg = header.get("alg")
    public_key = None
    if row is not None and row["kind"] == "jwt_public_key" and row["alg"] in PINNED_ALGS and alg == row["alg"]:
        public_key = _load_public_key(row["public_key"])
    if public_key is None:
        # spend one signature check so an unknown client times like a known one, then refuse
        _signature_ok("ES256", _DECOY_KEY, signing_input, signature if is_bytes_of_len(signature, 64) else b"\0" * 64)
        raise bad_client
    if not _signature_ok(alg, public_key, signing_input, signature):
        raise bad_client

    t = now()
    exp, aud, jti = payload.get("exp"), payload.get("aud"), payload.get("jti")
    auds = aud if isinstance(aud, list) else [aud]
    if (payload.get("sub") != payload.get("iss") or token_endpoint_url not in auds
            or not isinstance(exp, int) or isinstance(exp, bool) or exp <= t - CLOCK_LEEWAY
            or exp > t + MAX_ASSERTION_LIFETIME + CLOCK_LEEWAY
            or not isinstance(jti, str) or not _JTI.match(jti)):
        raise bad_client
    nbf, iat = payload.get("nbf"), payload.get("iat")
    if (isinstance(nbf, int) and nbf > t + CLOCK_LEEWAY) or (isinstance(iat, int) and iat > t + CLOCK_LEEWAY):
        raise bad_client
    if row["status"] == "revoked":
        raise bad_client
    org_status = "active" if row["status"] == "active" else str(row["status"]).removeprefix("org_")
    if org_status not in ORG_STATUSES_SERVED:
        raise OrgNotActiveError("the organization's status refuses this action")
    scopes = _parse_scope(form.get("scope"), row["scopes"])
    try:
        claim_nonce(conn, row["org_id"], f"assert:{client_id}:{jti}",
                    datetime.fromtimestamp(max(exp, int(t) + 1) + CLOCK_LEEWAY, timezone.utc))
    except ReplayError:
        raise bad_client from None
    issued_at = int(t)
    token = signer.issue({
        "iss": signer.issuer, "org_id": str(row["org_id"]), "credential_id": client_id,
        "scope": " ".join(scopes), "jti": str(uuid.uuid4()), "iat": issued_at, "exp": issued_at + ACCESS_TOKEN_TTL,
    })
    return IssuedToken(token, ACCESS_TOKEN_TTL, " ".join(scopes))


def make_client_assertion(private_key, *, alg: str, client_id: str, audience: str, lifetime: int = 120,
                          jti: str | None = None, now: float | None = None) -> str:
    """Build a client assertion (for clients and tests): ES256 with a P-256 key, or EdDSA with an Ed25519 key."""
    t = int(time.time() if now is None else now)
    header = {"alg": alg, "typ": "JWT"}
    payload = {"iss": client_id, "sub": client_id, "aud": audience, "iat": t, "exp": t + lifetime,
               "jti": jti or str(uuid.uuid4())}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     b64url(json.dumps(payload, separators=(",", ":")).encode()))
    if alg == "ES256":
        r, s = decode_dss_signature(private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif alg == "EdDSA":
        sig = private_key.sign(signing_input.encode("ascii"))
    else:
        raise TenancyError(f"unsupported assertion algorithm {alg!r}")
    return signing_input + "." + b64url(sig)
