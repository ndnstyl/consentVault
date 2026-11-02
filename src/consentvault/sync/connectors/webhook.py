"""The generic signed webhook connector (contracts/suppression-sync.md, outbound push).

``POST <system endpoint>`` with headers ``X-ConsentVault-Signature``, ``X-ConsentVault-Delivery`` (the outbox id) and
``Idempotency-Key``. The signature covers the exact body bytes (HMAC-SHA256 or Ed25519, per the system) and reads
``hmac-sha256=<hex>`` or ``ed25519=<hex>``. No timestamp header: the egress door forwards only these three headers and
the content type, and the body already carries the event time and the version; a receiver dedupes on the idempotency
key, which is the same on every retry of one push.

The call itself goes through a ``Transport``. The production one is ``EgressTransport``: the vault never opens a
connection to a client's endpoint from its own network; it hands the exact signed body to the egress Worker
(``edge/src/egress.ts``), which refuses private and metadata addresses, allows 10 seconds, and answers 200 or 502 with
the receiver's status in the body. A test injects a fake transport, so no test makes a network call.

``classify`` turns what came back into one of three decisions (policy, suppression-sync.md and data-model 9.1):
2xx acknowledged; 5xx, 408, 429, a timeout or an unreachable receiver retry with backoff; any other 4xx (a poison
message), including a 401 or 403, dead at once.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable, Protocol

from ...safelog import describe, http_error_response
from ...lengths import is_bytes_of_len
from ...urlguard import open_no_redirect
from ..errors import CredentialError, TransportError

HEADER_SIGNATURE = "X-ConsentVault-Signature"
HEADER_DELIVERY = "X-ConsentVault-Delivery"
HEADER_IDEMPOTENCY = "Idempotency-Key"
RECEIVER_TIMEOUT_SECONDS = 10
EGRESS_TIMEOUT_SECONDS = 15  # the door's own 10 s plus its answer

ERROR_CLASSES = ("timeout", "http_4xx", "http_5xx", "signature_rejected", "unreachable")
_REFUSED_BY_DOOR = {"target_address_refused", "target_not_https", "target_port_refused", "target_has_credentials",
                    "bad_target"}
_UNREACHABLE_BY_DOOR = {"receiver_unreachable", "dns_failed", "dns_no_answer"}


@dataclass(frozen=True)
class PushRequest:
    target_url: str
    body: bytes
    headers: dict[str, str]

    def __repr__(self) -> str:  # a body can carry a contact point; it never reaches a log line
        return f"PushRequest(target_url={self.target_url!r}, body=<{len(self.body)} bytes>)"


@dataclass(frozen=True)
class TransportResult:
    """What came back. kind: response (http_status set), timeout, unreachable, or refused (the door will never send)."""
    kind: str
    http_status: int | None = None
    detail: str = ""


@dataclass(frozen=True)
class Outcome:
    kind: str  # acknowledged | retry | dead
    error_class: str | None
    http_status: int | None
    detail: str


class Transport(Protocol):
    def send(self, request: PushRequest) -> TransportResult: ...


def idempotency_key(org_id, contact_fp: str, channel: str, purpose: str, version: int) -> str:
    """(org, contact fingerprint, channel, purpose, version) digested; identical on every retry of one push."""
    raw = "\x1f".join((str(org_id), contact_fp, channel, purpose, str(int(version))))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sign_body(scheme: str, secret: bytes, body: bytes) -> str:
    if scheme == "hmac":
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise CredentialError("an HMAC secret must be at least 16 bytes")
        return "hmac-sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if scheme == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not is_bytes_of_len(secret, 32):
            raise CredentialError("an Ed25519 private key is 32 raw bytes")
        return "ed25519=" + Ed25519PrivateKey.from_private_bytes(secret).sign(body).hex()
    raise CredentialError(f"unknown signature kind {scheme!r}")


def verify_signature(scheme: str, key: bytes, body: bytes, header: str) -> bool:
    """The receiver's check, kept here so the sender's tests can prove a round trip. ``key`` is the HMAC secret or the
    raw 32-byte Ed25519 public key."""
    if scheme == "hmac":
        return hmac.compare_digest(sign_body("hmac", key, body), header)
    if scheme == "ed25519":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not header.startswith("ed25519="):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(header[8:]), body)
        except (InvalidSignature, ValueError):
            return False
        return True
    return False


def build_request(*, endpoint: str, signature: str, secret: bytes, body: bytes, outbox_id, org_id, contact_fp: str,
                  channel: str, purpose: str, version: int) -> PushRequest:
    return PushRequest(endpoint, body, {
        HEADER_SIGNATURE: sign_body(signature, secret, body),
        HEADER_DELIVERY: str(outbox_id),
        HEADER_IDEMPOTENCY: idempotency_key(org_id, contact_fp, channel, purpose, version),
        "Content-Type": "application/json",
    })


def classify(result: TransportResult) -> Outcome:
    if result.kind == "timeout":
        return Outcome("retry", "timeout", None, result.detail or "the receiver did not answer in time")
    if result.kind == "unreachable":
        return Outcome("retry", "unreachable", None, result.detail or "the receiver could not be reached")
    if result.kind == "refused":
        return Outcome("dead", "unreachable", None, result.detail or "the delivery door refuses this target")
    if result.kind != "response" or result.http_status is None:
        raise TransportError(f"unknown transport result {result!r}")
    s = result.http_status
    if 200 <= s < 300:
        return Outcome("acknowledged", None, s, "")
    if s in (401, 403):
        return Outcome("dead", "signature_rejected", s, f"the receiver answered {s}")
    if s in (408, 429):
        return Outcome("retry", "http_4xx", s, f"the receiver answered {s}")
    if 300 <= s < 500:
        return Outcome("dead", "http_4xx", s, f"the receiver answered {s}" + (" (redirects are not followed)" if s < 400 else ""))
    if 500 <= s < 600:
        return Outcome("retry", "http_5xx", s, f"the receiver answered {s}")
    return Outcome("retry", "unreachable", s, f"the receiver answered an unexpected status {s}")


@dataclass
class EgressTransport:
    """Hands the signed body to the egress Worker and reads the receiver's status out of its answer."""
    egress_url: str
    secret: str = field(repr=False)
    timeout: float = EGRESS_TIMEOUT_SECONDS
    opener: Callable[..., object] = open_no_redirect

    def __post_init__(self) -> None:
        if not self.egress_url.startswith("https://") or not self.secret:
            raise TransportError("the egress transport needs an https egress URL and its secret")

    def send(self, request: PushRequest) -> TransportResult:
        wire = json.dumps({"target_url": request.target_url, "payload": request.body.decode("utf-8"),
                           "headers": dict(request.headers)}, separators=(",", ":")).encode("utf-8")
        http = urllib.request.Request(self.egress_url.rstrip("/") + "/push", data=wire, method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self.secret}"})
        try:
            with self.opener(http, timeout=self.timeout) as res:
                status, raw = res.status, res.read()
        except urllib.error.HTTPError as exc:
            status, _headers, raw = http_error_response(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"the egress door could not be reached: {describe(exc)}") from exc
        return interpret_egress(status, raw)

    def call(self, method: str, url: str, headers: dict, payload):
        """One call to a connected system's JSON API through the door's ``/call`` (the Twenty connector). Returns a
        ``twenty_api.CallResult``; the door itself failing raises ``TransportError``."""
        wire = json.dumps({"target_url": url, "method": method, "headers": dict(headers), "payload": payload},
                          separators=(",", ":")).encode("utf-8")
        http = urllib.request.Request(self.egress_url.rstrip("/") + "/call", data=wire, method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self.secret}"})
        try:
            with self.opener(http, timeout=self.timeout) as res:
                status, raw = res.status, res.read()
        except urllib.error.HTTPError as exc:
            status, _headers, raw = http_error_response(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"the egress door could not be reached: {describe(exc)}") from exc
        return interpret_call(status, raw)


def interpret_call(status: int, raw: bytes):
    """Read the door's ``/call`` answer: the receiver's status, its rate-limit headers and its JSON body; or one of the door's
    named outcomes (timeout, unreachable, refused). A redirect or an oversized answer is the receiver's; anything else is the
    door failing and raises ``TransportError``."""
    from .twenty_api import CallResult

    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        data = None
    if not isinstance(data, dict):
        raise TransportError(f"the egress door answered {status} with a body that is not JSON")
    code, msg = data.get("error"), str(data.get("message") or "")
    if status == 200 and isinstance(data.get("receiver_status"), int):
        headers = data.get("receiver_headers") if isinstance(data.get("receiver_headers"), dict) else {}
        return CallResult("response", data["receiver_status"], headers, data.get("receiver_body"))
    if code == "receiver_redirect" and isinstance(data.get("receiver_status"), int):
        return CallResult("response", data["receiver_status"], {}, None, "redirects are not followed")
    if code == "receiver_body_too_large":
        return CallResult("response", 502, {}, None, "the answer was over 256 KB")
    if code == "receiver_timeout":
        return CallResult("timeout", detail=msg)
    if code in _UNREACHABLE_BY_DOOR:
        return CallResult("unreachable", detail=f"{code}: {msg}")
    if code in _REFUSED_BY_DOOR:
        return CallResult("refused", detail=f"{code}: {msg}")
    raise TransportError(f"the egress door answered {status} {code!r}: {msg}")


def interpret_egress(status: int, raw: bytes) -> TransportResult:
    """Read the egress Worker's answer. Anything that is not the receiver's own status or one of the door's named
    per-target refusals is the door failing, not the receiver, and raises ``TransportError``."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        data = None
    if not isinstance(data, dict):
        raise TransportError(f"the egress door answered {status} with a body that is not JSON")
    receiver = data.get("receiver_status")
    if isinstance(receiver, int):
        return TransportResult("response", receiver, str(data.get("message") or data.get("error") or ""))
    code = data.get("error")
    msg = str(data.get("message") or "")
    if code == "receiver_timeout":
        return TransportResult("timeout", None, msg)
    if code in _UNREACHABLE_BY_DOOR:
        return TransportResult("unreachable", None, f"{code}: {msg}")
    if code in _REFUSED_BY_DOOR:
        return TransportResult("refused", None, f"{code}: {msg}")
    raise TransportError(f"the egress door answered {status} {code!r}: {msg}")


def probe_body(org_id) -> bytes:
    """A test push (systems.md): marked ``test: true`` and carrying no contact point."""
    return json.dumps({"org_id": str(org_id), "test": True, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def send_test_push(transport: Transport, *, endpoint: str, signature: str, secret: bytes, org_id,
                   clock: Callable[[], float] = time.monotonic) -> dict:
    """Send one test push and report the receiver's answer as systems.md defines it. A bad answer is the answer."""
    body = probe_body(org_id)
    request = PushRequest(endpoint, body, {
        HEADER_SIGNATURE: sign_body(signature, secret, body), HEADER_DELIVERY: str(uuid.uuid4()),
        HEADER_IDEMPOTENCY: hashlib.sha256(body).hexdigest(), "Content-Type": "application/json"})
    started = clock()
    result = transport.send(request)
    latency = int((clock() - started) * 1000)
    if result.kind == "response":
        s = result.http_status
        verdict = "accepted" if 200 <= s < 300 else "rejected" if 300 <= s < 500 else "server_error"
        return {"result": verdict, "http_status": s, "latency_ms": latency}
    verdict = "timeout" if result.kind == "timeout" else "unreachable"
    return {"result": verdict, "http_status": None, "latency_ms": latency}
