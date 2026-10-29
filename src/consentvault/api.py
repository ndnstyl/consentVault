"""Optional HTTP API on the stdlib: signed event intake, permission check, proof lookup.

POST /v1/events        body signed with HMAC-SHA256 over "<timestamp>.<body>" (field contract: docs/api.md)
GET  /v1/permission    ?contact=&channel=&purpose=   (bearer token)
GET  /v1/proof         ?contact=                      (bearer token)

No CORS headers are ever sent. Requests whose Host header is not allowlisted are refused.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qs, urlsplit

from . import config as config_mod
from .capture import capture_and_release, capture_verified
from .db import connect
from .errors import ConfigError, ConsentVaultError, NormalizationError
from .gate import REASON_DB_DOWN, may_contact
from .ledger import record_event
from .proof import lookup

REPLAY_WINDOW_SECONDS = 300
MAX_BODY_BYTES = 1 << 20
SIGNATURE_HEADER = "X-ConsentVault-Signature"
TIMESTAMP_HEADER = "X-ConsentVault-Timestamp"

ENV_SECRET = "CONSENTVAULT_API_SECRET"
ENV_VERIFIED_SECRET = "CONSENTVAULT_API_VERIFIED_SECRET"
ENV_TOKEN = "CONSENTVAULT_API_TOKEN"
ENV_HOSTS = "CONSENTVAULT_API_HOSTS"

DEFAULT_HOSTS = ("localhost", "127.0.0.1", "[::1]")

_EVENT_FIELDS = (
    "contact", "event_type", "channels", "purposes", "method", "origin", "disclosure_sha256",
    "subject_key", "captured_at", "page_url", "client_ip", "user_agent", "session_ref",
    "bot_check", "source", "recorded_by", "edge_received_at", "payload_sha256", "contact_verification",
)
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ApiSettings:
    dsn: str
    secret: str
    token: str
    purposes: tuple[str, ...]
    allowed_hosts: tuple[str, ...] = DEFAULT_HOSTS
    verified_secret: str | None = None
    default_region: str | None = None
    replay_window: int = REPLAY_WINDOW_SECONDS


def load_api_settings(path: str | os.PathLike | None = None, env: Mapping[str, str] | None = None) -> ApiSettings:
    """Read the API settings: environment wins over the ``[api]`` table of consentvault.toml."""
    env = os.environ if env is None else env
    cfg = config_mod.load_config(path, env)
    file_path = path or env.get(config_mod.ENV_CONFIG) or ("consentvault.toml" if Path("consentvault.toml").is_file() else None)
    table: dict = {}
    if file_path:
        try:
            table = tomllib.loads(Path(file_path).read_text(encoding="utf-8")).get("api", {})
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read the [api] settings from {file_path}: {exc}") from exc
    secret = env.get(ENV_SECRET) or table.get("secret")
    token = env.get(ENV_TOKEN) or table.get("token")
    if not secret:
        raise ConfigError(f"no API signing secret: set {ENV_SECRET} or 'secret' under [api] in consentvault.toml")
    if not token:
        raise ConfigError(f"no API bearer token: set {ENV_TOKEN} or 'token' under [api] in consentvault.toml")
    hosts_env = env.get(ENV_HOSTS)
    if hosts_env:
        hosts = tuple(h.strip().lower() for h in hosts_env.split(",") if h.strip())
    else:
        hosts = tuple(str(h).lower() for h in table.get("allowed_hosts", DEFAULT_HOSTS))
    return ApiSettings(
        dsn=cfg.require_dsn(), secret=secret, token=token, purposes=cfg.require_purposes(), allowed_hosts=hosts,
        verified_secret=env.get(ENV_VERIFIED_SECRET) or table.get("verified_secret"),
        default_region=cfg.default_region,
    )


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """The signature a client sends: hex HMAC-SHA256 over ``<timestamp>.<body>``."""
    return hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


class _Replay:
    """Remembers signatures seen inside the replay window."""

    def __init__(self, window: int):
        self.window = window
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def first_use(self, signature: str, now: float) -> bool:
        with self._lock:
            for key in [k for k, t in self._seen.items() if now - t > self.window * 2]:
                del self._seen[key]
            if signature in self._seen:
                return False
            self._seen[signature] = now
            return True


class _Handler(BaseHTTPRequestHandler):
    server_version = "consentvault"
    sys_version = ""
    settings: ApiSettings
    replay: _Replay

    def log_message(self, fmt, *args):  # quiet by default
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, status: int, error: str, detail: str) -> None:
        self._send(status, {"ok": False, "error": error, "detail": detail})

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        if host.startswith("["):
            host = host.split("]")[0] + "]"
        else:
            host = host.split(":")[0]
        return host in self.settings.allowed_hosts

    def _bearer_ok(self) -> bool:
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth[7:].encode("utf-8"), self.settings.token.encode("utf-8"))

    def _guard(self) -> bool:
        if not self._host_ok():
            self._fail(421, "host_not_allowed", "the Host header is not on the allowlist")
            return False
        return True

    def do_OPTIONS(self):
        self._fail(405, "method_not_allowed", "no CORS preflight is served")

    def do_PUT(self):
        self._fail(405, "method_not_allowed", "only GET and POST are served")

    do_DELETE = do_PATCH = do_PUT

    def do_POST(self):
        if not self._guard():
            return
        if urlsplit(self.path).path != "/v1/events":
            return self._fail(404, "not_found", "unknown path")
        try:
            length = int(self.headers.get("Content-Length") or "-1")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            return self._fail(413, "bad_length", f"Content-Length must be 0..{MAX_BODY_BYTES}")
        body = self.rfile.read(length)

        ts = self.headers.get(TIMESTAMP_HEADER) or ""
        sig = (self.headers.get(SIGNATURE_HEADER) or "").strip().lower()
        if sig.startswith("sha256="):
            sig = sig[7:]
        if not ts or not sig:
            return self._fail(401, "unsigned", f"{SIGNATURE_HEADER} and {TIMESTAMP_HEADER} are required")
        expected = sign(self.settings.secret, ts, body)
        by_verified_key = False
        if not hmac.compare_digest(sig.encode("utf-8"), expected.encode("utf-8")):
            vs = self.settings.verified_secret
            if not (vs and hmac.compare_digest(sig.encode("utf-8"), sign(vs, ts, body).encode("utf-8"))):
                return self._fail(401, "bad_signature", "signature does not match the body")
            by_verified_key = True
        try:
            sent = float(ts)
        except ValueError:
            return self._fail(401, "bad_timestamp", "timestamp must be unix seconds")
        now = time.time()
        if abs(now - sent) > self.settings.replay_window:
            return self._fail(401, "stale_timestamp", f"timestamp is outside the {self.settings.replay_window}s window")
        if not self.replay.first_use(sig, now):
            return self._fail(409, "replay", "this signed request was already accepted")

        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
        except (ValueError, UnicodeDecodeError) as exc:
            return self._fail(400, "bad_json", str(exc))
        if "disclosure_text" in payload:
            return self._fail(400, "disclosure_text_refused",
                              "wording is not accepted on the wire; an operator registers it first "
                              "(consentvault disclosure register) and the request carries only its sha256")
        unknown = sorted(set(payload) - set(_EVENT_FIELDS) - {"checked", "inbound_message"})
        if unknown:
            return self._fail(400, "unknown_fields", f"unknown fields: {unknown}")
        fields = {k: payload[k] for k in _EVENT_FIELDS if k in payload}
        for required in ("contact", "event_type", "channels", "purposes"):
            if required not in fields:
                return self._fail(400, "missing_field", f"'{required}' is required")
        if fields.get("contact_verification", "none") != "none" and not by_verified_key:
            return self._fail(403, "verification_key_required",
                              "a grant that claims a verified contact point must be signed with the verified-grant "
                              f"secret ({ENV_VERIFIED_SECRET}); the capture edge's secret cannot claim it")
        fields.setdefault("method", "checkbox")
        fields.setdefault("origin", "consumer")
        for name in ("captured_at", "edge_received_at"):
            if fields.get(name) is not None:
                try:
                    fields[name] = datetime.fromisoformat(str(fields[name]).replace("Z", "+00:00"))
                except ValueError:
                    return self._fail(400, f"bad_{name}", f"{name} must be ISO 8601 with a timezone")
        if fields.get("payload_sha256") is not None and not _SHA256_HEX.match(str(fields["payload_sha256"])):
            return self._fail(400, "bad_payload_sha256", "payload_sha256 must be 64 lowercase hex characters")
        fields.setdefault("payload_sha256", hashlib.sha256(body).hexdigest())
        fields["region"] = self.settings.default_region
        fields["allowed_purposes"] = self.settings.purposes
        try:
            with connect(self.settings.dsn) as conn:
                if fields["event_type"] == "grant":
                    fields.pop("event_type")
                    fields.setdefault("disclosure_sha256", "")
                    verification = fields.pop("contact_verification", "none")
                    if verification == "none" and "inbound_message" in payload:
                        return self._fail(400, "bad_inbound_message",
                                          "inbound_message belongs only to an inbound_keyword grant")
                    if verification == "none":
                        ev, release, release_error = capture_and_release(
                            conn, checked=payload.get("checked") is True, **fields)
                    else:
                        if payload.get("checked") is not True:
                            return self._fail(422, "UncheckedConsentError", "the consent box was not checked; no grant recorded")
                        ev, release, release_error = capture_verified(
                            conn, verification=verification, inbound_message=payload.get("inbound_message"), **fields)
                else:
                    ev, release, release_error = record_event(conn, **fields), None, None
        except ConsentVaultError as exc:
            return self._fail(422, type(exc).__name__, str(exc))
        answer = {"ok": True, "event_id": ev.event_id, "seq": ev.seq, "row_hash": ev.row_hash}
        if release is not None:
            answer["release"] = release
        if release_error is not None:
            answer["release_error"] = release_error
        self._send(201, answer)

    def do_GET(self):
        if not self._guard():
            return
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path not in ("/v1/permission", "/v1/proof"):
            return self._fail(404, "not_found", "unknown path")
        if not self._bearer_ok():
            return self._fail(401, "bad_token", "a valid bearer token is required")
        contact = q.get("contact", "")
        if not contact:
            return self._fail(400, "missing_field", "'contact' is required")
        if url.path == "/v1/proof":
            try:
                with connect(self.settings.dsn) as conn:
                    return self._send(200, lookup(conn, contact, self.settings.default_region))
            except NormalizationError as exc:
                return self._fail(400, "bad_contact", str(exc))
            except Exception as exc:  # the failure is named in the answer, never an empty proof
                return self._fail(500, type(exc).__name__, str(exc))
        channel, purpose = q.get("channel", ""), q.get("purpose", "")
        if not channel or not purpose:
            return self._fail(400, "missing_field", "'channel' and 'purpose' are required")
        try:
            with connect(self.settings.dsn) as conn:
                decision = may_contact(conn, contact, channel, purpose, self.settings.default_region)
        except Exception as exc:  # fail closed: any fault is the gate's named denial, never a guess
            return self._send(503, {"allowed": False, "reason": f"{REASON_DB_DOWN}:{type(exc).__name__}",
                                    "basis_event_ids": []})
        self._send(200, {"allowed": decision.allowed, "reason": decision.reason,
                         "basis_event_ids": list(decision.basis_event_ids)})


def make_server(settings: ApiSettings, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Build (not start) the server. ``port=0`` picks a free port."""
    handler = type("ConsentVaultHandler", (_Handler,), {
        "settings": settings, "replay": _Replay(settings.replay_window),
    })
    return ThreadingHTTPServer((host, port), handler)


def serve(settings: ApiSettings, host: str = "127.0.0.1", port: int = 8080) -> None:
    server = make_server(settings, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
