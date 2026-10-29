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


# Multi-tenant API (managed service and multi-company self-host) -------------------------------------------------------
#
# POST /v1/oauth/token          private_key_jwt client credentials -> 5-minute access token   (contracts/auth.md)
# POST /v1/events               capture, signed receipt                                       (contracts/capture.md)
# POST /v1/permission[:batch]   evidence status and the client's approved policy action       (contracts/gate.md)
# POST /v1/proof                everything on record for one contact in the caller's org      (contracts/proof-export.md)
# POST /v1/ebr-records          client-supplied EBR record, stored as evidence                (contracts/admin.md)
# POST /v1/dnc-scrubs           client-supplied DNC registry scrub result, stored as evidence  (contracts/admin.md)
# plus every other lane's route object handed in through ``CloudApiSettings.routes``.
#
# The organisation always comes from the access token, never from a path or body. At startup the server calls
# consentvault.require_multi_tenant() (multi mode, and every owner-rights function and row-secured table owned by a role
# that row-level security binds) and reads consentvault.owner_rights_violations(); any failure refuses to serve.

import importlib
import logging
import uuid as _uuid
from datetime import timezone

import psycopg

from .tenancy import logscrub as _logscrub

_log = logging.getLogger("consentvault.api")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _optional_module(name: str):
    """Import another lane's route module if it exists; an import error inside an existing module is raised."""
    full = f"{__package__}{name}"
    try:
        return importlib.import_module(full)
    except ModuleNotFoundError as exc:
        if exc.name == full:
            return None
        raise


# one line per lane that ships routes in its own module (tasks.md, "Build lanes"); imported only by the multi-tenant
# server, so the single-company API never loads them
ROUTE_MODULE_NAMES = (
    ("admin", ".tenancy.admin_routes"),
    ("sync", ".sync.routes"),
    ("evidence", ".evidence_routes"),
    ("billing", ".billing.routes"),
)


def route_modules() -> dict:
    """The other lanes' route modules that exist in this build."""
    return {k: m for k, m in ((k, _optional_module(n)) for k, n in ROUTE_MODULE_NAMES) if m is not None}


class StartupRefusedError(ConsentVaultError):
    """The multi-tenant API refuses to serve this database (single mode, or owner rights that bypass row security)."""


class ServiceUnavailableError(ConsentVaultError):
    """The database or a provider did not answer; nothing was written."""


@dataclass(frozen=True)
class CloudApiSettings:
    dsn: str  # the runtime role (consentvault_app); never the owner
    token_key: object  # tenancy.tokens.TokenKey: signs the tenant token the database checks
    access_tokens: object  # tenancy.oauth.AccessTokenSigner
    receipts: object  # tenancy.pipeline.ReceiptSigner
    crypto: object  # tenancy.crypto.TenantCrypto
    evidence_store: object  # providers.evidence.EvidenceStore
    token_endpoint_url: str
    cursor_key: bytes
    allowed_hosts: tuple[str, ...] = DEFAULT_HOSTS
    default_retain_years: int = 7
    region: str | None = None
    routes: tuple = ()  # route objects of other lanes: handles(method, path) -> bool; handle(method, path, ...)
    portal_caller: object = None  # callable(headers) -> caller for portal routes (session lane), or None

    def __repr__(self) -> str:
        return f"CloudApiSettings(token_endpoint_url={self.token_endpoint_url!r}, hosts={self.allowed_hosts!r})"


def startup_check(dsn: str) -> None:
    """Conditions 1 and 2 of the tenancy review: refuse to serve unless the vault is in multi mode and every
    owner-rights function and row-secured table is owned by the non-superuser schema owner or the operator role."""
    try:
        with connect(dsn) as conn:
            conn.execute("SELECT consentvault.require_multi_tenant()")
            bad = conn.execute("SELECT * FROM consentvault.owner_rights_violations()").fetchall()
    except psycopg.Error as exc:
        raise StartupRefusedError(f"the multi-tenant API will not serve this database: "
                                  f"{exc.diag.message_primary or type(exc).__name__}") from exc
    except ConsentVaultError as exc:
        raise StartupRefusedError(f"the multi-tenant API cannot reach the database: {exc}") from exc
    if bad:
        first = bad[0]
        raise StartupRefusedError(f"the multi-tenant API will not serve this database: {first['object_kind']} "
                                  f"{first['object_name']} (owner {first['owner_name']}): {first['problem']}")


def _api_error(name: str, detail: str, fields: dict | None = None):
    from .tenancy.admin_base import ApiError

    return ApiError(name, detail, fields)


class _CloudHandler(BaseHTTPRequestHandler):
    server_version = "consentvault"
    sys_version = ""
    settings: CloudApiSettings
    pipeline: object

    def log_message(self, fmt, *args):  # request lines carry no body; nothing personal is logged here
        pass

    # plumbing ---------------------------------------------------------------------------------------------------
    def _rid(self) -> str:
        sent = self.headers.get("X-Request-Id") or ""
        return sent if _REQUEST_ID.match(sent) else str(_uuid.uuid4())

    def _send(self, status: int, payload: dict, extra: dict | None = None) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-Id", self.request_id)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, name: str, detail: str, status: int, fields: dict | None = None) -> None:
        body = {"error": name, "detail": detail, "request_id": self.request_id}
        if fields:
            body["fields"] = fields
        self._send(status, body)

    def _refuse(self, exc) -> None:
        self._send(exc.status, exc.body(self.request_id))

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        host = host.split("]")[0] + "]" if host.startswith("[") else host.split(":")[0]
        return host in self.settings.allowed_hosts

    def _body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length") or "-1")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._error("invalid_request", f"Content-Length must be 0..{MAX_BODY_BYTES}", 400)
            return None
        return self.rfile.read(length)

    def _json(self, body: bytes):
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise _api_error("invalid_request", "the body is not JSON") from None

    def do_GET(self):
        self.request_id = self._rid()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("GET")

    def do_PUT(self):
        self.request_id = self._rid()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("PUT")

    def do_PATCH(self):
        self.request_id = self._rid()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("PATCH")

    def do_DELETE(self):
        self.request_id = self._rid()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("DELETE")

    def do_OPTIONS(self):
        self.request_id = self._rid()
        self._error("not_found", "no CORS preflight is served", 404)

    def _other_lanes(self, method: str, body: bytes | None = None) -> None:
        from .route_wiring import BodyNotJson

        url = urlsplit(self.path)
        path = url.path
        for route in self.settings.routes:
            if route.handles(method, path):
                if body is None:
                    body = self._body() if method in ("POST", "PUT", "PATCH") else b""
                    if body is None:
                        return
                # the request id replaces any the client sent under another casing; nothing else is trusted here:
                # every route produces its caller from a verified credential (route_wiring)
                headers = {k: v for k, v in self.headers.items() if k.lower() != "x-request-id"}
                kwargs = {"body": body, "headers": {**headers, "X-Request-Id": self.request_id}}
                if getattr(route, "wants_query", False):
                    kwargs["query"] = {k: v[0] for k, v in parse_qs(url.query).items() if len(v) == 1}
                if self.settings.portal_caller is not None:
                    kwargs["caller"] = self.settings.portal_caller(kwargs["headers"])
                try:
                    res = route.handle(method, path, **kwargs)
                except BodyNotJson:
                    return self._error("invalid_request", "the body is not JSON", 400)
                status, payload = (res.status, res.payload) if hasattr(res, "status") else res
                raw, extra = getattr(res, "raw", None), dict(getattr(res, "headers", None) or {})
                if raw is not None:
                    return self._send_raw(status, raw, extra)
                if status == 204:
                    return self._send_raw(204, b"", {})
                return self._send(status, payload, {k: v for k, v in extra.items()
                                                    if k.lower() not in ("content-type", "cache-control", "content-length")})
        self._error("not_found", "no such endpoint", 404)

    def _send_raw(self, status: int, raw: bytes, headers: dict) -> None:
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        if status != 204:
            self.send_header("Content-Length", str(len(raw)))
        if "cache-control" not in {k.lower() for k in headers}:
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-Id", self.request_id)
        self.end_headers()
        if status != 204:
            self.wfile.write(raw)

    # authentication -----------------------------------------------------------------------------------------------
    def _claims(self, *needed: str):
        from .tenancy.oauth import UnauthenticatedError

        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            raise UnauthenticatedError("a bearer access token is required")
        claims = self.settings.access_tokens.verify(auth[7:].strip())
        if not set(needed) & set(claims.scopes):
            raise _api_error("role_not_allowed", "this credential's scopes may not call this endpoint",
                             {"role": "machine:" + " ".join(claims.scopes)})
        return claims

    def _tenant_token(self, claims, scopes=None) -> str:
        from .tenancy.tokens import mint_org_token

        ttl = max(1, min(300, claims.seconds_left()))
        return mint_org_token(self.settings.token_key, claims.org_id, scopes or claims.scopes,
                              credential_id=str(claims.credential_id), ttl_seconds=ttl)

    def _enter(self, token: str):
        from .tenancy.tokens import org_transaction

        return lambda conn: org_transaction(conn, token)

    # routes -------------------------------------------------------------------------------------------------------
    def do_POST(self):
        from .alarms import AlarmWriteError
        from .tenancy.admin_base import ApiError
        from .tenancy.errors import KeyProviderError, TenantTokenError
        from .tenancy.oauth import OAuthError
        from .tenancy.pipeline import EvidenceStoreUnavailable

        self.request_id = self._rid()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        path = urlsplit(self.path).path
        route = {"/v1/oauth/token": self._token, "/v1/events": self._events, "/v1/permission": self._permission,
                 "/v1/permission:batch": self._permission_batch, "/v1/proof": self._proof,
                 "/v1/ebr-records": self._ebr, "/v1/dnc-scrubs": self._dnc}.get(path)
        if route is None:
            return self._other_lanes("POST")
        body = self._body()
        if body is None:
            return
        try:
            route(body)
        except (OAuthError, ApiError) as exc:
            self._send(exc.status, {"error": exc.name, "detail": exc.detail, "request_id": self.request_id,
                                    **({"fields": exc.fields} if getattr(exc, "fields", None) else {})})
        except KeyProviderError:
            self._error("key_unavailable", "the organization key could not be used; nothing was written or read", 503)
        except AlarmWriteError as exc:
            _log.critical("request %s failed: %s", self.request_id, exc)
            self._error("alarm_unavailable", "the event was recorded, but a follow-up decision and its operator alarm"
                        " could not be written; the operator must be told by another route", 503)
        except EvidenceStoreUnavailable:
            _log.error("evidence store refused an object (request %s)", self.request_id)
            self._error("evidence_store_unavailable", "the write-once store did not take the evidence; nothing was "
                        "recorded", 503)
        except (TenantTokenError, ServiceUnavailableError, psycopg.Error) as exc:
            _log.error("service unavailable on %s (request %s): %s", path, self.request_id, type(exc).__name__)
            self._error("service_unavailable", "the vault could not complete the request; nothing was written", 503)
        except ConsentVaultError as exc:
            _log.error("refused on %s (request %s): %s", path, self.request_id, type(exc).__name__)
            self._error("service_unavailable", "the vault could not complete the request; nothing was written", 503)

    def _token(self, body: bytes) -> None:
        from .tenancy.oauth import issue_token

        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            raise _api_error("invalid_request", "the token request must be application/x-www-form-urlencoded")
        try:
            form = {k: v[0] for k, v in parse_qs(body.decode("ascii"), strict_parsing=False).items() if len(v) == 1}
        except UnicodeDecodeError:
            raise _api_error("invalid_request", "the token request is not ASCII form data") from None
        with connect(self.settings.dsn) as conn:
            issued = issue_token(conn, form, token_endpoint_url=self.settings.token_endpoint_url,
                                 signer=self.settings.access_tokens)
        self._send(200, issued.answer())

    def _events(self, body: bytes) -> None:
        from .errors import (ConsentRefusedError, InvalidEventError, LedgerError, NormalizationError,
                             UnknownDisclosureError, UnknownPurposeError)
        from .release import release_after_tenant_grant
        from .tenancy.pipeline import parse_capture

        claims = self._claims("capture", "capture_verified")
        req = parse_capture(self._json(body), body, claims.scopes)
        token = self._tenant_token(claims)
        try:
            with connect(self.settings.dsn) as conn:
                result = self.pipeline.capture(conn, self._enter(token), req, credential_id=claims.credential_id)
                if req.fields["event_type"] == "grant" and req.fields.get("origin", "consumer") == "consumer":
                    reader = self._tenant_token(claims, ("capture", "gate_read"))
                    try:
                        with self._enter(reader)(conn):
                            release_after_tenant_grant(conn, self.settings.crypto, result.event_id)
                    except (ConsentVaultError, psycopg.Error) as exc:
                        # the grant stands; the missing decision becomes an operator alarm row, not only a log line
                        self._release_alarm(conn, token, result.event_id, exc)
        except UnknownDisclosureError:
            raise _api_error("UnknownDisclosureError", "this organization has not registered that wording") from None
        except UnknownPurposeError:
            raise _api_error("UnknownPurposeError", "the purpose is not in this organization's configured list") from None
        except NormalizationError:
            raise _api_error("invalid_contact", "the contact point is not a valid phone number or email address") from None
        except (InvalidEventError, ConsentRefusedError) as exc:
            raise _api_error("validation_failed", str(exc), {"event": type(exc).__name__}) from None
        except LedgerError as exc:
            if isinstance(exc.__cause__, psycopg.errors.IntegrityError):
                raise _api_error("validation_failed", "the ledger refused the event: it breaks a ledger rule",
                                 {"event": "LedgerError"}) from None
            raise
        self._send(201, {"ok": True, "event_id": result.event_id, "receipt": result.receipt})

    def _release_alarm(self, conn, token: str, event_id: str, exc: BaseException) -> None:
        from .alarms import ALARM_RELEASE_NOT_WRITTEN, AlarmWriteError, raise_operator_alarm

        _log.error("release decision not written for event %s (request %s): %s",
                   event_id, self.request_id, type(exc).__name__)
        try:
            with self._enter(token)(conn):
                raise_operator_alarm(conn, name=ALARM_RELEASE_NOT_WRITTEN, error_class=type(exc).__name__,
                                     ref_kind="event", ref_id=event_id, request_id=self.request_id)
        except (AlarmWriteError, ConsentVaultError, psycopg.Error) as alarm_exc:
            _log.critical("operator alarm %s NOT written for event %s (request %s): %s; the release decision is"
                          " missing and nothing in the database says so", ALARM_RELEASE_NOT_WRITTEN, event_id,
                          self.request_id, type(alarm_exc).__name__)
            # never only a log: the request fails with a named error (the grant itself stays recorded)
            raise AlarmWriteError(f"event {event_id} was recorded, but neither its release decision nor the operator"
                                  f" alarm could be written ({type(alarm_exc).__name__})") from alarm_exc

    def _gate_items(self, payload, many: bool):
        from .gate import MAX_BATCH, GateItem

        if not isinstance(payload, dict):
            raise _api_error("invalid_request", "the body must be a JSON object")
        if not many:
            unknown = sorted(set(payload) - {"contact", "channel", "purpose"})
            if unknown:
                raise _api_error("validation_failed", f"unknown fields: {unknown}", {u: "unknown field" for u in unknown})
            return [GateItem(payload.get("contact"), payload.get("channel"), payload.get("purpose"))]
        items = payload.get("items")
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_BATCH or set(payload) != {"items"}:
            raise _api_error("validation_failed", f"items must be a list of 1 to {MAX_BATCH} checks",
                             {"items": f"1 to {MAX_BATCH} items"})
        if not all(isinstance(i, dict) for i in items):
            raise _api_error("validation_failed", "each item is {contact, channel, purpose}", {"items": "objects"})
        return [GateItem(i.get("contact"), i.get("channel"), i.get("purpose")) for i in items]

    def _gate(self, body: bytes, many: bool) -> None:
        from .gate import GateRecordError, TenantGate
        from .gate_rules.engine import NOTICE
        from .tenancy.admin_base import ApiError
        from .tenancy.pipeline import require_serving

        claims = self._claims("gate_read")
        items = self._gate_items(self._json(body), many)
        token = self._tenant_token(claims)
        try:
            with connect(self.settings.dsn) as conn, self._enter(token)(conn) as org:
                require_serving(conn)
                gate = TenantGate(conn, self.settings.crypto, org=org, requested_by=str(claims.credential_id),
                                  region=self.settings.region)
                if not many:
                    status, answer = gate.check(items[0])
                    return self._send(status, answer)
                batch_id = str(_uuid.uuid4())
                answers = []
                for item in items:
                    try:
                        answers.append(gate.check(item, batch_id=batch_id)[1])
                    except ApiError as exc:
                        answers.append({"error": exc.name, "detail": exc.detail})
                return self._send(200, {"items": answers, "batch_id": batch_id})
        except (GateRecordError, psycopg.Error, ServiceUnavailableError) as exc:
            _log.error("gate unavailable (request %s): %s", self.request_id, type(exc).__name__)
            self._send(503, {"evidence_status": "unavailable:database", "policy_action": None,
                             "notice": NOTICE, "request_id": self.request_id})

    def _permission(self, body: bytes) -> None:
        self._gate(body, False)

    def _permission_batch(self, body: bytes) -> None:
        self._gate(body, True)

    def _proof(self, body: bytes) -> None:
        from .gate_rules.policy import PolicyStoreError, approved_policy
        from .proof import tenant_lookup
        from .tenancy.pipeline import require_serving

        claims = self._claims("proof_read")
        payload = self._json(body)
        if not isinstance(payload, dict) or set(payload) - {"contact", "page"}:
            raise _api_error("validation_failed", "the body is {contact, page?}", {"body": "contact and page only"})
        token = self._tenant_token(claims)
        with connect(self.settings.dsn) as conn, self._enter(token)(conn) as org:
            require_serving(conn)
            try:
                with conn.transaction():
                    policy = approved_policy(conn)
            except PolicyStoreError:
                policy = None  # the permissions section is then marked partial below
                policy_failed = True
            else:
                policy_failed = False
            answer = tenant_lookup(conn, self.settings.crypto, org=org, contact=payload.get("contact"),
                                   page=payload.get("page"), region=self.settings.region,
                                   cursor_key=self.settings.cursor_key, policy=policy)
        if policy_failed and answer.get("found") and "permissions" in answer:
            answer["permissions"] = None
            answer["partial"] = sorted(set(answer.get("partial", [])) | {"permissions"})
        self._send(200, answer)

    def _client_evidence(self, body: bytes, kind: str) -> None:
        from datetime import date

        from .tenancy import crypto as tc
        from .tenancy.pipeline import contact_key, normalize, require_serving

        claims = self._claims("capture")
        p = self._json(body)
        if not isinstance(p, dict):
            raise _api_error("invalid_request", "the body must be a JSON object")
        if kind == "ebr":
            allowed = {"contact", "relationship_type", "started_on", "ended_on", "evidence_refs", "source"}
            required = ("contact", "relationship_type", "started_on", "source")
        else:
            allowed = {"contact", "registry", "scrubbed_at", "result", "provider", "evidence_ref"}
            required = ("contact", "registry", "scrubbed_at", "result", "provider")
        unknown = sorted(set(p) - allowed)
        missing = [r for r in required if p.get(r) in (None, "")]
        if unknown or missing:
            raise _api_error("validation_failed", "unknown or missing fields",
                             {**{u: "unknown field" for u in unknown}, **{m: "required" for m in missing}})

        def day(name):
            if p.get(name) is None:
                return None
            try:
                return date.fromisoformat(str(p[name]))
            except ValueError:
                raise _api_error("validation_failed", f"{name} must be a date", {name: "YYYY-MM-DD"}) from None

        kind_norm = normalize(p["contact"], self.settings.region)
        token = self._tenant_token(claims)
        new_id = str(_uuid.uuid4())
        with connect(self.settings.dsn) as conn, self._enter(token)(conn) as org:
            require_serving(conn)
            fp, dk = contact_key(conn, self.settings.crypto, org, *kind_norm, create=True)
            try:
                if kind == "ebr":
                    refs = p.get("evidence_refs")
                    if refs is not None and (not isinstance(refs, list) or not all(isinstance(r, str) for r in refs)):
                        raise _api_error("validation_failed", "evidence_refs must be a list of text",
                                         {"evidence_refs": "list of text"})
                    with conn.transaction():
                        conn.execute(
                            "INSERT INTO consentvault.ebr_record (org_id, ebr_id, contact_fp, relationship_type,"
                            " started_on, ended_on, evidence_refs_ct, source, recorded_by)"
                            " VALUES (consentvault.current_org(), %s, %s, %s, %s, %s, %s, %s, %s)",
                            (new_id, fp, p["relationship_type"], day("started_on"), day("ended_on"),
                             tc.encrypt_field(dk, org, new_id, "evidence_refs", json.dumps(refs)) if refs else None,
                             str(p["source"]), str(claims.credential_id)))
                else:
                    scrubbed = datetime.fromisoformat(str(p["scrubbed_at"]).replace("Z", "+00:00"))
                    if scrubbed.tzinfo is None:
                        raise _api_error("validation_failed", "scrubbed_at must carry a time zone",
                                         {"scrubbed_at": "ISO 8601 with a time zone"})
                    ref = p.get("evidence_ref")
                    with conn.transaction():
                        conn.execute(
                            "INSERT INTO consentvault.dnc_scrub_result (org_id, scrub_id, contact_fp, registry,"
                            " scrubbed_at, result, provider, evidence_ref_ct, recorded_by)"
                            " VALUES (consentvault.current_org(), %s, %s, %s, %s, %s, %s, %s, %s)",
                            (new_id, fp, p["registry"], scrubbed, p["result"], str(p["provider"]),
                             tc.encrypt_field(dk, org, new_id, "evidence_ref", str(ref)) if ref else None,
                             str(claims.credential_id)))
            except ValueError:
                raise _api_error("validation_failed", "a field is malformed", {"body": "malformed field"}) from None
            except psycopg.errors.CheckViolation:
                raise _api_error("validation_failed", "a field is outside its allowed values",
                                 {"body": "value not allowed"}) from None
        self._send(201, {("ebr_id" if kind == "ebr" else "scrub_id"): new_id, "recorded_at":
                         datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")})

    def _ebr(self, body: bytes) -> None:
        self._client_evidence(body, "ebr")

    def _dnc(self, body: bytes) -> None:
        self._client_evidence(body, "dnc")


def make_cloud_server(settings: CloudApiSettings, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Build (not start) the multi-tenant server. Refuses (``StartupRefusedError``) unless ``startup_check`` passes."""
    from .tenancy.pipeline import CapturePipeline

    if not isinstance(settings.cursor_key, bytes) or len(settings.cursor_key) < 32:
        raise ConfigError("cursor_key must be at least 32 bytes")
    for route in settings.routes:
        if not (callable(getattr(route, "handles", None)) and callable(getattr(route, "handle", None))):
            raise ConfigError(f"route object {route!r} needs handles(method, path) and handle(method, path, ...)")
    startup_check(settings.dsn)
    route_modules()  # an existing lane module that fails to import refuses the start, loudly
    _logscrub.install(_log)
    pipeline = CapturePipeline(store=settings.evidence_store, crypto=settings.crypto, receipts=settings.receipts,
                               default_retain_years=settings.default_retain_years, region=settings.region)
    handler = type("ConsentVaultCloudHandler", (_CloudHandler,), {"settings": settings, "pipeline": pipeline})
    return ThreadingHTTPServer((host, port), handler)
