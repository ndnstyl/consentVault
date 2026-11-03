"""Optional HTTP API on the stdlib: signed event intake, permission check, proof lookup.

POST /v1/events        body signed with HMAC-SHA256 over "<timestamp>.<body>" (field contract: docs/api.md)
GET  /v1/permission    ?contact=&channel=&purpose=   (bearer token)
GET  /v1/proof         ?contact=                      (bearer token)

No CORS headers are ever sent. Requests whose Host header is not allowlisted are refused.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qs, urlsplit

from .safelog import caller_detail, db_code, describe, refusal_code
from . import config as config_mod
from . import edge_envelope
from .capture import capture_and_release, capture_verified
from .capture_http import (Downstream, cors_headers, is_capture_path, is_preflight, read_any_body, request_headers,
                           unavailable_answer)
from . import dbclock
from .db import connect
from .errors import ConfigError, ConsentVaultError, NormalizationError
from .gate import REASON_DB_DOWN, may_contact
from .ledger import record_event
from .proof import lookup

REPLAY_WINDOW_SECONDS = 300
MAX_REPLAY_WINDOW_SECONDS = 39600  # the guard keeps a signature for twice the window (22 h), the database caps expiry at a day: 2 h of clock skew margin
MAX_BODY_BYTES = 1 << 20
SIGNATURE_HEADER = "X-ConsentVault-Signature"
TIMESTAMP_HEADER = "X-ConsentVault-Timestamp"

SINGLE_CAPTURE_PREFIXES = ("/v1/events", "/v1/capture")
CLOUD_CAPTURE_PREFIXES = ("/v1/events", "/v1/capture")

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
    raw_posts: object | None = None  # rawpost.RawPostWriter; None stores the bytes as sent (no key provider, no object store)
    raw_post_inline_limit_bytes: int = config_mod.DEFAULT_RAW_POST_INLINE_BYTES
    raw_post_unusual_size_bytes: int = config_mod.DEFAULT_RAW_POST_UNUSUAL_BYTES


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
            raise ConfigError(f"cannot read the [api] settings from {file_path}: {describe(exc)}") from exc
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
        default_region=cfg.default_region, raw_post_inline_limit_bytes=cfg.raw_post_inline_limit_bytes,
        raw_post_unusual_size_bytes=cfg.raw_post_unusual_size_bytes,
    )


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """The signature a client sends: hex HMAC-SHA256 over ``<timestamp>.<body>``."""
    return hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


class SafeHTTPServer(ThreadingHTTPServer):
    """The server, with its default error printer replaced: an exception that escapes a request is logged as its class and the frames
    it passed through, never its message, a local or the client address (socketserver would print the whole traceback to stderr).
    ``drain`` waits for the work that follows an answer (reading the stored post, alarms, the transitional event)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.downstream = Downstream()

    def drain(self, timeout: float = 60.0) -> None:
        self.downstream.drain(timeout)

    def handle_error(self, request, client_address) -> None:
        _log.error("a request failed outside its handler", exc_info=True)


class _Handler(BaseHTTPRequestHandler):
    server_version = "consentvault"
    sys_version = ""
    settings: ApiSettings

    def log_message(self, fmt, *args):  # quiet by default
        pass

    def _send(self, status: int, payload: dict, extra: dict | None = None) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
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

    def _authentication_failure(self, ts: str, sig: str, body: bytes) -> tuple[str | None, bool]:
        """(the reason this request does not authenticate or None, whether the verified-grant secret signed it). Every check runs (both secrets are always computed)
        so the failures do not differ in work done; the caller answers all of them with one refusal."""
        ts_ascii = ts.encode("ascii", "replace").decode("ascii")
        expected = sign(self.settings.secret, ts_ascii, body)
        vs = self.settings.verified_secret
        expected_v = sign(vs, ts_ascii, body) if vs else expected
        sig_b = sig.encode("utf-8")
        match_edge = hmac.compare_digest(sig_b, expected.encode("utf-8"))
        match_verified = bool(vs) and hmac.compare_digest(sig_b, expected_v.encode("utf-8"))
        try:
            sent = float(ts)
        except ValueError:
            sent = float("nan")
        finite = math.isfinite(sent)
        fresh = False
        if finite:
            try:
                with connect(self.settings.dsn) as conn:   # freshness is judged on the database's clock, never this host's
                    fresh = abs(dbclock.epoch(conn) - sent) <= self.settings.replay_window
            except psycopg.Error as exc:
                _log.error("events clock unavailable; request refused", error=type(exc).__name__)
                return f"clock_unavailable:{type(exc).__name__}", False
        by_verified = match_verified and not match_edge
        if not ts or not sig:
            return "unsigned", False
        if not (match_edge or match_verified):
            return "bad_signature", False
        if not finite:
            return "bad_timestamp", False
        if not fresh:
            return "stale_timestamp", False
        return None, by_verified

    def _claim_signature(self, sig: str) -> str | None:
        """Record the signature in the shared replay guard (every process and every restart sees it). None when it was
        fresh; the reason otherwise. A guard that cannot answer refuses the request: it never lets one through."""
        from .tenancy.errors import ReplayError, TenancyError
        from .tenancy.replay import claim_nonce

        try:
            with connect(self.settings.dsn) as conn:
                org = conn.execute("SELECT consentvault.home_org() AS o").fetchone()["o"]
                claim_nonce(conn, org, "events:" + sig,
                            dbclock.now(conn) + timedelta(seconds=2 * self.settings.replay_window))
        except ReplayError:
            return "replay"
        except (TenancyError, psycopg.Error) as exc:
            _log.error("events replay guard unavailable; request refused", error=type(exc).__name__)
            return f"replay_guard_unavailable:{type(exc).__name__}"
        return None

    def _guard(self) -> bool:
        if not self._host_ok():
            self._fail(421, "host_not_allowed", "the Host header is not on the allowlist")
            return False
        return True

    def _capturing(self) -> bool:
        return is_capture_path(urlsplit(self.path).path, SINGLE_CAPTURE_PREFIXES)

    def do_OPTIONS(self):
        if self._capturing():
            return self._capture()
        self._fail(405, "method_not_allowed", "only GET and POST are served here")

    def do_PUT(self):
        if self._capturing():
            return self._capture()
        self._fail(405, "method_not_allowed", "only GET and POST are served")

    do_DELETE = do_PATCH = do_PUT

    def do_POST(self):
        if self._capturing():
            return self._capture()
        if not self._guard():
            return
        self._fail(404, "not_found", "unknown path")

    def _capture(self) -> None:
        """Any request under a capture prefix: store it whole, answer with the receipt, then read it. Nothing about the
        request is checked first; what the checks found is a fact beside the post. A request the capture edge signed and
        forwarded is stored as the browser sent it, with the edge's facts beside it."""
        from .rawpost import Fact, RawRequest, StoreUnavailable

        body, facts = read_any_body(self)
        url = urlsplit(self.path)
        ts = self.headers.get(TIMESTAMP_HEADER) or ""
        sig = (self.headers.get(SIGNATURE_HEADER) or "").strip().lower()
        if sig.startswith("sha256="):
            sig = sig[7:]
        reason, by_verified_key = self._authentication_failure(ts, sig, body)
        replay = self._claim_signature(sig) if reason is None else None
        facts += [Fact("vault", "host_on_list", self._host_ok()), Fact("vault", "origin_header", self.headers.get("Origin")),
                  Fact("vault", "request_signature", reason or "valid"), Fact("vault", "replay", replay or "fresh"),
                  Fact("vault", "peer_address", self.client_address[0])]
        envelope = None
        if reason is None and not by_verified_key and edge_envelope.looks_like_envelope(body):
            try:
                envelope = edge_envelope.unpack(body)
                facts += [Fact("edge", str(n), v) for n, v in envelope.edge_facts.items()]
                if envelope.claimed_sha256 is not None and envelope.claimed_sha256 != hashlib.sha256(envelope.body).hexdigest():
                    facts.append(Fact("vault", "edge_body_sha256_mismatch", True))
            except edge_envelope.EnvelopeUnreadable as exc:  # loud-failure-exempt: recorded as the fact edge_envelope_unreadable; the signed bytes are stored as received
                facts.append(Fact("vault", "edge_envelope_unreadable", describe(exc)))
        preflight = is_preflight(self)
        if envelope is not None:
            inner_preflight = envelope.method.upper() == "OPTIONS" and any(
                n.lower() == "access-control-request-method" for n, _ in envelope.headers)
            raw = RawRequest(intake="edge_single", method=envelope.method, path=envelope.path, query=envelope.query,
                             headers=envelope.headers, body=envelope.body, headers_presented_by="edge-worker",
                             kind="preflight" if inner_preflight else "post", edge_received_at=envelope.edge_received_at,
                             facts=tuple(facts))
        else:
            raw = RawRequest(intake="api_single", method=self.command, path=url.path, query=url.query,
                             headers=request_headers(self), body=body, kind="preflight" if preflight else "post",
                             facts=tuple(facts))
        cors = cors_headers(self)
        with self.server.downstream.track():
            try:
                with connect(self.settings.dsn) as conn:
                    stored = self.writer.write(conn, None, raw)
            except (StoreUnavailable, ConsentVaultError, psycopg.Error) as exc:
                _log.critical("a post could not be stored", error=type(exc).__name__)
                status, answer = unavailable_answer()
                return self._send(status, answer, cors)
            if preflight and envelope is None:
                self.send_response(204)
                for k, v in cors.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(201, stored.answer(), cors)
            self._after_answer(stored, raw, body, reason, replay, by_verified_key, envelope)

    def _after_answer(self, stored, raw, body: bytes, reason, replay, by_verified_key, envelope=None) -> None:
        """Read the stored post and, for an authenticated event post, derive the transitional event. Never raises: the
        answer is given and the post is stored; a failure is logged loudly and left as a fact."""
        from . import intake
        from .rawpost import Fact

        try:
            with connect(self.settings.dsn) as conn:
                intake.read_after_commit(self.writer, conn, None, stored, raw)
                if raw.kind == "post" and raw.method == "POST" and (envelope is not None or raw.path == "/v1/events"):
                    outcome, event_id = ("not_authenticated:" + reason, None) if reason else (
                        ("replay", None) if replay else self._derive_event(conn, body, by_verified_key, envelope))
                    self.writer.add_facts(conn, None, stored, [Fact("vault", "event_derived", event_id) if event_id else
                                                               Fact("vault", "event_not_derived", outcome)])
                    if event_id:
                        self.writer.link_event(conn, None, stored, event_id)
        except Exception as exc:  # loud-failure-exempt: logged critical below; the answer is given and the post is stored
            _log.critical("the work after an answer failed; the post is stored", error=type(exc).__name__)

    def _derive_event(self, conn, body: bytes, by_verified_key: bool, envelope=None) -> tuple[str, str | None]:
        """The transitional step: an authenticated post that names a contact point and the event's own fields is also
        written as a ledger event, so the contact check keeps answering until it reads the posts. Whatever it cannot do is
        returned as the reason (stored as a fact); the post is never touched."""
        if envelope is not None:
            body = envelope.body
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):  # loud-failure-exempt: returned as the stored reason not_json
            return "not_json", None
        if not isinstance(payload, dict):
            return "not_a_json_object", None
        if envelope is not None:
            payload = edge_envelope.widget_event(payload, envelope.headers, envelope.edge_facts)
            payload.pop("source_id", None)
            payload.pop("brand_ids", None)
            payload["payload_sha256"] = hashlib.sha256(body).hexdigest()
        fields = {k: payload[k] for k in _EVENT_FIELDS if k in payload}
        for required in ("contact", "event_type", "channels", "purposes"):
            if required not in fields:
                return f"missing_field:{required}", None
        if fields.get("contact_verification", "none") != "none" and not by_verified_key:
            return "verification_key_required", None
        fields.setdefault("method", "checkbox")
        fields.setdefault("origin", "consumer")
        for name in ("captured_at", "edge_received_at"):
            if fields.get(name) is not None:
                try:
                    fields[name] = datetime.fromisoformat(str(fields[name]).replace("Z", "+00:00"))
                except ValueError:  # loud-failure-exempt: returned as the stored reason bad_<field>
                    return f"bad_{name}", None
        if fields.get("payload_sha256") is not None and not _SHA256_HEX.match(str(fields["payload_sha256"])):
            fields.pop("payload_sha256")
        fields.setdefault("payload_sha256", hashlib.sha256(body).hexdigest())
        fields["region"] = self.settings.default_region
        fields["allowed_purposes"] = self.settings.purposes
        try:
            if fields["event_type"] == "grant":
                fields.pop("event_type")
                fields.setdefault("disclosure_sha256", "")
                verification = fields.pop("contact_verification", "none")
                if verification == "none":
                    if "inbound_message" in payload:
                        return "bad_inbound_message", None
                    ev = capture_and_release(conn, checked=payload.get("checked") is True, **fields)[0]
                else:
                    ev = capture_verified(conn, verification=verification, checked=payload.get("checked") is True,
                                          inbound_message=payload.get("inbound_message"), **fields)[0]
            else:
                ev = record_event(conn, **fields)
        except ConsentVaultError as exc:
            return type(exc).__name__, None
        return "derived", ev.event_id

    def do_GET(self):
        if self._capturing():
            return self._capture()
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
                return self._fail(400, "bad_contact", caller_detail(exc))
            except Exception as exc:  # the failure is named in the answer, never an empty proof
                return self._fail(500, type(exc).__name__, caller_detail(exc))
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
    if not 0 < settings.replay_window <= MAX_REPLAY_WINDOW_SECONDS:
        raise ConfigError(f"replay_window must be 1 to {MAX_REPLAY_WINDOW_SECONDS} seconds: the replay guard keeps a "
                          "signature for twice the window and the database refuses a longer expiry")
    from .rawpost import RawPostWriter

    handler = type("ConsentVaultHandler", (_Handler,), {
        "settings": settings,
        "writer": settings.raw_posts if settings.raw_posts is not None else RawPostWriter(
            inline_limit=settings.raw_post_inline_limit_bytes, unusual_size=settings.raw_post_unusual_size_bytes),
    })
    return SafeHTTPServer((host, port), handler)


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
from . import safelog
import uuid as _uuid
from datetime import timezone

import psycopg

from .tenancy import logscrub as _logscrub

_log = safelog.get("consentvault.api")
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
    edge_signing_secret: bytes | None = None  # the capture edge's HMAC secret; None means edge captures are stored as received
    edge_timestamp_window_s: int = 300
    raw_post_inline_limit_bytes: int = config_mod.DEFAULT_RAW_POST_INLINE_BYTES
    raw_post_unusual_size_bytes: int = config_mod.DEFAULT_RAW_POST_UNUSUAL_BYTES

    def __repr__(self) -> str:
        return f"CloudApiSettings(token_endpoint_url={self.token_endpoint_url!r}, hosts={self.allowed_hosts!r})"


_SESSION_RIGHTS = """
SELECT r.rolname AS login, r.rolsuper AS superuser,
       EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
                WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
                  AND (n.nspowner OPERATOR(pg_catalog.=) r.oid OR pg_catalog.pg_has_role(r.oid, n.nspowner, 'MEMBER')))
           AS owner,
       (SELECT pg_catalog.string_agg(b.rolname::text, ', ' ORDER BY b.rolname) FROM pg_catalog.pg_roles b
         WHERE b.rolbypassrls AND pg_catalog.pg_has_role(r.oid, b.oid, 'MEMBER')) AS bypass
  FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) session_user
"""


def _session_refusal(conn) -> str | None:
    """Why the login itself must not serve tenants, or None: it is a superuser, the schema owner or a member of it, or a
    member of a BYPASSRLS role (row security would not bind it, or it could SET ROLE to one that it does not bind)."""
    me = conn.execute(_SESSION_RIGHTS).fetchone()
    if me is None:
        return "the session's login role could not be read"
    if me["superuser"]:
        return f"the login {me['login']} is a superuser"
    if me["owner"]:
        return f"the login {me['login']} is the schema owner or a member of it (it would hold the owner's rights)"
    if me["bypass"]:
        return f"the login {me['login']} is a member of the BYPASSRLS role(s) {me['bypass']}"
    return None


# Every role that can log in and acts with the schema owner's rights through membership (direct or through other roles):
# a migration login. One exists only during a migration run; a superuser (or the managed service's master user) is the
# break-glass and is not one.
_MIGRATION_LOGINS = """
WITH RECURSIVE owner AS (
    SELECT n.nspowner AS oid FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
), members(oid) AS (
    SELECT m.member FROM pg_catalog.pg_auth_members m, owner WHERE m.roleid OPERATOR(pg_catalog.=) owner.oid
    UNION
    SELECT m.member FROM pg_catalog.pg_auth_members m JOIN members x ON m.roleid OPERATOR(pg_catalog.=) x.oid
)
SELECT r.rolname::text AS login FROM members JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) members.oid
 WHERE r.rolcanlogin AND NOT r.rolsuper
   AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname OPERATOR(pg_catalog.=) 'rds_superuser'
                    AND pg_catalog.pg_has_role(r.oid, g.oid, 'MEMBER'))
 ORDER BY 1
"""


def _migration_logins(conn) -> list[str]:
    """The login roles that hold the schema owner's rights (a migration login), by name."""
    return [r["login"] for r in conn.execute(_MIGRATION_LOGINS).fetchall()]


def _manifest_drift(conn) -> list[str]:
    """The live security surface against the manifest shipped with this build; every drifted object by name."""
    from . import surface

    try:
        return surface.drift(surface.live_surface(conn), surface.load_manifest())
    except surface.ManifestError as exc:
        return [describe(exc)]


SINGLE_MODE_REFUSAL = db_code("require_multi_tenant", "consentvault tenancy: this vault is in single mode; a multi-tenant "
                              "service must not serve it")


# A role by this name once let a test login name the time the Twenty connector's functions wrote with. Nothing reads it now (every
# connector function uses the database's clock), and a superuser or a managed service's master user (CREATEROLE, migration 0026)
# could still create it, so its presence on a production server is refused at start and raised by the nightly self-test.
TEST_CLOCK_ROLE = "consentvault_test_clock"
_TEST_CLOCK_ROLE = ("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname OPERATOR(pg_catalog.=) 'consentvault_test_clock')"
                    " AS present")


def startup_check_code(problem: str) -> str:
    """The stable code of one start-up check, made from the fixed sentence the check reports (owner_rights_violations() and
    pin_violations() each report one product sentence per kind of problem): ``startup_the_schema_owner_can_log_in``."""
    slug = re.sub(r"[^a-z0-9]+", "_", problem.lower()).strip("_")
    return "startup_" + (slug[:56].rstrip("_") or "violation")


def _refuse_violation(row) -> None:
    """Refuse naming the object from the violation row itself (data the check returned, never an error's text), with the code of
    the check that found it."""
    raise StartupRefusedError(f"the multi-tenant API will not serve this database: {row['object_kind']} {row['object_name']} "
                              f"(owner {row['owner_name']}): {row['problem']}", code=startup_check_code(row["problem"]))


def _refuse_from_database(conn, exc: BaseException) -> None:
    """require_multi_tenant() refused. Single mode is named by its registered database code; an owner-rights violation is read
    back as rows (the check's data), so the refusal names the object and its own check, never the database's text."""
    if refusal_code(exc) == SINGLE_MODE_REFUSAL:
        raise StartupRefusedError("the multi-tenant API will not serve this database: this vault is in single mode; a "
                                  "multi-tenant service must not serve it", code="startup_single_mode") from exc
    rows = conn.execute("SELECT * FROM consentvault.owner_rights_violations()").fetchall()
    if rows:
        try:
            _refuse_violation(rows[0])
        except StartupRefusedError as refused:
            raise refused from exc
    raise StartupRefusedError(f"the multi-tenant API will not serve this database: {describe(exc)}",
                              code="startup_tenancy_check_refused") from exc


def startup_check(dsn: str) -> None:
    """Conditions 1 and 2 of the tenancy review: refuse to serve unless the vault is in multi mode, the login is neither
    a superuser, the schema owner (or a member of it) nor a member of a BYPASSRLS role, every owner-rights function and
    row-secured table is owned by the non-superuser schema owner or the operator role, no member of the operator console
    bypasses row security, and every pinned trigger guard is as pinned (read from the superuser-owned guard schema
    directly too, so a replaced consentvault.owner_rights_violations() cannot hide a changed guard). Then no migration
    login may still log in (one exists only during a migration run), and the live security surface must match the
    manifest shipped with this build (consentvault.surface), read from the system catalogs: any drift refuses, naming
    every object added, changed or removed."""
    try:
        with connect(dsn) as conn:
            refusal = _session_refusal(conn)
            if refusal is not None:
                raise StartupRefusedError(f"the multi-tenant API will not serve this database: {refusal}", code='startup_session_refused')
            try:
                conn.execute("SELECT consentvault.require_multi_tenant()")
            except psycopg.Error as exc:
                _refuse_from_database(conn, exc)
            owner_bad = conn.execute("SELECT * FROM consentvault.owner_rights_violations()").fetchall()
            guard_missing = conn.execute("SELECT to_regprocedure('consentvault_guard.pin_violations()') IS NULL AS missing"
                                         ).fetchone()["missing"]
            pin_bad = [] if guard_missing else conn.execute("SELECT * FROM consentvault_guard.pin_violations()").fetchall()
            logins = _migration_logins(conn)
            test_clock = conn.execute(_TEST_CLOCK_ROLE).fetchone()["present"]
            drifted = _manifest_drift(conn)
    except psycopg.Error as exc:
        raise StartupRefusedError(f"the multi-tenant API will not serve this database: "
                                  f"{describe(exc)}", code='startup_database_refused') from exc
    except StartupRefusedError:
        raise
    except ConsentVaultError as exc:
        raise StartupRefusedError(f"the multi-tenant API cannot reach the database: {describe(exc)}", code='startup_database_unreachable') from exc
    # each check refuses with its own code, so an operator can tell which fired without reading the message
    if owner_bad:
        _refuse_violation(owner_bad[0])
    if guard_missing:
        raise StartupRefusedError("the multi-tenant API will not serve this database: event trigger "
                                  "consentvault_guard.pin_violations() (owner -): the trigger guard predates guard pinning: run "
                                  "docker/initdb/20-trigger-guard.sql again as a superuser", code="startup_guard_predates_pinning")
    if pin_bad:
        _refuse_violation(pin_bad[0])
    if logins:
        raise StartupRefusedError(
            f"the multi-tenant API will not serve this database: the migration login {', '.join(logins)} can still log "
            "in; a migration login exists only during a migration run (as the superuser: ALTER ROLE <login> NOLOGIN, or "
            "DROP ROLE, once the run and the superuser's pin_guards() are done)", code='startup_migration_login_can_log_in')
    if test_clock:
        raise StartupRefusedError(
            "the multi-tenant API will not serve this database: the role consentvault_test_clock exists on its server; it belongs "
            "to a test cluster only (as the superuser or the managed service's master: DROP ROLE consentvault_test_clock)",
            code='startup_test_clock_role')
    if drifted:
        raise StartupRefusedError(
            "the multi-tenant API will not serve this database: its security surface differs from the security manifest "
            "shipped with this build (" + str(len(drifted)) + "): " + "; ".join(drifted), code='startup_manifest_drift')


def _api_error(name: str, detail: str, fields: dict | None = None):
    from .tenancy.admin_base import ApiError

    return ApiError(name, detail, fields)


_CAPTURE_KEYS = frozenset({
    "contact", "event_type", "channels", "purposes", "method", "origin", "disclosure_sha256", "subject_key", "captured_at",
    "page_url", "client_ip", "user_agent", "session_ref", "bot_check", "source", "edge_received_at", "contact_verification",
    "checked", "inbound_message", "source_id", "brand_ids", "attribution", "display"})


@dataclass(frozen=True)
class _EdgeClaims:
    """Stands where verified access-token claims stand, for a capture the edge forwarded: capture scope only, one minute."""
    org_id: object
    credential_id: object
    scopes: tuple = ("capture",)

    def seconds_left(self) -> int:
        return 60


class _CloudHandler(BaseHTTPRequestHandler):
    server_version = "consentvault"
    sys_version = ""
    settings: CloudApiSettings
    pipeline: object

    def log_message(self, fmt, *args):  # request lines carry no body; nothing personal is logged here
        pass

    def send_response(self, code, message=None):
        self._sent_status = code  # read by the metrics hook in do_POST
        super().send_response(code, message)

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
        if is_capture_path(urlsplit(self.path).path, CLOUD_CAPTURE_PREFIXES):
            return self._capture()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("GET")

    def do_PUT(self):
        self.request_id = self._rid()
        if is_capture_path(urlsplit(self.path).path, CLOUD_CAPTURE_PREFIXES):
            return self._capture()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("PUT")

    def do_PATCH(self):
        self.request_id = self._rid()
        if is_capture_path(urlsplit(self.path).path, CLOUD_CAPTURE_PREFIXES):
            return self._capture()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("PATCH")

    def do_DELETE(self):
        self.request_id = self._rid()
        if is_capture_path(urlsplit(self.path).path, CLOUD_CAPTURE_PREFIXES):
            return self._capture()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        self._other_lanes("DELETE")

    def do_OPTIONS(self):
        self.request_id = self._rid()
        if is_capture_path(urlsplit(self.path).path, CLOUD_CAPTURE_PREFIXES):
            return self._capture()
        self._error("not_found", "no CORS preflight is served here", 404)

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
        from .sync.connectors.twenty_workflow import SCOPE as WORKFLOW_SCOPE, is_workflow_secret

        if is_workflow_secret(auth[7:].strip()):  # a Twenty workflow credential checks POST /v1/permission and nothing else
            raise _api_error("role_not_allowed", "a workflow credential may call POST /v1/permission only",
                             {"role": "machine:" + WORKFLOW_SCOPE})
        claims = self.settings.access_tokens.verify(auth[7:].strip())
        if not set(needed) & set(claims.scopes):
            raise _api_error("role_not_allowed", "this credential's scopes may not call this endpoint",
                             {"role": "machine:" + " ".join(claims.scopes)})
        return claims

    def _workflow_claims(self, many: bool):
        """A Twenty workflow credential's claims for one check (twenty.md 4.2), None for any other bearer, or "rate_limited"
        once the 429 has been sent. Unknown, revoked and expired credentials are refused as unauthenticated."""
        import uuid as _uuid_mod

        from .sync.connectors import twenty_workflow as wf
        from .tenancy.oauth import AccessClaims, UnauthenticatedError

        auth = (self.headers.get("Authorization") or "")[7:].strip()
        if not wf.is_workflow_secret(auth) or many:
            return None  # a workflow credential on the batch route is refused by _claims as role_not_allowed
        with connect(self.settings.dsn) as conn:
            got = wf.use(conn, auth)
        if got["outcome"] == "rate_limited":
            self._send(429, {"error": "rate_limited", "detail": "this workflow credential's checks a minute are used up",
                             "request_id": self.request_id}, {"Retry-After": str(got["retry_after"])})
            return "rate_limited"
        if got["outcome"] != "ok":
            raise UnauthenticatedError(f"the workflow credential is {got['outcome']}")
        return AccessClaims(got["org_id"], got["credential_id"], ("gate_read",), str(_uuid_mod.uuid4()), int(time.time()) + 60)

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
        """Every POST, then its application metrics (capture error rate, gate latency and 503s; consentvault.metrics):
        counts and timings only, written as embedded-metric log lines."""
        from . import metrics

        self._sent_status = None
        started = time.monotonic()
        try:
            self._do_post()
        finally:
            metrics.observe_request(urlsplit(self.path).path, self._sent_status, (time.monotonic() - started) * 1000)

    def _do_post(self):
        from .alarms import AlarmWriteError
        from .tenancy.admin_base import ApiError
        from .tenancy.errors import KeyProviderError, TenantTokenError
        from .tenancy.oauth import OAuthError
        from .tenancy.pipeline import EvidenceStoreUnavailable

        self.request_id = self._rid()
        path = urlsplit(self.path).path
        if is_capture_path(path, CLOUD_CAPTURE_PREFIXES):
            return self._capture()
        if not self._host_ok():
            return self._error("invalid_request", "the Host header is not on the allowlist", 421)
        route = {"/v1/oauth/token": self._token, "/v1/permission": self._permission,
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
            self._send(exc.status, {"error": exc.name, "detail": caller_detail(exc), "request_id": self.request_id,
                                    **({"fields": exc.fields} if getattr(exc, "fields", None) else {})})
        except KeyProviderError:
            self._error("key_unavailable", "the organization key could not be used; nothing was written or read", 503)
        except AlarmWriteError as exc:
            _log.critical("request failed", request_id=self.request_id, error=type(exc).__name__)
            self._error("alarm_unavailable", "the event was recorded, but a follow-up decision and its operator alarm"
                        " could not be written; the operator must be told by another route", 503)
        except EvidenceStoreUnavailable:
            _log.error("evidence store refused an object", request_id=self.request_id)
            self._error("evidence_store_unavailable", "the write-once store did not take the evidence; nothing was "
                        "recorded", 503)
        except (TenantTokenError, ServiceUnavailableError, psycopg.Error) as exc:
            _log.error("service unavailable", path=path, request_id=self.request_id, error=type(exc).__name__)
            self._error("service_unavailable", "the vault could not complete the request; nothing was written", 503)
        except ConsentVaultError as exc:
            _log.error("refused", path=path, request_id=self.request_id, error=type(exc).__name__)
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

    # capture: store everything, answer with a receipt, then read it -------------------------------------------------------
    def _home_token(self, conn) -> tuple[str, str]:
        from .tenancy.tokens import mint_org_token

        home = conn.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
        return str(home), mint_org_token(self.settings.token_key, home, ("capture",), credential_id=None, ttl_seconds=60)

    def _capture(self) -> None:
        """Any request under a capture prefix, any method, any body: written whole to the raw post store before anything
        reads it, answered with the receipt, then read. Authentication, the site key, the origin, the signature and the
        bot check are facts beside the post, never reasons to refuse it (contracts/capture-api.md)."""
        from .rawpost import Fact, RawRequest, StoreUnavailable

        self.request_id = self._rid()
        body, facts = read_any_body(self)
        url = urlsplit(self.path)
        headers = request_headers(self)
        preflight = is_preflight(self)
        facts += [Fact("vault", "host_on_list", self._host_ok()), Fact("vault", "origin_header", self.headers.get("Origin")),
                  Fact("vault", "peer_address", self.client_address[0])]
        identity = self._capture_identity(body, headers, url, facts)
        if identity["envelope"]:  # the edge answers the browser's permission check itself; to the edge the vault answers with a receipt
            preflight_inner = (identity["method"] or "").upper() == "OPTIONS" and any(
                n.lower() == "access-control-request-method" for n, _ in identity["headers"] or ())
        else:
            preflight_inner = preflight
        cors = cors_headers(self)
        with self.server.downstream.track():
            try:
                with connect(self.settings.dsn) as conn:
                    if identity["claims"] is not None:
                        org_token = self._tenant_token(identity["claims"], ("capture",))
                    elif identity["owner"] is not None:  # the key names an organisation even when it is revoked or its source retired
                        from .tenancy.tokens import mint_org_token

                        org_token = mint_org_token(self.settings.token_key, identity["owner"].org_id, ("capture",),
                                                   credential_id=None, ttl_seconds=60)
                    else:
                        _, org_token = self._home_token(conn)
                    enter = self._enter(org_token)
                    raw = RawRequest(
                        intake=identity["intake"], method=identity["method"] or self.command, path=identity["path"] or url.path,
                        query=identity["query"] if identity["query"] is not None else url.query,
                        headers=identity["headers"] if identity["headers"] is not None else headers,
                        body=identity["body"] if identity["body"] is not None else body,
                        headers_presented_by="edge-worker" if identity["envelope"] else "vault-http",
                        kind="preflight" if preflight_inner else "post", edge_received_at=identity["edge_received_at"],
                        facts=tuple(facts))
                    stored = self.writer.write(conn, enter, raw)
            except (StoreUnavailable, ConsentVaultError, psycopg.Error) as exc:
                _log.critical("a post could not be stored", request_id=self.request_id, error=type(exc).__name__)
                status, answer = unavailable_answer()
                return self._send(status, answer, cors)
            if preflight and not identity["envelope"]:
                self.send_response(204)
                for k, v in cors.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "0")
                self.send_header("X-Request-Id", self.request_id)
                self.end_headers()
            else:
                self._send(201, stored.answer(), cors)
            self._after_answer(stored, raw, enter, identity)

    def _capture_identity(self, body: bytes, headers, url, facts: list) -> dict:
        """Who the post came from, as far as it can be told. Never raises and never refuses: what could not be verified is
        a fact and the post goes to the platform intake (the home organisation's chain)."""
        from .rawpost import Fact

        out = {"claims": None, "intake": "api", "method": None, "path": None, "query": None, "headers": None, "body": None,
               "envelope": False, "edge_received_at": None, "owner": None, "browser_body": None, "edge_facts": {}}
        auth = (self.headers.get("Authorization") or "").strip()
        signed = bool(self.headers.get(SIGNATURE_HEADER)) and not auth
        if auth:
            try:
                out["claims"] = self._claims("capture", "capture_verified")
                facts.append(Fact("vault", "credential", {"state": "verified", "credential_id": str(out["claims"].credential_id)}))
            except Exception as exc:  # loud-failure-exempt: the failure is the stored fact credential, the post goes to the platform intake
                facts.append(Fact("vault", "credential", {"state": "refused", "reason": type(exc).__name__}))
        elif signed and self.command == "POST":
            self._edge_envelope(body, facts, out)
        return out

    def _edge_envelope(self, body: bytes, facts: list, out: dict) -> None:
        """A capture the edge forwarded: when the edge's signature verifies, the envelope is unpacked and the browser's own
        request (method, path, headers, exact bytes) is what is stored, with the edge's facts beside it. When it does not
        verify, the request as received (the envelope itself) is stored and nothing in it is trusted."""
        from .rawpost import Fact
        from .tenancy.errors import ReplayError
        from .tenancy.replay import claim_nonce
        from .tenancy.site_keys import resolve_site_key

        secret = self.settings.edge_signing_secret
        ts = self.headers.get(TIMESTAMP_HEADER) or ""
        sig = (self.headers.get(SIGNATURE_HEADER) or "").strip().lower()
        if not edge_envelope.verified(secret, ts, sig, body):
            facts.append(Fact("vault", "edge_envelope_signature", "failed" if secret else "no_edge_secret_configured"))
            return
        facts.append(Fact("vault", "edge_envelope_signature", "verified"))
        try:
            env = edge_envelope.unpack(body)
        except edge_envelope.EnvelopeUnreadable as exc:  # loud-failure-exempt: recorded as the fact edge_envelope_unreadable; the signed bytes are stored as received
            facts.append(Fact("vault", "edge_envelope_unreadable", describe(exc)))
            return
        out.update(envelope=True, intake="edge_site_key", method=env.method, path=env.path, query=env.query,
                   headers=env.headers, body=env.body, browser_body=env.body, edge_received_at=env.edge_received_at,
                   edge_facts=env.edge_facts)
        if env.claimed_sha256 is not None and env.claimed_sha256 != hashlib.sha256(env.body).hexdigest():
            facts.append(Fact("vault", "edge_body_sha256_mismatch", True))
        for name, value in env.edge_facts.items():
            facts.append(Fact("edge", str(name), value))
        site_key = next((v for n, v in env.headers if n.lower() == "x-consentvault-site-key"), None)
        window = self.settings.edge_timestamp_window_s
        try:
            with connect(self.settings.dsn) as conn:
                owner = resolve_site_key(conn, site_key) if site_key else None
                facts.append(Fact("vault", "site_key_state", owner.state if owner else "unknown"))
                try:
                    facts.append(Fact("vault", "edge_timestamp",
                                      "fresh" if abs(dbclock.epoch(conn) - float(ts)) <= window else "stale"))
                except ValueError:  # loud-failure-exempt: recorded as the fact edge_timestamp unreadable
                    facts.append(Fact("vault", "edge_timestamp", "unreadable"))
                home = str(conn.execute("SELECT consentvault.home_org() AS h").fetchone()["h"])
                try:
                    claim_nonce(conn, owner.org_id if owner else home, "edge:" + sig,
                                dbclock.now(conn) + timedelta(seconds=2 * window))
                    facts.append(Fact("vault", "replay", "fresh"))
                except ReplayError:  # loud-failure-exempt: recorded as the fact replay; the post is stored again
                    facts.append(Fact("vault", "replay", "seen_before"))
                    out["replayed"] = True
        except (ConsentVaultError, psycopg.Error) as exc:
            facts.append(Fact("vault", "site_key_lookup", "failed:" + type(exc).__name__))
            return
        if owner is not None:
            out["owner"] = owner
            if owner.state == "active":
                out["claims"] = _EdgeClaims(owner.org_id, owner.credential_id)
            origin = next((v for n, v in env.headers if n.lower() == "origin"), "")
            facts.append(Fact("vault", "origin_on_list", origin in owner.allowed_origins))

    def _after_answer(self, stored, raw, enter, identity: dict) -> None:
        """Read the stored post and, for an identified post, derive the transitional event. Never raises: the answer is
        given and the post is stored; a failure is logged loudly and left as a fact."""
        from . import intake
        from .rawpost import Fact

        owner = identity["owner"]
        try:
            with connect(self.settings.dsn) as conn:
                intake.read_after_commit(self.writer, conn, enter, stored, raw,
                                         source_id=owner.source_id if owner else None, request_id=self.request_id)
                if raw.kind == "post" and raw.method == "POST" and identity["claims"] is not None \
                        and not identity.get("replayed") and (identity["envelope"] or raw.path == "/v1/events"):
                    outcome, event_id = self._derive_event(conn, identity, raw)
                    self.writer.add_facts(conn, enter, stored, [Fact("vault", "event_derived", event_id) if event_id else
                                                                Fact("vault", "event_not_derived", outcome)])
                    if event_id:
                        self.writer.link_event(conn, enter, stored, event_id)
        except Exception as exc:  # loud-failure-exempt: logged critical below; the answer is given and the post is stored
            _log.critical("the work after an answer failed; the post is stored", request_id=self.request_id,
                          error=type(exc).__name__)

    def _derive_event(self, conn, identity: dict, raw) -> tuple[str, str | None]:
        """The transitional step: an identified post that carries the event's own fields (or the widget's) is also written as
        a ledger event, so the contact check keeps answering until it reads the posts. Whatever it cannot do is returned as
        the reason (stored as a fact); the post is never touched."""
        from .errors import (ConsentRefusedError, InvalidEventError, LedgerError, NormalizationError, UnknownDisclosureError,
                             UnknownPurposeError)
        from .release import release_after_tenant_grant
        from .tenancy.admin_base import ApiError
        from .tenancy.pipeline import EvidenceStoreUnavailable, parse_capture

        claims, body = identity["claims"], bytes(raw.body)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):  # loud-failure-exempt: returned as the stored reason not_json
            return "not_json", None
        if not isinstance(payload, dict):
            return "not_a_json_object", None
        if identity["envelope"]:
            owner = identity["owner"]
            payload = edge_envelope.widget_event(payload, raw.headers, identity["edge_facts"],
                                                 source_id=owner.source_id if owner else None,
                                                 brand_ids=owner.brand_ids if owner else None, source="site_key")
        else:
            payload = {k: v for k, v in payload.items() if k in _CAPTURE_KEYS}
        try:
            req = parse_capture(payload, body, claims.scopes)
            token = self._tenant_token(claims)
            result = self.pipeline.capture(conn, self._enter(token), req, credential_id=claims.credential_id)
            if req.fields["event_type"] == "grant" and req.fields.get("origin", "consumer") == "consumer":
                reader = self._tenant_token(claims, ("capture", "gate_read"))
                try:
                    with self._enter(reader)(conn):
                        release_after_tenant_grant(conn, self.settings.crypto, result.event_id)
                except (ConsentVaultError, psycopg.Error) as exc:
                    try:
                        self._release_alarm(conn, token, result.event_id, exc)
                    except ConsentVaultError as alarm_exc:  # the event stands; the missing alarm was logged critical by _release_alarm
                        _log.critical("the event is recorded but neither its release decision nor its alarm was written",
                                      event_id=result.event_id, request_id=self.request_id, error=type(alarm_exc).__name__)
        except ApiError as exc:
            return exc.name, None
        except (UnknownDisclosureError, UnknownPurposeError, NormalizationError, InvalidEventError, ConsentRefusedError,
                EvidenceStoreUnavailable) as exc:
            return type(exc).__name__, None
        except LedgerError as exc:
            return ("LedgerError:" + type(exc.__cause__).__name__ if exc.__cause__ else "LedgerError"), None
        except (ConsentVaultError, psycopg.Error) as exc:
            return "unavailable:" + type(exc).__name__, None
        return "derived", result.event_id

    def _release_alarm(self, conn, token: str, event_id: str, exc: BaseException) -> None:
        from .alarms import ALARM_RELEASE_NOT_WRITTEN, AlarmWriteError, raise_operator_alarm

        _log.error("release decision not written", event_id=event_id, request_id=self.request_id,
                   error=type(exc).__name__)
        try:
            with self._enter(token)(conn):
                raise_operator_alarm(conn, name=ALARM_RELEASE_NOT_WRITTEN, error_class=type(exc).__name__,
                                     ref_kind="event", ref_id=event_id, request_id=self.request_id)
        except (AlarmWriteError, ConsentVaultError, psycopg.Error) as alarm_exc:
            _log.critical("operator alarm NOT written; the release decision is missing and nothing in the database says so",
                          alarm=ALARM_RELEASE_NOT_WRITTEN, event_id=event_id, request_id=self.request_id,
                          error=type(alarm_exc).__name__)
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

        claims = self._workflow_claims(many)
        if claims == "rate_limited":
            return
        claims = claims or self._claims("gate_read")
        items = self._gate_items(self._json(body), many)
        token = self._tenant_token(claims)
        loaded = None  # the gate, once it has read the organisation's approved policy
        try:
            with connect(self.settings.dsn) as conn, self._enter(token)(conn) as org:
                require_serving(conn)
                gate = TenantGate(conn, self.settings.crypto, org=org, requested_by=str(claims.credential_id),
                                  region=self.settings.region)
                loaded = (gate.policy, frozenset(gate.channels), frozenset(gate.purposes))
                if not many:
                    reply = gate.check(items[0])
                else:
                    batch_id = str(_uuid.uuid4())
                    answers = []
                    for item in items:
                        try:
                            answers.append(gate.check(item, batch_id=batch_id)[1])
                        except ApiError as exc:
                            answers.append({"error": exc.name, "detail": caller_detail(exc)})
                    reply = (200, {"items": answers, "batch_id": batch_id})
            # the transaction has committed: only now does the caller hear an answer (a failed commit is the 503 below,
            # with nothing recorded, never a 200 for a decision that was not kept)
            return self._send(*reply)
        except (GateRecordError, psycopg.Error, ServiceUnavailableError) as exc:
            _log.error("gate unavailable", request_id=self.request_id, error=type(exc).__name__)
            cause = "restore_in_progress" if self._restore_pending() else "database"
            body = {"evidence_status": f"unavailable:{cause}", "policy_action": None, "policy_version": None,
                    **({"error": "restore_in_progress"} if cause == "restore_in_progress" else {}),
                    "notice": NOTICE, "request_id": self.request_id}
            if loaded is not None and loaded[0] is not None:  # the approved policy's own cell for "unavailable"
                from .gate_rules import engine

                def unavailable(item):
                    ch, pu = item.channel, item.purpose
                    if not (isinstance(ch, str) and isinstance(pu, str) and ch in loaded[1]
                            and pu.strip().lower() in loaded[2]):
                        return {}
                    out = engine.unavailable(cause, loaded[0], ch, pu.strip().lower())
                    return {"policy_action": out.policy_action, "policy_version": out.policy_version}

                if many:
                    body["items"] = [{"evidence_status": body["evidence_status"], **unavailable(i)} for i in items]
                else:
                    body.update(unavailable(items[0]))
            self._send(503, body)

    def _restore_pending(self) -> bool:
        """True while a database restore is unreconciled (the gate refuses to answer until an operator finishes it)."""
        try:
            with connect(self.settings.dsn) as conn:
                return bool(conn.execute("SELECT consentvault.restore_pending() AS p").fetchone()["p"])
        except (ConsentVaultError, psycopg.Error):  # loud-failure-exempt: the answer is already a 503 naming the database
            return False

    def _permission(self, body: bytes) -> None:
        self._gate(body, False)

    def _permission_batch(self, body: bytes) -> None:
        self._gate(body, True)

    def _portal_proof_token(self):
        """A portal session's read token for POST /v1/proof (contracts/proof-export.md: admin and compliance viewer, never a
        developer), or None when the caller sent no session token. The role comes from the member row, via the same
        ``portal_caller`` the billing routes use; the token minted here carries the one scope the lookup needs."""
        from .tenancy.oauth import UnauthenticatedError
        from .tenancy.session import MEMBER_CREDENTIAL_PREFIX
        from .tenancy.tokens import mint_org_token

        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer v1."):
            return None
        caller = self.settings.portal_caller(dict(self.headers.items())) if self.settings.portal_caller else None
        if caller is None:
            raise UnauthenticatedError("the session token is missing, expired or not valid")
        if caller.role not in ("admin", "compliance_viewer"):
            raise _api_error("role_not_allowed", "this role may not read evidence", {"role": str(caller.role)})
        if not caller.member_id:
            raise UnauthenticatedError("the session token does not name a member")
        return mint_org_token(self.settings.token_key, caller.org_id, ("proof_read",),
                              credential_id=MEMBER_CREDENTIAL_PREFIX + caller.member_id, ttl_seconds=60), caller.member_id

    def _proof(self, body: bytes) -> None:
        from .gate_rules.policy import PolicyStoreError, approved_policy
        from .proof import tenant_lookup
        from .tenancy.pipeline import require_serving

        portal, member_id = self._portal_proof_token() or (None, None)
        claims = None if portal else self._claims("proof_read")
        payload = self._json(body)
        if not isinstance(payload, dict) or set(payload) - {"contact", "page"}:
            raise _api_error("validation_failed", "the body is {contact, page?}", {"body": "contact and page only"})
        token = portal or self._tenant_token(claims)
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
            if member_id:  # a portal read is tied to the person: the audit row names the member and a fingerprint prefix
                from .tenancy import audit
                from .tenancy.pipeline import normalize

                kind, norm = normalize(payload["contact"], self.settings.region)
                fp = self.settings.crypto.contact_fingerprint(org, kind, norm)
                with conn.transaction():
                    audit.append(conn, actor_kind="member", actor_id=member_id, action="proof.read", target_kind="contact",
                                 target_id=fp[:8], request_id=self.request_id)
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
    _logscrub.install(_log.logger)  # the backstop sits on the standard logger the safe logger writes through
    pipeline = CapturePipeline(store=settings.evidence_store, crypto=settings.crypto, receipts=settings.receipts,
                               default_retain_years=settings.default_retain_years, region=settings.region)
    from .rawpost import RawPostWriter

    writer = RawPostWriter(crypto=settings.crypto, store=settings.evidence_store, receipts=settings.receipts,
                           retain_years=settings.default_retain_years, inline_limit=settings.raw_post_inline_limit_bytes,
                           unusual_size=settings.raw_post_unusual_size_bytes)
    handler = type("ConsentVaultCloudHandler", (_CloudHandler,), {"settings": settings, "pipeline": pipeline, "writer": writer})
    return SafeHTTPServer((host, port), handler)
