"""Routes of the suppression-sync lane, independent of any web framework.

How the API lane registers them, once, in one line:

    sync = SyncRoutes(connect=open_app_connection, crypto=tenant_crypto, region=cfg.default_region,
                      allowed_purposes=cfg.purposes)
    ...
    if sync.matches(method, path):
        response = sync.handle(Request(method=method, path=path, body=parsed_json, query=query, request_id=rid,
                                       org_id=org, scopes=frozenset(token_scopes), credential_id=cid, token=tenant_token,
                                       role=role, actor=actor))
        # send response.status and response.body (already in the contracts' error shape)

``connect`` returns a fresh autocommit connection as the runtime role (closed here after the call). ``token`` is the
tenant token the API minted for this request, with exactly the credential's or portal session's scopes. A client error
is a ``Response`` (the contracts' error table); a fault of our own (the database, a bug) propagates, so the API lane
answers it as a 5xx and alarms. The routes:

    POST /v1/signals                         scope capture (a system's signal credential)
    POST /v1/deliveries:query                admin, proof_read; never developer
    GET  /v1/systems/{system_id}/deliveries  admin, developer, proof_read
    POST /v1/deliveries:redrive              admin, developer
    GET  /v1/redrives/{redrive_id}           admin, developer

The role check here is a courtesy that gives the contract's error; the owner-rights functions refuse a token without
the scope themselves, so a route that forgot the check would still be refused by the database.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

import psycopg

from .. import dbclock
from ..safelog import caller_detail
from ..errors import NormalizationError
from ..ledger import CHANNELS  # noqa: F401  (documented channel list)
from ..normalize import normalize_contact
from ..tenancy import crypto as tc
from ..tenancy.errors import KeyProviderError, TenantTokenError
from ..tenancy.tokens import org_transaction
from .errors import InvalidContactError, SignalValidationError
from .outbox import iso_z
from .signals import parse_signal, process_signal

CURSOR_TTL_SECONDS = 24 * 3600
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
STATUS_FILTERS = ("pending", "acknowledged", "dead", "superseded")


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    org_id: Any
    scopes: frozenset
    token: str
    body: Any = None
    query: Mapping[str, str] = field(default_factory=dict)
    request_id: str = ""
    credential_id: str | None = None
    role: str | None = None
    actor: str | None = None


@dataclass(frozen=True)
class Response:
    status: int
    body: dict


@dataclass(frozen=True)
class Route:
    method: str
    template: str
    name: str
    scopes: frozenset


ROUTES = (
    Route("POST", "/v1/signals", "signals", frozenset({"capture"})),
    Route("POST", "/v1/systems/{system_id}:test", "system_test", frozenset({"admin", "developer"})),
    Route("POST", "/v1/deliveries:query", "deliveries_query", frozenset({"admin", "proof_read"})),
    Route("GET", "/v1/systems/{system_id}/deliveries", "system_deliveries", frozenset({"admin", "developer", "proof_read"})),
    Route("POST", "/v1/deliveries:redrive", "redrive", frozenset({"admin", "developer"})),
    Route("GET", "/v1/redrives/{redrive_id}", "redrive_status", frozenset({"admin", "developer"})),
)


def _match(route: Route, method: str, path: str) -> dict | None:
    if method != route.method:
        return None
    have, want = path.rstrip("/").split("/"), route.template.split("/")
    if len(have) != len(want):
        return None
    params: dict[str, str] = {}
    for h, w in zip(have, want):
        if w.startswith("{"):
            name, _, suffix = w[1:].partition("}")  # "{system_id}:test" keeps its ":test" fixed
            if suffix and not h.endswith(suffix):
                return None
            params[name] = h[:-len(suffix)] if suffix else h
        elif h != w:
            return None
    return params


def _error(status: int, name: str, detail: str, rid: str, fields: dict | None = None) -> Response:
    body = {"error": name, "detail": detail, "request_id": rid}
    if fields:
        body["fields"] = fields
    return Response(status, body)


def _uuid(value) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


class SyncRoutes:
    def __init__(self, connect: Callable[[], psycopg.Connection], crypto: tc.TenantCrypto, *, region: str | None = None,
                 allowed_purposes=None, clock: Optional[Callable[[], float]] = None, custody=None, transport=None, mint_token=None) -> None:
        self.custody, self.transport, self.mint_token = custody, transport, mint_token  # a test push needs the key custody and the egress door
        self.connect = connect
        self.crypto = crypto
        self.region = region
        self.allowed_purposes = allowed_purposes
        self.clock = clock or dbclock.epoch_clock(connect)   # tests pin one; production reads the database's

    def matches(self, method: str, path: str) -> bool:
        return any(_match(r, method, path) is not None for r in ROUTES)

    def handle(self, req: Request) -> Response:
        for route in ROUTES:
            params = _match(route, req.method, req.path)
            if params is None:
                continue
            if not (route.scopes & set(req.scopes)):
                fields = {"role": req.role} if req.role else {"scopes": sorted(req.scopes)}
                return _error(403, "role_not_allowed", "this role may not call this endpoint", req.request_id, fields)
            try:
                return getattr(self, "_" + route.name)(req, params)
            except TenantTokenError as exc:
                return _error(401, "unauthenticated", caller_detail(exc), req.request_id)
            except KeyProviderError as exc:
                return _error(503, "key_unavailable", f"the organization key could not be used: {caller_detail(exc)}", req.request_id)
            except psycopg.errors.InsufficientPrivilege:
                return _error(403, "role_not_allowed", "the token holds none of the scopes this call needs", req.request_id)
        return _error(404, "not_found", "no such route", req.request_id)

    # cursors ----------------------------------------------------------------------------------------------------------

    def _cursor_out(self, last: dict, kind: str) -> str:
        raw = json.dumps({"c": last["created_at"].astimezone(timezone.utc).isoformat(), "i": str(last["outbox_id"]),
                          "t": int(self.clock()), "k": kind}, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode("ascii")

    def _cursor_in(self, cursor, kind: str) -> tuple[datetime, uuid.UUID] | None:
        if cursor is None:
            return None
        try:
            data = json.loads(base64.urlsafe_b64decode(str(cursor).encode("ascii")))
            if data["k"] != kind or self.clock() - int(data["t"]) > CURSOR_TTL_SECONDS:
                raise ValueError("expired or issued by another endpoint")
            return datetime.fromisoformat(data["c"]), uuid.UUID(data["i"])
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise _Refusal(_error(400, "invalid_cursor", "the cursor expired or was not issued by this endpoint", "")) from exc

    def _limit(self, raw) -> int:
        if raw is None:
            return DEFAULT_LIMIT
        try:
            n = int(raw)
        except (TypeError, ValueError):
            n = 0
        if not 1 <= n <= MAX_LIMIT:
            raise _Refusal(_error(422, "validation_failed", "limit must be 1 to 200", "", {"limit": "must be 1 to 200"}))
        return n

    # handlers ---------------------------------------------------------------------------------------------------------

    def _system_test(self, req: Request, params: dict) -> Response:
        from datetime import datetime as dt

        from .connectors.webhook import send_test_push
        from .systems import CredentialError, open_credentials

        sid = _uuid(params["system_id"])
        if sid is None:
            return _error(404, "not_found", "no such connected system", req.request_id)
        if self.custody is None or self.transport is None:
            return _error(503, "service_unavailable", "test pushes are not configured on this server", req.request_id)
        # 1. in a short transaction: find the system, count the last minute in the database, take the sealed credential
        with self.connect() as conn, org_transaction(conn, req.token):
            row = conn.execute("SELECT found, limited, endpoint, signature, credentials_ct FROM consentvault.system_test_begin(%s)",
                               (sid,)).fetchone()
        if not row["found"]:
            return _error(404, "not_found", "no such connected system", req.request_id)
        if row["limited"]:
            return _error(429, "rate_limited", "at most 6 test pushes a minute for one system", req.request_id)
        try:
            secret = open_credentials(self.custody, req.org_id, sid, row["credentials_ct"])
        except CredentialError as exc:
            return _error(503, "key_unavailable", caller_detail(exc), req.request_id)
        # 2. the outbound call, with no transaction and no connection held while the receiver answers
        answer = send_test_push(self.transport, endpoint=row["endpoint"], signature=row["signature"], secret=secret,
                                org_id=req.org_id)
        answer["at"] = dt.fromtimestamp(self.clock(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # 3. record the answer through the scoped function, on a fresh token: the request's own may have run out while a slow
        # receiver answered
        token = self.mint_token(req.org_id, sorted(req.scopes)) if self.mint_token is not None else req.token
        with self.connect() as conn, org_transaction(conn, token):
            conn.execute("SELECT consentvault.system_test_record(%s, %s::jsonb)", (sid, json.dumps(answer)))
        return Response(200, answer)

    def _signals(self, req: Request, params: dict) -> Response:
        try:
            signal = parse_signal(req.body)
        except SignalValidationError as exc:
            return _error(422, "validation_failed", caller_detail(exc), req.request_id, exc.fields)
        cid = _uuid(req.credential_id)
        with self.connect() as conn, org_transaction(conn, req.token):
            system_id = conn.execute("SELECT consentvault.sync_system_of_credential(%s) AS s", (cid,)).fetchone()["s"] \
                if cid else None
            if system_id is None:
                return _error(403, "role_not_allowed",
                              "this credential is not bound to a connected system, so it cannot send signals",
                              req.request_id)
            try:
                result = process_signal(conn, self.crypto, org_id=req.org_id, system_id=system_id, signal=signal,
                                        region=self.region, allowed_purposes=self.allowed_purposes)
            except InvalidContactError as exc:
                return _error(422, "invalid_contact", caller_detail(exc), req.request_id)
        body = {"signal_id": str(result.signal_id), "resolution": result.resolution}
        if result.event_id:
            body["event_id"] = result.event_id
        return Response(202, body)

    def _deliveries_query(self, req: Request, params: dict) -> Response:
        try:
            body = req.body if isinstance(req.body, dict) else {}
            problems = {}
            if not isinstance(body.get("contact"), str) or not body.get("contact", "").strip():
                problems["contact"] = "is required"
            system_id = _uuid(body.get("system_id"))
            if system_id is None:
                problems["system_id"] = "is required and must be a UUID"
            unknown = set(body) - {"contact", "system_id", "cursor", "limit"}
            problems.update({k: "unknown field" for k in unknown})
            if problems:
                return _error(422, "validation_failed", "a field is missing or malformed", req.request_id, problems)
            limit = self._limit(body.get("limit"))
            after = self._cursor_in(body.get("cursor"), "deliveries_query")
            try:
                kind, norm = normalize_contact(body["contact"], None, self.region)
            except NormalizationError as exc:
                return _error(422, "invalid_contact", caller_detail(exc), req.request_id)
        except _Refusal as r:
            return _fill(r.refusal_response, req.request_id)
        fp = self.crypto.contact_fingerprint(req.org_id, kind, norm)
        try:
            with self.connect() as conn, org_transaction(conn, req.token):
                rows = conn.execute("SELECT * FROM consentvault.sync_deliveries_of_contact(%s, %s, %s, %s, %s)",
                                    (fp, system_id, limit + 1, after[0] if after else None,
                                     after[1] if after else None)).fetchall()
        except psycopg.errors.NoDataFound:
            return _error(404, "not_found", "no such connected system in this organization", req.request_id)
        items, more = rows[:limit], len(rows) > limit
        return Response(200, {"items": [{
            "outbox_id": str(r["outbox_id"]), "created_at": iso_z(r["created_at"]), "channel": r["channel"],
            "purpose": r["purpose"], "version": r["version"], "status": r["status"], "attempts": r["attempts"],
            "last_http_status": r["last_http_status"], "last_error_class": r["last_error_class"]} for r in items],
            "next_cursor": self._cursor_out(items[-1], "deliveries_query") if more else None})

    def _system_deliveries(self, req: Request, params: dict) -> Response:
        system_id = _uuid(params["system_id"])
        if system_id is None:
            return _error(404, "not_found", "no such connected system in this organization", req.request_id)
        q = req.query
        try:
            limit = self._limit(q.get("limit"))
            after = self._cursor_in(q.get("cursor"), "system_deliveries")
        except _Refusal as r:
            return _fill(r.refusal_response, req.request_id)
        status = q.get("status")
        if status is not None and status not in STATUS_FILTERS:
            return _error(422, "validation_failed", "status must be one of " + ", ".join(STATUS_FILTERS),
                          req.request_id, {"status": f"must be one of {list(STATUS_FILTERS)}"})
        bounds: dict[str, datetime | None] = {}
        for name in ("from", "to"):
            try:
                bounds[name] = datetime.fromisoformat(q[name].replace("Z", "+00:00")) if q.get(name) else None
                if bounds[name] is not None and bounds[name].tzinfo is None:
                    raise ValueError("no timezone")
            except ValueError:
                return _error(422, "validation_failed", f"{name} must be ISO 8601 with a timezone", req.request_id,
                              {name: "must be ISO 8601 with a timezone"})
        try:
            with self.connect() as conn, org_transaction(conn, req.token):
                rows = conn.execute(
                    "SELECT * FROM consentvault.sync_deliveries_of_system(%s, %s, %s, %s, %s, %s, %s)",
                    (system_id, status, bounds["from"], bounds["to"], limit + 1, after[0] if after else None,
                     after[1] if after else None)).fetchall()
        except psycopg.errors.NoDataFound:
            return _error(404, "not_found", "no such connected system in this organization", req.request_id)
        items, more = rows[:limit], len(rows) > limit
        return Response(200, {"items": [{
            "outbox_id": str(r["outbox_id"]), "created_at": iso_z(r["created_at"]), "contact_fp_hint": r["contact_fp_hint"],
            "channel": r["channel"], "purpose": r["purpose"], "version": r["version"], "status": r["status"],
            "attempts": r["attempts"], "last_attempt_at": iso_z(r["last_attempt_at"]) if r["last_attempt_at"] else None,
            "last_http_status": r["last_http_status"], "last_error_class": r["last_error_class"]} for r in items],
            "next_cursor": self._cursor_out(items[-1], "system_deliveries") if more else None})

    def _redrive(self, req: Request, params: dict) -> Response:
        body = req.body if isinstance(req.body, dict) else {}
        problems = {k: "unknown field" for k in set(body) - {"system_id", "reason"}}
        system_id = _uuid(body.get("system_id"))
        if system_id is None:
            problems["system_id"] = "is required and must be a UUID"
        reason = body.get("reason")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            problems["reason"] = "is required, 1 to 1000 characters"
        if problems:
            return _error(422, "validation_failed", "a field is missing or malformed", req.request_id, problems)
        try:
            with self.connect() as conn, org_transaction(conn, req.token):
                refusal = self._org_refusal(conn, req.request_id)
                if refusal is not None:
                    return refusal
                row = conn.execute("SELECT * FROM consentvault.sync_redrive_start(%s, %s, %s)",
                                   (system_id, reason, req.actor)).fetchone()
        except psycopg.errors.NoDataFound:
            return _error(404, "not_found", "no such connected system in this organization", req.request_id)
        except psycopg.errors.UniqueViolation:
            return _error(409, "redrive_in_progress", "a redrive for that system is still running", req.request_id)
        return Response(202, {"redrive_id": str(row["redrive_id"]), "requeued": row["requeued"]})

    def _redrive_status(self, req: Request, params: dict) -> Response:
        rid = _uuid(params["redrive_id"])
        if rid is None:
            return _error(404, "not_found", "no such redrive in this organization", req.request_id)
        try:
            with self.connect() as conn, org_transaction(conn, req.token):
                r = conn.execute("SELECT * FROM consentvault.sync_redrive_status(%s)", (rid,)).fetchone()
        except psycopg.errors.NoDataFound:
            return _error(404, "not_found", "no such redrive in this organization", req.request_id)
        return Response(200, {
            "redrive_id": str(r["redrive_id"]), "system_id": str(r["system_id"]), "status": r["status"],
            "requeued": r["requeued"], "acknowledged": r["acknowledged"], "dead_again": r["dead_again"],
            "remaining": r["remaining"], "started_at": iso_z(r["started_at"]),
            "finished_at": iso_z(r["finished_at"]) if r["finished_at"] else None})

    @staticmethod
    def _org_refusal(conn: psycopg.Connection, rid: str) -> Response | None:
        row = conn.execute("SELECT status FROM consentvault.organization WHERE org_id = consentvault.current_org()").fetchone()
        status = row["status"] if row else None
        if status == "suspended":
            return _error(403, "org_suspended", "the action is paused while the organization is suspended", rid)
        if status in ("offboarding", "closed", None):
            return _error(403, "org_not_active", "the organization's status refuses this action entirely", rid)
        return None


class _Refusal(Exception):
    def __init__(self, response: Response) -> None:
        super().__init__(response.body["error"])
        self.refusal_response = response  # the ready API response for the caller


def _fill(response: Response, rid: str) -> Response:
    return Response(response.status, {**response.body, "request_id": rid})
