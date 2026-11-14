"""HTTP surface of the evidence package: POST /v1/exports, GET /v1/exports, GET /v1/exports/{id},
POST /v1/exports/{id}:link, POST /v1/exports/{id}:resume and the one-time proxied download.

Framework-neutral on purpose: ``handle(service, request)`` takes a parsed ``Request`` (the API lane verifies the
credential or portal session first and fills in the ``Principal``) and returns a ``Response`` (status, JSON body, headers,
or raw bytes for the download). It returns ``None`` for a path that is not one of these routes, so the API can try the
next router. The contact point arrives in a POST body only and is never read from a URL, logged or echoed in an error.

The download route is the one route that carries no principal: its link is the credential (contracts/proof-export.md).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .safelog import caller_detail
from .evidence import Actor, ExportError, ExportService

_ID = r"(?P<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
_ROUTES = (
    ("collection", re.compile(r"^/v1/exports$")),
    ("one", re.compile(rf"^/v1/exports/{_ID}$")),
    ("link", re.compile(rf"^/v1/exports/{_ID}:link$")),
    ("resume", re.compile(rf"^/v1/exports/{_ID}:resume$")),
    ("download", re.compile(rf"^/v1/exports/{_ID}/download$")),
)

# error name -> HTTP status (contracts/README.md section 5 lists every one)
STATUS = {
    "invalid_request": 400, "invalid_cursor": 400, "unauthenticated": 401, "role_not_allowed": 403,
    "org_not_active": 403, "org_suspended": 403, "export_link_invalid": 403, "not_found": 404, "no_records": 404,
    "export_expired": 410, "export_link_used": 410, "export_not_ready": 409, "export_not_resumable": 409,
    "validation_failed": 422, "invalid_contact": 422, "key_unavailable": 503, "signing_unavailable": 503,
    "export_storage_failed": 502, "export_integrity_failed": 500, "export_failed": 500,
}
PORTAL_ROLES_READING = ("admin", "compliance_viewer")


@dataclass(frozen=True)
class Principal:
    """A verified caller. ``kind`` is ``portal`` (role is admin, developer or compliance_viewer) or ``machine``
    (``scopes`` holds the credential's scopes)."""

    org_id: uuid.UUID
    actor_id: uuid.UUID
    kind: str
    role: str | None = None
    scopes: frozenset = frozenset()


    @property
    def actor(self) -> Actor:
        return Actor("member" if self.kind == "portal" else "credential", self.actor_id)


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: dict = field(default_factory=dict)
    body: dict | None = None
    principal: Principal | None = None
    request_id: str = ""


@dataclass
class Response:
    status: int
    body: dict | None = None
    headers: dict = field(default_factory=dict)
    raw: bytes | None = None


class _Refusal(Exception):
    def __init__(self, name: str, detail: str, fields: dict | None = None) -> None:
        super().__init__(detail)
        self.name, self.detail, self.fields = name, detail, fields


def matches(path: str) -> bool:
    return any(rx.match(path) for _, rx in _ROUTES)


def _error(req: Request, name: str, detail: str, fields: dict | None = None) -> Response:
    body = {"error": name, "detail": detail, "request_id": req.request_id}
    if fields:
        body["fields"] = fields
    return Response(STATUS[name], body, {"Cache-Control": "no-store"})


def _require(req: Request, *, machine_scope: str | None = None) -> Principal:
    p = req.principal
    if p is None:
        raise _Refusal("unauthenticated", "a session or token is required")
    if p.kind == "portal" and p.role in PORTAL_ROLES_READING:
        return p
    if machine_scope and p.kind == "machine" and machine_scope in p.scopes:
        return p
    raise _Refusal("role_not_allowed", "this caller may not use evidence packages",
                   {"role": p.role or ",".join(sorted(p.scopes)) or p.kind})


def _when(text: str, name: str) -> datetime:
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise _Refusal("validation_failed", f"{name} is not an ISO 8601 time", {name: "not an ISO 8601 time"}) from None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def handle(service: ExportService, req: Request) -> Response | None:
    route, groups = None, {}
    for name, rx in _ROUTES:
        m = rx.match(req.path)
        if m:
            route, groups = name, m.groupdict()
            break
    if route is None:
        return None
    allowed = {"collection": ("GET", "POST"), "one": ("GET",), "link": ("POST",), "resume": ("POST",),
               "download": ("GET",)}[route]
    if req.method not in allowed:
        return Response(405, {"error": "invalid_request", "detail": f"{req.method} is not allowed here",
                              "request_id": req.request_id}, {"Allow": ", ".join(allowed)})
    try:
        if route == "download":
            return _download(service, req, groups["id"])
        if route == "collection" and req.method == "POST":
            return _create(service, req)
        if route in ("one", "link"):
            # the machine credential that created an export may read its status and take its link (same org through
            # the tenant, same credential through requested_by); portal readers see every export of their org
            p = _require(req, machine_scope="proof_read")
            own = p.actor_id if p.kind == "machine" else None
            if route == "one":
                return Response(200, service.status(p.org_id, p.actor, groups["id"], request_id=req.request_id,
                                                    requested_by=own), {"Cache-Control": "no-store"})
            return Response(200, service.issue_link(p.org_id, p.actor, groups["id"], request_id=req.request_id,
                                                    requested_by=own), {"Cache-Control": "no-store"})
        p = _require(req)
        org = p.org_id
        if route == "collection":
            q = req.query
            try:
                limit = int(q.get("limit", 50))
            except ValueError:
                raise _Refusal("validation_failed", "limit is not a number", {"limit": "not a number"}) from None
            return Response(200, service.list_jobs(
                org, status=q.get("status"),
                since=_when(q["from"], "from") if q.get("from") else None,
                until=_when(q["to"], "to") if q.get("to") else None,
                limit=limit, cursor=q.get("cursor")), {"Cache-Control": "no-store"})
        return Response(202, service.resume(org, p.actor, groups["id"], request_id=req.request_id),
                        {"Cache-Control": "no-store"})
    except _Refusal as r:
        return _error(req, r.name, caller_detail(r), r.fields)
    except ExportError as exc:
        return _error(req, getattr(exc, "error_name", "export_failed"), caller_detail(exc))


def _create(service: ExportService, req: Request) -> Response:
    p = _require(req, machine_scope="proof_read")
    body = req.body
    if not isinstance(body, dict):
        raise _Refusal("invalid_request", "the body must be a JSON object")
    contact = body.get("contact")
    if not isinstance(contact, str) or not contact.strip():
        raise _Refusal("validation_failed", "contact is required", {"contact": "required"})
    return Response(202, service.start(p.org_id, p.actor, contact, request_id=req.request_id),
                    {"Cache-Control": "no-store"})


def _download(service: ExportService, req: Request, export_id: str) -> Response:
    link = req.query.get("link")
    if not link:
        raise _Refusal("export_link_invalid", "the download link is not valid")
    package, sha = service.download(export_id, link, request_id=req.request_id)
    return Response(200, None, {
        "Content-Type": "application/zip",
        "Content-Disposition": f'attachment; filename="evidence-package-{export_id[:8]}.zip"',
        "Cache-Control": "no-store", "X-Package-Sha256": sha}, package)
