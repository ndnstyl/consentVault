"""Routes of the admin plane, as a framework-neutral table the API lane registers in one line.

    app = AdminApp(connect=..., owner_connect=..., token_key=..., sessions=..., custody=..., mailer=...)
    response = app.handle(Request(method, path, query, body, tenant_token=..., identity_token=..., request_id=...,
                                  operator_id=...))

``handle`` finds the route, authenticates the caller for that route's kind, checks the role against the route's role
list (the contract's role tables), runs the handler inside the caller's own tenant transaction and answers
``Response(status, body, headers)``. A contract-defined refusal is an ``ApiError`` and becomes
``{"error": name, "detail": ..., "request_id": ...}`` with the status from the one table in ``admin_base.STATUS``.
Anything else is a defect and propagates to the server layer, which logs it.

Kinds of route:
- ``tenant``    a portal session's tenant token (minted by ``session.SessionMinter.choose_org``); role from the member row.
- ``identity``  a signed-in person's identity token and no organisation chosen yet.
- ``public``    no sign-in (the invitation read); the edge rate-limits it.
- ``accept``    an identity token plus the invitation token in the path.
- ``operator``  an operator id the operator console established; runs on the operator console login's connection
                (``owner_connect``; a member of consentvault_console, never the schema owner).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import psycopg

from . import admin, admin_policy as pol, invite as invite_mod, session as session_mod
from .admin_base import (ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER, ApiError, Ctx, body_dict, iso)
from .errors import TenantTokenError
from .tokens import TokenKey, org_transaction, token_expires_at

A, D, V = ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER


@dataclass
class Request:
    method: str
    path: str
    query: dict = field(default_factory=dict)
    body: Any = None
    tenant_token: Optional[str] = None
    identity_token: Optional[str] = None
    request_id: str = "req-unset"
    operator_id: Optional[str] = None


@dataclass
class Response:
    status: int
    body: Any = None
    headers: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Route:
    method: str
    pattern: re.Pattern
    kind: str
    roles: tuple
    success: int
    handler: str


def _r(method: str, template: str, kind: str, roles: tuple, success: int, handler: str) -> Route:
    regex = "^" + re.sub(r"\{(\w+)\}", lambda m: f"(?P<{m.group(1)}>[^/:]+)", template) + "$"
    return Route(method, re.compile(regex), kind, roles, success, handler)


ROUTES: tuple[Route, ...] = (
    # session and organisation (session.md)
    _r("GET", "/v1/session", "identity", (), 200, "session_get"),
    _r("POST", "/v1/session/org", "identity", (), 200, "session_choose"),
    _r("GET", "/v1/session/current-org", "current_org", (A, D, V), 200, "current_org"),
    _r("GET", "/v1/org", "tenant", (A, D, V), 200, "org_get"),
    _r("GET", "/v1/health", "tenant", (A, D, V), 200, "health"),
    # operator (admin.md section 1)
    _r("POST", "/v1/orgs", "operator", (), 201, "orgs_create"),
    _r("PATCH", "/v1/orgs/{org_id}/status", "operator", (), 200, "orgs_status"),
    _r("POST", "/v1/orgs/{org_id}/credentials", "operator", (), 201, "orgs_verified_credential"),
    # brands, sources, credentials, retention (admin.md)
    _r("GET", "/v1/brands", "tenant", (A, D), 200, "brands_list"),
    _r("POST", "/v1/brands", "tenant", (A,), 201, "brands_create"),
    _r("GET", "/v1/brand-names", "tenant", (A, D, V), 200, "brand_names"),
    _r("GET", "/v1/source-names", "tenant", (A, D, V), 200, "source_names"),
    _r("GET", "/v1/sources", "tenant", (A, D), 200, "sources_list"),
    _r("GET", "/v1/sources/{source_id}", "tenant", (A, D), 200, "sources_get"),
    _r("POST", "/v1/sources", "tenant", (A, D), 201, "sources_create"),
    _r("PATCH", "/v1/sources/{source_id}", "tenant", (A, D), 200, "sources_update"),
    _r("GET", "/v1/credentials", "tenant", (A, D), 200, "credentials_list"),
    _r("POST", "/v1/credentials", "tenant", (A, D), 201, "credentials_issue"),
    _r("POST", "/v1/credentials/{credential_id}:revoke", "tenant", (A, D), 200, "credentials_revoke"),
    _r("GET", "/v1/retention", "tenant", (A, V), 200, "retention_get"),
    _r("PUT", "/v1/retention", "tenant", (A,), 200, "retention_put"),
    # members, invitations, audit (members.md)
    _r("GET", "/v1/invites/{token}", "public", (), 200, "invites_read"),
    _r("POST", "/v1/invites/{token}:accept", "accept", (), 200, "invites_accept"),
    _r("GET", "/v1/members", "tenant", (A,), 200, "members_list"),
    _r("POST", "/v1/members", "tenant", (A,), 201, "members_invite"),
    _r("PATCH", "/v1/members/{member_id}", "tenant", (A,), 200, "members_role"),
    _r("DELETE", "/v1/members/{member_id}", "tenant", (A,), 204, "members_remove"),
    _r("DELETE", "/v1/invites/{invite_id}", "tenant", (A,), 204, "invites_withdraw"),
    _r("GET", "/v1/audit", "tenant", (A, V), 200, "audit_list"),
    _r("GET", "/v1/audit/actions", "tenant", (A, V), 200, "audit_actions"),
    # connected systems: registration only (systems.md); test push, deliveries and redrive belong to the sync lane
    _r("GET", "/v1/systems", "tenant", (A, D, V), 200, "systems_list"),
    _r("GET", "/v1/systems/{system_id}", "tenant", (A, D, V), 200, "systems_get"),
    _r("POST", "/v1/systems", "tenant", (A, D), 201, "systems_create"),
    _r("PATCH", "/v1/systems/{system_id}", "tenant", (A, D), 200, "systems_update"),
    # wording, policies, checklists, rule references (policy.md)
    _r("GET", "/v1/channels", "tenant", (A, D, V), 200, "channels"),
    _r("GET", "/v1/purposes", "tenant", (A, D, V), 200, "purposes"),
    _r("GET", "/v1/disclosures", "tenant", (A, D, V), 200, "wording_list"),
    _r("GET", "/v1/disclosures/{sha256}", "tenant", (A, D, V), 200, "wording_get"),
    _r("POST", "/v1/disclosures", "tenant", (A,), 201, "wording_register"),
    _r("GET", "/v1/policies", "tenant", (A, D, V), 200, "policies_list"),
    _r("GET", "/v1/policies/{version}", "tenant", (A, D, V), 200, "policies_get"),
    _r("POST", "/v1/policies", "tenant", (A,), 201, "policies_create"),
    _r("PUT", "/v1/policies/{version}", "tenant", (A,), 200, "policies_update"),
    _r("POST", "/v1/policies/{version}:approve", "tenant", (A,), 200, "policies_approve"),
    _r("GET", "/v1/policy-templates", "tenant", (A, D, V), 200, "policy_templates"),
    _r("GET", "/v1/attestations/current", "tenant", (A, D, V), 200, "attestation"),
    _r("GET", "/v1/checklists", "tenant", (A, D, V), 200, "checklists_list"),
    _r("GET", "/v1/checklists/{version}", "tenant", (A, D, V), 200, "checklists_get"),
    _r("GET", "/v1/checklist-templates", "tenant", (A, D, V), 200, "checklist_templates"),
    _r("POST", "/v1/checklists", "tenant", (A,), 201, "checklists_create"),
    _r("PUT", "/v1/checklists/{version}", "tenant", (A,), 200, "checklists_update"),
    _r("POST", "/v1/checklists/{version}:approve", "tenant", (A,), 200, "checklists_approve"),
    _r("POST", "/v1/doc-checks", "tenant", (A,), 201, "doc_checks"),
    _r("GET", "/v1/rule-references", "tenant", (A, D, V), 200, "rule_references"),
)


def _paging(q: dict) -> dict:
    return {"limit": q.get("limit"), "cursor": q.get("cursor")}


class AdminApp:
    def __init__(self, *, connect: Callable[[], psycopg.Connection], token_key: TokenKey,
                 sessions: Optional[session_mod.SessionMinter] = None, owner_connect: Optional[Callable] = None,
                 custody=None, mailer=None, cursor_key: Optional[bytes] = None, clock: Callable[[], float] = time.time):
        self._connect = connect
        self._owner_connect = owner_connect
        self._key = token_key
        self._sessions = sessions
        self._custody = custody
        self._mailer = mailer
        self._cursor_key = cursor_key if cursor_key is not None else token_key.secret
        self._clock = clock

    # ---- dispatch ---------------------------------------------------------------------------------------------------
    def handle(self, req: Request) -> Response:
        route, params = self._match(req)
        try:
            if route is None:
                raise ApiError("not_found", "no such endpoint")
            result = getattr(self, "_run_" + route.kind)(route, params, req)
        except ApiError as exc:  # loud-failure-exempt: a contract-defined refusal is answered to the caller with its named error
            return Response(exc.status, exc.body(req.request_id))
        if route.success == 204:
            return Response(204, None)
        return Response(route.success, result)

    @staticmethod
    def _match(req: Request):
        for r in ROUTES:
            m = r.pattern.match(req.path)
            if m and r.method == req.method:
                return r, m.groupdict()
        return None, {}

    def _ctx(self, conn, actor, req) -> Ctx:
        return Ctx(conn, actor, req.request_id, self._cursor_key, self._custody, self._clock)

    def _run_tenant(self, route: Route, params: dict, req: Request):
        if not req.tenant_token:
            raise ApiError("unauthenticated", "no session token was presented")
        conn = self._connect()
        try:
            try:
                with org_transaction(conn, req.tenant_token):
                    actor = session_mod.actor_from_token(conn)
                    actor.require(*route.roles)
                    ctx = self._ctx(conn, actor, req)
                    return getattr(self, "h_" + route.handler)(ctx, params, req.query or {}, req.body)
            except TenantTokenError:
                raise ApiError("unauthenticated", "the session token is missing, expired or not valid") from None
        finally:
            conn.close()

    def _run_identity(self, route: Route, params: dict, req: Request):
        if self._sessions is None:
            raise ApiError("unauthenticated", "portal sessions are not configured on this server")
        conn = self._connect()
        try:
            if route.handler == "session_get":
                return self._sessions.memberships(conn, req.identity_token, **_paging(req.query or {}), now=self._clock())
            body = body_dict(req.body)
            return self._sessions.choose_org(conn, req.identity_token, body.get("org_id"), request_id=req.request_id).body()
        finally:
            conn.close()

    def _run_current_org(self, route: Route, params: dict, req: Request):
        if req.tenant_token:
            out = dict(self._run_tenant(route, params, req))
            out["expires_at"] = iso(token_expires_at(req.tenant_token))
            return out
        if req.identity_token and self._sessions is not None:
            self._sessions.verify(req.identity_token)
            raise ApiError("no_org_selected", "no organization is chosen for this session; choose one with POST /v1/session/org")
        raise ApiError("unauthenticated", "no session token was presented")

    def _run_public(self, route: Route, params: dict, req: Request):
        conn = self._connect()
        try:
            return invite_mod.public_view(invite_mod.resolve(conn, self._key, params["token"]))
        finally:
            conn.close()

    def _run_accept(self, route: Route, params: dict, req: Request):
        if self._sessions is None:
            raise ApiError("unauthenticated", "portal sessions are not configured on this server")
        who = self._sessions.verify(req.identity_token)
        conn = self._connect()
        try:
            return invite_mod.accept(conn, self._key, token=params["token"], identity=who, request_id=req.request_id)
        finally:
            conn.close()

    def _run_operator(self, route: Route, params: dict, req: Request):
        if not req.operator_id or self._owner_connect is None:
            raise ApiError("unauthenticated", "operator functions need an operator session")
        conn = self._owner_connect()
        try:
            return getattr(self, "h_" + route.handler)(conn, params, req)
        finally:
            conn.close()

    # ---- operator handlers ---------------------------------------------------------------------------------------------
    def h_orgs_create(self, conn, p, req):
        b = body_dict(req.body)
        return admin.create_org(conn, token_key=self._key, custody=self._custody, operator_id=req.operator_id,
                                request_id=req.request_id, name=b.get("name"), admin_email=b.get("admin_email"),
                                region=b.get("region"), status=b.get("status", "trial"), mailer=self._mailer)

    def h_orgs_status(self, conn, p, req):
        b = body_dict(req.body)
        return admin.set_org_status(conn, token_key=self._key, operator_id=req.operator_id, request_id=req.request_id,
                                    org_id=p["org_id"], status=b.get("status"), reason=b.get("reason"))

    def h_orgs_verified_credential(self, conn, p, req):
        b = body_dict(req.body)
        return admin.issue_verified_credential(conn, token_key=self._key, custody=self._custody,
                                               operator_id=req.operator_id, request_id=req.request_id, org_id=p["org_id"],
                                               name=b.get("name"), kind=b.get("kind"), source_id=b.get("source_id"),
                                               public_key=b.get("public_key"), algorithm=b.get("algorithm"))

    # ---- tenant handlers -----------------------------------------------------------------------------------------------
    def h_current_org(self, ctx, p, q, b):
        return admin.current_org(ctx)

    def h_brand_names(self, ctx, p, q, b):
        return admin.list_brand_names(ctx, **_paging(q))

    def h_source_names(self, ctx, p, q, b):
        return admin.list_source_names(ctx, **_paging(q))

    def h_doc_checks(self, ctx, p, q, b):
        return pol.record_doc_checks(ctx, b)

    def h_org_get(self, ctx, p, q, b):
        return admin.get_org(ctx)

    def h_health(self, ctx, p, q, b):
        return admin.health(ctx)

    def h_brands_list(self, ctx, p, q, b):
        return admin.list_brands(ctx, **_paging(q))

    def h_brands_create(self, ctx, p, q, b):
        return admin.create_brand(ctx, b)

    def h_sources_list(self, ctx, p, q, b):
        return admin.list_sources(ctx, brand_id=q.get("brand_id"), status=q.get("status"), kind=q.get("kind"), **_paging(q))

    def h_sources_get(self, ctx, p, q, b):
        return admin.get_source(ctx, p["source_id"])

    def h_sources_create(self, ctx, p, q, b):
        return admin.create_source(ctx, b)

    def h_sources_update(self, ctx, p, q, b):
        return admin.update_source(ctx, p["source_id"], b)

    def h_credentials_list(self, ctx, p, q, b):
        return admin.list_credentials(ctx, source_id=q.get("source_id"), kind=q.get("kind"), scope=q.get("scope"),
                                      status=q.get("status"), **_paging(q))

    def h_credentials_issue(self, ctx, p, q, b):
        return admin.issue_credential(ctx, b)

    def h_credentials_revoke(self, ctx, p, q, b):
        return admin.revoke_credential(ctx, p["credential_id"], b)

    def h_retention_get(self, ctx, p, q, b):
        return admin.get_retention(ctx, **_paging(q))

    def h_retention_put(self, ctx, p, q, b):
        return admin.put_retention(ctx, b)

    def h_members_list(self, ctx, p, q, b):
        return admin.list_members(ctx, include=q.get("include"), role=q.get("role"), status=q.get("status"), **_paging(q))

    def h_members_invite(self, ctx, p, q, b):
        return admin.invite_member(ctx, b, mailer=self._mailer)

    def h_members_role(self, ctx, p, q, b):
        return admin.change_role(ctx, p["member_id"], b)

    def h_members_remove(self, ctx, p, q, b):
        return admin.remove_member(ctx, p["member_id"])

    def h_invites_withdraw(self, ctx, p, q, b):
        return admin.withdraw_invite(ctx, p["invite_id"])

    def h_audit_list(self, ctx, p, q, b):
        return admin.list_audit(ctx, action=q.get("action"), actor=q.get("actor"), target_kind=q.get("target_kind"),
                                from_=q.get("from"), to=q.get("to"), **_paging(q))

    def h_audit_actions(self, ctx, p, q, b):
        return admin.list_audit_actions(ctx, **_paging(q))

    def h_systems_list(self, ctx, p, q, b):
        return admin.list_systems(ctx, kind=q.get("kind"), status=q.get("status"), **_paging(q))

    def h_systems_get(self, ctx, p, q, b):
        return admin.get_system(ctx, p["system_id"])

    def h_systems_create(self, ctx, p, q, b):
        return admin.create_system(ctx, b)

    def h_systems_update(self, ctx, p, q, b):
        return admin.update_system(ctx, p["system_id"], b)

    def h_channels(self, ctx, p, q, b):
        return pol.list_channels(ctx, **_paging(q))

    def h_purposes(self, ctx, p, q, b):
        return pol.list_purposes(ctx, **_paging(q))

    def h_wording_list(self, ctx, p, q, b):
        return pol.list_wording(ctx, brand_id=q.get("brand_id"), channel=q.get("channel"), purpose=q.get("purpose"),
                                state=q.get("state"), **_paging(q))

    def h_wording_get(self, ctx, p, q, b):
        return pol.get_wording(ctx, p["sha256"])

    def h_wording_register(self, ctx, p, q, b):
        return pol.register_wording(ctx, b)

    def h_policies_list(self, ctx, p, q, b):
        return pol.list_policies(ctx, status=q.get("status"), **_paging(q))

    def h_policies_get(self, ctx, p, q, b):
        return pol.get_policy(ctx, p["version"])

    def h_policies_create(self, ctx, p, q, b):
        return pol.create_policy(ctx, b)

    def h_policies_update(self, ctx, p, q, b):
        return pol.update_policy(ctx, p["version"], b)

    def h_policies_approve(self, ctx, p, q, b):
        return pol.approve_policy(ctx, p["version"], b)

    def h_policy_templates(self, ctx, p, q, b):
        return pol.list_policy_templates(ctx, **_paging(q))

    def h_attestation(self, ctx, p, q, b):
        return pol.current_attestation(ctx)

    def h_checklists_list(self, ctx, p, q, b):
        return pol.list_checklists(ctx, kind=q.get("kind"), status=q.get("status"), **_paging(q))

    def h_checklists_get(self, ctx, p, q, b):
        return pol.get_checklist(ctx, p["version"])

    def h_checklist_templates(self, ctx, p, q, b):
        return pol.list_checklist_templates(ctx, **_paging(q))

    def h_checklists_create(self, ctx, p, q, b):
        return pol.create_checklist(ctx, b)

    def h_checklists_update(self, ctx, p, q, b):
        return pol.update_checklist(ctx, p["version"], b)

    def h_checklists_approve(self, ctx, p, q, b):
        return pol.approve_checklist(ctx, p["version"], b)

    def h_rule_references(self, ctx, p, q, b):
        return pol.list_rule_references(ctx, jurisdiction=q.get("jurisdiction"), **_paging(q))
