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

from .. import dbclock, safelog
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import psycopg

from .. import records_exports
from . import admin, admin_policy as pol, invite as invite_mod, records_admin as rec, session as session_mod, setup as setup_mod
from .admin_base import (ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER, ApiError, Ctx, body_dict, iso)
from .errors import TenantTokenError
from .tokens import TENANT_TOKEN_HEADER, TokenKey, org_transaction, token_expires_at

A, D, V = ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER
_log = safelog.get(__name__)


@dataclass
class Request:
    method: str
    path: str
    query: dict = field(default_factory=dict)
    body: Any = None
    tenant_token: Optional[str] = None
    identity_token: Optional[str] = None
    edge_assertion: Optional[str] = None  # the portal edge's signed statement of how the person signed in (identity routes)
    request_id: str = "req-unset"
    operator_id: Optional[str] = None


@dataclass
class Response:
    status: int
    body: Any = None
    headers: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _WithHeaders:
    body: Any
    headers: dict


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
    _r("PATCH", "/v1/orgs/{org_id}/default-region", "operator", (), 200, "orgs_default_region"),
    _r("PUT", "/v1/orgs/{org_id}/sso-binding", "operator", (), 200, "orgs_sso_bind"),
    _r("DELETE", "/v1/orgs/{org_id}/sso-binding", "operator", (), 200, "orgs_sso_unbind"),
    _r("POST", "/v1/orgs/{org_id}/sso:break-glass", "operator", (), 200, "orgs_sso_break_glass"),
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
    _r("GET", "/v1/sources/{source_id}/field-maps", "tenant", (A, D), 200, "field_maps_list"),
    _r("POST", "/v1/sources/{source_id}/field-maps", "tenant", (A, D), 201, "field_maps_add"),
    _r("GET", "/v1/credentials", "tenant", (A, D), 200, "credentials_list"),
    _r("POST", "/v1/credentials", "tenant", (A, D), 201, "credentials_issue"),
    _r("POST", "/v1/credentials/{credential_id}:revoke", "tenant", (A, D), 200, "credentials_revoke"),
    _r("PUT", "/v1/org/sso", "tenant", (A,), 200, "sso_put"),
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
    # the contact record list (records.md) and the record-id form of proof and evidence packages (proof-export.md amendment)
    _r("GET", "/v1/records", "tenant", (A, D, V), 200, "records_list"),
    _r("GET", "/v1/records/summary", "tenant", (A, D, V), 200, "records_summary"),
    _r("POST", "/v1/records:search", "tenant", (A, V), 200, "records_search"),
    _r("POST", "/v1/records:reveal", "tenant", (A, V), 200, "records_reveal"),
    _r("POST", "/v1/records/exports", "tenant", (A, V), 202, "records_export_request"),
    _r("GET", "/v1/records/exports", "tenant", (A, V), 200, "records_exports_list"),
    _r("GET", "/v1/records/exports/{export_id}", "tenant", (A, V), 200, "records_exports_get"),
    _r("POST", "/v1/records/exports/{export_id}:link", "tenant", (A, V), 200, "records_exports_link"),
    _r("GET", "/v1/records/exports/{export_id}/download", "download", (), 200, "records_exports_download"),
    # setup progress (setup.md): derived from facts; only a skip of an optional step is stored
    _r("GET", "/v1/setup", "tenant", (A, D, V), 200, "setup_get"),
    _r("POST", "/v1/setup/steps/{step}:skip", "tenant", (A, D), 200, "setup_skip"),
    _r("POST", "/v1/setup/steps/{step}:unskip", "tenant", (A, D), 200, "setup_unskip"),
    # confirmation messages (confirmations.md): sending accounts, rules, templates, sends and replies
    _r("GET", "/v1/confirmations/settings", "tenant", (A, D, V), 200, "confirm_settings_get"),
    _r("PUT", "/v1/confirmations/settings", "tenant", (A,), 200, "confirm_settings_put"),
    _r("POST", "/v1/confirmations/sending-accounts", "tenant", (A, D), 201, "confirm_account_connect"),
    _r("POST", "/v1/confirmations/sending-accounts/{account_id}:check", "tenant", (A, D), 200, "confirm_account_check"),
    _r("PATCH", "/v1/confirmations/sending-accounts/{account_id}", "tenant", (A, D), 200, "confirm_account_patch"),
    _r("DELETE", "/v1/confirmations/sending-accounts/{account_id}", "tenant", (A,), 200, "confirm_account_delete"),
    _r("POST", "/v1/confirmations/link-host", "tenant", (A, D), 200, "confirm_link_host_set"),
    _r("POST", "/v1/confirmations/link-host:verify", "tenant", (A, D), 200, "confirm_link_host_verify"),
    _r("POST", "/v1/confirmations/texting-registration", "tenant", (A,), 200, "confirm_registration_mark"),
    _r("POST", "/v1/confirmations/texting-registration:withdraw", "tenant", (A,), 200, "confirm_registration_withdraw"),
    _r("GET", "/v1/confirmations/rules", "tenant", (A, D, V), 200, "confirm_rules_list"),
    _r("PUT", "/v1/confirmations/rules/{source_id}/{channel}", "tenant", (A,), 200, "confirm_rule_put"),
    _r("GET", "/v1/confirmations/templates", "tenant", (A, D, V), 200, "confirm_templates_list"),
    _r("GET", "/v1/confirmations/templates/{template_id}", "tenant", (A, D, V), 200, "confirm_templates_get"),
    _r("POST", "/v1/confirmations/templates", "tenant", (A,), 201, "confirm_templates_create"),
    _r("POST", "/v1/confirmations:preview", "tenant", (A, D, V), 200, "confirm_preview"),
    _r("POST", "/v1/confirmations:test", "tenant", (A,), 200, "confirm_test"),
    _r("GET", "/v1/confirmations/sends", "tenant", (A, D, V), 200, "confirm_sends_list"),
    _r("GET", "/v1/confirmations/replies", "tenant", (A, V), 200, "confirm_replies_list"),
    _r("POST", "/v1/confirmations/replies/{reply_id}:mark", "tenant", (A,), 200, "confirm_reply_mark"),
    _r("POST", "/v1/proof", "tenant", (A, V), 200, "proof"),
    _r("POST", "/v1/exports", "tenant", (A, V), 202, "evidence_export_start"),
    # connected systems: registration only (systems.md); test push, deliveries and redrive belong to the sync lane
    _r("GET", "/v1/systems", "tenant", (A, D, V), 200, "systems_list"),
    _r("GET", "/v1/systems/{system_id}", "tenant", (A, D, V), 200, "systems_get"),
    _r("POST", "/v1/systems", "tenant", (A, D), 201, "systems_create"),
    _r("PATCH", "/v1/systems/{system_id}", "tenant", (A, D), 200, "systems_update"),
    # the Twenty workflow credential (twenty.md 4.2): admin only, shown once, every issue and revoke audited
    _r("POST", "/v1/systems/{system_id}/workflow-credential", "tenant", (A,), 201, "systems_workflow_credential_issue"),
    _r("POST", "/v1/systems/{system_id}/workflow-credential/{credential_id}:revoke", "tenant", (A,), 200,
       "systems_workflow_credential_revoke"),
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


def _has_nul(value: Any) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_has_nul(k) or _has_nul(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_has_nul(v) for v in value)
    return False


def _refuse_nul(req: "Request") -> None:
    """A text field cannot hold a NUL byte; refuse it by name here rather than let the database refuse it as a 500."""
    # a contact point is checked by its own normalisation (invalid_contact), so it is not scanned here
    body = {k: v for k, v in req.body.items() if k != "contact"} if isinstance(req.body, dict) else req.body
    if _has_nul(req.query) or _has_nul(body) or _has_nul(req.path):
        raise ApiError("validation_failed", "a value contains a NUL (0x00) character", {"body": "no NUL characters"})


def _paging(q: dict) -> dict:
    return {"limit": q.get("limit"), "cursor": q.get("cursor")}


class AdminApp:
    def __init__(self, *, connect: Callable[[], psycopg.Connection], token_key: TokenKey,
                 sessions: Optional[session_mod.SessionMinter] = None, owner_connect: Optional[Callable] = None,
                 custody=None, mailer=None, cursor_key: Optional[bytes] = None, clock: Optional[Callable[[], float]] = None,
                 evidence_store=None, crypto=None, exports=None, confirmations=None):
        self._connect = connect
        self._owner_connect = owner_connect
        self._key = token_key
        self._sessions = sessions
        self._custody = custody
        self._mailer = mailer
        self._cursor_key = cursor_key if cursor_key is not None else token_key.secret
        self._clock = clock or dbclock.epoch_clock(connect)   # tests pin one; production reads the database's
        self.evidence_store = evidence_store  # the write-once store list exports are kept in (records.md section 7)
        self._crypto = crypto  # tenancy.crypto.TenantCrypto; built from custody and the database when not given
        self.confirmations = confirmations  # confirm.ConfirmationService behind every /v1/confirmations route (confirmations.md section 13)
        self.exports = exports  # evidence.ExportService behind POST /v1/exports (the contact form of the evidence package)
        self._links = records_exports.Links(token_key.secret)

    # ---- dispatch ---------------------------------------------------------------------------------------------------
    def handle(self, req: Request) -> Response:
        """Every /v1 answer, success or refusal, carries ``Cache-Control: no-store`` and ``Pragma: no-cache`` (records.md section 1):
        names, contact points and masks must never sit in a browser or proxy cache."""
        res = self._handle(req)
        res.headers = {**res.headers, "Cache-Control": "no-store", "Pragma": "no-cache"}
        return res

    def _handle(self, req: Request) -> Response:
        route, params = self._match(req)
        try:
            _refuse_nul(req)
            if route is None:
                raise ApiError("not_found", "no such endpoint")
            try:
                result = getattr(self, "_run_" + route.kind)(route, params, req)
                self._after_commit(route, result)
            except psycopg.OperationalError as exc:
                raise ApiError("service_unavailable", "the vault could not reach its database; nothing was read or changed") from exc
        except ApiError as exc:  # loud-failure-exempt: a contract-defined refusal is answered to the caller with its named error
            return Response(exc.status, exc.body(req.request_id),
                            {"Retry-After": str(exc.retry_after)} if exc.retry_after else {})
        if route.success == 204:
            return Response(204, None)
        if isinstance(result, _WithHeaders):
            return Response(route.success, result.body, result.headers)
        return Response(route.success, result)

    @staticmethod
    def _match(req: Request):
        for r in ROUTES:
            m = r.pattern.match(req.path)
            if m and r.method == req.method:
                return r, m.groupdict()
        return None, {}

    @property
    def crypto(self):
        """The tenant crypto (fingerprints, contact keys, display key): the one given, else built over the key custody and
        the database's wrapped secrets. A server with neither refuses the routes that need it, by name."""
        if self._crypto is None:
            if self._custody is None or self._owner_connect is None:
                raise ApiError("service_unavailable", "this server has no key custody configured for the records routes")
            from .crypto import TenantCrypto
            from .keys_adapter import CustodyKeyAdapter
            self._crypto = TenantCrypto(CustodyKeyAdapter.from_database(self._custody, self._owner_connect, self._key))
        return self._crypto

    def _ctx(self, conn, actor, req) -> Ctx:
        return Ctx(conn, actor, req.request_id, self._cursor_key, self._custody, self._clock,
                   token=req.tenant_token, connect=self._connect)

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

    def _after_commit(self, route: Route, result: Any) -> None:
        """A list export small enough to build at once is built right after its request commits when this process has an
        export worker configured (the answer still says building); otherwise, and for a larger one, the scheduled pass builds it. The job row is the record either way."""
        if (route.handler == "records_export_request" and records_exports.configured()
                and (result.get("row_estimate") or 0) <= rec.INLINE_BUILD_MAX):
            try:
                records_exports.run_export_builds()
            except Exception:  # loud-failure-exempt: logged at critical; the job stays building and the scheduled pass retries it
                _log.critical("the inline records export pass failed after a request", export_id=result.get("export_id"), exc_info=True)

    def _run_download(self, route: Route, params: dict, req: Request):
        """The one route with no session: the signed link in the query is the credential (records.md section 7)."""
        data, headers = records_exports.download(self, (req.query or {}).get("link"), self._clock(), params.get("export_id"))
        return _WithHeaders(data, headers)

    def _run_identity(self, route: Route, params: dict, req: Request):
        if self._sessions is None:
            raise ApiError("unauthenticated", "portal sessions are not configured on this server")
        conn = self._connect()
        try:
            if route.handler == "session_get":
                return self._sessions.memberships(conn, req.identity_token, **_paging(req.query or {}), now=self._clock(), assertion=req.edge_assertion)
            body = body_dict(req.body)
            chosen = self._sessions.choose_org(conn, req.identity_token, body.get("org_id"), request_id=req.request_id,
                                           assertion=req.edge_assertion)
            return _WithHeaders(chosen.body(), {TENANT_TOKEN_HEADER: chosen.token})
        finally:
            conn.close()

    def _run_current_org(self, route: Route, params: dict, req: Request):
        if req.tenant_token:
            out = dict(self._run_tenant(route, params, req))
            out["expires_at"] = iso(token_expires_at(req.tenant_token))
            return out
        if req.identity_token and self._sessions is not None:
            self._sessions.verify(req.identity_token, req.edge_assertion)
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
        who = self._sessions.verify(req.identity_token, req.edge_assertion)
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
        extra = {k: b[k] for k in ("channels", "purposes", "default_region") if k in b}
        return admin.create_org(conn, token_key=self._key, custody=self._custody, operator_id=req.operator_id,
                                request_id=req.request_id, name=b.get("name"), admin_email=b.get("admin_email"),
                                region=b.get("region"), status=b.get("status", "trial"), mailer=self._mailer, **extra)

    def h_orgs_default_region(self, conn, p, req):
        b = body_dict(req.body)
        return admin.set_default_region(conn, token_key=self._key, operator_id=req.operator_id, request_id=req.request_id,
                                        org_id=p["org_id"], default_region=b.get("default_region"), reason=b.get("reason"))

    def h_orgs_sso_bind(self, conn, p, req):
        return admin.bind_sso(conn, token_key=self._key, operator_id=req.operator_id, request_id=req.request_id,
                              org_id=p["org_id"], body=req.body)

    def h_orgs_sso_unbind(self, conn, p, req):
        return admin.unbind_sso(conn, token_key=self._key, operator_id=req.operator_id, request_id=req.request_id,
                                org_id=p["org_id"])

    def h_orgs_sso_break_glass(self, conn, p, req):
        return admin.sso_break_glass(conn, token_key=self._key, operator_id=req.operator_id, request_id=req.request_id,
                                     org_id=p["org_id"], body=req.body)

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

    def h_field_maps_list(self, ctx, p, q, b):
        return admin.list_field_maps(ctx, p["source_id"])

    def h_field_maps_add(self, ctx, p, q, b):
        return admin.add_field_map(ctx, p["source_id"], b)

    def h_credentials_list(self, ctx, p, q, b):
        return admin.list_credentials(ctx, source_id=q.get("source_id"), kind=q.get("kind"), scope=q.get("scope"),
                                      status=q.get("status"), **_paging(q))

    def h_credentials_issue(self, ctx, p, q, b):
        return admin.issue_credential(ctx, b)

    def h_credentials_revoke(self, ctx, p, q, b):
        return admin.revoke_credential(ctx, p["credential_id"], b)

    def h_sso_put(self, ctx, p, q, b):
        return admin.put_sso(ctx, b)

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

    def h_records_list(self, ctx, p, q, b):
        ctx.crypto = self.crypto if ctx.actor.role != D else None
        return rec.list_records(ctx, q)

    def h_records_summary(self, ctx, p, q, b):
        return rec.summary(ctx, q)

    def h_records_search(self, ctx, p, q, b):
        ctx.crypto = self.crypto
        return rec.search(ctx, b)

    def h_records_reveal(self, ctx, p, q, b):
        ctx.crypto = self.crypto
        return rec.reveal(ctx, b)

    def h_records_export_request(self, ctx, p, q, b):
        return rec.request_export(ctx, b)

    def h_records_exports_list(self, ctx, p, q, b):
        return rec.list_exports(ctx, q)

    def h_records_exports_get(self, ctx, p, q, b):
        return rec.get_export(ctx, p["export_id"], self._links)

    def h_records_exports_link(self, ctx, p, q, b):
        from datetime import datetime, timezone
        job = rec._export_row(ctx, p["export_id"])
        now = datetime.fromtimestamp(ctx.now(), tz=timezone.utc)
        status = rec.effective_status(job, now)
        if status == "expired":
            raise ApiError("export_expired", "the file is no longer kept; request a new export")
        if status != "ready":
            raise ApiError("export_not_ready", "the file is not ready")
        url, exp = self._links.mint(ctx.conn, job["org_id"], job["export_id"], ctx.actor.id, now)
        return {"download_url": url, "expires_at": iso(exp)}

    def h_setup_get(self, ctx, p, q, b):
        return setup_mod.get_setup(ctx)

    def h_setup_skip(self, ctx, p, q, b):
        return setup_mod.skip_step(ctx, p["step"], b)

    def h_setup_unskip(self, ctx, p, q, b):
        return setup_mod.unskip_step(ctx, p["step"], b)

    # ---- confirmation messages (confirmations.md) -------------------------------------------------------------------------
    def _confirm(self):
        if self.confirmations is None:
            raise ApiError("service_unavailable", "confirmation messages are not configured on this server")
        return self.confirmations

    def h_confirm_settings_get(self, ctx, p, q, b):
        return self._confirm().get_settings(ctx)

    def h_confirm_settings_put(self, ctx, p, q, b):
        return self._confirm().put_settings(ctx, b)

    def h_confirm_account_connect(self, ctx, p, q, b):
        return self._confirm().connect_account(ctx, b)

    def h_confirm_account_check(self, ctx, p, q, b):
        return self._confirm().check_account(ctx, p["account_id"], b)

    def h_confirm_account_patch(self, ctx, p, q, b):
        return self._confirm().patch_account(ctx, p["account_id"], b)

    def h_confirm_account_delete(self, ctx, p, q, b):
        return self._confirm().delete_account(ctx, p["account_id"], b)

    def h_confirm_link_host_set(self, ctx, p, q, b):
        return self._confirm().set_link_host(ctx, b)

    def h_confirm_link_host_verify(self, ctx, p, q, b):
        return self._confirm().verify_link_host(ctx, b)

    def h_confirm_registration_mark(self, ctx, p, q, b):
        return self._confirm().mark_registration(ctx, b)

    def h_confirm_registration_withdraw(self, ctx, p, q, b):
        return self._confirm().withdraw_registration(ctx, b)

    def h_confirm_rules_list(self, ctx, p, q, b):
        return self._confirm().list_rules(ctx)

    def h_confirm_rule_put(self, ctx, p, q, b):
        return self._confirm().put_rule(ctx, p["source_id"], p["channel"], b)

    def h_confirm_templates_list(self, ctx, p, q, b):
        return self._confirm().list_templates(ctx)

    def h_confirm_templates_get(self, ctx, p, q, b):
        return self._confirm().get_template(ctx, p["template_id"])

    def h_confirm_templates_create(self, ctx, p, q, b):
        return self._confirm().create_template(ctx, b)

    def h_confirm_preview(self, ctx, p, q, b):
        return self._confirm().preview(ctx, b)

    def h_confirm_test(self, ctx, p, q, b):
        return self._confirm().test_message(ctx, b)

    def h_confirm_sends_list(self, ctx, p, q, b):
        return self._confirm().list_sends(ctx, q)

    def h_confirm_replies_list(self, ctx, p, q, b):
        return self._confirm().list_replies(ctx, q)

    def h_confirm_reply_mark(self, ctx, p, q, b):
        return self._confirm().mark_reply(ctx, p["reply_id"], b)

    def h_proof(self, ctx, p, q, b):
        ctx.crypto = self.crypto
        return proof_for(ctx, b, region=rec.region_of(ctx))

    def h_evidence_export_start(self, ctx, p, q, b):
        ctx.crypto = self.crypto
        return evidence_export_start(ctx, b, self.exports)

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

    def h_systems_workflow_credential_issue(self, ctx, p, q, b):
        from ..sync.connectors import twenty_workflow

        return twenty_workflow.admin_issue(ctx, p["system_id"], b)

    def h_systems_workflow_credential_revoke(self, ctx, p, q, b):
        from ..sync.connectors import twenty_workflow

        return twenty_workflow.admin_revoke(ctx, p["system_id"], p["credential_id"], b)

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


# ---- proof and evidence packages, by contact or by record id (proof-export.md, amendment 2026-10-30) -----------------------
def _one_of_contact_or_record(b: Any, allowed: tuple[str, ...]) -> dict:
    b = body_dict(b)
    extra = set(b) - set(allowed)
    if extra:
        raise ApiError("validation_failed", "the body has fields this call does not take", {k: "not accepted" for k in extra})
    if ("contact" in b) == ("record_id" in b):
        raise ApiError("validation_failed", "give exactly one of contact or record_id",
                       {"contact": "exactly one of contact or record_id", "record_id": "exactly one of contact or record_id"})
    return b


def proof_for(ctx: Ctx, body: Any, *, region: str) -> dict:
    """POST /v1/proof for a portal session (admin or compliance viewer): by contact point as before, or by ``record_id``,
    which adds ``record_id``, the masked contact and the person and never the full contact point."""
    from ..proof import tenant_lookup
    from .pipeline import normalize, require_serving

    b = _one_of_contact_or_record(body, ("contact", "record_id", "page"))
    org = ctx.org_id()
    require_serving(ctx.conn)
    row = None
    if "record_id" in b:
        row = rec.record_for_proof(ctx, b["record_id"])
        fp, kind = row["contact_fp"], row["contact_kind"]
    else:
        kind, norm = normalize(b["contact"], region)
        fp = ctx.crypto.contact_fingerprint(org, kind, norm)
    answer = tenant_lookup(ctx.conn, ctx.crypto, org=org, contact_fp=fp, contact_kind=kind, page=b.get("page"), region=region,
                           cursor_key=ctx.cursor_key, now=ctx.now())
    if row is not None:
        who = rec.record_identity(ctx, row)
        answer = {**answer, "record_id": str(row["record_id"]), "contact": who["contact"], "person": who["person"]}
        if who["partial"]:
            answer["partial"] = sorted(set(answer.get("partial", [])) | set(who["partial"]))
        if row["erased_at"] is not None:
            answer["found"] = True
    with ctx.conn.transaction():
        ctx.audit("proof.read", "contact", fp[:8])
    return answer


def evidence_export_start(ctx: Ctx, body: Any, service) -> dict:
    """POST /v1/exports for a portal session: validates the contact-or-record_id rule, then hands the contact point to the
    evidence package service. A server with no such service refuses by name."""
    from ..evidence import Actor as ExportActor

    b = _one_of_contact_or_record(body, ("contact", "record_id"))
    contact = b.get("contact")
    if "record_id" in b:
        row = rec.record_for_proof(ctx, b["record_id"])
        if row["erased_at"] is not None:
            raise ApiError("no_records", "no records for that contact in this organization")
        try:
            contact = rec._contact_of(ctx, ctx.org_id(), row["contact_fp"])
        except Exception as exc:  # loud-failure-exempt: re-raised as the named key_unavailable refusal
            raise ApiError("key_unavailable", "the contact key could not be used; nothing was read") from exc
    if service is None:
        raise ApiError("service_unavailable", "evidence packages are not configured on this server")
    return service.start(ctx.org_id(), ExportActor("member", ctx.actor.member_uuid), contact, request_id=ctx.request_id)
