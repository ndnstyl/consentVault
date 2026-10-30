"""The other lanes' routes, adapted to the multi-tenant server's route interface, and the callers they run as.

The server (``api.make_cloud_server``) calls ``route.handles(method, path)`` and then
``route.handle(method, path, body=<bytes>, headers=<dict>, caller=<portal caller or None>[, query=<dict>])`` and sends
``reply.status`` with ``reply.payload`` (JSON), or ``reply.raw`` bytes with ``reply.headers``.

Every principal is produced here from what the request proves, never from what it claims:

- a **portal caller** from a tenant session token (``Authorization: Bearer v1....``) that the database verifies; the
  role is read from the member row (``session.actor_from_token``);
- a **machine principal** from a platform access token (``AccessTokenSigner.verify``);
- an **operator id** from an identity token the identity provider verifies, with a second factor, whose
  (issuer, subject) is on the deployment's operator list. No header names an operator: a request that sends one is
  treated exactly as a request that does not.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

import psycopg

from .errors import ConsentVaultError

TENANT_TOKEN_PREFIX = "v1."
DEFAULT_OPERATOR_MAX_SIGNIN_AGE_S = 900  # an operator proved who they are within the last 15 minutes, configurable

_log = logging.getLogger("consentvault.route_wiring")


@dataclass
class Reply:
    status: int
    payload: Any = None
    headers: dict = field(default_factory=dict)
    raw: bytes | None = None


@dataclass(frozen=True)
class PortalPrincipal:
    org_id: uuid.UUID
    member_id: str
    role: str
    scopes: tuple[str, ...]
    token: str


class BodyNotJson(ConsentVaultError):
    """The request body is not JSON."""


class OperatorRefusalNotRecorded(ConsentVaultError):
    """An operator attempt was refused, and the audit row that must record the refusal could not be written."""


@dataclass(frozen=True)
class OperatorDecision:
    """The outcome of checking the operator console credential: an operator id, or a named refusal (never both)."""
    operator_id: str | None
    reason: str          # "verified" or the refusal reason: a name, never token text
    actor: str           # "issuer|subject" once the identity provider verified the token, else "unverified"


def _lower(headers: Mapping[str, str] | None) -> dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}


def _bearer(headers: Mapping[str, str] | None) -> str | None:
    auth = _lower(headers).get("authorization", "")
    return (auth[7:].strip() or None) if auth.startswith("Bearer ") else None


def _rid(headers) -> str:
    return _lower(headers).get("x-request-id", "")


def _err(status: int, name: str, detail: str, rid: str) -> Reply:
    return Reply(status, {"error": name, "detail": detail, "request_id": rid})


def _json_body(body: bytes):
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BodyNotJson("the body is not JSON") from exc


class Authenticator:
    """Produces callers from authenticated credentials only.

    ``connect``       a runtime-role connection (closed here) for checking portal session tokens.
    ``access_tokens`` the platform's ``AccessTokenSigner`` (machine tokens).
    ``identity``      the operator console's own identity provider (``verify(token, require_mfa=...)``). It is built
                      with the console's own audience, so a token minted for the member portal never verifies here.
    ``operators``     {(issuer, subject): operator_id}; the deployment's operator list.
    ``max_signin_age_s``  how recently the operator must have signed in (the token's ``auth_time``); default 15 minutes.
                      A token with no ``auth_time`` cannot prove recency and is refused.
    ``clock``         seconds since the epoch; injectable for tests.
    """

    def __init__(self, *, connect: Callable[[], psycopg.Connection], access_tokens, identity=None,
                 operators: Mapping[tuple[str, str], str] | None = None,
                 max_signin_age_s: int = DEFAULT_OPERATOR_MAX_SIGNIN_AGE_S, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(max_signin_age_s, int) or isinstance(max_signin_age_s, bool) or not 1 <= max_signin_age_s <= 86400:
            raise ConsentVaultError("operator max_signin_age_s must be a whole number of seconds from 1 to 86400")
        self._connect, self._access, self._identity = connect, access_tokens, identity
        self._operators = dict(operators or {})
        self._max_age, self._clock = max_signin_age_s, clock

    def portal(self, headers) -> PortalPrincipal | None:
        from .tenancy.admin_base import ApiError
        from .tenancy.errors import TenantTokenError
        from .tenancy.session import actor_from_token
        from .tenancy.tokens import org_transaction

        token = _bearer(headers)
        if not token or not token.startswith(TENANT_TOKEN_PREFIX):
            return None
        try:
            with self._connect() as conn, org_transaction(conn, token) as org:
                actor = actor_from_token(conn)
                scopes = conn.execute("SELECT consentvault.current_token_scopes() AS s").fetchone()["s"]
        except (TenantTokenError, ApiError):  # loud-failure-exempt: an unproven session is no caller; the route answers unauthenticated
            return None
        return PortalPrincipal(org, actor.id, actor.role, tuple(scopes or ()), token)

    def machine(self, headers):
        from .tenancy.oauth import OAuthError

        token = _bearer(headers)
        if not token or token.startswith(TENANT_TOKEN_PREFIX):
            return None
        try:
            return self._access.verify(token)
        except OAuthError:  # loud-failure-exempt: an unverified token is no caller; the route answers unauthenticated
            return None

    def operator_decision(self, headers) -> OperatorDecision:
        """Check the operator console credential and say why it was refused when it is."""
        from .providers.errors import ProviderError

        token = _bearer(headers)
        if not token:
            return OperatorDecision(None, "no_credential", "unverified")
        if token.startswith(TENANT_TOKEN_PREFIX):
            return OperatorDecision(None, "member_session_not_accepted", "unverified")
        if self._identity is None:
            return OperatorDecision(None, "operator_identity_not_configured", "unverified")
        try:
            who = self._identity.verify(token, require_mfa=True)
        except ProviderError as exc:
            return OperatorDecision(None, f"token_rejected_{type(exc).__name__}", "unverified")
        except ConsentVaultError as exc:
            return OperatorDecision(None, f"token_rejected_{type(exc).__name__}", "unverified")
        actor = f"{who.issuer}|{who.subject}"[:200]
        operator_id = self._operators.get((who.issuer, who.subject))
        if operator_id is None:
            return OperatorDecision(None, "not_on_operator_list", actor)
        auth_time = getattr(who, "auth_time", None)
        if auth_time is None:
            return OperatorDecision(None, "sign_in_time_unproven", actor)
        age = self._clock() - auth_time.timestamp()
        if age > self._max_age:
            return OperatorDecision(None, "sign_in_not_recent", actor)
        if age < -30:
            return OperatorDecision(None, "sign_in_time_in_the_future", actor)
        return OperatorDecision(operator_id, "verified", actor)

    def operator(self, headers) -> str | None:
        return self.operator_decision(headers).operator_id

    def billing_caller(self, headers):
        """The ``portal_caller`` producer for the server (billing's ``Caller``)."""
        from .billing.routes import Caller

        p = self.portal(headers)
        return None if p is None else Caller(p.org_id, p.role, _rid(headers))


def record_operator_refusal(owner_connect, decision: OperatorDecision, method: str, handler: str, rid: str) -> None:
    """One platform audit row per refused operator attempt: who it claimed to be, which route, the reason name."""
    from .tenancy import audit

    if owner_connect is None:
        raise OperatorRefusalNotRecorded("this server has no operator console connection to write the audit row with")
    request_id = rid if rid and audit._REQUEST_ID.match(rid) else "refused-" + uuid.uuid4().hex
    try:
        conn = owner_connect()
        try:
            audit.append_platform(conn, operator_id=decision.actor, action="operator.refused", target_kind="route",
                                  target_id=f"{method} {handler}"[:200], reason=decision.reason, request_id=request_id)
        finally:
            conn.close()
    except (ConsentVaultError, psycopg.Error) as exc:  # AuditError and DatabaseError are both ConsentVaultError
        raise OperatorRefusalNotRecorded(f"{type(exc).__name__}: {exc}") from exc


class AdminRoutes:
    wants_query = True

    def __init__(self, app, auth: Authenticator) -> None:
        self._app, self._auth = app, auth

    def handles(self, method: str, path: str) -> bool:
        from .tenancy.admin_routes import Request

        return self._app._match(Request(method, path))[0] is not None

    def handle(self, method, path, *, body=b"", headers=None, caller=None, query=None) -> Reply:
        from .tenancy.admin_routes import Request

        rid = _rid(headers)
        parsed = _json_body(body)
        route, _ = self._app._match(Request(method, path))
        bearer = _bearer(headers)
        tenant = bearer if bearer and bearer.startswith(TENANT_TOKEN_PREFIX) else None
        identity = bearer if bearer and not tenant else None
        operator_id = None
        if route is not None and route.kind == "operator":
            decision = self._auth.operator_decision(headers)
            operator_id = decision.operator_id
            if operator_id is None:
                try:
                    record_operator_refusal(getattr(self._app, "_owner_connect", None), decision, method, route.handler,
                                            rid)
                except OperatorRefusalNotRecorded as exc:
                    _log.critical("operator refusal NOT recorded (request %s): %s", rid or "-", exc)
                    return _err(503, "audit_unavailable", "the attempt was refused, but its audit row could not be "
                                "written; nothing else was done", rid)
        res = self._app.handle(Request(method, path, dict(query or {}), parsed, tenant_token=tenant,
                                       identity_token=identity, request_id=rid, operator_id=operator_id))
        return Reply(res.status, res.body, dict(res.headers or {}))


class SyncRouteAdapter:
    wants_query = True

    def __init__(self, routes, auth: Authenticator, token_key) -> None:
        self._routes, self._auth, self._key = routes, auth, token_key

    def handles(self, method: str, path: str) -> bool:
        return self._routes.matches(method, path)

    def handle(self, method, path, *, body=b"", headers=None, caller=None, query=None) -> Reply:
        from .sync.routes import Request
        from .tenancy.tokens import mint_org_token

        rid = _rid(headers)
        parsed = _json_body(body)
        claims = self._auth.machine(headers)
        if claims is not None:  # a machine credential, inbound /v1/signals included
            ttl = max(1, min(300, claims.seconds_left()))
            token = mint_org_token(self._key, claims.org_id, claims.scopes, credential_id=str(claims.credential_id),
                                   ttl_seconds=ttl)
            req = Request(method, path, claims.org_id, frozenset(claims.scopes), token, parsed, dict(query or {}), rid,
                          credential_id=str(claims.credential_id))
        else:
            p = self._auth.portal(headers)
            if p is None:
                return _err(401, "unauthenticated", "a session or access token is required", rid)
            req = Request(method, path, p.org_id, frozenset(p.scopes), p.token, parsed, dict(query or {}), rid,
                          role=p.role, actor=p.member_id)
        res = self._routes.handle(req)
        return Reply(res.status, res.body)


class ExportRouteAdapter:
    wants_query = True

    def __init__(self, service, auth: Authenticator) -> None:
        self._service, self._auth = service, auth

    def handles(self, method: str, path: str) -> bool:
        from .evidence_routes import matches

        return matches(path)

    def handle(self, method, path, *, body=b"", headers=None, caller=None, query=None) -> Reply:
        from .evidence_routes import Principal, Request, handle

        rid = _rid(headers)
        parsed = _json_body(body)
        principal = None
        claims = self._auth.machine(headers)
        if claims is not None:
            principal = Principal(claims.org_id, claims.credential_id, "machine", scopes=frozenset(claims.scopes))
        else:
            p = self._auth.portal(headers)
            if p is not None:
                principal = Principal(p.org_id, uuid.UUID(p.member_id), "portal", role=p.role)
        res = handle(self._service, Request(method, path, dict(query or {}), parsed, principal, rid))
        return Reply(res.status, res.body, dict(res.headers or {}), res.raw)


def lifecycle_routes(app, auth): from .tenancy.lifecycle_routes import LifecycleRoutes; return LifecycleRoutes(app, auth)  # noqa: E701,E702,E704  erasure, offboarding, legal holds, operator access
