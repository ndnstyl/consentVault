"""Routes for erasure, offboarding, legal holds and operator access, registered through ``route_wiring`` in one line.

Callers come only from ``route_wiring.Authenticator``: a portal session (role read from the member row) or an operator
the identity provider signed in with a second factor (``Authenticator.operator``). Operator routes act on the schema
owner's connection and always name the target organisation in the path (``/v1/orgs/{org_id}/...``); an ``org_id`` in a
body is never read. A portal caller's organisation always comes from its session.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

import psycopg

from ..safelog import caller_detail
from . import erasure, holds, key_rotation, legal_process, offboard
from .admin_base import ROLE_ADMIN, ApiError, Ctx, body_dict, to_uuid
from .erasure import LedgerUnavailableError, LifecycleError, LifecycleLedger
from .errors import TenantTokenError
from .tokens import TokenKey, org_transaction


@dataclass(frozen=True)
class _Route:
    method: str
    pattern: re.Pattern
    tenant: bool
    operator: bool
    success: int
    handler: str


def _r(method: str, template: str, *, tenant: bool, operator: bool, success: int, handler: str) -> _Route:
    regex = "^" + re.sub(r"\{(\w+)\}", lambda m: f"(?P<{m.group(1)}>[^/:]+)", template) + "$"
    return _Route(method, re.compile(regex), tenant, operator, success, handler)


ROUTES = (
    _r("POST", "/v1/contacts:erase", tenant=True, operator=False, success=202, handler="erase_request"),
    _r("GET", "/v1/erasures/{erasure_id}", tenant=True, operator=False, success=200, handler="erase_get"),
    _r("POST", "/v1/orgs/{org_id}/erasures/{erasure_id}:confirm", tenant=False, operator=True, success=200,
       handler="erase_confirm"),
    _r("POST", "/v1/orgs/{org_id}/offboard", tenant=False, operator=True, success=200, handler="offboard"),
    _r("GET", "/v1/offboarding/{request_id}/final-export", tenant=True, operator=False, success=200,
       handler="final_export_download"),
    _r("POST", "/v1/offboarding/{request_id}/final-export:confirm", tenant=True, operator=False, success=200,
       handler="final_export_confirm"),
    _r("POST", "/v1/operator-access-approvals", tenant=True, operator=False, success=201, handler="access_approve"),
    _r("POST", "/v1/offboarding-requests", tenant=True, operator=False, success=202, handler="offboard_request"),
    _r("POST", "/v1/legal-holds", tenant=True, operator=False, success=201, handler="hold_place"),
    _r("POST", "/v1/legal-holds/{hold_id}:release", tenant=True, operator=False, success=200, handler="hold_release"),
    _r("POST", "/v1/orgs/{org_id}/legal-holds", tenant=False, operator=True, success=201, handler="hold_place"),
    _r("POST", "/v1/orgs/{org_id}/legal-holds/{hold_id}:release", tenant=False, operator=True, success=200,
       handler="hold_release"),
    _r("POST", "/v1/orgs/{org_id}/operator-access", tenant=False, operator=True, success=201, handler="access_open"),
    _r("POST", "/v1/orgs/{org_id}/operator-access/{access_id}:close", tenant=False, operator=True, success=200,
       handler="access_close"),
    _r("POST", "/v1/orgs/{org_id}/key-rotations", tenant=False, operator=True, success=202, handler="key_rotation_start"),
    _r("GET", "/v1/orgs/{org_id}/key-rotations/{rotation_id}", tenant=False, operator=True, success=200,
       handler="key_rotation_get"),
)

# named lifecycle failures -> (HTTP status, contract error name)
_FAILURES = ((LedgerUnavailableError, 503, "evidence_store_unavailable"),
             (holds.HoldEnforcementError, 503, "key_unavailable"),
             (offboard.DestructionError, 503, "key_unavailable"),
             (offboard.OffboardNoticeError, 502, "email_send_failed"),
             (legal_process.AccessNoticeError, 502, "email_send_failed"),
             (LifecycleError, 503, "service_unavailable"))


class LifecycleApp:
    """``connect``: runtime-role connections; ``owner_connect``: the operator console login's (consentvault_console;
    the schema owner cannot log in), for operator steps and the resume after a release. ``custody`` is the key provider (destruction), ``crypto`` the tenant crypto
    (fingerprints, final export), ``ledger`` the lifecycle ledger, ``store`` the archive store for the final export."""

    def __init__(self, *, connect: Callable[[], psycopg.Connection], owner_connect: Callable[[], psycopg.Connection],
                 token_key: TokenKey, crypto, custody, ledger: LifecycleLedger, store, signer, notifier,
                 export_cache=None, region: Optional[str] = None, deliver_export=None, links=None):
        self.connect, self.owner_connect, self.key = connect, owner_connect, token_key
        self.crypto, self.custody, self.ledger, self.store, self.signer = crypto, custody, ledger, store, signer
        self.notifier, self.export_cache, self.region = notifier, export_cache, region
        self.links = links  # the evidence ExportService: issues and spends the one-time final-export link
        self.deliver_export = deliver_export  # (org_id, request_id, package, sha256); None stops before destruction


class LifecycleRoutes:
    wants_query = True

    def __init__(self, app: LifecycleApp, auth) -> None:
        self._app, self._auth = app, auth

    @staticmethod
    def _match(method: str, path: str):
        for r in ROUTES:
            m = r.pattern.match(path)
            if m and r.method == method:
                return r, m.groupdict()
        return None, {}

    def handles(self, method: str, path: str) -> bool:
        return self._match(method, path)[0] is not None

    def handle(self, method, path, *, body=b"", headers=None, caller=None, query=None):
        from ..route_wiring import TENANT_TOKEN_PREFIX, Reply, _bearer, _json_body, _rid

        rid = _rid(headers) or "req-unset"
        route, params = self._match(method, path)
        parsed = _json_body(body)
        if route.handler in ("final_export_download", "final_export_confirm"):  # a signed-in admin, and the link
            return self._final_export(route.handler, params, query or {}, parsed, _bearer(headers), rid)
        try:
            bearer = _bearer(headers)
            operator_id = None
            if route.operator:
                from ..route_wiring import OperatorRefusalNotRecorded, record_operator_refusal

                decision = self._auth.operator_decision(headers)
                operator_id = decision.operator_id
                if operator_id is None:
                    try:
                        record_operator_refusal(self._app.owner_connect, decision, method, route.handler, rid)
                    except OperatorRefusalNotRecorded as exc:
                        return Reply(503, {"error": "audit_unavailable", "detail": caller_detail(exc), "request_id": rid})
            if operator_id is not None:
                result = getattr(self, "op_" + route.handler)(operator_id, params, body_dict(parsed or {}), rid)
            elif route.tenant and bearer and bearer.startswith(TENANT_TOKEN_PREFIX):
                result = self._tenant(route, params, parsed, bearer, rid)
            else:
                raise ApiError("unauthenticated", "a session or an operator sign-in is required")
        except ApiError as exc:  # loud-failure-exempt: a contract refusal is answered to the caller by name
            return Reply(exc.status, exc.body(rid))
        except tuple(f[0] for f in _FAILURES) as exc:  # loud-failure-exempt: answered by name with its status
            status, name = next((s, n) for cls, s, n in _FAILURES if isinstance(exc, cls))
            return Reply(status, {"error": name, "detail": caller_detail(exc), "request_id": rid})
        return Reply(route.success, result)

    def _admin_session(self, bearer: Optional[str]):
        """The signed-in admin of a portal session: (org, actor). Anything else is ``unauthenticated`` or refused."""
        from ..route_wiring import TENANT_TOKEN_PREFIX
        from .session import actor_from_token

        if not bearer or not bearer.startswith(TENANT_TOKEN_PREFIX):
            raise ApiError("unauthenticated", "a signed-in admin of the organization is required with the link")
        conn = self._app.connect()
        try:
            with org_transaction(conn, bearer) as org:
                actor = actor_from_token(conn)
                actor.require(ROLE_ADMIN)
                return org, actor
        except TenantTokenError:
            raise ApiError("unauthenticated", "the session token is missing, expired or not valid") from None
        finally:
            conn.close()

    def _final_export(self, handler: str, params: dict, query: dict, body: Any, bearer: Optional[str], rid: str):
        from ..evidence import ExportError
        from ..route_wiring import Reply
        from ..evidence_routes import STATUS

        a = self._app
        try:
            org, actor = self._admin_session(bearer)
            if handler == "final_export_confirm":
                with a.owner_connect() as owner:
                    return Reply(200, offboard.confirm_final_export(
                        owner, token_key=a.key, session_org=org, request_id_str=params["request_id"],
                        sha256=body_dict(body or {}).get("sha256"), actor_kind=actor.kind, actor_id=actor.id, rid=rid))
            link = query.get("link")
            if a.links is None or not link:
                return Reply(STATUS["export_link_invalid"], {"error": "export_link_invalid",
                                                              "detail": "the download link is not valid",
                                                              "request_id": rid})
            with a.owner_connect() as owner:
                package, sha = offboard.download_final_export(
                    owner, links=a.links, token_key=a.key, custody=a.custody, store=a.store,
                    request_id_str=params["request_id"], link=link, rid=rid, session_org=org)
        except ApiError as exc:  # loud-failure-exempt: a contract refusal is answered by name
            return Reply(exc.status, exc.body(rid))
        except ExportError as exc:  # loud-failure-exempt: answered by name with its status
            name = getattr(exc, "error_name", "export_failed")
            return Reply(STATUS.get(name, 500), {"error": name, "detail": caller_detail(exc), "request_id": rid})
        except tuple(f[0] for f in _FAILURES) as exc:  # loud-failure-exempt: answered by name with its status
            status, name = next((s, n) for cls, s, n in _FAILURES if isinstance(exc, cls))
            return Reply(status, {"error": name, "detail": caller_detail(exc), "request_id": rid})
        return Reply(200, None, {"Content-Type": "application/zip", "Cache-Control": "no-store", "X-Package-Sha256": sha,
                                 "Content-Disposition": 'attachment; filename="final-export.zip"'}, package)

    # ---- tenant (portal) --------------------------------------------------------------------------------------------
    def _tenant(self, route: _Route, params: dict, body: Any, token: str, rid: str):
        from .session import actor_from_token

        a = self._app
        conn = a.connect()
        try:
            try:
                with org_transaction(conn, token) as org:
                    actor = actor_from_token(conn)
                    actor.require(ROLE_ADMIN)
                    ctx = Ctx(conn, actor, rid)
                    h = route.handler
                    if h == "erase_request":
                        return erasure.request_erasure(ctx, body, crypto=a.crypto, region=a.region)
                    if h == "erase_get":
                        return erasure.get_erasure(ctx, params["erasure_id"])
                    if h == "offboard_request":
                        return offboard.request_offboarding(ctx, body)
                    if h == "access_approve":
                        return legal_process.approve_operator_access(ctx, body)
                    if h == "hold_place":
                        out = holds.place_hold_member(ctx, body, ledger=a.ledger, crypto=a.crypto, region=a.region)
                    else:
                        out = holds.release_hold_member(ctx, params["hold_id"], body, ledger=a.ledger, crypto=a.crypto)
            except TenantTokenError:
                raise ApiError("unauthenticated", "the session token is missing, expired or not valid") from None
        finally:
            conn.close()
        with a.owner_connect() as owner:  # after commit: the provider side of a hold, or the queue a release frees
            if route.handler == "hold_place":
                out["destruction_cancelled"] = holds.enforce_on_keys(owner, token_key=a.key, custody=a.custody,
                                                                     org_id=org, actor_id=actor.id, request_id=rid)
            else:
                out["resumed"] = holds.resume(owner, token_key=a.key, ledger=a.ledger, custody=a.custody, crypto=a.crypto,
                                              org_id=org, request_id=rid, export_cache=a.export_cache)
        return out

    # ---- operator ----------------------------------------------------------------------------------------------------
    def _owner(self, fn):
        with self._app.owner_connect() as conn:
            return fn(conn)

    @staticmethod
    def _org(p: dict):
        return to_uuid(p.get("org_id"), "organization")

    def op_erase_confirm(self, op, p, b, rid):
        a = self._app
        return self._owner(lambda c: erasure.confirm_erasure(
            c, token_key=a.key, ledger=a.ledger, crypto=a.crypto, operator_id=op, request_id=rid, org_id=self._org(p),
            erasure_id=p["erasure_id"], export_cache=a.export_cache))

    def op_offboard(self, op, p, b, rid):
        a = self._app
        return self._owner(lambda c: offboard.run_offboard(
            c, token_key=a.key, custody=a.custody, crypto=a.crypto, signer=a.signer, store=a.store, notifier=a.notifier,
            operator_id=op, request_id=rid, org_id=p["org_id"], reason=b.get("reason"),
            window_days=b.get("window_days") or offboard.MIN_WINDOW_DAYS, deliver=a.deliver_export, links=a.links))

    def op_hold_place(self, op, p, b, rid):
        a = self._app
        return self._owner(lambda c: holds.place_hold_operator(
            c, token_key=a.key, ledger=a.ledger, custody=a.custody, operator_id=op, request_id=rid,
            org_id=self._org(p), scope=b.get("scope"), reason=b.get("reason"), contacts=b.get("contacts") or (),
            crypto=a.crypto, region=a.region))

    def op_hold_release(self, op, p, b, rid):
        a = self._app
        return self._owner(lambda c: holds.release_hold_operator(
            c, token_key=a.key, ledger=a.ledger, custody=a.custody, operator_id=op, request_id=rid,
            org_id=self._org(p), hold_id=p["hold_id"], reason=b.get("reason"), crypto=a.crypto, export_cache=a.export_cache))

    def op_access_open(self, op, p, b, rid):
        a = self._app
        return self._owner(lambda c: legal_process.open_operator_access(
            c, token_key=a.key, notifier=a.notifier, operator_id=op, request_id=rid, org_id=self._org(p),
            reason=b.get("reason"), approval_id=b.get("approval_id"), approved_by_member=b.get("approved_by_member"),
            emergency=b.get("emergency") is True))

    def op_key_rotation_start(self, op, p, b, rid):
        a = self._app
        return self._owner(lambda c: key_rotation.start_rotation(
            c, token_key=a.key, custody=a.custody, operator_id=op, request_id=rid, org_id=self._org(p),
            reason=b.get("reason")))

    def op_key_rotation_get(self, op, p, b, rid):
        return key_rotation.get_rotation(self._app.owner_connect, self._app.key, self._org(p), p["rotation_id"])

    def op_access_close(self, op, p, b, rid):
        a = self._app
        return self._owner(lambda c: legal_process.close_operator_access(
            c, token_key=a.key, operator_id=op, request_id=rid, org_id=self._org(p), access_id=p["access_id"]))
