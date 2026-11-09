"""The admin API's functions: organisations (operator), brands, capture sources, credentials, retention, members,
connected-system registrations, the organisation and health reads, and the audit read.

Conventions
- Tenant functions take a ``Ctx`` whose connection is already inside ``org_transaction`` for the caller's organisation.
  They never take an organisation argument; every query filters on ``current_org()`` itself (row security is the
  second lock, not the only one), and each function checks the caller's role first.
- Operator functions (``create_org``, ``set_org_status``, ``issue_verified_credential``) take the schema owner's
  connection, enter the target organisation with a token the vault mints, and write the organisation's chain and the
  platform chain. They return plain dictionaries shaped as the contract's answers.
- Nothing here states a legal conclusion; reasons are staff text about an action and never a contact point.
"""

from __future__ import annotations

import os
import re
import secrets
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

import psycopg

from ..safelog import caller_detail, describe, text_has
from ..providers.errors import KeyProviderError as CustodyError
from ..providers.keys import wrapped_version
from . import audit, invite as invite_mod, site_keys
from .admin_base import (CLIENT_ROLES, PLATFORM_MINIMUM_RETENTION_YEARS, ROLE_ADMIN, ROLE_DEVELOPER, ROLE_OPERATOR,
                         ROLE_VIEWER, Actor, ApiError, Ctx, body_dict, clean_email, invalid, iso, need_list, need_text,
                         page_list, paginate, require_can_add, require_not_closed, to_uuid, want_enum)
from .errors import TenancyError
from .tokens import TokenKey, mint_org_token, org_transaction

DEFAULT_CHANNELS = (("voice", "Voice call"), ("artificial_voice", "Artificial or prerecorded voice"),
                    ("sms", "Text message"), ("email", "Email"))
DEFAULT_PURPOSES = (("marketing", "Marketing", "Marketing contact"),)
ORG_STATUSES = ("trial", "active", "past_due", "suspended", "offboarding", "closed")
OPERATOR_STATUS_TARGETS = ("suspended", "active", "offboarding", "closed")
_TRANSITIONS = {"trial": {"suspended", "offboarding"}, "active": {"suspended", "offboarding"},
                "past_due": {"suspended", "offboarding"}, "suspended": {"active", "offboarding", "suspended"}, "offboarding": {"closed"}}
_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


def _operator_ctx(conn, operator_id: str, request_id: str, cursor_key: bytes = b"") -> Ctx:
    return Ctx(conn, Actor("operator", operator_id, ROLE_OPERATOR), request_id, cursor_key)


def _custody_error(exc: Exception) -> ApiError:
    return ApiError("key_unavailable", f"the organization key could not be used ({type(exc).__name__}); nothing was written")


# ======================================================================================================================
# Organisations (operator)
# ======================================================================================================================
def create_org(conn: psycopg.Connection, *, token_key: TokenKey, custody, operator_id: str, request_id: str, name: str,
               admin_email: str, region: Optional[str] = None, status: str = "trial", channels=None, purposes=None,
               mailer=None, default_region: Optional[str] = None) -> dict:
    """POST /v1/orgs: the one creation route.

    Creates the organisation key through the key provider, the organisation, its key record, its wrapped fingerprint
    secret, its channel and purpose lists, retention at the platform minimum, an empty ledger (the chain starts on its
    first event; the evidence prefix is ``orgs/<id>/``) and the first admin's invitation, all audited in the
    organisation's chain and the platform chain. ``conn`` is the schema owner's connection (idle, autocommit).
    """
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 200:
        raise invalid(name="required text, 1 to 200 characters")
    if region is not None and (not isinstance(region, str) or not 1 <= len(region) <= 64):
        raise invalid(region="1 to 64 characters")
    want_enum(status, "status", ("trial", "active"))
    email = clean_email(admin_email, "admin_email")
    phone_region = _phone_region(default_region) if default_region is not None else "US"
    chans = list(channels) if channels is not None else [list(c) for c in DEFAULT_CHANNELS]
    purps = list(purposes) if purposes is not None else [list(p) for p in DEFAULT_PURPOSES]
    org_id = uuid.uuid4()
    try:
        key_ref = custody.create_org_key(str(org_id))
        wrapped_fp = custody.wrap(str(org_id), os.urandom(32))
        wrapped_display = custody.wrap(str(org_id), os.urandom(32))  # the display key seals names and masks (records.md section 8)
    except CustodyError as exc:
        raise _custody_error(exc) from exc
    token = mint_org_token(token_key, org_id, ["admin"], credential_id=None, ttl_seconds=120)
    try:
        with org_transaction(conn, token):
            conn.execute("INSERT INTO consentvault.organization (org_id, name, region, status, default_region)"
                         " VALUES (%s, %s, %s, %s, %s)", (org_id, name.strip(), region, status, phone_region))
            conn.execute("INSERT INTO consentvault.org_key (org_id, version, kms_key_ref) VALUES (%s, 1, %s)", (org_id, key_ref))
            conn.execute("INSERT INTO consentvault.org_fingerprint_secret (org_id, wrapped) VALUES (%s, %s)", (org_id, wrapped_fp))
            conn.execute("INSERT INTO consentvault.org_display_key (org_id, wrapped, key_version) VALUES (%s, %s, %s)",
                         (org_id, wrapped_display, wrapped_version(wrapped_display)))
            for c in chans:
                conn.execute("INSERT INTO consentvault.channel (org_id, channel, label) VALUES (%s, %s, %s)", (org_id, c[0], c[1]))
            for p in purps:
                conn.execute("INSERT INTO consentvault.purpose (org_id, purpose, label, description) VALUES (%s, %s, %s, %s)",
                             (org_id, p[0], p[1], p[2] if len(p) > 2 else ""))
            conn.execute("INSERT INTO consentvault.retention_policy (org_id, version, evidence_years, platform_minimum_years,"
                         " reason) VALUES (%s, 1, %s, %s, 'platform minimum at organization creation')",
                         (org_id, PLATFORM_MINIMUM_RETENTION_YEARS, PLATFORM_MINIMUM_RETENTION_YEARS))
            ctx = _operator_ctx(conn, operator_id, request_id)
            ctx.audit("org.created", "org", str(org_id))
            inv = invite_mod.create(ctx, email=email, role=ROLE_ADMIN, mailer=mailer)
            audit.append_platform(conn, operator_id=operator_id, action="org.created", target_kind="org",
                                  target_id=str(org_id), request_id=request_id)
    except psycopg.Error as exc:
        raise TenancyError(f"organization creation failed after its key {key_ref!r} was created; the key is unused "
                           f"and should be scheduled for destruction ({describe(exc)})") from exc
    except ApiError as exc:
        # nothing was written (the transaction rolled back); the key provider has an unused key for this id
        raise ApiError(exc.name, caller_detail(exc) + f" (an unused organization key {key_ref!r} was created and should be "
                       "scheduled for destruction)", exc.fields) from exc
    out = {"org_id": str(org_id), "name": name.strip(), "status": status, "region": region,
           "evidence_prefix": f"orgs/{org_id}/", "invite_id": inv["invite_id"], "invite_expires_at": inv["expires_at"]}
    if "token" in inv:
        out["invite_token"] = inv["token"]
    return out


def _phone_region(value: Any) -> str:
    """An ISO 3166-1 alpha-2 code in upper case (records.md, phone region). This is not the hosting ``region`` field."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z]{2}", value):
        raise invalid(default_region="two upper-case letters, an ISO 3166-1 alpha-2 country code such as US or GB")
    return value


def set_default_region(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id: Any,
                       default_region: Any, reason: Any) -> dict:
    """PATCH /v1/orgs/{id}/default-region: the operator changes the phone region with a reason; audited with the old and new."""
    new = _phone_region(default_region)
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise invalid(reason="required, 1 to 500 characters")
    oid = to_uuid(org_id, "organization")
    token = mint_org_token(token_key, oid, ["admin"], credential_id=None, ttl_seconds=120)
    with org_transaction(conn, token):
        row = conn.execute("SELECT default_region FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                           " FOR UPDATE").fetchone()
        if row is None:
            raise ApiError("not_found", "no such organization")
        conn.execute("UPDATE consentvault.organization SET default_region = %s WHERE org_id = (SELECT consentvault.current_org())",
                     (new,))
        ctx = _operator_ctx(conn, operator_id, request_id)
        ctx.audit("org.default_region_changed", "org", str(oid), reason.strip()[:500],
                  {"from": row["default_region"], "to": new})
        audit.append_platform(conn, operator_id=operator_id, action="org.default_region_changed", target_kind="org",
                              target_id=str(oid), reason=reason.strip(), request_id=request_id)
    return {"org_id": str(oid), "default_region": new, "previous_default_region": row["default_region"]}


def set_org_status(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id: Any,
                   status: str, reason: str) -> dict:
    """PATCH /v1/orgs/{id}/status: suspended, active (reactivate) or offboarding (begin), per billing transitions."""
    target = want_enum(status, "status", OPERATOR_STATUS_TARGETS)
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise invalid(reason="required, 1 to 500 characters")
    oid = to_uuid(org_id, "organization")
    token = mint_org_token(token_key, oid, ["admin"], credential_id=None, ttl_seconds=120)
    with org_transaction(conn, token):
        row = conn.execute("SELECT status FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                           " FOR UPDATE").fetchone()
        if row is None:
            raise ApiError("not_found", "no such organization")
        if target not in _TRANSITIONS.get(row["status"], set()):
            raise invalid(status=f"an organization in {row['status']} cannot move to {target}")
        if target == "closed" and conn.execute(
                "SELECT 1 FROM consentvault.destruction_record WHERE org_id = (SELECT consentvault.current_org())"
                " AND kind = 'destroyed' LIMIT 1").fetchone() is None:
            raise ApiError("validation_failed", "an organization closes only after its destruction record exists",
                           {"status": "no destruction record yet"})
        conn.execute("SELECT set_config('consentvault.status_cause', 'operator', true),"
                     " set_config('consentvault.status_actor', %s, true)", (operator_id,))
        conn.execute("UPDATE consentvault.organization SET status = %s WHERE org_id = (SELECT consentvault.current_org())",
                     (target,))
        ctx = _operator_ctx(conn, operator_id, request_id)
        ctx.audit("org.status_changed", "org", str(oid), f"{row['status']} to {target}: {reason.strip()}"[:500])
        audit.append_platform(conn, operator_id=operator_id, action="org.status_changed", target_kind="org",
                              target_id=str(oid), reason=reason.strip(), request_id=request_id)
    return {"org_id": str(oid), "status": target, "previous_status": row["status"]}


def issue_verified_credential(conn: psycopg.Connection, *, token_key: TokenKey, custody, operator_id: str, request_id: str,
                              org_id: Any, name: str, kind: str, source_id: Any, public_key: Optional[str] = None,
                              algorithm: Optional[str] = None) -> dict:
    """POST /v1/orgs/{id}/credentials: the only route that can issue ``capture_verified``. Never a site key."""
    want_enum(kind, "kind", ("jwt_public_key", "hmac_fallback"))
    oid = to_uuid(org_id, "organization")
    token = mint_org_token(token_key, oid, ["admin"], credential_id=None, ttl_seconds=120)
    with org_transaction(conn, token):
        ctx = _operator_ctx(conn, operator_id, request_id)
        require_can_add(ctx)
        out = _issue(ctx, name=name, kind=kind, scope="capture_verified", source_id=source_id, public_key=public_key,
                     algorithm=algorithm, custody=custody)
        audit.append_platform(conn, operator_id=operator_id, action="credential.issued", target_kind="credential",
                              target_id=out["credential_id"], reason="capture_verified", request_id=request_id)
    return out


# ======================================================================================================================
# Brands
# ======================================================================================================================
def list_brands(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    sql = ("SELECT b.brand_id, b.display_name, b.created_at, lower(b.display_name) AS _k1, b.brand_id::text AS _k2,"
           " (SELECT count(*) FROM consentvault.capture_source s WHERE s.org_id = b.org_id AND b.brand_id = ANY (s.brand_ids)) AS sources,"
           " (SELECT count(*) FROM consentvault.disclosure d WHERE d.org_id = b.org_id AND b.brand_id = ANY (d.brand_ids)) AS disclosures"
           " FROM consentvault.brand b WHERE b.org_id = (SELECT consentvault.current_org())")
    return paginate(ctx, endpoint="GET /v1/brands", select_sql=sql, params=[], key_cols=("_k1", "_k2"),
                    key_types=("text", "text"), descending=False, limit=limit, cursor=cursor,
                    shape=lambda r: {"brand_id": str(r["brand_id"]), "display_name": r["display_name"],
                                     "created_at": iso(r["created_at"]), "source_count": r["sources"],
                                     "disclosure_count": r["disclosures"]})


def current_org(ctx: Ctx) -> dict:
    """GET /v1/session/current-org: the organization this session chose, for any signed-in role."""
    ctx.actor.require(*CLIENT_ROLES)
    row = ctx.conn.execute("SELECT org_id, name, status FROM consentvault.organization"
                           " WHERE org_id = (SELECT consentvault.current_org())").fetchone()
    if row is None:
        raise ApiError("not_found", "no such organization")
    return {"org_id": str(row["org_id"]), "name": row["name"], "role": ctx.actor.role, "status": row["status"]}


def list_brand_names(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    """GET /v1/brand-names: id and name only, for every role that reads records (a lookup shows names, not ids)."""
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
    sql = ("SELECT b.brand_id, b.display_name, lower(b.display_name) AS _k1, b.brand_id::text AS _k2"
           " FROM consentvault.brand b WHERE b.org_id = (SELECT consentvault.current_org())")
    return paginate(ctx, endpoint="GET /v1/brand-names", select_sql=sql, params=[], key_cols=("_k1", "_k2"),
                    key_types=("text", "text"), descending=False, limit=limit, cursor=cursor,
                    shape=lambda r: {"brand_id": str(r["brand_id"]), "display_name": r["display_name"]})


def list_source_names(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    """GET /v1/source-names: id and name only; no origins, brands, status or last event."""
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
    sql = ("SELECT s.source_id, s.name, lower(coalesce(s.name, '')) AS _k1, s.source_id::text AS _k2"
           " FROM consentvault.capture_source s WHERE s.org_id = (SELECT consentvault.current_org())")
    return paginate(ctx, endpoint="GET /v1/source-names", select_sql=sql, params=[], key_cols=("_k1", "_k2"),
                    key_types=("text", "text"), descending=False, limit=limit, cursor=cursor,
                    shape=lambda r: {"source_id": str(r["source_id"]), "name": r["name"]})


def create_brand(ctx: Ctx, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    name = need_text(body_dict(body), "display_name")
    try:
        row = ctx.conn.execute("INSERT INTO consentvault.brand (org_id, display_name, created_by)"
                               " VALUES ((SELECT consentvault.current_org()), %s, %s) RETURNING brand_id, created_at",
                               (name, ctx.actor.member_uuid)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("brand_exists", "a brand with that display name already exists") from None
    ctx.audit("brand.created", "brand", str(row["brand_id"]))
    return {"brand_id": str(row["brand_id"]), "display_name": name, "created_at": iso(row["created_at"])}


# ======================================================================================================================
# Capture sources
# ======================================================================================================================
def _check_brands(ctx: Ctx, brand_ids: list) -> list[uuid.UUID]:
    ids = []
    for b in brand_ids:
        try:
            ids.append(uuid.UUID(str(b)))
        except ValueError:
            raise ApiError("unknown_brand", "a brand id does not belong to this organization") from None
    ids = sorted(set(ids))
    n = ctx.conn.execute("SELECT count(*) AS n FROM consentvault.brand WHERE org_id = (SELECT consentvault.current_org())"
                         " AND brand_id = ANY (%s)", (ids,)).fetchone()["n"]
    if n != len(ids):
        raise ApiError("unknown_brand", "a brand id does not belong to this organization")
    return ids


def _check_origins(kind: str, origins: list) -> list[str]:
    if kind == "server":
        if origins:
            raise invalid(allowed_origins="a server source takes no origins")
        return []
    if not origins:
        raise invalid(allowed_origins="a site key source needs at least one origin")
    out = []
    for o in origins:
        if not isinstance(o, str) or not _ORIGIN.match(o):
            raise ApiError("invalid_origin", "an allowed origin must be scheme://host[:port] with no path",
                           {"allowed_origins": str(o)[:200]})
        out.append(o.lower())
    return sorted(set(out))


def _source_obj(row: dict, last: Optional[dict]) -> dict:
    return {"source_id": str(row["source_id"]), "name": row["name"], "kind": row["kind"],
            "brand_ids": [str(b) for b in row["brand_ids"]], "allowed_origins": list(row["allowed_origins"]),
            "status": row["status"], "created_at": iso(row["created_at"]),
            "last_event_at": iso(last["last_event_at"]) if last else None,
            "last_event_seq": last["last_event_seq"] if last else None,
            "last_event_sealed": last["last_event_sealed"] if last else None}


def _last_events(ctx: Ctx) -> dict:
    return {r["source_id"]: r for r in ctx.conn.execute("SELECT * FROM consentvault.source_last_events()").fetchall()}


def list_sources(ctx: Ctx, *, brand_id=None, status=None, kind=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    where, params = ["s.org_id = (SELECT consentvault.current_org())"], []
    if brand_id:
        where.append("%s = ANY (s.brand_ids)")
        params.append(to_uuid(brand_id, "brand"))
    if status:
        where.append("s.status = %s")
        params.append(want_enum(status, "status", ("active", "retired")))
    if kind:
        where.append("s.kind = %s")
        params.append(want_enum(kind, "kind", ("site_key", "server")))
    sql = ("SELECT s.*, s.created_at AS _k1, s.source_id::text AS _k2 FROM consentvault.capture_source s WHERE "
           + " AND ".join(where))
    last = _last_events(ctx)
    return paginate(ctx, endpoint="GET /v1/sources", select_sql=sql, params=params, key_cols=("_k1", "_k2"),
                    key_types=("timestamptz", "text"), descending=True, limit=limit, cursor=cursor,
                    shape=lambda r: _source_obj(r, last.get(r["source_id"])))


def get_source(ctx: Ctx, source_id) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    row = ctx.conn.execute("SELECT * FROM consentvault.capture_source WHERE org_id = (SELECT consentvault.current_org())"
                           " AND source_id = %s", (to_uuid(source_id, "source"),)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such source in this organization")
    return _source_obj(row, _last_events(ctx).get(row["source_id"]))


def create_source(ctx: Ctx, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    b = body_dict(body)
    name = need_text(b, "name")
    kind = want_enum(b.get("kind"), "kind", ("site_key", "server"))
    brand_ids = _check_brands(ctx, need_list(b, "brand_ids", min_items=1, max_items=100))
    origins = _check_origins(kind, need_list(b, "allowed_origins", max_items=50) if "allowed_origins" in b else [])
    try:
        row = ctx.conn.execute(
            "INSERT INTO consentvault.capture_source (org_id, name, kind, brand_ids, allowed_origins, created_by)"
            " VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s) RETURNING *",
            (name, kind, brand_ids, origins, ctx.actor.member_uuid)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("source_exists", "a source with that name already exists") from None
    ctx.audit("source.created", "source", str(row["source_id"]))
    return _source_obj(row, None)


def update_source(ctx: Ctx, source_id, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    b = body_dict(body)
    sid = to_uuid(source_id, "source")
    cur = ctx.conn.execute("SELECT * FROM consentvault.capture_source WHERE org_id = (SELECT consentvault.current_org())"
                           " AND source_id = %s FOR UPDATE", (sid,)).fetchone()
    if cur is None:
        raise ApiError("not_found", "no such source in this organization")
    if cur["status"] == "retired":
        raise invalid(status="a retired source does not change")
    name = need_text(b, "name") if "name" in b else cur["name"]
    brand_ids = _check_brands(ctx, need_list(b, "brand_ids", min_items=1, max_items=100)) if "brand_ids" in b \
        else list(cur["brand_ids"])
    origins = _check_origins(cur["kind"], need_list(b, "allowed_origins", max_items=50)) if "allowed_origins" in b \
        else list(cur["allowed_origins"])
    status = cur["status"]
    if "status" in b:
        status = want_enum(b["status"], "status", ("retired",))
    try:
        row = ctx.conn.execute(
            "UPDATE consentvault.capture_source SET name = %s, brand_ids = %s, allowed_origins = %s, status = %s,"
            " retired_at = CASE WHEN %s = 'retired' THEN clock_timestamp() ELSE retired_at END"
            " WHERE org_id = (SELECT consentvault.current_org()) AND source_id = %s RETURNING *",
            (name, brand_ids, origins, status, status, sid)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("source_exists", "a source with that name already exists") from None
    ctx.audit("source.updated", "source", str(sid), "retired" if status == "retired" else None)
    return _source_obj(row, _last_events(ctx).get(sid))


# ======================================================================================================================
# Field maps (where a form puts its fields): versions are added, never edited
# ======================================================================================================================
MAP_BODY_FORMATS = ("json", "form_urlencoded", "multipart", "text")
MAP_CONTACT_KINDS = ("phone", "email")
_MAP_PATH_FIELDS = ("decision_time_path", "wording_path", "wording_hash_path", "form_version_path", "checkbox_default_path",
                    "submit_context_path", "third_party_cert_path", "jurisdiction_path", "channel_scope_path")
_MAP_KEYS = {"body_format", "consent_paths", "consent_ticked_value", "contact_paths", "seller_paths", *_MAP_PATH_FIELDS}


def _map_path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 500:
        raise invalid(**{name: "a path is text of 1 to 500 characters"})
    return value


def _map_paths(b: dict, name: str, *, required: bool) -> Optional[list[str]]:
    if b.get(name) is None and not required:
        return None
    return [_map_path(v, name) for v in need_list(b, name, min_items=1 if required else 0, max_items=50)]


def _field_map_obj(r: dict) -> dict:
    out = {"source_id": str(r["source_id"]) if r["source_id"] else None, "map_version": r["map_version"],
           "body_format": r["body_format"], "consent_paths": list(r["consent_paths"]),
           "consent_ticked_value": r["consent_ticked_value"], "seller_paths": list(r["seller_paths"]) if r["seller_paths"] is not None else None,
           "contact_paths": [{"path": c["path"], "kind": c.get("kind", "detect")} for c in (r["contact_paths"] or [])],
           "set_by": r["set_by"], "set_at": iso(r["set_at"])}
    for f in _MAP_PATH_FIELDS:
        out[f] = r[f]
    return out


def _built_in_widget_map() -> dict:
    from .. import extract
    w = extract.WIDGET_MAP
    out = {"label": w.label, "body_format": w.body_format, "consent_paths": list(w.consent_paths),
           "consent_ticked_value": w.consent_ticked_value, "seller_paths": list(w.seller_paths) or None,
           "contact_paths": [{"path": p, "kind": k} for p, k in w.contact_paths]}
    for f in _MAP_PATH_FIELDS:
        out[f] = getattr(w, f)
    return out


def _source_exists(ctx: Ctx, source_id) -> uuid.UUID:
    sid = to_uuid(source_id, "source")
    if ctx.conn.execute("SELECT 1 FROM consentvault.capture_source WHERE org_id = (SELECT consentvault.current_org())"
                        " AND source_id = %s", (sid,)).fetchone() is None:
        raise ApiError("not_found", "no such source in this organization")
    return sid


def list_field_maps(ctx: Ctx, source_id) -> dict:
    """GET /v1/sources/{id}/field-maps: every stored version, newest first, with who set it and when, and the vault's built-in
    map for the widget (the map in force for a widget post when a source has no version of its own)."""
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    sid = _source_exists(ctx, source_id)
    rows = ctx.conn.execute("SELECT * FROM consentvault.form_field_map WHERE org_id = (SELECT consentvault.current_org())"
                            " AND source_id = %s ORDER BY map_version DESC", (sid,)).fetchall()
    return {"items": [_field_map_obj(r) for r in rows], "built_in": _built_in_widget_map()}


def add_field_map(ctx: Ctx, source_id, body: Any) -> dict:
    """POST /v1/sources/{id}/field-maps: a new version. An old version is never edited; the version number, the member who set
    it and the time are stated by the vault, never by the caller."""
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    b = body_dict(body)
    unknown = sorted(set(b) - _MAP_KEYS)
    if unknown:
        raise invalid(**{k: "not a field map setting" for k in unknown})
    sid = _active_source(ctx, source_id)
    fmt = want_enum(b.get("body_format"), "body_format", MAP_BODY_FORMATS)
    consent = _map_paths(b, "consent_paths", required=True)
    ticked = b.get("consent_ticked_value")
    if ticked is not None and (not isinstance(ticked, str) or len(ticked) > 200):
        raise invalid(consent_ticked_value="text of up to 200 characters")
    contacts = []
    for c in need_list(b, "contact_paths", max_items=20) if "contact_paths" in b else []:
        if not isinstance(c, dict):
            raise invalid(contact_paths="each is an object with a path and a kind")
        contacts.append((_map_path(c.get("path"), "contact_paths"), want_enum(c.get("kind"), "contact_paths", MAP_CONTACT_KINDS)))
    paths: dict[str, Any] = {}
    for f in _MAP_PATH_FIELDS:
        if b.get(f) is not None:
            paths[f] = _map_path(b[f], f)
    sellers = _map_paths(b, "seller_paths", required=False)
    if sellers is not None:
        paths["seller_paths"] = sellers
    ctx.conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"form_field_map:{sid}",))
    from .. import extract
    version = extract.add_field_map(ctx.conn, set_by=ctx.actor.id, source_id=sid, body_format=fmt, consent_paths=consent,
                                    consent_ticked_value=ticked, contact_paths=contacts, **paths)
    ctx.audit("field_map.added", "source", str(sid), f"version {version}")
    row = ctx.conn.execute("SELECT * FROM consentvault.form_field_map WHERE org_id = (SELECT consentvault.current_org())"
                           " AND source_id = %s AND map_version = %s", (sid, version)).fetchone()
    return _field_map_obj(row)


# ======================================================================================================================
# Credentials
# ======================================================================================================================
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
CLIENT_SCOPES = ("capture", "gate_read", "proof_read")
KINDS = ("edge_site_key", "jwt_public_key", "hmac_fallback")


def _public_key_ok(pem: str, algorithm: str) -> None:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, UnsupportedAlgorithm):
        raise invalid(public_key="not a public key in PEM form") from None
    if algorithm == "ES256" and not (isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"):
        raise invalid(public_key="ES256 needs a P-256 public key")
    if algorithm == "EdDSA" and not isinstance(key, ed25519.Ed25519PublicKey):
        raise invalid(public_key="EdDSA needs an Ed25519 public key")


def _active_source(ctx: Ctx, source_id) -> uuid.UUID:
    sid = to_uuid(source_id, "source")
    row = ctx.conn.execute("SELECT status FROM consentvault.capture_source WHERE org_id = (SELECT consentvault.current_org())"
                           " AND source_id = %s", (sid,)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such source in this organization")
    if row["status"] != "active":
        raise invalid(source_id="that source is retired")
    return sid


def _issue(ctx: Ctx, *, name, kind, scope, source_id, public_key, algorithm, custody) -> dict:
    name = need_text({"name": name}, "name")
    want_enum(kind, "kind", KINDS)
    org = ctx.org_id()
    sid = _active_source(ctx, source_id) if source_id is not None else None
    alg = None
    pem = None
    secret_ct = None
    secret_hex = None
    site_key = None
    if kind == "edge_site_key":
        if scope != "capture":
            raise invalid(scope="an edge site key is a capture credential")
        if sid is None:
            raise invalid(source_id="required for an edge site key")
        site_key = "cv_site_" + secrets.token_urlsafe(18)
    elif kind == "jwt_public_key":
        if not isinstance(public_key, str) or not public_key.strip():
            raise invalid(public_key="required, in PEM form")
        if _PRIVATE_KEY.search(public_key):
            # never stored, never echoed: the caller must treat that key as exposed
            raise ApiError("private_key_refused", "the pasted material contains a private key; treat that key as exposed")
        alg = want_enum(algorithm, "algorithm", ("ES256", "EdDSA"))
        _public_key_ok(public_key, alg)
        pem = public_key.strip()
        if scope in ("capture", "capture_verified") and sid is None:
            raise invalid(source_id="required for a capture credential")
    else:  # hmac_fallback
        if sid is None:
            raise invalid(source_id="required for an HMAC fallback credential")
        if custody is None:
            raise ApiError("key_unavailable", "no key provider is configured; nothing was written")
        raw = secrets.token_bytes(32)
        try:
            secret_ct = custody.wrap(str(org), raw)
        except CustodyError as exc:
            raise _custody_error(exc) from exc
        secret_hex = raw.hex()
    row = ctx.conn.execute(
        "INSERT INTO consentvault.credential (org_id, name, source_id, kind, alg, public_key, secret_ct, scope, created_by,"
        " site_key_id, site_key_hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING credential_id, created_at",
        (org, name, sid, kind, alg, pem, secret_ct, [scope], ctx.actor.member_uuid, site_key,
         site_keys.hash_site_key(site_key) if site_key else None)).fetchone()
    cid = str(row["credential_id"])
    ctx.audit("credential.issued", "credential", cid, scope)
    out = {"credential_id": cid, "name": name, "kind": kind, "scope": scope,
           "source_id": str(sid) if sid else None, "algorithm": alg, "created_at": iso(row["created_at"]),
           "shown_once": secret_hex is not None}
    if kind in ("jwt_public_key", "hmac_fallback"):
        out["client_id"] = cid
    if site_key:
        out["site_key_id"] = site_key
    if secret_hex:
        out["secret"] = secret_hex
    return out


def issue_credential(ctx: Ctx, body: Any, *, custody=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    b = body_dict(body)
    scope = b.get("scope")
    if scope == "capture_verified":
        raise ApiError("role_not_allowed", "a verified-contact credential is issued by the operator only",
                       {"role": ctx.actor.role})
    want_enum(scope, "scope", CLIENT_SCOPES)
    if scope != "capture" and ctx.actor.role != ROLE_ADMIN:
        raise ApiError("role_not_allowed", "only an admin issues read credentials", {"role": ctx.actor.role})
    require_can_add(ctx)
    if scope == "gate_read" and ctx.conn.execute(
            "SELECT 1 FROM consentvault.policy WHERE org_id = (SELECT consentvault.current_org()) AND status = 'approved'"
    ).fetchone() is None:
        raise ApiError("policy_required", "a gate credential needs an approved policy in force first")
    return _issue(ctx, name=b.get("name"), kind=b.get("kind"), scope=scope, source_id=b.get("source_id"),
                  public_key=b.get("public_key"), algorithm=b.get("algorithm"),
                  custody=custody if custody is not None else ctx.custody)


def _credential_obj(r: dict) -> dict:
    return {"credential_id": str(r["credential_id"]), "name": r["name"], "kind": r["kind"],
            "scope": r["scope"][0] if r["scope"] else None, "source_id": str(r["source_id"]) if r["source_id"] else None,
            "algorithm": r["alg"], "created_by": str(r["created_by"]) if r["created_by"] else None,
            "created_at": iso(r["created_at"]), "revoked_at": iso(r["revoked_at"]), "last_used_at": iso(r["last_used_at"])}


def list_credentials(ctx: Ctx, *, source_id=None, kind=None, scope=None, status=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    where, params = ["c.org_id = (SELECT consentvault.current_org())"], []
    if ctx.actor.role == ROLE_DEVELOPER:
        where.append("c.scope = ARRAY['capture']::text[]")
    if source_id:
        where.append("c.source_id = %s")
        params.append(to_uuid(source_id, "source"))
    if kind:
        where.append("c.kind = %s")
        params.append(want_enum(kind, "kind", KINDS))
    if scope:
        where.append("%s = ANY (c.scope)")
        params.append(want_enum(scope, "scope", CLIENT_SCOPES + ("capture_verified",)))
    if status:
        want_enum(status, "status", ("active", "revoked"))
        where.append("c.revoked_at IS NOT NULL" if status == "revoked" else "c.revoked_at IS NULL")
    cols = ("c.credential_id, c.name, c.kind, c.scope, c.source_id, c.alg, c.created_by, c.created_at, c.revoked_at,"
            " c.last_used_at, c.created_at AS _k1, c.credential_id::text AS _k2")
    return paginate(ctx, endpoint="GET /v1/credentials",
                    select_sql=f"SELECT {cols} FROM consentvault.credential c WHERE " + " AND ".join(where),
                    params=params, key_cols=("_k1", "_k2"), key_types=("timestamptz", "text"), descending=True,
                    limit=limit, cursor=cursor, shape=_credential_obj)


def revoke_credential(ctx: Ctx, credential_id, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    reason = need_text(body_dict(body), "reason", max_len=500)
    cid = to_uuid(credential_id, "credential")
    cur = ctx.conn.execute("SELECT scope, created_by, created_at, revoked_at FROM consentvault.credential"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND credential_id = %s FOR UPDATE",
                           (cid,)).fetchone()
    if cur is None:
        raise ApiError("not_found", "no such credential in this organization")
    if ctx.actor.role == ROLE_DEVELOPER and (cur["created_by"] != ctx.actor.member_uuid or cur["scope"] != ["capture"]):
        raise ApiError("role_not_allowed", "a developer revokes only the capture credentials it issued", {"role": ctx.actor.role})
    if cur["revoked_at"] is not None:
        raise ApiError("already_revoked", "the credential is already revoked")
    row = ctx.conn.execute("UPDATE consentvault.credential SET revoked_at = clock_timestamp(), revoked_by = %s, revoke_reason = %s"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND credential_id = %s RETURNING revoked_at",
                           (ctx.actor.member_uuid, reason, cid)).fetchone()
    ctx.audit("credential.revoked", "credential", str(cid), reason)
    return {"credential_id": str(cid), "created_at": iso(cur["created_at"]), "revoked_at": iso(row["revoked_at"])}


# ======================================================================================================================
# Retention
# ======================================================================================================================
def _retention_obj(r: dict) -> dict:
    return {"version": r["version"], "evidence_years": r["evidence_years"], "applies_from": iso(r["applies_from"]),
            "set_by": str(r["set_by"]) if r["set_by"] else None}


def get_retention(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_VIEWER)
    cur = ctx.conn.execute("SELECT * FROM consentvault.retention_policy WHERE org_id = (SELECT consentvault.current_org())"
                           " ORDER BY version DESC LIMIT 1").fetchone()
    page = paginate(ctx, endpoint="GET /v1/retention",
                    select_sql=("SELECT *, version AS _k1, version::text AS _k2 FROM consentvault.retention_policy"
                                " WHERE org_id = (SELECT consentvault.current_org())"),
                    params=[], key_cols=("_k1", "_k2"), key_types=("integer", "text"), descending=True, limit=limit,
                    cursor=cursor, shape=_retention_obj)
    return {"current": _retention_obj(cur) if cur else None,
            "platform_minimum_years": PLATFORM_MINIMUM_RETENTION_YEARS, **page}


def put_retention(ctx: Ctx, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    years = b.get("evidence_years")
    if isinstance(years, bool) or not isinstance(years, int) or years < 1 or years > 100:
        raise invalid(evidence_years="a whole number of years from 1 to 100")
    reason = need_text(b, "reason", max_len=500)
    if years < PLATFORM_MINIMUM_RETENTION_YEARS:
        raise ApiError("below_platform_minimum", f"retention cannot be below the platform minimum of "
                                                 f"{PLATFORM_MINIMUM_RETENTION_YEARS} years")
    ctx.conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.retention:' || (SELECT consentvault.current_org())::text))")
    row = ctx.conn.execute(
        "INSERT INTO consentvault.retention_policy (org_id, version, evidence_years, platform_minimum_years, reason, set_by)"
        " SELECT o, coalesce((SELECT max(version) FROM consentvault.retention_policy WHERE org_id = o), 0) + 1, %s, %s, %s, %s"
        " FROM (SELECT (SELECT consentvault.current_org()) AS o) x RETURNING version, evidence_years, applies_from",
        (years, PLATFORM_MINIMUM_RETENTION_YEARS, reason, ctx.actor.member_uuid)).fetchone()
    ctx.audit("retention.set", "retention", str(row["version"]), reason)
    return {"version": row["version"], "evidence_years": row["evidence_years"], "applies_from": iso(row["applies_from"])}


# WorkOS ids are a prefix and a 26-character ULID (Crockford base32, upper case); anything else can never match a sign-in
_CONNECTION_ID = re.compile(r"conn_[0-9A-HJKMNP-TV-Z]{26}")
_WORKOS_ORG_ID = re.compile(r"org_[0-9A-HJKMNP-TV-Z]{26}")


def _sso_lock(conn: psycopg.Connection) -> None:
    conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.sso:' || (SELECT consentvault.current_org())::text))")


def _require_entered_org(conn: psycopg.Connection) -> None:
    if conn.execute("SELECT 1 FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())").fetchone() is None:
        raise ApiError("not_found", "no such organization")


def _open_lifted_alarm(conn: psycopg.Connection) -> None:
    conn.execute("INSERT INTO consentvault.org_alarm (org_id, kind, detail) VALUES ((SELECT consentvault.current_org()),"
                 " 'sso.required_lifted', '{}'::jsonb)")


def put_sso(ctx: Ctx, body: Any) -> dict:
    """Turn the company sign-in requirement on or off. Admin only. The admin never names a connection: the operator bound it.
    Turning it on needs a binding an admin has proved by signing in through it, and the admin must be signed in through it too
    (otherwise turning it on would lock the admin out of their own organization)."""
    from .session import current_sso, write_sso
    from .tokens import token_sso
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    unknown = sorted(set(b) - {"require_sso"})
    if unknown:
        raise invalid(**{u: "not accepted: the connection is bound by your operator" for u in unknown})
    required = b.get("require_sso")
    if not isinstance(required, bool):
        raise invalid(require_sso="true or false")
    _sso_lock(ctx.conn)
    now = current_sso(ctx.conn)
    if required:
        entered = ctx.conn.execute("SELECT nullif(pg_catalog.current_setting('consentvault.org_token', true), '') AS t").fetchone()["t"]
        if not now["verified"] or token_sso(entered) not in now["bound_connections"]:
            raise invalid(require_sso="sign in through your company account as an admin first; that proves the connection is yours, "
                                      "and keeps you from locking yourself out")
    row = write_sso(ctx.conn, require_sso=required, set_by=ctx.actor.member_uuid)
    ctx.audit("sso.updated", "org_sso", str(row["version"]), "required for every member" if required else "not required")
    if required:  # an operator's break-glass notice is answered
        ctx.conn.execute("SELECT consentvault.org_alarm_clear('sso.required_lifted')")
    return {"version": row["version"], "required": row["require_sso"], "verified": row["verified"],
            "connection_id": row["connection_id"], "applies_from": iso(row["applies_from"])}


def bind_sso(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id: Any, body: Any) -> dict:
    """PUT /v1/orgs/{id}/sso-binding (operator): bind the sign-in service's organization and its connections to this
    organization. A new binding is unproved and not required, and ends every session that came through the old one."""
    from .session import current_sso, write_sso
    b = body_dict(body)
    unknown = sorted(set(b) - {"workos_organization_id", "connection_ids"})
    if unknown:
        raise invalid(**{u: "unknown field" for u in unknown})
    wos, conns = b.get("workos_organization_id"), b.get("connection_ids")
    if not isinstance(wos, str) or not _WORKOS_ORG_ID.fullmatch(wos):
        raise invalid(workos_organization_id="the sign-in service's organization id, like org_01E4ZCR3C56J083X43JQXF3JK5")
    if not isinstance(conns, list) or not conns or not all(isinstance(c, str) and _CONNECTION_ID.fullmatch(c) for c in conns):
        raise invalid(connection_ids="one or more connection ids, like conn_01E4ZCR3C56J083X43JQXF3JK5")
    oid = to_uuid(org_id, "organization")
    token = mint_org_token(token_key, oid, ["admin"], credential_id=None, ttl_seconds=120)
    with org_transaction(conn, token):
        _require_entered_org(conn)
        _sso_lock(conn)
        try:
            conn.execute("SELECT consentvault.sso_binding_check(%s)", (wos,))
        except psycopg.errors.UniqueViolation:
            raise ApiError("sso_binding_taken", "that sign-in-service organization is already bound to another organization") from None
        lifted = current_sso(conn)["required"]
        row = write_sso(conn, workos_org_id=wos, bound_connections=sorted(set(conns)), connection_id=None, verified=False,
                        require_sso=False, set_by_operator=operator_id)
        if lifted:
            _open_lifted_alarm(conn)
        ctx = _operator_ctx(conn, operator_id, request_id)
        ctx.audit("sso.bound", "org_sso", str(row["version"]), f"{wos}: {len(set(conns))} connection(s)")
        audit.append_platform(conn, operator_id=operator_id, action="sso.bound", target_kind="org", target_id=str(oid),
                              reason=f"{wos}", request_id=request_id)
    return {"version": row["version"], "workos_organization_id": wos, "connection_ids": row["bound_connections"],
            "verified": False, "required": False}


def unbind_sso(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id: Any) -> dict:
    """DELETE /v1/orgs/{id}/sso-binding (operator): no company sign-in; the requirement is lifted with it."""
    from .session import current_sso, write_sso
    oid = to_uuid(org_id, "organization")
    token = mint_org_token(token_key, oid, ["admin"], credential_id=None, ttl_seconds=120)
    with org_transaction(conn, token):
        _require_entered_org(conn)
        _sso_lock(conn)
        lifted = current_sso(conn)["required"]
        conn.execute("SELECT consentvault.org_alarm_clear('sso.required_lifted')")  # an earlier break-glass notice is answered
        row = write_sso(conn, workos_org_id=None, bound_connections=[], connection_id=None, verified=False, require_sso=False,
                        set_by_operator=operator_id)
        if lifted:
            _open_lifted_alarm(conn)
        ctx = _operator_ctx(conn, operator_id, request_id)
        ctx.audit("sso.unbound", "org_sso", str(row["version"]), "company sign-in removed")
        audit.append_platform(conn, operator_id=operator_id, action="sso.unbound", target_kind="org", target_id=str(oid),
                              reason="company sign-in removed", request_id=request_id)
    return {"version": row["version"], "verified": False, "required": False}


def sso_break_glass(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id: Any, body: Any) -> dict:
    """POST /v1/orgs/{id}/sso:break-glass (operator): the identity provider is down and members cannot sign in, so turn the
    requirement off. The binding and its proof stay. The organization's admins are told through the overview alarm list."""
    from .session import current_sso, write_sso
    b = body_dict(body)
    reason = b.get("reason")
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise invalid(reason="required, 1 to 500 characters")
    oid = to_uuid(org_id, "organization")
    token = mint_org_token(token_key, oid, ["admin"], credential_id=None, ttl_seconds=120)
    with org_transaction(conn, token):
        _require_entered_org(conn)
        _sso_lock(conn)
        if not current_sso(conn)["required"]:
            raise invalid(org_id="this organization does not require company sign-in; there is nothing to lift")
        row = write_sso(conn, require_sso=False, set_by_operator=operator_id)
        _open_lifted_alarm(conn)
        ctx = _operator_ctx(conn, operator_id, request_id)
        ctx.audit("sso.break_glass", "org_sso", str(row["version"]), reason.strip())
        audit.append_platform(conn, operator_id=operator_id, action="sso.break_glass", target_kind="org", target_id=str(oid),
                              reason=reason.strip(), request_id=request_id)
    return {"version": row["version"], "required": False, "verified": row["verified"]}


# ======================================================================================================================
# Members and invitations
# ======================================================================================================================
def list_members(ctx: Ctx, *, include=None, role=None, status=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    if role:
        want_enum(role, "role", CLIENT_ROLES)
    if status:
        want_enum(status, "status", ("active", "invited"))
    if include not in (None, "", "invites"):
        raise invalid(include="only 'invites' is accepted")
    want_members = status != "invited"
    want_invites = include == "invites" or status == "invited"
    parts = []
    params: list = []
    if want_members:
        parts.append("SELECT 'member' AS kind, m.member_id AS id, m.display_name, m.email_norm AS email, m.role,"
                     " 'active' AS status, m.created_at, m.last_sign_in_at, NULL::timestamptz AS expires_at,"
                     " (SELECT i.display_name FROM consentvault.member i WHERE i.org_id = m.org_id AND i.member_id = m.invited_by)"
                     " AS invited_by_name FROM consentvault.member m WHERE m.org_id = (SELECT consentvault.current_org())"
                     + (" AND m.role = %s" if role else ""))
        if role:
            params.append(role)
    if want_invites:
        parts.append("SELECT 'invite' AS kind, v.invite_id AS id, NULL::text AS display_name, v.email_norm AS email, v.role,"
                     " 'invited' AS status, v.created_at, NULL::timestamptz AS last_sign_in_at, v.expires_at,"
                     " coalesce((SELECT i.display_name FROM consentvault.member i WHERE i.org_id = v.org_id AND i.member_id = v.invited_by),"
                     " 'ConsentVault') AS invited_by_name FROM consentvault.invite v WHERE v.org_id = (SELECT consentvault.current_org())"
                     " AND v.accepted_at IS NULL AND v.withdrawn_at IS NULL AND v.expires_at > now()"
                     + (" AND v.role = %s" if role else ""))
        if role:
            params.append(role)
    sql = ("SELECT u.*, u.created_at AS _k1, u.id::text AS _k2 FROM (" + " UNION ALL ".join(parts) + ") u")
    return paginate(ctx, endpoint="GET /v1/members", select_sql=sql, params=params, key_cols=("_k1", "_k2"),
                    key_types=("timestamptz", "text"), descending=True, limit=limit, cursor=cursor,
                    shape=lambda r: {"kind": r["kind"], "id": str(r["id"]), "display_name": r["display_name"],
                                     "email": r["email"], "role": r["role"], "status": r["status"],
                                     "created_at": iso(r["created_at"]), "last_sign_in_at": iso(r["last_sign_in_at"]),
                                     "expires_at": iso(r["expires_at"]), "invited_by_name": r["invited_by_name"]})


def invite_member(ctx: Ctx, body: Any, *, mailer=None) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    require_not_closed(ctx)
    out = invite_mod.create(ctx, email=b.get("email"), role=b.get("role"), mailer=mailer)
    return {"invite_id": out["invite_id"], "email": out["email"], "role": out["role"], "expires_at": out["expires_at"]}


def _last_admin(exc: psycopg.Error) -> bool:
    return isinstance(exc, psycopg.errors.IntegrityConstraintViolation) and text_has(exc, "last_admin")


def change_role(ctx: Ctx, member_id, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    role = want_enum(body_dict(body).get("role"), "role", CLIENT_ROLES)
    mid = to_uuid(member_id, "member")
    try:
        row = ctx.conn.execute("UPDATE consentvault.member SET role = %s WHERE org_id = (SELECT consentvault.current_org())"
                               " AND member_id = %s RETURNING member_id, role", (role, mid)).fetchone()
    except psycopg.errors.IntegrityConstraintViolation as exc:
        if _last_admin(exc):
            raise ApiError("last_admin", "the change would leave the organization with no admin") from None
        raise
    if row is None:
        raise ApiError("not_found", "no such member in this organization")
    ctx.audit("member.role_changed", "member", str(mid), role)
    return {"member_id": str(mid), "role": role}


def remove_member(ctx: Ctx, member_id) -> None:
    ctx.actor.require(ROLE_ADMIN)
    mid = to_uuid(member_id, "member")
    try:
        row = ctx.conn.execute("DELETE FROM consentvault.member WHERE org_id = (SELECT consentvault.current_org())"
                               " AND member_id = %s RETURNING member_id", (mid,)).fetchone()
    except psycopg.errors.IntegrityConstraintViolation as exc:
        if _last_admin(exc):
            raise ApiError("last_admin", "the change would leave the organization with no admin") from None
        raise
    if row is None:
        raise ApiError("not_found", "no such member in this organization")
    ctx.audit("member.removed", "member", str(mid))


def withdraw_invite(ctx: Ctx, invite_id) -> None:
    invite_mod.withdraw(ctx, invite_id)


# ======================================================================================================================
# Audit read
# ======================================================================================================================
def list_audit(ctx: Ctx, *, action=None, actor=None, target_kind=None, from_=None, to=None, limit=None,
               cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_VIEWER)
    where, params = ["a.org_id = (SELECT consentvault.current_org())"], []
    if action:
        want_enum(action, "action", audit.ACTIONS)
        where.append("a.action = %s")
        params.append(action)
    if actor:
        where.append("a.actor_id = %s")
        params.append(str(actor))
    if target_kind:
        where.append("a.target_kind = %s")
        params.append(str(target_kind))
    t_from = t_to = None
    if from_:
        t_from = need_time_param(from_, "from")
        where.append("a.at >= %s")
        params.append(t_from)
    if to:
        t_to = need_time_param(to, "to")
        where.append("a.at <= %s")
        params.append(t_to)
    if t_from and t_to and t_from > t_to:
        raise invalid(**{"from": "later than to"})
    sql = ("SELECT a.audit_id, a.at, a.action, a.actor_kind, a.actor_id, a.target_kind, a.target_id, a.reason, a.request_id, a.detail,"
           " (SELECT m.display_name FROM consentvault.member m WHERE m.org_id = a.org_id AND a.actor_kind = 'member'"
           "  AND m.member_id::text = a.actor_id) AS actor_name, a.at AS _k1, a.audit_id::text AS _k2"
           " FROM consentvault.audit_event a WHERE " + " AND ".join(where))
    return paginate(ctx, endpoint="GET /v1/audit", select_sql=sql, params=params, key_cols=("_k1", "_k2"),
                    key_types=("timestamptz", "text"), descending=True, limit=limit, cursor=cursor,
                    shape=lambda r: {"audit_id": str(r["audit_id"]), "at": iso(r["at"]), "action": r["action"],
                                     "actor": {"kind": r["actor_kind"], "id": r["actor_id"], "display_name": r["actor_name"]},
                                     "target": {"kind": r["target_kind"], "id": r["target_id"]},
                                     "reason": r["reason"], "request_id": r["request_id"],
                                     **({"detail": r["detail"]} if r["detail"] is not None else {})})


def need_time_param(value: str, name: str):
    from .admin_base import need_iso_time
    return need_iso_time({name: value}, name)


def list_audit_actions(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_VIEWER)
    rows = sorted(audit.ACTIONS.items(), key=lambda kv: (kv[1], kv[0]))
    return page_list(ctx, endpoint="GET /v1/audit/actions", rows=rows, key=lambda kv: kv[0], limit=limit, cursor=cursor,
                     shape=lambda kv: {"action": kv[0], "label": kv[1]})


# ======================================================================================================================
# Connected systems (registration; deliveries, test push and redrive belong to the sync lane)
# ======================================================================================================================
SYSTEM_KINDS = ("crm", "dialer", "sms", "email", "ai_agent", "webhook")


def _system_obj(r: dict) -> dict:
    return {"system_id": str(r["system_id"]), "name": r["name"], "kind": r["kind"], "connector": r["connector"],
            "endpoint": r["endpoint"], "signature": r["signature"], "contact_form": r["contact_form"],
            "retry_window_hours": r["retry_window_hours"], "status": r["status"], "public_key": r["public_key"],
            "created_at": iso(r["created_at"]), "last_delivery_at": iso(r.get("last_delivery_at")), "counts": None,
            "last_test": r.get("last_test"), "partial": ["counts"]}


_UNBIND = "unbind"


def _signal_credential(b: dict):
    """The optional ``signal_credential_id``: the capture credential this system's signals arrive on. ``null`` (edit
    only) clears it back to none; absent leaves it as it is."""
    if "signal_credential_id" not in b:
        return None
    if b["signal_credential_id"] is None:
        return _UNBIND
    try:
        return to_uuid(b["signal_credential_id"], "signal credential")
    except ApiError:
        raise invalid(signal_credential_id="the id of a live capture credential of this organization") from None


def _bind_signal(ctx: Ctx, system_id, credential_id: uuid.UUID | None) -> None:
    """Bind the system's signal credential through the sync lane's one door (``bind_signal_credential``)."""
    if credential_id is None:
        return
    from ..sync.errors import SystemNotFoundError
    from ..sync.systems import bind_signal_credential, unbind_signal_credential
    if credential_id == _UNBIND:
        try:
            was = unbind_signal_credential(ctx.conn, system_id)
        except SystemNotFoundError:
            raise ApiError("not_found", "no such connected system in this organization") from None
        ctx.audit("system.signal_unbound", "system", str(system_id),
                  f"signal credential {was} unbound" if was else "no signal credential was bound")
        return
    try:
        bind_signal_credential(ctx.conn, system_id, credential_id)
    except SystemNotFoundError:
        raise invalid(signal_credential_id="a live capture credential of this organization that no other system"
                                           " already carries") from None
    ctx.audit("system.signal_bound", "system", str(system_id), f"signal credential {credential_id} bound")


def _check_endpoint(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2000 or re.search(r"\s", value):
        raise invalid(endpoint="required web address")
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ApiError("endpoint_not_https", "a connected system endpoint must be an https address")
    if not parts.hostname or parts.username or parts.password:
        raise invalid(endpoint="needs a host and no embedded credentials")
    return value


def list_systems(ctx: Ctx, *, kind=None, status=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
    where, params = ["s.org_id = (SELECT consentvault.current_org())", "s.name IS NOT NULL"], []
    if kind:
        where.append("s.kind = %s")
        params.append(want_enum(kind, "kind", SYSTEM_KINDS))
    if status:
        where.append("s.status = %s")
        params.append(want_enum(status, "status", ("active", "paused")))
    cols = ("s.system_id, s.name, s.kind, s.connector, s.endpoint, s.signature, s.contact_form, s.retry_window_hours,"
            " s.status, s.public_key, s.created_at, s.last_delivery_at, s.last_test, lower(s.name) AS _k1, s.system_id::text AS _k2")
    return paginate(ctx, endpoint="GET /v1/systems", select_sql=f"SELECT {cols} FROM consentvault.connected_system s WHERE "
                    + " AND ".join(where), params=params, key_cols=("_k1", "_k2"), key_types=("text", "text"),
                    descending=False, limit=limit, cursor=cursor, shape=_system_obj)


def get_system(ctx: Ctx, system_id) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
    row = ctx.conn.execute(
        "SELECT system_id, name, kind, connector, endpoint, signature, contact_form, retry_window_hours, status, public_key,"
        " created_at, last_delivery_at, last_test FROM consentvault.connected_system WHERE org_id = (SELECT consentvault.current_org())"
        " AND system_id = %s AND name IS NOT NULL", (to_uuid(system_id, "system"),)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such connected system in this organization")
    return _system_obj(row)


def create_system(ctx: Ctx, body: Any, *, custody=None) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    b = body_dict(body)
    require_can_add(ctx)
    name = need_text(b, "name")
    kind = want_enum(b.get("kind"), "kind", SYSTEM_KINDS)
    endpoint = _check_endpoint(b.get("endpoint"))
    scheme = want_enum(b.get("signature"), "signature", ("ed25519", "hmac"))
    contact_form = want_enum(b.get("contact_form"), "contact_form", ("plaintext", "fingerprint"))
    hours = b.get("retry_window_hours", 24)
    if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 168:
        raise invalid(retry_window_hours="a whole number of hours from 1 to 168")
    signal_cred = _signal_credential(b)
    if signal_cred == _UNBIND:
        raise invalid(signal_credential_id="a new system starts with no signal credential; omit the field")
    custody = custody if custody is not None else ctx.custody
    if custody is None:
        raise ApiError("key_unavailable", "no key provider is configured; nothing was written")
    org = ctx.org_id()
    public_pem = None
    shown = None
    try:
        if scheme == "ed25519":
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            priv = ed25519.Ed25519PrivateKey.generate()
            seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
            public_pem = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            credentials_ct = custody.wrap(str(org), seed)
        else:
            raw = secrets.token_bytes(32)
            credentials_ct = custody.wrap(str(org), raw)
            shown = raw.hex()
    except CustodyError as exc:
        raise _custody_error(exc) from exc
    try:
        row = ctx.conn.execute(
            "INSERT INTO consentvault.connected_system (org_id, name, kind, connector, endpoint, signature, contact_form,"
            " retry_window_hours, public_key, credentials_ct, created_by) VALUES (%s, %s, %s, 'generic_webhook', %s, %s,"
            " %s, %s, %s, %s, %s) RETURNING system_id, name, kind, connector, endpoint, signature, contact_form,"
            " retry_window_hours, status, public_key, created_at, last_delivery_at, last_test",
            (org, name, kind, endpoint, scheme, contact_form, hours, public_pem, credentials_ct, ctx.actor.member_uuid)
        ).fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("system_exists", "a connected system with that name already exists") from None
    _bind_signal(ctx, row["system_id"], signal_cred)
    ctx.audit("system.registered", "system", str(row["system_id"]),
              "contact point sent in plaintext" if contact_form == "plaintext" else None)
    out = _system_obj(row)
    if shown:
        out["hmac_secret"] = shown
    return out


def update_system(ctx: Ctx, system_id, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    b = body_dict(body)
    if "signature" in b:
        raise invalid(signature="the signature kind cannot change; connect a new system instead")
    sid = to_uuid(system_id, "system")
    cur = ctx.conn.execute("SELECT name, endpoint, contact_form, retry_window_hours, status FROM consentvault.connected_system"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND system_id = %s AND name IS NOT NULL"
                           " FOR UPDATE", (sid,)).fetchone()
    if cur is None:
        raise ApiError("not_found", "no such connected system in this organization")
    name = need_text(b, "name") if "name" in b else cur["name"]
    endpoint = _check_endpoint(b["endpoint"]) if "endpoint" in b else cur["endpoint"]
    contact_form = want_enum(b["contact_form"], "contact_form", ("plaintext", "fingerprint")) if "contact_form" in b \
        else cur["contact_form"]
    hours = b.get("retry_window_hours", cur["retry_window_hours"])
    if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 168:
        raise invalid(retry_window_hours="a whole number of hours from 1 to 168")
    status = want_enum(b["status"], "status", ("active", "paused")) if "status" in b else cur["status"]
    signal_cred = _signal_credential(b)
    try:
        row = ctx.conn.execute(
            "UPDATE consentvault.connected_system SET name = %s, endpoint = %s, contact_form = %s, retry_window_hours = %s,"
            " status = %s WHERE org_id = (SELECT consentvault.current_org()) AND system_id = %s RETURNING system_id, name,"
            " kind, connector, endpoint, signature, contact_form, retry_window_hours, status, public_key, created_at,"
            " last_delivery_at, last_test", (name, endpoint, contact_form, hours, status, sid)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("system_exists", "a connected system with that name already exists") from None
    _bind_signal(ctx, sid, signal_cred)
    ctx.audit("system.updated", "system", str(sid),
              "contact point sent in plaintext" if contact_form == "plaintext" and cur["contact_form"] != "plaintext" else None)
    return _system_obj(row)


# ======================================================================================================================
# The organisation and its health (session.md)
# ======================================================================================================================
def get_org(ctx: Ctx) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
    o = ctx.conn.execute("SELECT org_id, name, status, region, default_region, created_at FROM consentvault.organization"
                         " WHERE org_id = (SELECT consentvault.current_org())").fetchone()
    if o is None:
        raise ApiError("not_found", "no such organization")
    if ctx.actor.role != ROLE_ADMIN:
        return {"org_id": str(o["org_id"]), "name": o["name"], "status": o["status"], "region": o["region"],
                "default_region": o["default_region"], "role": ctx.actor.role}
    from .session import current_sso
    sso = current_sso(ctx.conn)
    k = ctx.conn.execute("SELECT status, version, destroy_after FROM consentvault.org_key"
                         " WHERE org_id = (SELECT consentvault.current_org()) ORDER BY version DESC LIMIT 1").fetchone()
    return {"org_id": str(o["org_id"]), "name": o["name"], "status": o["status"], "region": o["region"],
            "default_region": o["default_region"], "created_at": iso(o["created_at"]), "plan": None,
            "key": {"status": k["status"], "version": k["version"], "destroy_after": iso(k["destroy_after"])} if k else None,
            "offboarding": None, "trial": {"started_at": iso(o["created_at"])} if o["status"] == "trial" else None,
            "sso": {"connected": bool(sso["bound_connections"]), "connection_id": sso["connection_id"], "required": sso["required"],
                    "verified": sso["verified"]},
            "partial": ["plan", "offboarding"] + ([] if k else ["key"])}


# What a customer reads for each alarm (admin.md, "which alarms a customer sees"). Names are as the code writes them. An alarm
# with no entry here is not shown to customers: usage_* alarms stay with the operator.
NEXT_ACTION = {
    "restore.stops_unconfirmed": "After a restore, some stops were put back without their confirmation. Review them on the evidence "
                                 "lookup page. A stop stays in force; it is lifted only through the normal release rules.",
    "billing.second_live_subscription": "Your organization has two live subscriptions. Cancel the extra one in the billing portal "
                                        "(Manage billing on Stripe).",
    "sso.required_lifted": "An operator turned off the company sign-in requirement because your identity provider could not be reached. "
                           "Passkeys work again. When your provider is back, turn the requirement on again in Company sign-in.",
    "reveal_volume": "Open the audit log, find who revealed them, and check that this was work they meant to do.",
    "sending_account_failing": "Open the confirmation settings, run the account check, and fix the account with your provider. "
                               "Sending resumes when the check passes.",
    "inbound_signature_failures": "Check the webhook secret on your sending account matches the one saved here.",
    "replies_unread_24h": "Open the replies list and read them. A reply may be a request to stop.",
    "delivery_reports_stale": "Check the status-callback address saved with your provider, and send a test message.",
    "link_host_failing": "Check the wording link address in the confirmation settings, and fix the address or your DNS.",
    "optout_reply_dead": "Open the sends list, find the failed stop reply, and check the sending account. The opt-out itself was recorded.",
    "provider_refusal_stop": "Nothing is lost: the stop is on record. Make sure your other systems also honor it.",
    "send_cap_reached": "Wait for the next hour, or raise the limit in the confirmation settings if this is normal volume.",
}


def customer_alarms(ctx: Ctx, out: dict):
    """Open alarms for this role, newest first: [{name, since, count|null, next_action}]. A developer gets none. If a read fails
    the answer is None and ``partial`` names it, never an empty list."""
    if ctx.actor.role not in (ROLE_ADMIN, ROLE_VIEWER):
        return []
    try:
        with ctx.conn.transaction():
            rows = [(r["name"], r["since"], r["count"]) for r in ctx.conn.execute(
                "SELECT name, since, count FROM consentvault.customer_alarm_rows(%s)", (ctx.actor.role == ROLE_ADMIN,)).fetchall()]
            rows += [(r["kind"], r["opened_at"], (r["detail"] or {}).get("count") if isinstance(r["detail"], dict) else None)
                     for r in ctx.conn.execute("SELECT kind, opened_at, detail FROM consentvault.org_alarm"
                                               " WHERE org_id = (SELECT consentvault.current_org()) AND cleared_at IS NULL").fetchall()]
    except psycopg.Error:  # loud-failure-exempt: the answer carries alarms: null and names it in partial; never an empty list
        out.setdefault("partial", []).append("alarms")
        return None
    rows = [r for r in rows if r[0] in NEXT_ACTION and not r[0].startswith("usage_")]
    rows.sort(key=lambda r: r[1], reverse=True)
    return [{"name": n, "since": iso(t), "count": c if isinstance(c, int) else None, "next_action": NEXT_ACTION[n]} for n, t, c in rows]


def health(ctx: Ctx) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
    h = ctx.conn.execute("SELECT unsealed_over_1h, first_event_at, first_event_sealed, clock_timestamp() AS now"
                         " FROM consentvault.health_counts()").fetchone()
    out = {"evaluated_at": iso(h["now"]), "unsealed_events_over_1h": h["unsealed_over_1h"], "dead_deliveries": None,
           "last_chain_verification": None,
           "first_event": {"at": iso(h["first_event_at"]), "sealed": h["first_event_sealed"]} if h["first_event_at"] else None}
    out["alarms"] = customer_alarms(ctx, out)
    return out
