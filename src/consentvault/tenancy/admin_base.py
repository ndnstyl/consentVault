"""Shared pieces of the admin plane: named API errors, the caller (actor) and request context, role checks, input
checks, organisation-status gates and keyset pagination with signed cursors.

An ``ApiError`` carries one of the names in contracts/README.md section 5 and no more: the HTTP status is looked up in
``STATUS`` by name and nowhere else. Messages are plain sentences about records and never state a legal conclusion.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Sequence

import psycopg

from .. import dbclock
from . import audit
from .errors import TenancyError

# name -> HTTP status; the single table (contracts/README.md section 5)
STATUS: dict[str, int] = {
    "invalid_request": 400, "invalid_cursor": 400, "unauthenticated": 401, "invalid_client": 401,
    "second_factor_required": 403, "role_not_allowed": 403, "not_a_member": 403, "org_not_active": 403,
    "org_suspended": 403, "source_not_allowed": 403, "brand_not_allowed": 403, "invite_wrong_account": 403,
    "not_found": 404, "invite_not_found": 404, "no_records": 404, "invite_expired": 410, "invite_used": 410,
    "invite_withdrawn": 410, "no_org_selected": 409, "export_expired": 410, "brand_exists": 409, "source_exists": 409, "system_exists": 409, "credential_exists": 409,
    "disclosure_exists": 409, "already_member": 409, "already_revoked": 409, "already_subscribed": 409,
    "policy_required": 409, "policy_superseded": 409, "version_not_draft": 409, "attestation_mismatch": 409,
    "last_admin": 409, "legal_hold_active": 409, "export_not_ready": 409, "export_not_resumable": 409,
    "redrive_in_progress": 409, "erasure_already_requested": 409, "contact_already_erased": 409,
    "contact_not_held": 404, "offboarding_already_requested": 409, "rotation_in_progress": 409, "validation_failed": 422,
    "invalid_origin": 422, "private_key_refused": 422, "below_platform_minimum": 422, "endpoint_not_https": 422,
    "unknown_brand": 422, "invalid_contact": 422, "invalid_channel": 422, "UnknownPurposeError": 422,
    "UnknownDisclosureError": 422, "policy_incomplete": 422, "stop_cannot_proceed": 422, "unavailable_cannot_proceed": 422,
    "acknowledgement_required": 422, "org_name_mismatch": 422, "rate_limited": 429, "email_send_failed": 502,
    "stripe_unavailable": 502, "key_unavailable": 503, "misconfigured": 500, "sso_not_connected": 403, "sso_required": 403,
    "sso_binding_taken": 409, "audit_unavailable": 503, "service_unavailable": 503, "export_too_large": 422,
    "export_in_progress": 409, "export_link_expired": 410, "export_link_used": 410, "export_link_invalid": 403,
    "texting_not_registered": 409, "inbound_not_verified": 409, "no_sending_account": 409, "sender_details_missing": 409,
    "link_host_not_verified": 409, "link_host_dns_missing": 422, "sender_not_verified": 422, "provider_not_supported": 422,
    "provider_unreachable": 502, "inbound_still_pointed_here": 409, "inbound_too_large": 413, "inbound_number_mismatch": 403,
    "provider_refused": 502, "step_not_skippable": 422,
}

ROLE_ADMIN = "admin"
ROLE_DEVELOPER = "developer"
ROLE_VIEWER = "compliance_viewer"
ROLE_OPERATOR = "operator"
CLIENT_ROLES = (ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)

# role -> portal scopes (contracts/auth.md is the one place this mapping is written; this is its code)
ROLE_SCOPES: dict[str, tuple[str, ...]] = {
    ROLE_ADMIN: ("admin",),
    ROLE_DEVELOPER: ("developer",),
    ROLE_VIEWER: ("proof_read", "audit_read", "records_read"),
}

PLATFORM_MINIMUM_RETENTION_YEARS = 5


class ApiError(TenancyError):
    """A named, contract-defined refusal. ``name`` is the error name; ``fields`` is machine-readable context."""

    def __init__(self, name: str, detail: str, fields: Optional[dict] = None):
        if name not in STATUS:
            raise TenancyError(f"{name!r} is not an error name defined in contracts/README.md section 5")
        super().__init__(detail)
        self.name = name
        self.detail = detail
        self.fields = fields
        self.retry_after: Optional[int] = None  # seconds, for a rate_limited refusal (sent as Retry-After)

    @property
    def status(self) -> int:
        return STATUS[self.name]

    def body(self, request_id: str) -> dict:
        out = {"error": self.name, "detail": self.detail, "request_id": request_id}
        if self.fields:
            out["fields"] = self.fields
        return out


@dataclass(frozen=True)
class Actor:
    """Who is calling. ``kind`` is member, credential, operator or system; ``role`` is the client role for a member."""

    kind: str
    id: str
    role: Optional[str] = None
    display_name: Optional[str] = None

    def require(self, *roles: str) -> None:
        if self.role not in roles:
            raise ApiError("role_not_allowed", f"the {self.role or self.kind} role may not do this",
                           {"role": self.role or self.kind})

    @property
    def member_uuid(self) -> Optional[uuid.UUID]:
        if self.kind != "member":
            return None
        return uuid.UUID(self.id)



@dataclass
class Ctx:
    """One request: a connection already inside ``org_transaction`` for tenant calls, who is calling, and the
    request id every audit row and error carries. ``cursor_key`` signs pagination cursors."""

    conn: psycopg.Connection
    actor: Actor
    request_id: str
    cursor_key: bytes = b""
    custody: Any = None
    now: Optional[Callable[[], float]] = None   # seconds since the epoch; None reads the database's clock on this request's connection
    crypto: Any = None  # tenancy.crypto.TenantCrypto, for the records routes (fingerprints, display key, contact keys)
    token: Optional[str] = None  # the caller's tenant token, to write an audit row that commits on its own connection
    connect: Any = None  # a runtime-role connection factory, for the same

    def __post_init__(self) -> None:
        if self.now is None:
            self.now = lambda: dbclock.epoch(self.conn)

    def org_id(self) -> uuid.UUID:
        row = self.conn.execute("SELECT consentvault.current_org() AS org").fetchone()
        if row["org"] is None:
            raise ApiError("unauthenticated", "no organization is entered for this request")
        return row["org"]

    def audit(self, action: str, target_kind: str, target_id: Optional[str] = None, reason: Optional[str] = None,
              detail: Optional[dict] = None):
        return audit.append(self.conn, actor_kind=self.actor.kind, actor_id=self.actor.id, action=action,
                            target_kind=target_kind, target_id=target_id, reason=reason, request_id=self.request_id,
                            detail=detail)


# ---- organisation status gates (contracts/billing.md table) -----------------------------------------------------------
def org_status(ctx: Ctx) -> str:
    row = ctx.conn.execute("SELECT status FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                           ).fetchone()
    if row is None:
        raise ApiError("not_found", "no such organization")
    return row["status"]


def require_can_add(ctx: Ctx) -> None:
    """New credentials and new systems: refused when suspended (paused), closed or offboarding."""
    status = org_status(ctx)
    if status == "suspended":
        raise ApiError("org_suspended", "new credentials and systems are paused while the organization is suspended")
    if status in ("offboarding", "closed"):
        raise ApiError("org_not_active", f"the organization is {status}; this action is refused")


def require_not_closed(ctx: Ctx) -> None:
    if org_status(ctx) == "closed":
        raise ApiError("org_not_active", "the organization is closed")


# ---- input checks -------------------------------------------------------------------------------------------------------
def invalid(**fields: str) -> ApiError:
    return ApiError("validation_failed", "a field is missing or malformed", dict(fields))


def body_dict(body: Any) -> dict:
    if not isinstance(body, dict):
        raise ApiError("invalid_request", "the body must be a JSON object")
    return body


def need_text(body: dict, name: str, *, min_len: int = 1, max_len: int = 200, strip: bool = True) -> str:
    v = body.get(name)
    if not isinstance(v, str):
        raise invalid(**{name: "required text"})
    v2 = v.strip() if strip else v
    if not min_len <= len(v2) <= max_len:
        raise invalid(**{name: f"must be {min_len} to {max_len} characters"})
    return v2


def opt_text(body: dict, name: str, *, max_len: int = 200) -> Optional[str]:
    if body.get(name) is None:
        return None
    return need_text(body, name, max_len=max_len)


def need_list(body: dict, name: str, *, min_items: int = 0, max_items: int = 200) -> list:
    v = body.get(name)
    if not isinstance(v, list) or not min_items <= len(v) <= max_items:
        raise invalid(**{name: f"must be a list of {min_items} to {max_items} items"})
    return v


def to_uuid(value: Any, name: str = "id") -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        raise ApiError("not_found", f"no such {name}") from None


def need_uuid(body: dict, name: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(body.get(name)))
    except (ValueError, AttributeError, TypeError):
        raise invalid(**{name: "must be an id"}) from None


def need_iso_time(body: dict, name: str):
    from datetime import datetime, timezone
    v = body.get(name)
    if not isinstance(v, str):
        raise invalid(**{name: "required UTC time like 2026-10-29T14:00:00Z"})
    try:
        t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise invalid(**{name: "not a time"}) from None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t


def iso(dt) -> Optional[str]:
    if dt is None:
        return None
    from datetime import timezone
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0").rstrip(".") + "Z"


# ---- pagination ---------------------------------------------------------------------------------------------------------
CURSOR_TTL_SECONDS = 24 * 3600
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def parse_limit(value: Any) -> int:
    if value is None or value == "":
        return DEFAULT_LIMIT
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise invalid(limit="must be a whole number from 1 to 200") from None
    if not 1 <= n <= MAX_LIMIT:
        raise invalid(limit="must be a whole number from 1 to 200")
    return n


def encode_cursor(key: bytes, endpoint: str, values: Sequence[str], now: float) -> str:
    payload = json.dumps({"e": endpoint, "x": int(now) + CURSOR_TTL_SECONDS, "k": list(values)},
                         separators=(",", ":")).encode()
    mac = hmac.new(b"cursor.v1:" + key, payload, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=") + "." + mac


def decode_cursor(key: bytes, endpoint: str, cursor: str, now: float) -> list[str]:
    bad = ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
    try:
        body, mac = cursor.rsplit(".", 1)
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, AttributeError):
        raise bad from None
    want = hmac.new(b"cursor.v1:" + key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, mac):
        raise bad
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        raise bad from None
    if data.get("e") != endpoint or int(data.get("x", 0)) < now or not isinstance(data.get("k"), list):
        raise bad
    return [str(x) for x in data["k"]]


_SQL_NAME = re.compile(r"[a-z_][a-z0-9_]*")


def paginate(ctx: Ctx, *, endpoint: str, select_sql: str, params: Sequence[Any], key_cols: tuple[str, str],
             key_types: tuple[str, str], descending: bool, limit: Any, cursor: Optional[str],
             shape: Callable[[dict], dict]) -> dict:
    """Keyset page over ``select_sql`` (which must expose the two sort-key columns named in ``key_cols``).

    The second key is a unique id, so the order is stable. Answers ``{items, next_cursor}``.
    """
    if not all(_SQL_NAME.fullmatch(c) for c in key_cols) or not all(_SQL_NAME.fullmatch(t) for t in key_types):
        raise ValueError("a sort-key column or type is not a plain SQL name")
    n = parse_limit(limit)
    args = list(params)
    where = ""
    op = "<" if descending else ">"
    if cursor:
        k = decode_cursor(ctx.cursor_key, endpoint, cursor, ctx.now())
        if len(k) != 2:
            raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
        where = f" WHERE ({key_cols[0]}, {key_cols[1]}) {op} (%s::{key_types[0]}, %s::{key_types[1]})"
        args += k
    direction = "DESC" if descending else "ASC"
    sql = (f"SELECT * FROM ({select_sql}) q{where} ORDER BY {key_cols[0]} {direction}, {key_cols[1]} {direction}"
           f" LIMIT %s")
    args.append(n + 1)
    try:
        rows = ctx.conn.execute(sql, args).fetchall()
    except psycopg.errors.InvalidTextRepresentation:
        raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint") from None
    more = len(rows) > n
    rows = rows[:n]
    nxt = None
    if more and rows:
        last = rows[-1]
        nxt = encode_cursor(ctx.cursor_key, endpoint, [str(last[key_cols[0]]), str(last[key_cols[1]])], ctx.now())
    return {"items": [shape(r) for r in rows], "next_cursor": nxt}


def want_enum(value: Any, name: str, allowed: Iterable[str]) -> str:
    allowed = tuple(allowed)
    if value not in allowed:
        raise invalid(**{name: f"must be one of {', '.join(allowed)}"})
    return value


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def clean_email(raw: Any, name: str = "email") -> str:
    if not isinstance(raw, str):
        raise invalid(**{name: "required email address"})
    v = raw.strip().lower()
    if not _EMAIL.match(v) or len(v) > 320:
        raise invalid(**{name: "not a valid email address"})
    return v


def email_hint(email_norm: str) -> str:
    """The invited address with its middle masked: a***@acme.com."""
    local, _, domain = email_norm.partition("@")
    return f"{local[:1]}***@{domain}"


def page_list(ctx: Ctx, *, endpoint: str, rows: Sequence[Any], key: Callable[[Any], str], limit: Any,
              cursor: Optional[str], shape: Callable[[Any], dict]) -> dict:
    """Page an already-sorted, small, in-memory list (a catalog) with the same signed cursor as ``paginate``."""
    n = parse_limit(limit)
    start = 0
    if cursor:
        k = decode_cursor(ctx.cursor_key, endpoint, cursor, ctx.now())
        keys = [key(r) for r in rows]
        if len(k) != 1 or k[0] not in keys:
            raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
        start = keys.index(k[0]) + 1
    page = list(rows[start:start + n])
    nxt = encode_cursor(ctx.cursor_key, endpoint, [key(page[-1])], ctx.now()) if page and start + n < len(rows) else None
    return {"items": [shape(r) for r in page], "next_cursor": nxt}
