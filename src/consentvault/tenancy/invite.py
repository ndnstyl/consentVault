"""Invite-led onboarding. The only way into an organisation is an invitation; nothing joins by email domain.

An invitation is single use, lives seven days, and can be accepted only by the person signed in with the address it
was sent to (the binding is never relaxed by an admin). The token is shown once, in the link, and the vault keeps only
its digest. Everything after the pre-tenant lookup runs inside the invited organisation's own tenant token, so row
security applies to the acceptance as to any other write.

- ``create`` writes the invitation inside the caller's tenant transaction and, when a mailer is given, sends the
  email last; a send that fails raises ``email_send_failed`` and the surrounding transaction rolls back, so nothing
  is created.
- ``lookup`` / ``public_view`` answer the pre-sign-in read (organisation name, role, who invited, masked address).
- ``accept`` verifies the signed-in identity (second factor, verified address equal to the invited address) and
  creates the membership with the invited role.
- ``withdraw`` ends an open invitation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol

import psycopg

from ..normalize import normalize_email
from ..errors import NormalizationError
from .admin_base import (ROLE_ADMIN, CLIENT_ROLES, ApiError, Actor, Ctx, clean_email, email_hint, iso, to_uuid,
                         want_enum)
from .tokens import TokenKey, mint_org_token, org_transaction

INVITE_DAYS = 7
ACCEPT_TOKEN_SECONDS = 60


class Mailer(Protocol):
    def send_invite(self, *, to: str, org_name: str, role: str, token: str, expires_at: datetime,
                    invited_by_name: str) -> None:
        """Send the invitation email. Raise on any failure; the caller turns it into ``email_send_failed``."""
        ...


def new_token() -> str:
    return secrets.token_urlsafe(32)


def digest(token: str) -> str:
    return hashlib.sha256(b"consentvault.invite.v1:" + token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Resolved:
    org_id: object
    invite_id: object
    org_name: str
    org_status: str
    role: str
    invited_by_name: str
    email_norm: str
    expires_at: datetime


def _lookup(conn: psycopg.Connection, token: str) -> dict:
    """The pre-tenant read of an invitation row by token digest; refuses one that is not usable."""
    if not isinstance(token, str) or not 20 <= len(token) <= 200:
        raise ApiError("invite_not_found", "no invitation for that link")
    row = conn.execute("SELECT l.*, clock_timestamp() AS now FROM consentvault.invite_lookup(%s) l",
                       (digest(token),)).fetchone()
    if row is None:
        raise ApiError("invite_not_found", "no invitation for that link")
    if row["withdrawn_at"] is not None:
        raise ApiError("invite_withdrawn", "this invitation was withdrawn")
    if row["accepted_at"] is not None:
        raise ApiError("invite_used", "this invitation was already accepted")
    if row["expires_at"] <= row["now"]:
        raise ApiError("invite_expired", "this invitation has expired")
    return row


def resolve(conn: psycopg.Connection, token_key: TokenKey, token: str) -> Resolved:
    """Find an invitation by its token and refuse one that is not usable. The pre-tenant lookup answers ids and status
    only; the organisation's name and the inviter's name are read inside the invitation's own tenant (a short token),
    because the operator role that does the lookup reads neither."""
    row = _lookup(conn, token)
    entry = mint_org_token(token_key, row["org_id"], ["invite_read"], credential_id=None, ttl_seconds=30)
    with org_transaction(conn, entry):
        org = conn.execute("SELECT name FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())").fetchone()
        by = conn.execute("SELECT display_name FROM consentvault.member WHERE org_id = (SELECT consentvault.current_org())"
                          " AND member_id = %s", (row["invited_by"],)).fetchone() if row["invited_by"] else None
    return Resolved(row["org_id"], row["invite_id"], org["name"], row["org_status"], row["role"],
                    (by["display_name"] if by and by["display_name"] else "ConsentVault"), row["email_norm"], row["expires_at"])


def public_view(r: Resolved) -> dict:
    """What the sign-in page may show: never the organisation id, never the full address."""
    return {"org_name": r.org_name, "role": r.role, "invited_by_name": r.invited_by_name,
            "invited_email_hint": email_hint(r.email_norm), "expires_at": iso(r.expires_at)}


def create(ctx: Ctx, *, email, role, mailer: Optional[Mailer] = None) -> dict:
    """Create an invitation for the current organisation. An admin (or the operator, for the first admin)."""
    if ctx.actor.kind == "member":
        ctx.actor.require(ROLE_ADMIN)
    email_norm = clean_email(email)
    want_enum(role, "role", CLIENT_ROLES)
    conn = ctx.conn
    org = ctx.org_id()
    # an invitation that ran out of time no longer holds the address
    conn.execute("UPDATE consentvault.invite SET withdrawn_at = now() WHERE org_id = %s AND email_norm = %s"
                 " AND accepted_at IS NULL AND withdrawn_at IS NULL AND expires_at <= now()", (org, email_norm))
    if conn.execute("SELECT 1 FROM consentvault.member WHERE org_id = %s AND email_norm = %s", (org, email_norm)).fetchone() \
            or conn.execute("SELECT 1 FROM consentvault.invite WHERE org_id = %s AND email_norm = %s"
                            " AND accepted_at IS NULL AND withdrawn_at IS NULL", (org, email_norm)).fetchone():
        raise ApiError("already_member", "that person is already a member or has an open invitation")
    token = new_token()
    by_member = ctx.actor.member_uuid
    by_operator = ctx.actor.id if ctx.actor.kind == "operator" else None
    row = conn.execute(
        "INSERT INTO consentvault.invite (org_id, token_digest, email_norm, role, invited_by, invited_by_operator,"
        " expires_at) VALUES (%s, %s, %s, %s, %s, %s, now() + make_interval(days => %s))"
        " RETURNING invite_id, expires_at", (org, digest(token), email_norm, role, by_member, by_operator, INVITE_DAYS)
    ).fetchone()
    ctx.audit("member.invited", "invite", str(row["invite_id"]))
    out = {"invite_id": str(row["invite_id"]), "email": email_norm, "role": role, "expires_at": iso(row["expires_at"])}
    if mailer is None:
        out["token"] = token  # no mailer: the caller delivers it; it is never readable again
    else:
        org_name = conn.execute("SELECT name FROM consentvault.organization WHERE org_id = %s", (org,)).fetchone()["name"]
        try:
            mailer.send_invite(to=email_norm, org_name=org_name, role=role, token=token, expires_at=row["expires_at"],
                               invited_by_name=ctx.actor.display_name or "ConsentVault")
        except Exception as exc:  # any send failure: nothing is created
            raise ApiError("email_send_failed", f"the invitation email could not be sent ({type(exc).__name__}); "
                                                f"nothing was created") from exc
    return out


def withdraw(ctx: Ctx, invite_id) -> None:
    ctx.actor.require(ROLE_ADMIN)
    iid = to_uuid(invite_id, "invitation")
    conn = ctx.conn
    row = conn.execute("UPDATE consentvault.invite SET withdrawn_at = now() WHERE org_id = (SELECT consentvault.current_org())"
                       " AND invite_id = %s AND accepted_at IS NULL AND withdrawn_at IS NULL RETURNING invite_id",
                       (iid,)).fetchone()
    if row is None:
        cur = conn.execute("SELECT accepted_at, withdrawn_at FROM consentvault.invite"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND invite_id = %s", (iid,)).fetchone()
        if cur is None:
            raise ApiError("not_found", "no such invitation in this organization")
        if cur["accepted_at"] is not None:
            raise ApiError("invite_used", "this invitation was already accepted")
        return  # already withdrawn: nothing to do
    ctx.audit("invite.withdrawn", "invite", str(iid))


def accept(conn: psycopg.Connection, token_key: TokenKey, *, token: str, identity, request_id: str) -> dict:
    """Accept an invitation as the signed-in person. ``identity`` is a verified ``providers.identity.Identity``.

    Refuses: no second factor, an address the identity provider has not verified, an address other than the invited
    one, and any invitation that is withdrawn, used or expired. Creates the membership with the invited role.
    """
    if not getattr(identity, "multi_factor", False):
        raise ApiError("second_factor_required", "the sign-in shows no passkey or second factor")
    claims = identity.claims
    raw_email = claims.get("email")
    if not isinstance(raw_email, str) or claims.get("email_verified") is not True:
        raise ApiError("invite_wrong_account", "the signed-in address has not been verified by the sign-in provider")
    try:
        signed_in = normalize_email(raw_email)
    except NormalizationError:
        raise ApiError("invite_wrong_account", "the signed-in address is not a valid email address") from None
    r = resolve(conn, token_key, token)
    if not hmac.compare_digest(hashlib.sha256(signed_in.encode()).digest(), hashlib.sha256(r.email_norm.encode()).digest()):
        raise ApiError("invite_wrong_account", f"this invitation was sent to {email_hint(r.email_norm)}; "
                                               f"sign in with that address")
    if r.org_status == "closed":
        raise ApiError("org_not_active", "the organization is closed")
    entry = mint_org_token(token_key, r.org_id, ["invite_accept"], credential_id=None, ttl_seconds=ACCEPT_TOKEN_SECONDS)
    display = claims.get("name") if isinstance(claims.get("name"), str) and claims.get("name").strip() else None
    try:
        with org_transaction(conn, entry):
            from .session import check_sso_entry, current_sso
            check_sso_entry(current_sso(conn), claims.get("sso_connection_id"), None, claims.get("sso_organization_id"))
            row = conn.execute(
                "UPDATE consentvault.invite SET accepted_at = now() WHERE org_id = (SELECT consentvault.current_org())"
                " AND invite_id = %s AND accepted_at IS NULL AND withdrawn_at IS NULL AND expires_at > now()"
                " RETURNING role", (r.invite_id,)).fetchone()
            if row is None:
                _lookup(conn, token)  # raises the precise reason (used, withdrawn, expired) after a lost race
                raise ApiError("invite_not_found", "no invitation for that link")
            m = conn.execute(
                "INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role, email_norm, display_name,"
                " invited_by, last_sign_in_at) VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s,"
                " (SELECT invited_by FROM consentvault.invite WHERE org_id = (SELECT consentvault.current_org())"
                " AND invite_id = %s), now()) RETURNING member_id",
                (identity.issuer, identity.subject, row["role"], signed_in, display, r.invite_id)).fetchone()
            conn.execute("UPDATE consentvault.invite SET accepted_member_id = %s WHERE org_id = (SELECT consentvault.current_org())"
                         " AND invite_id = %s", (m["member_id"], r.invite_id))
            audit_actor = Actor("member", str(m["member_id"]), row["role"], display)
            from . import audit as audit_mod
            audit_mod.append(conn, actor_kind="member", actor_id=audit_actor.id, action="invite.accepted",
                             target_kind="invite", target_id=str(r.invite_id), request_id=request_id)
            org = conn.execute("SELECT name, status FROM consentvault.organization"
                               " WHERE org_id = (SELECT consentvault.current_org())").fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("already_member", "that person is already a member of this organization") from None
    return {"org_id": str(r.org_id), "name": org["name"], "role": row["role"], "status": org["status"]}
