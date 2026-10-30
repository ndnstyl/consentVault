"""Portal sessions: from a signed-in person to a short-lived tenant token, and back to a caller on each request.

The portal never holds a machine token. The vault verifies the identity provider's token (``providers.identity``),
requires a second factor, finds the person's memberships, and only then mints the tenant token itself, with the
portal scopes of the person's role and nothing else (``admin_base.ROLE_SCOPES``). There is no auto-join: a
membership is a row an invitation created, so a person who signs in with a matching email domain and no invitation
has no organisation (``not_a_member``). An organisation that does not exist and one the person does not belong to
answer the same way.

On every later request ``actor_from_token`` reads the person and the role from the database inside the entered
tenant, never from the token or the browser: a removed member or a changed role takes effect on the next request.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

import psycopg

from ..providers.errors import IdentityError, MfaRequiredError
from . import audit
from .admin_base import (CLIENT_ROLES, ROLE_SCOPES, Actor, ApiError, decode_cursor, encode_cursor, iso, parse_limit,
                         to_uuid)
from .tokens import TokenKey, mint_org_token, org_transaction, token_expires_at

PORTAL_TOKEN_SECONDS = 300
MEMBER_CREDENTIAL_PREFIX = "member:"


@dataclass(frozen=True)
class OrgSession:
    token: str
    org_id: str
    name: str
    role: str
    status: str
    member_id: str
    expires_in: int
    expires_at: str = ""

    def body(self) -> dict:
        """The answer to POST /v1/session/org. The token travels to the edge worker, never to the browser."""
        return {"org_id": self.org_id, "name": self.name, "role": self.role, "status": self.status,
                "expires_at": self.expires_at}


class SessionMinter:
    def __init__(self, identity, token_key: TokenKey, *, ttl_seconds: int = PORTAL_TOKEN_SECONDS,
                 cursor_key: Optional[bytes] = None):
        self._identity = identity
        self._key = token_key
        self._ttl = ttl_seconds
        self._cursor_key = cursor_key if cursor_key is not None else token_key.secret

    def verify(self, id_token: Any):
        """The signed-in identity, second factor required. Raises only ``unauthenticated`` or ``second_factor_required``."""
        if not isinstance(id_token, str) or not id_token:
            raise ApiError("unauthenticated", "no sign-in token was presented")
        try:
            return self._identity.verify(id_token, require_mfa=True)
        except MfaRequiredError:
            raise ApiError("second_factor_required", "the sign-in token shows no passkey or second factor") from None
        except IdentityError:
            raise ApiError("unauthenticated", "the sign-in token is missing, expired or not valid") from None

    def memberships(self, conn: psycopg.Connection, id_token: Any, *, limit: Any = None,
                    cursor: Optional[str] = None, now: float = 0.0) -> dict:
        """GET /v1/session: who is signed in and every membership (an empty list is an account with none)."""
        who = self.verify(id_token)
        rows = self._named(conn, who)
        n = parse_limit(limit)
        stamp = now or time.time()
        start = 0
        if cursor:
            k = decode_cursor(self._cursor_key, "GET /v1/session", cursor, stamp)
            ids = [str(r["org_id"]) for r in rows]
            if len(k) != 1 or k[0] not in ids:
                raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
            start = ids.index(k[0]) + 1
        page = rows[start:start + n]
        nxt = encode_cursor(self._cursor_key, "GET /v1/session", [str(page[-1]["org_id"])], stamp) \
            if page and start + n < len(rows) else None
        claims = who.claims
        return {"expires_at": iso(who.expires_at),
                "user": {"display_name": claims.get("name") if isinstance(claims.get("name"), str) else None,
                         "email": claims.get("email") if isinstance(claims.get("email"), str) else None},
                "items": [{"org_id": str(r["org_id"]), "name": r["org_name"], "role": r["role"], "status": r["status"]}
                          for r in page],
                "next_cursor": nxt}

    def _named(self, conn: psycopg.Connection, who) -> list[dict]:
        """Every membership with its organisation's name, sorted by name. The lookup that finds the memberships reads no
        organisation name (the operator role reads none), so each name is read inside its own organisation."""
        rows = conn.execute("SELECT org_id, member_id, role, status FROM consentvault.session_memberships(%s, %s)",
                            (who.issuer, who.subject)).fetchall()
        out = []
        for r in rows:
            token = mint_org_token(self._key, r["org_id"], ["session_read"], credential_id=None, ttl_seconds=30)
            with org_transaction(conn, token):
                name = conn.execute("SELECT name FROM consentvault.organization"
                                    " WHERE org_id = (SELECT consentvault.current_org())").fetchone()["name"]
            out.append({**r, "org_name": name})
        return sorted(out, key=lambda r: (r["org_name"].lower(), str(r["org_id"])))

    def choose_org(self, conn: psycopg.Connection, id_token: Any, org_id: Any, *, request_id: str) -> OrgSession:
        """POST /v1/session/org: verify, find the membership, mint the tenant token."""
        who = self.verify(id_token)
        try:
            wanted = to_uuid(org_id, "organization")
        except ApiError:
            raise ApiError("not_a_member", "the person has no membership in that organization") from None
        rows = conn.execute("SELECT org_id, member_id, role, status FROM consentvault.session_memberships(%s, %s)",
                            (who.issuer, who.subject)).fetchall()
        mine = next((r for r in rows if r["org_id"] == wanted), None)
        if mine is None:
            raise ApiError("not_a_member", "the person has no membership in that organization")
        if mine["role"] not in CLIENT_ROLES:
            raise ApiError("not_a_member", "the person has no usable role in that organization")
        if mine["status"] == "closed":
            raise ApiError("org_not_active", "the organization is closed")
        token = mint_org_token(self._key, wanted, ROLE_SCOPES[mine["role"]],
                               credential_id=MEMBER_CREDENTIAL_PREFIX + str(mine["member_id"]), ttl_seconds=self._ttl)
        name = who.claims.get("name") if isinstance(who.claims.get("name"), str) else None
        with org_transaction(conn, token):
            org_name = conn.execute("SELECT name FROM consentvault.organization"
                                    " WHERE org_id = (SELECT consentvault.current_org())").fetchone()["name"]
            conn.execute("UPDATE consentvault.member SET last_sign_in_at = now(),"
                         " display_name = coalesce(display_name, %s) WHERE org_id = (SELECT consentvault.current_org())"
                         " AND member_id = %s", (name, mine["member_id"]))
            audit.append(conn, actor_kind="member", actor_id=str(mine["member_id"]), action="session.opened",
                         target_kind="org", target_id=str(wanted), request_id=request_id)
        return OrgSession(token, str(wanted), org_name, mine["role"], mine["status"], str(mine["member_id"]),
                          self._ttl, iso(token_expires_at(token)))


def actor_from_token(conn: psycopg.Connection) -> Actor:
    """The caller of a portal request, read inside an entered tenant. Role comes from the member row."""
    claim = conn.execute("SELECT org_id, scopes, credential_id FROM consentvault.current_token_claims()").fetchone()
    if claim is None:
        raise ApiError("unauthenticated", "the session token is missing, expired or not valid")
    cid = claim["credential_id"] or ""
    if not cid.startswith(MEMBER_CREDENTIAL_PREFIX):
        raise ApiError("unauthenticated", "this endpoint takes a portal session, not a machine credential")
    try:
        member_id = to_uuid(cid[len(MEMBER_CREDENTIAL_PREFIX):], "member")
    except ApiError:
        raise ApiError("unauthenticated", "the session token is not valid") from None
    row = conn.execute("SELECT member_id, role, display_name FROM consentvault.member"
                       " WHERE org_id = (SELECT consentvault.current_org()) AND member_id = %s", (member_id,)).fetchone()
    if row is None:
        raise ApiError("unauthenticated", "this person is no longer a member of the organization")
    if sorted(claim["scopes"]) != sorted(ROLE_SCOPES.get(row["role"], ())):
        raise ApiError("unauthenticated", "the role changed since this session began; sign in to the organization again")
    return Actor("member", str(row["member_id"]), row["role"], row["display_name"])
