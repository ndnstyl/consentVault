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
import dataclasses
from dataclasses import dataclass
from typing import Any, Optional

import psycopg

from .. import dbclock
from ..safelog import caller_detail
from ..providers.errors import EdgeKeyUnknownError, IdentityError, MfaRequiredError, TokenMalformedError
from ..providers.identity import amr_is_multi_factor
from . import audit
from .admin_base import (CLIENT_ROLES, ROLE_SCOPES, Actor, ApiError, decode_cursor, encode_cursor, iso, parse_limit,
                         to_uuid)
from .tokens import TokenKey, mint_org_token, org_transaction, token_expires_at, token_sso

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
                 cursor_key: Optional[bytes] = None, assertions=None):
        self._identity = identity
        self._assertions = assertions  # providers.identity.EdgeAssertionVerifier, or None: the token's own amr decides
        self._key = token_key
        self._ttl = ttl_seconds
        self._cursor_key = cursor_key if cursor_key is not None else token_key.secret

    def verify(self, id_token: Any, assertion: Optional[str] = None):
        """The signed-in identity, second factor required. Raises only ``unauthenticated`` or ``second_factor_required``.

        With an edge assertion verifier configured (an issuer whose tokens carry no ``amr``), the authentication methods come
        from the portal edge's signed assertion for this person and this token, never from the token."""
        if not isinstance(id_token, str) or not id_token:
            raise ApiError("unauthenticated", "no sign-in token was presented")
        try:
            if self._assertions is None:
                return self._identity.verify(id_token, require_mfa=True)
            who = self._identity.verify(id_token, require_mfa=False)
            facts = self._assertions.check(who, id_token, assertion)
            if (facts.sso_connection_id is not None or facts.sso_organization_id is not None) and facts.amr != ("sso",):
                # a connection id beside any other method is a contradiction: the vault does not trust the edge to have
                # kept the two apart, an SSO sign-in is exactly the one method "sso" or it is nothing
                raise TokenMalformedError("a company connection was named beside other sign-in methods")
            # the company's identity provider vouches, through a named connection of a named organization
            sso = facts.amr == ("sso",) and facts.sso_connection_id is not None and facts.sso_organization_id is not None
            if not (amr_is_multi_factor(facts.amr) or sso):
                raise MfaRequiredError("the sign-in methods show no passkey or second factor")
            # The provider's tokens may carry no address; the one the provider verified arrives in the edge's signed
            # assertion and replaces whatever the token held, so display and invitations read one trusted source.
            claims = {**who.claims, "email": facts.email, "email_verified": facts.email_verified} if facts.email \
                else {k: v for k, v in who.claims.items() if k not in ("email", "email_verified")}
            claims = {k: v for k, v in claims.items() if k != "sso_connection_id"}
            claims.pop("sso_organization_id", None)
            if sso:
                claims["sso_connection_id"] = facts.sso_connection_id
                claims["sso_organization_id"] = facts.sso_organization_id
            return dataclasses.replace(who, amr=facts.amr, multi_factor=True, claims=claims)
        except EdgeKeyUnknownError as exc:
            raise ApiError("misconfigured", caller_detail(exc)) from None
        except MfaRequiredError:
            raise ApiError("second_factor_required", "the sign-in token shows no passkey or second factor") from None
        except IdentityError:
            raise ApiError("unauthenticated", "the sign-in token is missing, expired or not valid") from None

    def memberships(self, conn: psycopg.Connection, id_token: Any, *, limit: Any = None,
                    cursor: Optional[str] = None, now: float = 0.0, assertion: Optional[str] = None) -> dict:
        """GET /v1/session: who is signed in and every membership (an empty list is an account with none)."""
        who = self.verify(id_token, assertion)
        rows = self._named(conn, who)
        mine = who.claims.get("sso_connection_id")
        if mine:  # a single sign-in sees only the organizations connected to that same connection (a pending one: admins only)
            wos = who.claims.get("sso_organization_id")
            rows = [r for r in rows if _admits(r["sso"], mine, r["role"], wos)]
        n = parse_limit(limit)
        stamp = now or dbclock.epoch(conn)   # the database's clock; a caller may pin a time for a test
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
                "items": [{"org_id": str(r["org_id"]), "name": r["org_name"], "role": r["role"], "status": r["status"],
                           "sso_required": r["sso"]["required"]}
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
                sso = current_sso(conn)
            out.append({**r, "org_name": name, "sso": sso})
        return sorted(out, key=lambda r: (r["org_name"].lower(), str(r["org_id"])))

    def choose_org(self, conn: psycopg.Connection, id_token: Any, org_id: Any, *, request_id: str,
                   assertion: Optional[str] = None) -> OrgSession:
        """POST /v1/session/org: verify, find the membership, mint the tenant token."""
        who = self.verify(id_token, assertion)
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
                               credential_id=MEMBER_CREDENTIAL_PREFIX + str(mine["member_id"]), ttl_seconds=self._ttl,
                               sso_connection=who.claims.get("sso_connection_id"))
        name = who.claims.get("name") if isinstance(who.claims.get("name"), str) else None
        with org_transaction(conn, token):
            org_name = conn.execute("SELECT name FROM consentvault.organization"
                                    " WHERE org_id = (SELECT consentvault.current_org())").fetchone()["name"]
            via = who.claims.get("sso_connection_id")
            if via:  # the same lock the admin's own changes take, so proving can never undo a change made at the same moment
                conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.sso:' || (SELECT consentvault.current_org())::text))")
            setting = current_sso(conn)
            check_sso_entry(setting, via, mine["role"], who.claims.get("sso_organization_id"))
            if via and not setting["verified"]:  # an admin got in through a bound connection: the binding is proved
                write_sso(conn, connection_id=via, verified=True, set_by=mine["member_id"])
                audit.append(conn, actor_kind="member", actor_id=str(mine["member_id"]), action="sso.verified",
                             target_kind="org_sso", target_id=via, request_id=request_id)
            conn.execute("UPDATE consentvault.member SET last_sign_in_at = now(),"
                         " display_name = coalesce(display_name, %s) WHERE org_id = (SELECT consentvault.current_org())"
                         " AND member_id = %s", (name, mine["member_id"]))
            audit.append(conn, actor_kind="member", actor_id=str(mine["member_id"]), action="session.opened",
                         target_kind="org", target_id=str(wanted), request_id=request_id,
                         reason="company single sign-on: the identity provider answered for the second factor"
                         if who.claims.get("sso_connection_id") else None)
        return OrgSession(token, str(wanted), org_name, mine["role"], mine["status"], str(mine["member_id"]),
                          self._ttl, iso(token_expires_at(token)))


def current_sso(conn: psycopg.Connection) -> dict:
    """The entered organization's single sign-on setting in force: the sign-in-service organization and connections the
    operator bound, the connection an admin proved it through (or None), and whether it is required."""
    row = conn.execute("SELECT workos_org_id, bound_connections, connection_id, require_sso, verified FROM consentvault.org_sso"
                       " WHERE org_id = (SELECT consentvault.current_org()) ORDER BY version DESC LIMIT 1").fetchone()
    if row is None:
        return {"workos_org_id": None, "bound_connections": [], "connection_id": None, "required": False, "verified": False}
    return {"workos_org_id": row["workos_org_id"], "bound_connections": list(row["bound_connections"]),
            "connection_id": row["connection_id"], "required": bool(row["require_sso"]), "verified": bool(row["verified"])}


def write_sso(conn: psycopg.Connection, *, set_by=None, set_by_operator=None, **changes) -> dict:
    """Append a new version of the entered organization's setting: the newest row with ``changes`` applied. The caller holds
    the setting's advisory lock. Returns the new row."""
    cur = current_sso(conn)
    new = {"workos_org_id": cur["workos_org_id"], "bound_connections": cur["bound_connections"],
           "connection_id": cur["connection_id"], "require_sso": cur["required"], "verified": cur["verified"], **changes}
    return conn.execute(
        "INSERT INTO consentvault.org_sso (org_id, version, workos_org_id, bound_connections, connection_id, require_sso, verified,"
        " set_by, set_by_operator) SELECT o, coalesce((SELECT max(version) FROM consentvault.org_sso WHERE org_id = o), 0) + 1,"
        " %s, %s, %s, %s, %s, %s, %s FROM (SELECT (SELECT consentvault.current_org()) AS o) x"
        " RETURNING version, workos_org_id, bound_connections, connection_id, require_sso, verified, applies_from",
        (new["workos_org_id"], new["bound_connections"], new["connection_id"], new["require_sso"], new["verified"], set_by,
         set_by_operator)).fetchone()


def _admits(setting: dict, connection, role, workos_org) -> bool:
    try:
        check_sso_entry(setting, connection, role, workos_org)
        return True
    except ApiError:
        return False


def check_sso_entry(setting: dict, signed_in_connection, role=None, workos_org=None) -> None:
    """The rule for entering an organization, applied at sign-in and again on every request. A company single sign-on enters
    only through a connection the operator bound to this organization (and, at sign-in, one that the sign-in service reports
    as belonging to the bound organization); while the binding is unproved only an admin may use it, and the admin's sign-in
    proves it. Any other sign-in is refused by an organization that requires single sign-on."""
    if signed_in_connection:
        if signed_in_connection not in setting["bound_connections"]:
            raise ApiError("sso_not_connected", "this organization has not connected that company sign-in")
        if workos_org is not None and workos_org != setting["workos_org_id"]:
            raise ApiError("sso_not_connected", "that company sign-in belongs to another company's account")
        if not setting["verified"] and role != "admin":
            raise ApiError("sso_not_connected", "this company sign-in is not proved yet: an admin must sign in through it first")
    elif setting["required"]:
        raise ApiError("sso_required", "this organization requires its company sign-in; sign in through it")


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
    # The single sign-on rule is checked on every request, not only at sign-in: turning on "require" or changing or removing
    # the connection ends every session that no longer fits, on its very next call.
    entered = conn.execute("SELECT nullif(pg_catalog.current_setting('consentvault.org_token', true), '') AS t").fetchone()["t"]
    check_sso_entry(current_sso(conn), token_sso(entered), row["role"])
    return Actor("member", str(row["member_id"]), row["role"], row["display_name"])


def require_edge_keys(config) -> None:
    from ..errors import ConfigError

    if not config.edge_assertion_keys:
        raise ConfigError("no edge assertion keys: set CONSENTVAULT_EDGE_ASSERTION_KEYS (JSON {key id: public key PEM}) or "
                          "[edge_assertion_keys] in consentvault.toml; portal sign-in is refused without them")


def session_minter_from_config(config, identity, token_key, *, clock) -> SessionMinter:
    """The portal's session minter for a deployment. Refuses (ConfigError) when no edge assertion key is configured: the
    portal edge Worker is the only source of how a person signed in, so without its public keys no portal route may work.
    Several keys may be listed (key rotation: add the new one, deploy the edge with it, then retire the old)."""
    from ..providers.identity import EdgeAssertionVerifier

    require_edge_keys(config)
    return SessionMinter(identity, token_key, assertions=EdgeAssertionVerifier(config.edge_assertion_keys, clock=clock))
