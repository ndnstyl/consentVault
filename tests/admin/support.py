"""A vault in multi mode with a key provider, a fake identity provider and the admin app, for the admin-plane tests."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psycopg

from consentvault import db
from consentvault.providers.errors import MfaRequiredError, TokenMalformedError
from consentvault.providers.identity import Identity
from consentvault.providers.keys import LocalFileKeyProvider
from consentvault.tenancy import admin
from consentvault.tenancy.admin_routes import AdminApp, Request
from consentvault.tenancy.session import SessionMinter
from consentvault.tenancy.tokens import TokenKey, token_expires_at

ISSUER = "https://idp.example.com"

REFRESH_LEAD_SECONDS = 30


class FakeIdentity:
    """Stands in for providers.identity.OIDCIdentityProvider: tokens are opaque strings this object issued."""

    def __init__(self) -> None:
        self.known: dict[str, Identity] = {}

    def issue(self, subject: str, email: str, *, name: str | None = None, mfa: bool = True, verified: bool = True,
              signed_in_s_ago: float | None = 0) -> str:
        token = "idt-" + uuid.uuid4().hex
        claims = {"sub": subject, "email": email, "email_verified": verified}
        if name:
            claims["name"] = name
        amr = ("hwk", "user") if mfa else ("pwd",)
        now = datetime.now(timezone.utc)
        at = None if signed_in_s_ago is None else now - timedelta(seconds=signed_in_s_ago)
        self.known[token] = Identity(ISSUER, subject, amr, mfa, now + timedelta(hours=1), claims, at)
        return token

    def verify(self, token, *, require_mfa=False):
        who = self.known.get(token)
        if who is None:
            raise TokenMalformedError("not a token this fake issued")
        if require_mfa and not who.multi_factor:
            raise MfaRequiredError("no second factor")
        return who


class RecordingMailer:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.fail = False

    def send_invite(self, **kw) -> None:
        if self.fail:
            raise RuntimeError("smtp down")
        self.sent.append(kw)

    def token_for(self, email: str) -> str:
        return [m for m in self.sent if m["to"] == email][-1]["token"]


@dataclass
class Person:
    """A signed-in member of one organisation."""
    vault: "Vault"
    org_id: str
    role: str
    email: str
    subject: str
    member_id: str
    token: str
    minted: str | None = None  # the tenant token sign_in chose; kept fresh the way the portal edge keeps it (gateway.ts)

    def _fresh_token(self) -> str:
        """The portal edge re-chooses the organization when its tenant token has under 30 seconds left (REFRESH_LEAD_SECONDS in
        edge/src/gateway.ts), so a signed-in person's token never runs out under them however long a test takes. Only the token
        sign_in minted is refreshed: a token a test set by hand is sent exactly as set."""
        if self.minted is None or self.token != self.minted:
            return self.token
        if (token_expires_at(self.token) - datetime.now(timezone.utc)).total_seconds() >= REFRESH_LEAD_SECONDS:
            return self.token
        with self.vault.appconn() as c:
            s = self.vault.sessions.choose_org(c, self.vault.idp.issue(self.subject, self.email), self.org_id,
                                               request_id="req-refresh")
        self.token = self.minted = s.token
        return self.token

    def call(self, method, path, query=None, body=None):
        return self.vault.app.handle(Request(method, path, query or {}, body, tenant_token=self._fresh_token(),
                                             request_id="req-" + uuid.uuid4().hex[:8]))

    def ok(self, method, path, query=None, body=None):
        r = self.call(method, path, query, body)
        assert r.status < 300, (method, path, r.status, r.body)
        return r.body

    def err(self, method, path, query=None, body=None, *, name=None, status=None):
        r = self.call(method, path, query, body)
        assert r.status >= 400, (method, path, r.status, r.body)
        if name:
            assert r.body["error"] == name, (name, r.body)
        if status:
            assert r.status == status
        return r.body


@dataclass
class Vault:
    operator_dsn: str
    app_dsn: str
    super_dsn: str
    key: TokenKey
    custody: LocalFileKeyProvider
    idp: FakeIdentity
    mailer: RecordingMailer
    sessions: SessionMinter
    app: AdminApp
    people: int = 0
    migrator_dsn: str = ""
    records_jobs_dsn: str = ""  # the login the records export worker runs as (a member of consentvault_records_jobs)

    def operator(self) -> psycopg.Connection:
        """The operator console's login (a member of consentvault_console); owns nothing."""
        return db.connect(self.operator_dsn)

    def migrator(self) -> psycopg.Connection:
        """The migration login, acting as the NOLOGIN schema owner: the strongest role a guard must still refuse."""
        return db.connect(self.migrator_dsn)

    def appconn(self) -> psycopg.Connection:
        return db.connect(self.app_dsn)

    def superuser(self) -> psycopg.Connection:
        return db.connect(self.super_dsn)

    def create_org(self, name: str, admin_email: str, **kw) -> dict:
        with self.operator() as c:
            return admin.create_org(c, token_key=self.key, custody=self.custody, operator_id="op-1",
                                    request_id="req-create", name=name, admin_email=admin_email, mailer=self.mailer, **kw)

    def join(self, org_id: str, email: str, role: str, *, invite_token: str, name: str | None = None) -> Person:
        self.people += 1
        subject = f"user_{self.people}_{uuid.uuid4().hex[:6]}"
        idt = self.idp.issue(subject, email, name=name or email.split("@")[0])
        r = self.app.handle(Request("POST", f"/v1/invites/{invite_token}:accept", identity_token=idt, request_id="req-accept"))
        assert r.status == 200, r.body
        assert r.body["org_id"] == org_id and r.body["role"] == role
        return self.sign_in(org_id, subject, email)

    def sign_in(self, org_id: str, subject: str, email: str) -> Person:
        idt = self.idp.issue(subject, email)
        with self.appconn() as c:
            s = self.sessions.choose_org(c, idt, org_id, request_id="req-signin")
        return Person(self, org_id, s.role, email, subject, s.member_id, s.token, s.token)

    def org_with_admin(self, name: str, email: str, **kw) -> tuple[dict, Person]:
        org = self.create_org(name, email, **kw)
        return org, self.join(org["org_id"], email, "admin", invite_token=self.mailer.token_for(email))

    def add_member(self, boss: Person, email: str, role: str) -> Person:
        boss.ok("POST", "/v1/members", body={"email": email, "role": role})
        return self.join(boss.org_id, email, role, invite_token=self.mailer.token_for(email))
