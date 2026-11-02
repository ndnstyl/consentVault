"""Shared pieces: the archive ledger on a local store, a key provider with a movable clock, recording notifiers, and
portal contexts for each organisation's admin."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from consentvault import db, dbclock
from consentvault.evidence import LocalEcdsaSigner
from consentvault.notify.errors import NotifyRefused
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.providers.keys import LocalFileKeyProvider
from consentvault.tenancy.admin_base import ROLE_SCOPES, Ctx
from consentvault.tenancy.erasure import LifecycleLedger
from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX, actor_from_token
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from isolation.harness import PHONE, Tenancy

OPERATOR = "op-1"
TEST_PASSPHRASE = "test-only-local-passphrase"


class Clock:
    def __init__(self) -> None:
        self.now = datetime.now(timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, days: int) -> None:
        self.now += timedelta(days=days)


class RecordingNotifier:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[tuple[str, str, dict]] = []
        self.fail = fail

    def send(self, template: str, to: str, variables: dict) -> str:
        if self.fail:
            raise NotifyRefused("the test notifier refuses every message")
        self.sent.append((template, to, variables))
        return "msg-" + uuid.uuid4().hex[:8]


class Env:
    def __init__(self, t: Tenancy, tmp_path):
        self.t = t
        self.clock = Clock()
        self.archive = LocalAppendOnlyEvidenceStore(tmp_path / "archive")
        self.ledger = LifecycleLedger(self.archive, clock=dbclock.datetime_clock(lambda: db.connect(t.app_dsn)))
        self.custody = LocalFileKeyProvider(tmp_path / "keys", TEST_PASSPHRASE, clock=self.clock)
        self.notifier = RecordingNotifier()
        self.signer = LocalEcdsaSigner.generate("evidence-test", 1)
        for org in (t.a, t.b):
            self.custody.create_org_key(str(org.org_id))
            with t.superuser() as su:
                su.execute("UPDATE consentvault.member SET email_norm = %s WHERE org_id = %s",
                           (f"admin@{org.name}.example.com", org.org_id))

    def fp(self, org, contact: str = PHONE) -> str:
        return self.t.crypto.contact_fingerprint(org.org_id, "phone", contact)

    def member_id(self, org) -> uuid.UUID:
        with self.t.superuser() as su:
            return su.execute("SELECT member_id FROM consentvault.member WHERE org_id = %s AND role = 'admin' LIMIT 1",
                              (org.org_id,)).fetchone()["member_id"]

    def portal_token(self, org) -> str:
        return mint_org_token(self.t.key, org.org_id, ROLE_SCOPES["admin"],
                              credential_id=MEMBER_CREDENTIAL_PREFIX + str(self.member_id(org)))

    @contextmanager
    def admin(self, org, *, superuser: bool = False):
        """A portal admin's request context inside ``org`` (on a superuser connection: row security off)."""
        conn = self.t.superuser() if superuser else self.t.app()
        try:
            with org_transaction(conn, self.portal_token(org)):
                yield Ctx(conn, actor_from_token(conn), "req-test")
        finally:
            conn.close()

    def key_present(self, org, contact: str = PHONE) -> bool:
        with self.t.superuser() as su:
            return su.execute("SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                              (org.org_id, self.fp(org, contact))).fetchone() is not None

    def operator(self):
        return self.t.operator()

    def open_access(self, org, operator: str = OPERATOR, reason: str = "offboarding delivery") -> dict:
        """The operator's access record for a read of ``org``'s data: the org's admin approves it in their own session,
        then the operator opens it against that approval."""
        from consentvault.tenancy import legal_process

        with self.admin(org) as ctx:
            ap = legal_process.approve_operator_access(ctx, {"operator_id": operator, "reason": reason})
        with self.operator() as c:
            return legal_process.open_operator_access(c, token_key=self.t.key, notifier=self.notifier,
                                                      operator_id=operator, request_id="req-access", org_id=org.org_id,
                                                      reason=reason, approval_id=ap["approval_id"])
