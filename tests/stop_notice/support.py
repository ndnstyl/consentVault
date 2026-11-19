"""A recorded stop, a worker login and a fake mail line for the stop-notice tests. No network: the sender is injected."""

from __future__ import annotations

import uuid
from datetime import timedelta

from consentvault import db
from consentvault.ledger import record_tenant_event
from consentvault.notify.base import InMemorySendLog
from consentvault.notify.errors import SendFailed
from consentvault.notify.service import Notifier
from consentvault.notify.stop_notice import StopNoticeSender
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from isolation.harness import FakeKeyProvider, make_login_role

PORTAL = "https://app.example.test"
_PROVIDER = FakeKeyProvider()


from consentvault.tenancy.errors import KeyProviderError  # noqa: E402


class NoDisplayKey(TenantCrypto):
    """A key service that cannot open the display key: the mask of a notice cannot be sealed."""

    def display_key(self, org_id):
        raise KeyProviderError("the display key is not available")


SHARED = TenantCrypto(_PROVIDER)  # one key service for every organisation a test makes: writer, sender and portal read the same keys


def _crypto(org_id) -> TenantCrypto:
    oid = uuid.UUID(str(org_id))
    if oid not in _PROVIDER.wrap_keys:
        _PROVIDER.add_org(oid)
    return SHARED


def record_stop(vault, org_id, contact: str, *, event_type="revoke", channels=("sms",), purposes=("marketing",), then=None,
                crypto=None):
    """A stop recorded the way the capture code records one: the ledger writer, inside the entered tenant. ``then`` runs inside
    the same transaction after the write (a test uses it to abort the transaction)."""
    token = mint_org_token(vault.key, org_id, ["capture"], credential_id=None)
    with vault.appconn() as c, org_transaction(c, token):
        _crypto(org_id)
        ev = record_tenant_event(c, crypto or SHARED, contact=contact, event_type=event_type, channels=list(channels),
                                 purposes=list(purposes), method="keyword", origin="consumer")
        if then is not None:
            then()
    return ev


def count(vault, sql: str, *params) -> int:
    with vault.superuser() as su:
        return su.execute(sql, params).fetchone()["n"]


class FakeSender:
    provider = "fake"

    def __init__(self) -> None:
        self.sent: list = []
        self.fail = False
        self.on_send = None  # a test's hook, run inside send() before the message is recorded

    def send(self, message) -> str:
        if self.fail:
            raise SendFailed(self.provider, "ConnectionError", 503)
        if self.on_send is not None:
            self.on_send(message)
        self.sent.append(message)
        return f"msg-{len(self.sent)}"


class Alarms:
    def __init__(self) -> None:
        self.raised: list = []

    def raise_alarm(self, name: str, detail: str) -> None:
        self.raised.append((name, detail))


class Mailroom:
    """The worker login, the notifier over a fake sender, and the in-memory send log."""

    def __init__(self, vault, pg_server, *, window_seconds: int = 0) -> None:
        dbname = vault.super_dsn.rsplit("/", 1)[1]
        self.dsn = make_login_role(pg_server["port"], dbname, "consentvault_worker")
        self.sender, self.log, self.alarms = FakeSender(), InMemorySendLog(), Alarms()
        self.sender_job = StopNoticeSender(Notifier(self.sender, self.log, self.alarms), portal_url=PORTAL,
                                           batch_window=timedelta(seconds=window_seconds))

    def run(self, **kw):
        with db.connect(self.dsn) as w:
            return self.sender_job.run_once(w, **kw)

    def to(self, address: str) -> list:
        return [m for m in self.sender.sent if m.to == address]


class JobNotifier:
    """What ``CONSENTVAULT_NOTIFIER`` names in the job test: the notifier over the shared fake sender, no network."""

    shared: "Mailroom | None" = None

    @classmethod
    def from_environment(cls, env):
        return Notifier(cls.shared.sender, cls.shared.log, cls.shared.alarms)
