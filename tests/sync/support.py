"""Shared fixtures-as-functions for the sync suites and the sync isolation suite. No test here makes a network call."""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from consentvault import db
from consentvault.ledger import record_tenant_event
from consentvault.normalize import normalize_contact
from consentvault.sync.connectors import webhook
from consentvault.sync.outbox import enqueue_event_pushes
from consentvault.sync.signals import ensure_contact_key
from consentvault.sync.systems import bind_signal_credential, seal_credentials
from consentvault.sync.worker import Alarm, SyncWorker, WorkerConfig
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import PHONE, Org, Tenancy, make_login_role


class FakeCustody:
    """The organisation-key custody the admin lane and the worker share (wrap and unwrap of 32 raw bytes), built on the
    isolation harness's per-organisation keys."""

    def __init__(self, provider) -> None:
        self.provider = provider

    def _key(self, org_id: str) -> bytes:
        return self.provider.wrap_keys[uuid.UUID(org_id)]

    def wrap(self, org_id: str, data_key: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key(org_id)).encrypt(nonce, data_key, org_id.encode())

    def unwrap(self, org_id: str, wrapped: bytes) -> bytes:
        return AESGCM(self._key(org_id)).decrypt(wrapped[:12], wrapped[12:], org_id.encode())


@dataclass(frozen=True)
class Sys:
    system_id: uuid.UUID
    name: str
    endpoint: str
    signature: str
    secret: bytes  # the raw HMAC secret or Ed25519 seed (what the vault holds sealed)

    @property
    def verify_key(self) -> bytes:
        if self.signature == "hmac":
            return self.secret
        return Ed25519PrivateKey.from_private_bytes(self.secret).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Clock:
    """Real time plus an offset the test moves. The database decides every sync time on its own clock (claims, leases, the
    retry window and the next attempt), so moving the clock also moves the sync rows' times back by the same span: time passes
    for both sides alike."""

    def __init__(self) -> None:
        self.offset = timedelta(0)
        self.on_advance = None

    def __call__(self) -> datetime:
        return datetime.now(timezone.utc) + self.offset

    def advance(self, **kw) -> None:
        delta = timedelta(**kw)
        self.offset += delta
        if self.on_advance is not None:
            self.on_advance(delta)


class FakeTransport:
    """Scripted receivers. ``script(endpoint, *results)`` queues answers for one endpoint; the default is 200."""

    def __init__(self) -> None:
        self.sent: list[webhook.PushRequest] = []
        self._queues: dict[str, deque] = defaultdict(deque)
        self.default = webhook.TransportResult("response", 200)
        self.raises: Exception | None = None

    def script(self, endpoint: str, *results) -> None:
        self._queues[endpoint].extend(
            r if isinstance(r, webhook.TransportResult) else webhook.TransportResult("response", r) for r in results)

    def send(self, request: webhook.PushRequest) -> webhook.TransportResult:
        if self.raises is not None:
            raise self.raises
        self.sent.append(request)
        q = self._queues[request.target_url]
        return q.popleft() if q else self.default

    def to(self, endpoint: str) -> list[webhook.PushRequest]:
        return [r for r in self.sent if r.target_url == endpoint]


class RecordingAlarms:
    def __init__(self) -> None:
        self.alarms: list[Alarm] = []
        self.fail = False

    def raise_alarm(self, alarm: Alarm) -> None:
        if self.fail:
            raise RuntimeError("the pager is down")
        self.alarms.append(alarm)


class SyncEnv:
    def __init__(self, t: Tenancy, port: int) -> None:
        self.t = t
        self.dbname = t.app_dsn.rsplit("/", 1)[1]
        self.worker_dsn = make_login_role(port, self.dbname, "consentvault_worker")
        self.clock = Clock()
        self.clock.on_advance = self.age_rows
        self.transport = FakeTransport()
        self.alarms = RecordingAlarms()
        # batch x send timeout must fit in the lease (second-wave review): 4 x 15 s = 60 s
        self.config = WorkerConfig(batch_size=4, lease_seconds=60, backoff_base_seconds=30, backoff_cap_seconds=3600)
        self.custody = FakeCustody(t.provider)
        self.systems: dict[str, Sys] = {}

    # roles --------------------------------------------------------------------------------------------------------

    def worker_conn(self) -> psycopg.Connection:
        return db.connect(self.worker_dsn)

    def make_worker(self, **config) -> SyncWorker:
        cfg = self.config if not config else WorkerConfig(**{**self.config.__dict__, **config})
        return SyncWorker(self.t.crypto, self.custody, self.transport, self.alarms, config=cfg, clock=self.clock)

    def run_worker(self, **config):
        with self.worker_conn() as w:
            return self.make_worker(**config).run_once(w)

    def dispatch(self, conn: psycopg.Connection, org: Org) -> str:
        rows = conn.execute("SELECT org_id, token FROM consentvault.dispatch_orgs('sync')").fetchall()
        return next(r["token"] for r in rows if r["org_id"] == org.org_id)

    # connected systems --------------------------------------------------------------------------------------------

    def add_system(self, org: Org, name: str, *, signature: str = "hmac", contact_form: str = "plaintext",
                   retry_window_hours: int = 24, signal: bool = False) -> Sys:
        """Register a system the way the admin lane does: an INSERT under an admin token, credential sealed by custody."""
        endpoint = f"https://{name}.{org.name}.example.test/hook"
        secret = os.urandom(32)
        public = None
        if signature == "ed25519":
            public = Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        sealed = seal_credentials(self.custody, org.org_id, secret)
        with self.t.operator() as o, org_transaction(o, self.t.admin_token(org.org_id)):
            sid = o.execute(
                "INSERT INTO consentvault.connected_system (org_id, name, kind, endpoint, signature, contact_form,"
                " retry_window_hours, public_key, credentials_ct) VALUES (%s, %s, 'crm', %s, %s, %s, %s, %s, %s)"
                " RETURNING system_id", (org.org_id, name, endpoint, signature, contact_form, retry_window_hours,
                                         public, sealed)).fetchone()["system_id"]
            if signal:
                bind_signal_credential(o, sid, org.credential_id)
        made = Sys(sid, name, endpoint, signature, secret)
        self.systems[f"{org.name}/{name}"] = made
        return made

    def system(self, org: Org, name: str) -> Sys:
        return self.systems[f"{org.name}/{name}"]

    def endpoint(self, org: Org, name: str) -> str:
        return self.system(org, name).endpoint

    # events -------------------------------------------------------------------------------------------------------

    def record(self, org: Org, contact: str, event_type: str, *, source_system_id=None, hook: bool = True, **kw):
        """What the capture code does: write the event and queue its pushes, in ONE transaction."""
        args = dict(channels=["sms"], purposes=["marketing"], method="keyword", origin="consumer")
        if event_type == "grant":
            args.update(method="checkbox", disclosure_sha256=org.disclosure)
        args.update(kw)
        # The ledger writer runs the outbox hook itself (integration pass); ``hook=False`` only hides the result.
        with self.t.app() as app, org_transaction(app, self.t.token(org, scopes=("capture",))):
            ev = record_tenant_event(app, self.t.crypto, contact=contact, event_type=event_type,
                                     source_system_id=source_system_id, **args)
        return (ev, ev.pushes) if hook else (ev, None)

    def register_wording(self, org: Org, body: str, channels=("sms",), purposes=("marketing",)) -> str:
        from consentvault import disclosure as disc

        with self.t.app() as app, org_transaction(app, self.t.token(org, scopes=("capture",))):
            return disc.register(app, body, f"{org.name}-extra", "en", list(channels), list(purposes))

    def grant(self, org: Org, contact: str, **kw):
        return self.record(org, contact, "grant", **kw)

    def stop(self, org: Org, contact: str, **kw):
        return self.record(org, contact, "revoke", **kw)

    def fp(self, org: Org, contact: str) -> str:
        kind, norm = normalize_contact(contact)
        return self.t.crypto.contact_fingerprint(org.org_id, kind, norm)

    # out-of-band inspection (a DBA's view; bypasses row security) ----------------------------------------------------

    def q(self, sql: str, params=()) -> list[dict]:
        with self.t.superuser() as su:
            cur = su.execute(sql, params or None)
            return cur.fetchall() if cur.description is not None else []

    def outbox(self, org: Org, **where) -> list[dict]:
        sql = "SELECT * FROM consentvault.outbox WHERE org_id = %s"
        params: list = [org.org_id]
        for k, v in where.items():
            sql += f" AND {k} = %s"
            params.append(v)
        return self.q(sql + " ORDER BY created_at, version", params)

    def age_rows(self, delta: timedelta) -> None:
        """Time passes for the database's side: every sync row's times move back by ``delta`` (seconds, so no zone moves them)."""
        secs = delta.total_seconds()
        self.q("UPDATE consentvault.outbox SET next_attempt_at = next_attempt_at - make_interval(secs => %s),"
               " claimed_until = claimed_until - make_interval(secs => %s), last_attempt_at = last_attempt_at - make_interval(secs => %s),"
               " window_start = window_start - make_interval(secs => %s)", [secs, secs, secs, secs])
        self.q("UPDATE consentvault.connector_person_lease SET lease_until = lease_until - make_interval(secs => %s)", [secs])
        self.q("UPDATE consentvault.connector_rate SET refilled_at = refilled_at - make_interval(secs => %s)", [secs])

    def ageing(self, org: Org, **where) -> None:
        """Make every waiting push due now (tests that do not move the clock)."""
        self.q("UPDATE consentvault.outbox SET next_attempt_at = clock_timestamp() - interval '1 second'"
               " WHERE org_id = %s AND status IN ('pending', 'failed')", [org.org_id])


def contact(n: int) -> str:
    return f"+1555555{2000 + n:04d}"[:12]


_E164 = re.compile(r"^\+1\d{10}$")
assert _E164.match(contact(1))
PHONES = [contact(i) for i in range(1, 40)]
__all__ = ["Clock", "FakeTransport", "RecordingAlarms", "SyncEnv", "PHONE", "PHONES", "contact"]


def of(report, org):
    """One organisation's part of a run report."""
    return next(o for o in report.orgs if o.org_id == org.org_id)
