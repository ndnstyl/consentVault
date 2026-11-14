"""A world for the records, confirmations and setup contracts: two organisations, each with an admin, a developer and a
compliance viewer, real brands and sources, registered wording, and a writer that records events through the core.

Everything here uses only what exists today (the admin app, the ledger writer, the key adapter). A feature that does not
exist yet is reached through ``need()``, which fails the test with a plain "not built yet" message instead of an import
error, so a red test always names the missing piece.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from consentvault import disclosure as disc
from consentvault.ledger import record_tenant_event
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.keys_adapter import CustodyKeyAdapter
from consentvault.tenancy.tokens import mint_org_token, org_transaction

PENDING = pytest.mark.contract_pending
PHONE = "+15555550142"
PHONE2 = "+15555550199"
EMAIL = "dana@example.com"
EMAIL2 = "lee@example.com"
CHANNELS = ("sms", "voice", "artificial_voice", "email")
WORDING = "Acme may text, call and email you about offers and billing. Reply STOP to end."


def need(module: str, attr: str | None = None):
    """Import a piece that is not built yet; fail the test loudly and plainly when it is missing."""
    try:
        mod = importlib.import_module(module)
    except ImportError as exc:
        pytest.fail(f"not built yet: module {module} ({exc})", pytrace=False)
    if attr is None:
        return mod
    if not hasattr(mod, attr):
        pytest.fail(f"not built yet: {module}.{attr}", pytrace=False)
    return getattr(mod, attr)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Org:
    name: str
    org_id: str
    boss: object
    dev: object
    viewer: object
    brand_id: str
    brand2_id: str
    web_id: str
    import_id: str
    wording: str
    wording_sms_only: str
    crypto: TenantCrypto
    event_ids: list = field(default_factory=list)

    @property
    def people(self):
        return {"admin": self.boss, "developer": self.dev, "compliance_viewer": self.viewer}

    def fp(self, contact: str, kind: str = "phone") -> str:
        return self.crypto.contact_fingerprint(uuid.UUID(self.org_id), kind, contact)


class World:
    def __init__(self, vault, tmp_path):
        from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
        self.vault = vault
        self.store = LocalAppendOnlyEvidenceStore(tmp_path / "evidence")
        self.adapter = CustodyKeyAdapter.from_database(vault.custody, vault.operator, vault.key)
        self.crypto = TenantCrypto(self.adapter)
        self.offset = 0.0
        self.app_with_store(self.store)  # every world mounts the evidence store on the admin app (list exports are kept there)
        self.a = self._org("acme")
        self.b = self._org("bravo")

    def extra_org(self, name: str, channels=None, default_region=None) -> Org:
        """An organization provisioned (through the operator route) with only the named channels and/or a default region."""
        return self._org(name, channels, default_region)

    def app_with_store(self, store):
        """Mount the evidence store on the admin app, with a clock the tests can move."""
        from consentvault.tenancy.admin_routes import AdminApp
        v = self.vault
        try:
            app = AdminApp(connect=lambda: __import__("consentvault.db", fromlist=["connect"]).connect(v.app_dsn),
                           owner_connect=lambda: __import__("consentvault.db", fromlist=["connect"]).connect(v.operator_dsn),
                           token_key=v.key, sessions=v.sessions, custody=v.custody, mailer=v.mailer, evidence_store=store,
                           exports=self._exports(store), clock=lambda: time.time() + self.offset)
        except TypeError as exc:
            pytest.fail(f"not built yet: AdminApp takes no evidence_store ({exc})", pytrace=False)
        v.app = app
        from consentvault import records_exports
        records_exports.configure(records_exports.worker_from_login(
            lambda: __import__("consentvault.db", fromlist=["connect"]).connect(v.records_jobs_dsn), v.custody, store,
            lambda: time.time() + self.offset))  # the export worker runs as its own login, never as the console
        return app

    def _exports(self, store):
        """The evidence package service the portal's POST /v1/exports hands a contact point to."""
        import os
        from consentvault import db
        from consentvault.evidence import ExportService, LocalEcdsaSigner
        v = self.vault
        return ExportService(connect=lambda: db.connect(v.app_dsn),
                             mint_token=lambda org_id, scopes: mint_org_token(v.key, org_id, scopes, credential_id=None),
                             crypto=self.crypto, signer=LocalEcdsaSigner.generate("evidence-test", 1), store=store,
                             link_secret=os.urandom(32))

    # ---- construction -------------------------------------------------------------------------------------------------
    def _org(self, name: str, channels=None, default_region=None) -> Org:
        v = self.vault
        extra = {"channels": [list(c) for c in channels]} if channels else {}
        if default_region:
            extra["default_region"] = default_region  # set by the operator at provisioning (records.md, phone region)
        try:
            info, boss = v.org_with_admin(name, f"boss@{name}.example", **extra)
        except TypeError as exc:
            pytest.fail(f"not built yet: organization creation takes no default_region ({exc})", pytrace=False)
        chans = [c[0] for c in channels] if channels else list(CHANNELS)
        dev = v.add_member(boss, f"dev@{name}.example", "developer")
        viewer = v.add_member(boss, f"cv@{name}.example", "compliance_viewer")
        oid = info["org_id"]
        brand = boss.ok("POST", "/v1/brands", body={"display_name": f"{name} Flooring"})["brand_id"]
        brand2 = boss.ok("POST", "/v1/brands", body={"display_name": f"{name} Coatings"})["brand_id"]
        web = boss.ok("POST", "/v1/sources", body={"name": "Web form", "kind": "server", "brand_ids": [brand, brand2]})["source_id"]
        imp = boss.ok("POST", "/v1/sources", body={"name": "Event sign-up", "kind": "server", "brand_ids": [brand, brand2]})["source_id"]
        with v.operator() as o, org_transaction(o, self.admin_token(oid)):
            o.execute("INSERT INTO consentvault.purpose (org_id, purpose, label) VALUES (%s, 'billing', 'Billing')", (oid,))
        with v.appconn() as c, org_transaction(c, self.capture_token(oid)):
            w = disc.register(c, f"{name}: {WORDING}", f"{name}-all", "en", chans, ["marketing", "billing"])
            w2 = disc.register(c, f"{name}: we may text you about offers. Reply STOP to end.", f"{name}-sms", "en", ["sms"], ["marketing"])
        return Org(name, oid, boss, dev, viewer, brand, brand2, web, imp, w, w2, self.crypto)

    def admin_token(self, org_id) -> str:
        return mint_org_token(self.vault.key, org_id, ["admin"], credential_id=None)

    def capture_token(self, org_id, scopes=("capture", "gate_read")) -> str:
        return mint_org_token(self.vault.key, org_id, list(scopes), credential_id=None)

    # ---- events -------------------------------------------------------------------------------------------------------
    def capture(self, org: Org, contact: str, *, event_type: str = "grant", channels=("sms",), purposes=("marketing",),
                display: dict | None = None, subject_key: str | None = None, source_id: str | None = None,
                brand_ids=None, wording: str | None = None, method: str = "checkbox", origin: str = "consumer",
                recorded_by: str | None = None, captured_at: datetime | None = None, kind: str | None = None,
                session_ref: str | None = None, contact_verification: str = "none", scopes=("capture", "gate_read")):
        kw = dict(contact=contact, event_type=event_type, channels=list(channels), purposes=list(purposes), method=method,
                  origin=origin, source_id=uuid.UUID(source_id or org.web_id), contact_verification=contact_verification)
        if event_type == "grant":
            kw["disclosure_sha256"] = wording or org.wording
            kw["brand_ids"] = [uuid.UUID(b) for b in (brand_ids or [org.brand_id])]
            kw["session_ref"] = session_ref or "s-" + uuid.uuid4().hex[:6]
        if event_type == "revoke":
            kw["method"] = method if method != "checkbox" else "keyword"
        if subject_key:
            kw["subject_key"] = subject_key
        if kind:
            kw["contact_kind"] = kind
        if captured_at:
            kw["captured_at"] = captured_at
        if recorded_by:
            kw["recorded_by"] = recorded_by
        if display is not None:
            kw["display"] = display
        with self.vault.appconn() as c, org_transaction(c, self.capture_token(org.org_id, scopes)):
            try:
                ev = record_tenant_event(c, self.crypto, **kw)
            except TypeError as exc:
                if "display" in str(exc):
                    pytest.fail(f"not built yet: record_tenant_event takes no display argument ({exc})", pytrace=False)
                raise
        org.event_ids.append(ev.event_id)
        return ev

    def capture_many(self, org: Org, n: int) -> list[str]:
        """n distinct grants in one tenant transaction (fast bulk setup); returns the contacts."""
        contacts = [f"+1305{2000000 + i:07d}" for i in range(n)]  # valid single-zone numbers
        with self.vault.appconn() as c, org_transaction(c, self.capture_token(org.org_id)):
            for contact in contacts:
                ev = record_tenant_event(c, self.crypto, contact=contact, event_type="grant", channels=["sms"], purposes=["marketing"],
                                         method="checkbox", origin="consumer", disclosure_sha256=org.wording,
                                         brand_ids=[uuid.UUID(org.brand_id)], session_ref="s-bulk", source_id=uuid.UUID(org.web_id))
        return contacts

    def register_wording(self, org: Org, text: str, channels, purposes) -> str:
        with self.vault.appconn() as c, org_transaction(c, self.capture_token(org.org_id)):
            return disc.register(c, text, "w-" + uuid.uuid4().hex[:6], "en", list(channels), list(purposes))

    def stop(self, org: Org, contact: str, *, channels=("sms",), method="keyword", origin="consumer", **kw):
        return self.capture(org, contact, event_type="revoke", channels=channels, purposes=("*",), method=method,
                            origin=origin, **kw)

    def email_grant(self, org: Org, contact: str = EMAIL, **kw):
        return self.capture(org, contact, channels=("email",), kind="email", **kw)

    # ---- database access ----------------------------------------------------------------------------------------------
    def sql(self, org: Org, query: str, params=()):
        """Read as the superuser (out of band), filtered by the caller to one organisation."""
        with self.vault.superuser() as su:
            return su.execute(query, params).fetchall()

    def set_status(self, org: Org, status: str) -> None:
        with self.vault.superuser() as su:
            su.execute("UPDATE consentvault.organization SET status = %s WHERE org_id = %s", (status, org.org_id))

    def backdate(self, org: Org, contact: str, *, first: datetime | None = None, last: datetime | None = None,
                 kind: str = "phone") -> None:
        """Move a record's dates, as a DBA could with triggers off for one session. Needs the records tables."""
        fp = org.fp(contact, kind)
        with self.vault.superuser() as su, su.transaction():
            su.execute("SET LOCAL session_replication_role = replica")
            if first:
                su.execute("UPDATE consentvault.record SET first_recorded_at = %s WHERE org_id = %s AND contact_fp = %s",
                           (first, org.org_id, fp))
            if last:
                su.execute("UPDATE consentvault.record_index SET last_event_at = %s WHERE org_id = %s AND record_id IN"
                           " (SELECT record_id FROM consentvault.record WHERE org_id = %s AND contact_fp = %s)",
                           (last, org.org_id, org.org_id, fp))

    def erase(self, org: Org, contact: str, kind: str = "phone") -> None:
        with self.vault.operator() as o, org_transaction(o, self.admin_token(org.org_id)):
            o.execute("SELECT consentvault.erase_contact(%s)", (org.fp(contact, kind),))

    def record_id(self, org: Org, contact: str) -> str:
        found = org.boss.ok("POST", "/v1/records:search", body={"contact": contact})["items"]
        assert len(found) == 1, found
        return found[0]["record_id"]

    # ---- audit --------------------------------------------------------------------------------------------------------
    def audit(self, person, action: str) -> list[dict]:
        return person.ok("GET", "/v1/audit", {"action": action, "limit": "200"})["items"]

    @contextlib.contextmanager
    def audit_refused(self, action: str):
        """While active, the audit chain refuses to append one named action (as a failing audit store would)."""
        name = "cvt_" + uuid.uuid4().hex[:8]
        with self.vault.superuser() as su:
            su.execute(f"CREATE FUNCTION public.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
                       f" IF NEW.action = '{action}' THEN RAISE EXCEPTION 'audit store down (test)'; END IF; RETURN NEW; END $$")
            su.execute(f"CREATE TRIGGER {name} BEFORE INSERT ON consentvault.audit_event FOR EACH ROW EXECUTE FUNCTION public.{name}()")
        try:
            yield
        finally:
            with self.vault.superuser() as su:
                su.execute(f"DROP TRIGGER {name} ON consentvault.audit_event")
                su.execute(f"DROP FUNCTION public.{name}()")

    @contextlib.contextmanager
    def fail_reads(self, *names):
        """The deterministic failed-reads switch (confirmations.md section 13): each named read behaves as if the database
        read had failed."""
        testing = need("consentvault.testing", "fail_reads")
        added = [n for n in names if n not in testing]
        testing.update(added)
        try:
            yield
        finally:
            testing.difference_update(added)

    @contextlib.contextmanager
    def hold_steps(self, *names):
        """consentvault.testing.hold_steps: a named step leaves its job unfinished until the name is removed."""
        held = need("consentvault.testing", "hold_steps")
        added = [n for n in names if n not in held]
        held.update(added)
        try:
            yield
        finally:
            held.difference_update(added)

    @contextlib.contextmanager
    def override(self, name, value):
        """consentvault.testing.overrides: a numeric override by name (records.reveal_rate_limit, records.export_max_rows)."""
        ov = need("consentvault.testing", "overrides")
        had = ov.get(name, None)
        ov[name] = value
        try:
            yield
        finally:
            if had is None:
                ov.pop(name, None)
            else:
                ov[name] = had

    @contextlib.contextmanager
    def custody_down(self, *, allow_first: int = 0):
        """While active, the key custody refuses every unwrap (after ``allow_first`` calls) and counts the calls."""
        from consentvault.providers.errors import KeyProviderError

        custody, real, calls = self.vault.custody, self.vault.custody.unwrap, {"n": 0}

        def unwrap(org_id, wrapped):
            calls["n"] += 1
            if calls["n"] > allow_first:
                raise KeyProviderError("custody down (test)")
            return real(org_id, wrapped)

        custody.unwrap = unwrap
        try:
            yield calls
        finally:
            del custody.unwrap

    @contextlib.contextmanager
    def custody_counting(self):
        custody, real, calls = self.vault.custody, self.vault.custody.unwrap, {"n": 0}

        def unwrap(org_id, wrapped):
            calls["n"] += 1
            return real(org_id, wrapped)

        custody.unwrap = unwrap
        try:
            yield calls
        finally:
            del custody.unwrap

    def advance_clock(self, seconds: float):
        """Move the admin app's clock forward (cursor expiry, export expiry). The records call limit and the reveal-volume log
        count on the database's clock (migration 0064), so their rows move back by the same span: time passes there too."""
        self.offset += seconds
        self.vault.app._clock = lambda: time.time() + self.offset
        with self.vault.superuser() as su:
            for table in ("record_call", "record_reveal_log"):
                if su.execute("SELECT to_regclass(%s) AS t", (f"consentvault.{table}",)).fetchone()["t"] is not None:
                    su.execute(f"UPDATE consentvault.{table} SET at = at - make_interval(secs => %s)", (seconds,))


def digits_in(obj, needle: str) -> bool:
    return needle in json.dumps(obj, default=str)
