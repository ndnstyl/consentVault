"""Shared helpers for the evidence export tests: a pinned migration chain, two populated organisations with real
version-2 seals, a service wired to local stand-ins, and a runner for the exported verifier."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consentvault import db, disclosure as disc
from consentvault.evidence import (Actor, EvidenceSigner, ExportService, LocalEcdsaSigner, verifier_seal_versions)
from consentvault.ledger import HASH_VERSIONS, _canon_value, canonical_dumps, record_tenant_event
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy import crypto as tc
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.keys_protocol import WrappedKey
from consentvault.tenancy.tokens import TokenKey, mint_org_token, org_transaction

from isolation.harness import FakeKeyProvider, Org, Tenancy, create_org, make_login_role

REPO = Path(__file__).resolve().parents[2]
SEAM = Path(__file__).parent / "sql" / "0004_export_seam.sql"
PHONE = "+15555550142"
OTHER_PHONE = "+15555550199"
SEAL_COLUMNS = tuple(HASH_VERSIONS[2]) + ("prev_hash", "row_hash")


def pinned_migrations(target: Path) -> Path:
    """The real migration chain. The admin lane's export_job (0005) has landed, so the export tests run on it; the
    tenant ledger writer also needs the sync outbox (0004)."""
    target.mkdir(parents=True, exist_ok=True)
    for path in db.list_migrations(REPO / "migrations"):
        shutil.copyfile(path, target / path.name)
    return target


def seam_migrations(target: Path) -> Path:
    """The foundation plus the lane's own restatement of export_job (kept for the conformance test only)."""
    target.mkdir(parents=True, exist_ok=True)
    for name in ("0001_init.sql", "0002_tenancy.sql", "0003_replay_guard.sql"):
        shutil.copyfile(REPO / "migrations" / name, target / name)
    shutil.copyfile(SEAM, target / "0004_export_seam.sql")
    return target


def build_empty_tenancy(dsn: str, port: int) -> Tenancy:
    """Two active organisations in multi mode with no ledger rows (the harness's own build fills synthetic seals)."""
    dbname = dsn.rsplit("/", 1)[1]
    key = TokenKey("test-k1", os.urandom(32))
    provider = FakeKeyProvider()
    with db.connect(dsn) as owner:  # the migrator: these setup steps (and a seam chain) have no console grants
        owner.execute("SELECT consentvault.install_token_key(%s, %s)", (key.key_id, key.secret))
        home = owner.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
        owner.execute("SELECT consentvault.enable_multi_tenant()")
        a = create_org(owner, key, provider, "alpha")
        b = create_org(owner, key, provider, "bravo")
    app_dsn = make_login_role(port, dbname, "consentvault_app")
    super_dsn = f"postgresql://postgres@127.0.0.1:{port}/{dbname}"
    from conftest import operator_dsn_for

    return Tenancy(operator_dsn_for(dsn), super_dsn, app_dsn, key, TenantCrypto(provider), provider, a, b, home,
                   migrator_dsn=dsn)


def worker_dsn(t: Tenancy, port: int) -> str:
    return make_login_role(port, t.app_dsn.rsplit("/", 1)[1], "consentvault_worker")


def token(t: Tenancy, org: Org, scopes=("proof_read",)) -> str:
    return mint_org_token(t.key, org.org_id, scopes, credential_id=None)


def seal_event(t: Tenancy, org: Org, tsa, event_id: str) -> None:
    """A real version-2 seal: the digest over the columns the verifier pins, stamped by the throwaway authority."""
    with t.superuser() as su:
        row = su.execute("SELECT * FROM consentvault.event WHERE org_id = %s AND event_id = %s",
                         (org.org_id, event_id)).fetchone()
    digest = hashlib.sha256(canonical_dumps({c: _canon_value(row[c]) for c in SEAL_COLUMNS}).encode()).digest()
    with t.app() as app, org_transaction(app, token(t, org, ("capture", "gate_read"))):
        app.execute("INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token, gen_time)"
                    " VALUES (%s, 2, %s, %s, 'https://tsa.example.com', %s, %s)",
                    (event_id, list(SEAL_COLUMNS), digest, tsa.stamp(digest.hex()), datetime.now(timezone.utc)))


def populate(t: Tenancy, org: Org, tsa=None, *, other_contact: bool = True) -> None:
    """Wording (two versions under one label), a grant with attribution, a stop, a second person, seals, a log entry
    and a review for PHONE; the same PHONE is a contact of both organisations."""
    with t.app() as app, org_transaction(app, token(t, org, ("capture", "gate_read"))):
        first = disc.register(app, f"{org.name}: texts about your account. Reply STOP to end.", f"{org.name}-form",
                              "en", ["sms"], ["marketing"])
        org.disclosure = disc.register(app, f"{org.name}: texts about offers and your account. Reply STOP to end.",
                                       f"{org.name}-form", "en", ["sms"], ["marketing"])
        g = record_tenant_event(app, t.crypto, contact=PHONE, event_type="grant", channels=["sms"],
                                purposes=["marketing"], method="checkbox", origin="consumer",
                                disclosure_sha256=org.disclosure, page_url=f"https://{org.name}.example.com/signup",
                                client_ip="203.0.113.7", user_agent="Mozilla/5.0 test", session_ref=f"s-{org.name}",
                                payload=b'{"form":"signup"}', source_id=org.source_id, brand_ids=[org.brand_id],
                                attribution={"campaign": f"{org.name}-fall", "list": "spring"})
        s = record_tenant_event(app, t.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                purposes=["marketing"], method="keyword", origin="consumer")
        ids = [g.event_id, s.event_id]
        if other_contact:
            o = record_tenant_event(app, t.crypto, contact=OTHER_PHONE, event_type="grant", channels=["sms"],
                                    purposes=["marketing"], method="checkbox", origin="consumer",
                                    disclosure_sha256=first, source_id=org.source_id, brand_ids=[org.brand_id],
                                    attribution={"campaign": f"{org.name}-other"})
            ids.append(o.event_id)
        org.event_ids = ids
        fp = t.crypto.contact_fingerprint(org.org_id, "phone", PHONE)
        held = app.execute("SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE contact_fp = %s",
                           (fp,)).fetchone()
        dk = t.crypto.open_contact_key(org.org_id, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
        log_id, review_id = str(uuid.uuid4()), str(uuid.uuid4())
        app.execute("INSERT INTO consentvault.contact_log (contact_log_uuid, contact_kind, contact_fp, contact_ct,"
                    " channel, purpose, contacted_at, outcome) VALUES (%s, 'phone', %s, %s, 'sms', 'marketing', %s, 'sent')",
                    (log_id, fp, tc.encrypt_field(dk, org.org_id, log_id, "contact_norm", PHONE),
                     datetime.now(timezone.utc)))
        app.execute("INSERT INTO consentvault.review (review_uuid, kind, contact_kind, contact_fp, contact_ct,"
                    " message_ct, event_id) VALUES (%s, 'stop_message', 'phone', %s, %s, %s, %s)",
                    (review_id, fp, tc.encrypt_field(dk, org.org_id, review_id, "contact_norm", PHONE),
                     tc.encrypt_field(dk, org.org_id, review_id, "message", "please stop"), s.event_id))
    if tsa is not None:
        for eid in ids:
            seal_event(t, org, tsa, eid)


class FailingOnce:
    """A store that refuses its first put, then behaves like the wrapped store."""

    def __init__(self, inner, error):
        self.inner, self.error, self.failed = inner, error, False
        self.enforces_retention = inner.enforces_retention

    def put(self, *a, **kw):
        if not self.failed:
            self.failed = True
            raise self.error
        return self.inner.put(*a, **kw)

    def get(self, *a, **kw):
        return self.inner.get(*a, **kw)


def make_service(t: Tenancy, tmp: Path, *, signer=None, store=None, dispatch=None, clock=None) -> ExportService:
    return ExportService(
        connect=lambda: db.connect(t.app_dsn),
        mint_token=lambda org_id, scopes: mint_org_token(t.key, org_id, scopes, credential_id=None),
        crypto=t.crypto, signer=signer or LocalEcdsaSigner.generate("evidence-test", 1),
        store=store or LocalAppendOnlyEvidenceStore(tmp / "store"), link_secret=os.urandom(32),
        dispatch=dispatch, clock=clock)


def actor() -> Actor:
    return Actor("member", uuid.uuid4())


def unzip(package: bytes, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(__import__("io").BytesIO(package)) as zf:
        zf.extractall(out)
    return out


def run_verifier(bundle: Path, ca, pub: Path, *extra, anchors=True, t_anchor: str | None = None):
    cmd = [sys.executable, str(bundle / "verify.py"), "--cafile", str(ca), *extra]
    if pub is not None:
        cmd += ["--evidence-key", str(pub)]
    if t_anchor:
        cmd += ["--anchor", t_anchor]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(bundle))


def head_anchor(t: Tenancy, org: Org) -> str:
    with t.superuser() as su:
        h = su.execute("SELECT seq, row_hash FROM consentvault.event WHERE org_id = %s ORDER BY seq DESC LIMIT 1",
                       (org.org_id,)).fetchone()
    return f"{h['seq']}:{h['row_hash']}"
