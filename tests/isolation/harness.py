"""Two synthetic organisations in one vault, populated through the runtime role, for the isolation suites.

Shared by tests/isolation/ and tests/test_ledger_tenancy.py. Every tenant table holds at least one row for each
organisation, so a query that leaks shows a row from the other one instead of passing on an empty table.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from consentvault import db, disclosure as disc
from consentvault.ledger import record_tenant_event
from consentvault.tenancy import crypto as tc
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.errors import KeyProviderError
from consentvault.tenancy.keys_protocol import WrappedKey
from consentvault.tenancy.tokens import TokenKey, mint_org_token, org_transaction
# The registry of tenant tables and views (and the platform tables left out of it) is the product's, read by the nightly
# isolation self-test too, so the suite and the job can never cover different tables.
from consentvault.isolation import PLATFORM_TABLES, tenant_tables, tenant_views  # noqa: F401

# The tables the harness fills for both synthetic orgs (the foundation ledger). The full tenant list is read from the
# catalog by tenant_tables(), so a lane that adds a table with an org_id column is covered without editing this file.
FILLED_TABLES = ("organization", "brand", "capture_source", "credential", "member", "org_key", "contact_key", "event",
                 "disclosure", "seal", "chain_head", "contact_log", "review")
PHONE = "+15555550142"  # the same person is a contact of both organisations


class FakeKeyProvider:
    """In-memory KeyProvider: one AES-GCM wrap key and one fingerprint secret per organisation."""

    def __init__(self) -> None:
        self.wrap_keys: dict[uuid.UUID, bytes] = {}
        self.fp_secrets: dict[uuid.UUID, bytes] = {}
        self.display_keys: dict[uuid.UUID, bytes] = {}
        self.calls: dict[str, int] = {"wrap_data_key": 0, "unwrap_data_key": 0, "fingerprint_secret": 0}

    def add_org(self, org_id: uuid.UUID) -> None:
        self.wrap_keys[org_id] = os.urandom(32)
        self.fp_secrets[org_id] = os.urandom(32)

    def _key(self, org_id: uuid.UUID) -> bytes:
        try:
            return self.wrap_keys[org_id]
        except KeyError:
            raise KeyProviderError(f"no key for organisation {org_id}") from None

    def wrap_data_key(self, org_id, data_key):
        self.calls["wrap_data_key"] += 1
        nonce = os.urandom(12)
        return WrappedKey(nonce + AESGCM(self._key(org_id)).encrypt(nonce, data_key, str(org_id).encode()), 1)

    def unwrap_data_key(self, org_id, wrapped):
        self.calls["unwrap_data_key"] += 1
        blob = wrapped.ciphertext
        return AESGCM(self._key(org_id)).decrypt(blob[:12], blob[12:], str(org_id).encode())

    def display_key(self, org_id):
        self._key(org_id)  # an organisation this provider does not know has no display key either
        return self.display_keys.setdefault(org_id, os.urandom(32))

    def fingerprint_secret(self, org_id):
        self.calls["fingerprint_secret"] += 1
        try:
            return self.fp_secrets[org_id]
        except KeyError:
            raise KeyProviderError(f"no fingerprint secret for organisation {org_id}") from None


@dataclass
class Org:
    name: str
    org_id: uuid.UUID
    credential_id: uuid.UUID
    source_id: uuid.UUID
    brand_id: uuid.UUID
    event_ids: list[str] = field(default_factory=list)
    disclosure: str = ""


@dataclass
class Tenancy:
    operator_dsn: str
    super_dsn: str
    app_dsn: str
    key: TokenKey
    crypto: TenantCrypto
    provider: FakeKeyProvider
    a: Org
    b: Org
    home: uuid.UUID
    migrator_dsn: str = ""
    projection_dsn: str = ""   # a login that is a member of consentvault_projection only, never of the app group

    def token(self, org: Org, scopes=("capture", "gate_read"), **kw) -> str:
        return mint_org_token(self.key, org.org_id, scopes, credential_id=str(org.credential_id), **kw)

    def app(self) -> psycopg.Connection:
        return db.connect(self.app_dsn)

    def operator(self) -> psycopg.Connection:
        """The operator console's login (a member of consentvault_console): owns nothing, holds only the console's
        grants, bound by row-level security like everyone else."""
        return db.connect(self.operator_dsn)

    def migrator(self) -> psycopg.Connection:
        """The migration login: a member of the NOLOGIN schema owner, so it acts with the owner's rights (setup steps
        such as installing the token key). Bound by row-level security (FORCE) and refused trigger changes."""
        return db.connect(self.migrator_dsn)

    def superuser(self) -> psycopg.Connection:
        """Out-of-band inspection only (a DBA's view): bypasses row security. The vault never runs as this."""
        return db.connect(self.super_dsn)

    def token_for_home(self, scopes=("capture", "gate_read")) -> str:
        return mint_org_token(self.key, self.home, scopes, credential_id=None)

    def admin_token(self, org_id) -> str:
        return mint_org_token(self.key, org_id, ["admin"], credential_id=None)


def make_login_role(port: int, dbname: str, group: str) -> str:
    role = "t_" + uuid.uuid4().hex[:10]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'CREATE ROLE "{role}" LOGIN IN ROLE {group}')
    return f"postgresql://{role}@127.0.0.1:{port}/{dbname}"


def create_org(conn: psycopg.Connection, key: TokenKey, provider: FakeKeyProvider, name: str) -> Org:
    """Create an organisation the way the admin path must in multi mode: inside a token for the new org's id."""
    org_id = uuid.uuid4()
    with org_transaction(conn, mint_org_token(key, org_id, ["admin"], credential_id=None)):
        org = _fill_org(conn, provider, name, org_id)
    return org


def _fill_org(owner: psycopg.Connection, provider: FakeKeyProvider, name: str, org_id: uuid.UUID) -> Org:
    owner.execute("INSERT INTO consentvault.organization (org_id, name) VALUES (%s, %s)", (org_id, name))
    provider.add_org(org_id)
    owner.execute("INSERT INTO consentvault.org_key (org_id, version, kms_key_ref) VALUES (%s, 1, %s)",
                  (org_id, f"test-kms/{name}"))
    brand = owner.execute("INSERT INTO consentvault.brand (org_id, display_name) VALUES (%s, %s) RETURNING brand_id",
                          (org_id, f"{name} Brand")).fetchone()["brand_id"]
    source = owner.execute(
        "INSERT INTO consentvault.capture_source (org_id, kind, brand_ids, allowed_origins)"
        " VALUES (%s, 'form', %s, %s) RETURNING source_id",
        (org_id, [brand], [f"https://{name}.example.com"])).fetchone()["source_id"]
    cred = owner.execute(
        "INSERT INTO consentvault.credential (org_id, source_id, kind, alg, public_key, scope)"
        " VALUES (%s, %s, 'jwt_public_key', 'ES256', %s, ARRAY['capture']) RETURNING credential_id",
        (org_id, source, f"-----BEGIN PUBLIC KEY----- {name} -----END PUBLIC KEY-----")).fetchone()["credential_id"]
    owner.execute("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role)"
                  " VALUES (%s, 'https://idp.example.com', %s, 'admin')", (org_id, f"user_{name}"))
    return Org(name, org_id, cred, source, brand)


def _populate(t: Tenancy, org: Org) -> None:
    """Fill the org's ledger tables through the runtime role, inside its own tenant."""
    with t.app() as app, org_transaction(app, t.token(org)):
        org.disclosure = disc.register(app, f"{org.name}: texts about your account. Reply STOP to end.",
                                       f"{org.name}-form", "en", ["sms"], ["marketing"])
        g = record_tenant_event(app, t.crypto, contact=PHONE, event_type="grant", channels=["sms"],
                                purposes=["marketing"], method="checkbox", origin="consumer",
                                disclosure_sha256=org.disclosure, page_url=f"https://{org.name}.example.com/signup",
                                client_ip="203.0.113.7", user_agent="Mozilla/5.0 test", session_ref=f"s-{org.name}",
                                payload=b'{"form":"signup"}', source_id=org.source_id, brand_ids=[org.brand_id],
                                attribution={"campaign": f"{org.name}-fall"})
        s = record_tenant_event(app, t.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                purposes=["marketing"], method="keyword", origin="consumer")
        org.event_ids = [g.event_id, s.event_id]
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
        app.execute("INSERT INTO consentvault.chain_head (seq, row_hash, sink) VALUES (%s, %s, 'test')",
                    (s.seq, s.row_hash))
        # seals are written by the seal job; a synthetic one is enough for isolation
        app.execute("INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token)"
                    " VALUES (%s, 2, ARRAY['seq'], %s, 'https://tsa.example.com', %s)",
                    (g.event_id, os.urandom(32), b"synthetic-token"))


def build_tenancy(dsn: str, port: int) -> Tenancy:
    """Two active organisations, A and B, in multi mode, plus the home organisation the migration made.

    ``dsn`` is the migrator's (a member of the NOLOGIN schema owner): it installs the token key and switches the vault to
    multi mode. The organisations are created on the operator console's login, the way the console creates them. Every
    login is bound by row-level security throughout.
    """
    from conftest import operator_dsn_for

    dbname = dsn.rsplit("/", 1)[1]
    key = TokenKey("test-k1", os.urandom(32))
    provider = FakeKeyProvider()
    operator_dsn = operator_dsn_for(dsn)
    with db.connect(dsn) as migrator:
        me = migrator.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
        assert me == {"rolsuper": False, "rolbypassrls": False}, "the isolation suite must run under a bound migrator"
        migrator.execute("SELECT consentvault.install_token_key(%s, %s)", (key.key_id, key.secret))
        home = migrator.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
        migrator.execute("SELECT consentvault.enable_multi_tenant()")
        if migrator.execute("SELECT to_regprocedure('consentvault.grant_projection_privileges()') IS NOT NULL AS has").fetchone()["has"]:
            migrator.execute("SELECT consentvault.grant_projection_privileges()")   # multi mode withdrew some of the app's privileges (a partial-schema suite has no projection role)
    with db.connect(operator_dsn) as operator:
        me = operator.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
        assert me == {"rolsuper": False, "rolbypassrls": False}, "the operator console must be bound by row security"
        a = create_org(operator, key, provider, "alpha")
        b = create_org(operator, key, provider, "bravo")
    app_dsn = make_login_role(port, dbname, "consentvault_app")
    super_dsn = f"postgresql://postgres@127.0.0.1:{port}/{dbname}"
    projection_dsn = make_login_role(port, dbname, "consentvault_projection")
    t = Tenancy(operator_dsn, super_dsn, app_dsn, key, TenantCrypto(provider), provider, a, b, home, migrator_dsn=dsn,
                projection_dsn=projection_dsn)
    _populate(t, a)
    _populate(t, b)
    return t


def expired_token(t: Tenancy, org: Org) -> str:
    past = (datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp()
    return t.token(org, now=past)
