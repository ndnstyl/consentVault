"""Migration 0004 up and down, the tables' shapes and the checks the database itself makes."""

import shutil
import uuid
from pathlib import Path

import psycopg
import pytest

from consentvault import db
from consentvault.sync.errors import CredentialError, SystemNotFoundError
from consentvault.sync.systems import bind_signal_credential, open_credentials, seal_credentials
from consentvault.tenancy.tokens import org_transaction

from .support import FakeCustody

MIGRATIONS = Path(__file__).resolve().parents[2] / "migrations"
TABLES = ("connected_system", "state_version", "outbox", "delivery", "inbound_signal", "redrive_run")


@pytest.fixture
def dsn4(raw_dsn, tmp_path):
    """A vault with migrations 0001 to 0004 only, so these tests do not depend on any later lane's migration."""
    for name in ("0001_init.sql", "0002_tenancy.sql", "0003_replay_guard.sql", "0004_sync.sql"):
        shutil.copy(MIGRATIONS / name, tmp_path / name)
    with db.connect(raw_dsn) as c:
        assert db.migrate(c, tmp_path) == ["0001_init.sql", "0002_tenancy.sql", "0003_replay_guard.sql", "0004_sync.sql"]
    return raw_dsn


def _functions(c) -> int:
    return c.execute("SELECT count(*) AS n FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
                     " WHERE n.nspname = 'consentvault' AND p.proname LIKE 'sync\\_%'").fetchone()["n"]


def test_down_then_up_round_trips(dsn4, super_dsn, tmp_path):
    with db.connect(dsn4) as c, db.connect(super_dsn) as su:
        assert _functions(c) == 20
        su.execute((MIGRATIONS / "down" / "0004_sync.sql").read_text())
        for t in TABLES:
            assert c.execute("SELECT to_regclass(%s) AS t", (f"consentvault.{t}",)).fetchone()["t"] is None
        assert _functions(c) == 0
        c.execute("DELETE FROM consentvault.schema_migration WHERE name = '0004_sync.sql'")
        assert db.migrate(c, tmp_path) == ["0004_sync.sql"]
        assert _functions(c) == 20


def test_down_refuses_while_delivery_history_exists(env, tmp_path):
    a = env.t.a
    env.add_system(a, "crm")
    with env.t.superuser() as su:
        with pytest.raises(psycopg.Error, match="down 0004 refused: the vault holds connected systems or delivery history"):
            su.execute((MIGRATIONS / "down" / "0004_sync.sql").read_text())
        su.execute("ROLLBACK")
        assert su.execute("SELECT to_regclass('consentvault.outbox') AS t").fetchone()["t"] is not None
        assert su.execute("SELECT count(*) AS n FROM consentvault.connected_system").fetchone()["n"] == 1


def test_down_run_as_a_row_filtered_role_changes_nothing(dsn4):
    with db.connect(dsn4) as owner:
        with pytest.raises(psycopg.Error):
            owner.execute((MIGRATIONS / "down" / "0004_sync.sql").read_text())
        owner.execute("ROLLBACK")
        assert owner.execute("SELECT to_regclass('consentvault.outbox') AS t").fetchone()["t"] is not None


def test_down_refuses_when_not_applied(raw_dsn, super_dsn):
    with db.connect(super_dsn) as su:
        su.execute("CREATE SCHEMA IF NOT EXISTS consentvault")
        with pytest.raises(psycopg.Error, match="0004 is not applied"):
            su.execute((MIGRATIONS / "down" / "0004_sync.sql").read_text())
        su.execute("ROLLBACK")


def test_every_table_is_row_level_secured_and_forced(dsn4):
    with db.connect(dsn4) as c:
        for t in TABLES:
            row = c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
                            (f"consentvault.{t}",)).fetchone()
            assert row == {"relrowsecurity": True, "relforcerowsecurity": True}, t
            pol = c.execute("SELECT count(*) AS n FROM pg_policies WHERE schemaname = 'consentvault' AND tablename = %s", (t,)).fetchone()["n"]
            assert pol == 1, t


def test_the_database_itself_refuses_a_non_https_endpoint_and_a_bad_shape(env):
    a = env.t.a
    base = ("INSERT INTO consentvault.connected_system (org_id, name, kind, endpoint, signature, contact_form, public_key,"
            " credentials_ct) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
    with env.t.operator() as o, org_transaction(o, env.t.admin_token(a.org_id)):
        for endpoint in ("http://crm.example.test/hook", "https://user:pw@crm.example.test/hook", "https://", "ftp://x"):
            with pytest.raises(psycopg.errors.CheckViolation):
                with o.transaction():
                    o.execute(base, (a.org_id, "x" + uuid.uuid4().hex[:6], "crm", endpoint, "hmac", "plaintext", None, b"c"))
        with pytest.raises(psycopg.errors.CheckViolation, match="public_key_shape"):  # an Ed25519 system needs its public key
            with o.transaction():
                o.execute(base, (a.org_id, "y", "crm", "https://crm.example.test/h", "ed25519", "plaintext", None, b"c"))
        with pytest.raises(psycopg.errors.CheckViolation):
            with o.transaction():
                o.execute(base, (a.org_id, "z", "pigeon", "https://crm.example.test/h", "hmac", "plaintext", None, b"c"))
        o.execute(base, (a.org_id, "ok", "crm", "https://crm.example.test/h?x=1#f", "hmac", "plaintext", None, b"c"))
        with pytest.raises(psycopg.errors.UniqueViolation):
            with o.transaction():
                o.execute(base, (a.org_id, "ok", "crm", "https://crm.example.test/h", "hmac", "plaintext", None, b"c"))


def test_the_outbox_refuses_impossible_rows(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.grant(a, "+15555552001")
    fp = env.fp(a, "+15555552001")
    with env.t.superuser() as su:
        row = su.execute("SELECT outbox_id FROM consentvault.outbox").fetchone()
        for sql in ("UPDATE consentvault.outbox SET status = 'waiting'",
                    "UPDATE consentvault.outbox SET next_attempt_at = NULL",  # pending needs a time
                    "UPDATE consentvault.outbox SET status = 'sent'",  # in flight needs a lease
                    "UPDATE consentvault.outbox SET status = 'dead'",  # finished needs an end
                    "UPDATE consentvault.outbox SET last_error_class = 'gremlins'",
                    "UPDATE consentvault.outbox SET version = 0",
                    "UPDATE consentvault.outbox SET contact_fp = 'abc'"):
            with pytest.raises(psycopg.errors.CheckViolation):
                su.execute(sql)
        with pytest.raises(psycopg.errors.UniqueViolation):  # the idempotency key of a push is unique
            su.execute("INSERT INTO consentvault.outbox (org_id, outbox_id, system_id, contact_fp, channel, purpose, version,"
                       " payload_ct, next_attempt_at) VALUES (%s, %s, %s, %s, 'sms', 'marketing', 1, %s, now())",
                       (a.org_id, uuid.uuid4(), s.system_id, fp, b"dup"))
        assert row["outbox_id"]


def test_a_signal_row_with_an_event_must_say_applied(env):
    a = env.t.a
    env.add_system(a, "crm")
    ev, _ = env.grant(a, "+15555552001")
    s = env.system(a, "crm")
    with env.t.superuser() as su:
        with pytest.raises(psycopg.errors.CheckViolation, match="event_iff_applied"):
            su.execute("INSERT INTO consentvault.inbound_signal (org_id, signal_id, system_id, contact_fp, channel, purpose,"
                       " claimed_state, resolution, event_id, external_ref_ct, external_ref_mac) VALUES (%s, %s, %s, %s, 'sms',"
                       " 'marketing', 'denied', 'no_change', %s, %s, %s)",
                       (a.org_id, uuid.uuid4(), s.system_id, env.fp(a, "+15555552001"), ev.event_id, b"x", "a" * 64))


def test_credentials_are_sealed_under_the_organisation_key_and_open_only_for_it(env):
    custody = FakeCustody(env.t.provider)
    a, b = env.t.a, env.t.b
    secret = b"k" * 32
    sealed = seal_credentials(custody, a.org_id, secret)
    assert secret not in sealed
    assert open_credentials(custody, a.org_id, "s", sealed) == secret
    with pytest.raises(CredentialError, match="cannot be opened"):
        open_credentials(custody, b.org_id, "s", sealed)  # another organisation's key
    with pytest.raises(CredentialError, match="cannot be opened"):
        open_credentials(custody, a.org_id, "s", sealed[:-1] + bytes([sealed[-1] ^ 1]))  # altered
    with pytest.raises(CredentialError, match="no signing credential"):
        open_credentials(custody, a.org_id, "s", None)
    for bad in (b"short", b"x" * 33):
        with pytest.raises(CredentialError):
            seal_credentials(custody, a.org_id, bad)


def test_binding_a_signal_credential_to_a_system(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    other = env.add_system(a, "dialer")
    with env.t.app() as c, org_transaction(c, env.t.admin_token(a.org_id)):
        bind_signal_credential(c, s.system_id, a.credential_id)
    with env.t.app() as c, org_transaction(c, env.t.token(a, scopes=("capture",))):
        assert c.execute("SELECT consentvault.sync_system_of_credential(%s) AS s", (a.credential_id,)).fetchone()["s"] == s.system_id
    with pytest.raises(SystemNotFoundError):  # a credential carries one system's signals, never two
        with env.t.app() as c, org_transaction(c, env.t.admin_token(a.org_id)):
            bind_signal_credential(c, other.system_id, a.credential_id)
    with pytest.raises(SystemNotFoundError):
        with env.t.app() as c, org_transaction(c, env.t.admin_token(a.org_id)):
            bind_signal_credential(c, uuid.uuid4(), a.credential_id)
    with pytest.raises(SystemNotFoundError):
        with env.t.app() as c, org_transaction(c, env.t.admin_token(a.org_id)):
            bind_signal_credential(c, other.system_id, uuid.uuid4())
