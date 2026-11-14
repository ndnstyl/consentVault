"""The key-destruction ledger a cloud key provider keeps in Postgres (migration 0028), never on a task's disk.

Platform table, owner-only, forced row security with no policy: every read and write goes through two functions owned
by the operator role. Only the operator console (the onboarding and key-lifecycle logins) may write; the runtime and
worker logins may read, so the data path can tell a destroyed key from a missing one.
"""

import psycopg
import pytest

from consentvault import db
from consentvault.providers.errors import KeyProviderError
from consentvault.providers.key_ledger import PostgresKeyLedgerStore

from .harness import make_login_role


def test_the_operator_console_writes_and_reads_the_ledger(tenancy):
    store = PostgresKeyLedgerStore(lambda: db.connect(tenancy.operator_dsn))
    assert store.read() == {}
    store.update("org-a", lambda e: e.update(scheduled_at="2026-01-01T00:00:00+00:00", keys={"1": "k1"}))
    store.update("org-a", lambda e: e.setdefault("destroyed_versions", []).append(1))
    store.update("org-b", lambda e: e.update(destroyed_at=None))
    assert store.read() == {"org-a": {"scheduled_at": "2026-01-01T00:00:00+00:00", "keys": {"1": "k1"},
                                      "destroyed_versions": [1]}, "org-b": {"destroyed_at": None}}


def test_the_runtime_and_worker_logins_read_but_never_write(tenancy, pg_server):
    PostgresKeyLedgerStore(lambda: db.connect(tenancy.operator_dsn)).update("org-a", lambda e: e.update(x=1))
    dbname = tenancy.app_dsn.rsplit("/", 1)[1]
    for dsn in (tenancy.app_dsn, make_login_role(pg_server["port"], dbname, "consentvault_worker")):
        store = PostgresKeyLedgerStore(lambda dsn=dsn: db.connect(dsn))
        assert store.read() == {"org-a": {"x": 1}}
        with pytest.raises(KeyProviderError, match="cannot be written"):
            store.update("org-a", lambda e: e.update(x=2))


def test_the_table_is_owner_only_with_forced_row_security(tenancy):
    with tenancy.superuser() as su:
        row = su.execute("SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c"
                         " WHERE c.oid = 'consentvault.kms_key_ledger'::regclass").fetchone()
        assert (row["relrowsecurity"], row["relforcerowsecurity"]) == (True, True)
        grants = su.execute("SELECT grantee FROM information_schema.role_table_grants"
                            " WHERE table_schema = 'consentvault' AND table_name = 'kms_key_ledger'"
                            " AND grantee <> (SELECT pg_get_userbyid(relowner) FROM pg_class"
                            " WHERE oid = 'consentvault.kms_key_ledger'::regclass)").fetchall()
        assert {g["grantee"] for g in grants} == {"consentvault_operator"}  # the NOLOGIN owner of the two functions
    for dsn in (tenancy.app_dsn, tenancy.operator_dsn):
        with db.connect(dsn) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM consentvault.kms_key_ledger")


def test_an_entry_that_is_not_an_object_or_an_unsafe_org_ref_is_refused(tenancy):
    with db.connect(tenancy.operator_dsn) as conn:
        for org, entry in (("org-a", "[1]"), ("../x", "{}"), ("", "{}")):
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                conn.execute("SELECT consentvault.kms_key_ledger_write(%s, %s::jsonb)", (org, entry))


def test_a_write_that_would_undo_a_destruction_is_refused(tenancy):
    store = PostgresKeyLedgerStore(lambda: db.connect(tenancy.operator_dsn))
    store.update("org-a", lambda e: e.update(destroyed_at="2026-02-01T00:00:00+00:00", destroyed_versions=[1, 2]))
    for change in (lambda e: e.update(destroyed_at=None), lambda e: e.pop("destroyed_at"),
                   lambda e: e.update(destroyed_at="2026-03-01T00:00:00+00:00"),
                   lambda e: e.update(destroyed_versions=[2]), lambda e: e.pop("destroyed_versions")):
        with pytest.raises(KeyProviderError, match="cannot be written"):
            store.update("org-a", change)
    store.update("org-a", lambda e: e["destroyed_versions"].append(3))  # adding is allowed
    assert store.read()["org-a"]["destroyed_versions"] == [1, 2, 3]
