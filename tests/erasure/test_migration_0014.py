"""The lifecycle migration: tables under forced row security, and a down file that refuses while a hold or a
destruction record exists and otherwise reverses cleanly."""

import os

import psycopg
import pytest

from consentvault import db

DOWN = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "down", "0014_erasure_holds.sql")
TABLES = ("legal_hold", "erasure_request", "offboarding_request", "destruction_record", "legal_process",
          "operator_access")


def _down(super_dsn):
    with psycopg.connect(super_dsn, autocommit=True) as su:
        su.execute(open(DOWN, encoding="utf-8").read())


def test_every_new_tenant_table_forces_row_security_and_restore_run_is_owner_only(dsn, super_dsn):
    with db.connect(super_dsn) as c:
        for t in TABLES:
            r = c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
                          (f"consentvault.{t}",)).fetchone()
            assert (r["relrowsecurity"], r["relforcerowsecurity"]) == (True, True), t
        grants = c.execute("SELECT grantee FROM information_schema.table_privileges WHERE table_schema = 'consentvault'"
                           " AND table_name = 'restore_run' AND grantee <> current_user AND grantee <> 'cv_test_owner'"
                           ).fetchall()
        # no tenant role reads or writes it; the operator console (once the owner's own connection) holds the restore's
        # select, insert and update and nothing more
        assert {(g["grantee"]) for g in grants} <= {"consentvault_console"}
        console = {r["privilege_type"] for r in c.execute(
            "SELECT privilege_type FROM information_schema.table_privileges WHERE table_schema = 'consentvault'"
            " AND table_name = 'restore_run' AND grantee = 'consentvault_console'").fetchall()}
        assert console <= {"SELECT", "INSERT", "UPDATE"}


def test_the_down_file_refuses_while_a_hold_exists_and_reverses_an_empty_install(env):
    t = env.t
    from consentvault.tenancy import holds

    with env.admin(t.a) as ctx:
        holds.place_hold_member(ctx, {"scope": "org", "reason": "keep"}, ledger=env.ledger, crypto=t.crypto)
    with pytest.raises(psycopg.errors.RaiseException, match="legal holds are recorded"):
        _down(t.super_dsn)
    with db.connect(t.super_dsn) as su:
        assert su.execute("SELECT to_regclass('consentvault.legal_hold') IS NOT NULL AS x").fetchone()["x"]


def test_the_down_file_reverses_an_empty_install(dsn, super_dsn):
    _down(super_dsn)
    with db.connect(super_dsn) as c:
        assert c.execute("SELECT to_regclass('consentvault.legal_hold') AS x").fetchone()["x"] is None
        assert c.execute("SELECT to_regprocedure('consentvault.evidence_org_ids()') IS NOT NULL AS x").fetchone()["x"]
