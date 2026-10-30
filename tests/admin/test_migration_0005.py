"""The admin-plane migration: what it creates, that it re-applies cleanly, and that its down file never destroys records."""

import os
import re

import psycopg
import pytest

from consentvault import db

DOWN = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "down", "0005_admin.sql")
UP = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "0005_admin.sql")
TABLES = ("channel", "purpose", "invite", "policy", "policy_approval", "policy_attestation", "doc_checklist",
          "retention_policy", "connected_system", "export_job", "audit_event", "org_fingerprint_secret", "attestation_text",
          "rule_reference")


def tables(c):
    return {r["table_name"] for r in c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'consentvault'")}


def test_every_section_twelve_table_for_this_migration_exists_with_row_security(dsn):
    with db.connect(dsn) as c:
        assert set(TABLES) <= tables(c)
        for t in TABLES:
            if t in ("attestation_text", "rule_reference"):  # platform tables: no org_id, read-only
                assert c.execute("SELECT count(*) AS n FROM information_schema.columns WHERE table_schema = 'consentvault'"
                                 " AND table_name = %s AND column_name = 'org_id'", (t,)).fetchone()["n"] == 0
                continue
            r = c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
                          (f"consentvault.{t}",)).fetchone()
            assert (r["relrowsecurity"], r["relforcerowsecurity"]) == (True, True), t
            assert c.execute("SELECT count(*) AS n FROM information_schema.columns WHERE table_schema = 'consentvault'"
                             " AND table_name = %s AND column_name = 'org_id' AND is_nullable = 'NO'", (t,)).fetchone()["n"] == (
                0 if t == "audit_event" else 1), t  # the platform chain holds NULL org_id rows by design


def test_every_foreign_key_of_a_new_tenant_table_includes_org_id(dsn):
    with db.connect(dsn) as c:
        bad = []
        for t in TABLES:
            for r in c.execute("SELECT conname, pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE contype = 'f'"
                               " AND conrelid = %s::regclass", (f"consentvault.{t}",)):
                if t not in ("audit_event",) and "org_id" not in r["d"].split("REFERENCES")[0]:
                    bad.append((t, r["d"]))
        assert bad == []


def test_the_new_owner_rights_functions_are_owned_by_the_operator_and_not_executable_by_public(dsn):
    names = ("append_audit", "append_platform_audit", "audit_head", "platform_audit_head", "health_counts",
             "source_last_events", "invite_lookup", "session_memberships")
    with db.connect(dsn) as c:
        for n in names:
            r = c.execute("SELECT pg_get_userbyid(proowner) AS owner, has_function_privilege('public', oid, 'EXECUTE') AS pub"
                          " FROM pg_proc WHERE proname = %s AND pronamespace = 'consentvault'::regnamespace", (n,)).fetchone()
            assert r == {"owner": "consentvault_operator", "pub": False}, n


def test_every_new_owner_rights_function_reads_current_org_itself_or_is_a_named_pre_tenant_lookup(dsn):
    tenant_fns = ("append_audit", "audit_head", "health_counts", "source_last_events")
    pre_tenant = ("invite_lookup", "session_memberships")
    with db.connect(dsn) as c:
        for n in tenant_fns:
            src = c.execute("SELECT prosrc FROM pg_proc WHERE proname = %s AND pronamespace = 'consentvault'::regnamespace", (n,)).fetchone()["prosrc"]
            assert "current_org()" in src, n
            assert not re.search(r"\bp_org\b|p_org_id", src), n  # takes no organisation argument
        for n in pre_tenant:
            args = c.execute("SELECT pg_get_function_arguments(oid) AS a FROM pg_proc WHERE proname = %s"
                             " AND pronamespace = 'consentvault'::regnamespace", (n,)).fetchone()["a"]
            assert "org" not in args, n


def test_the_down_file_reverses_a_pristine_apply_and_the_migration_applies_again(raw_dsn, super_dsn, tmp_path):
    # only the migrations up to this one, so a later lane's migration does not stand in the way of this file's down
    mig = os.path.join(os.path.dirname(UP))
    for n in ("0001_init.sql", "0002_tenancy.sql", "0003_replay_guard.sql", "0005_admin.sql"):
        (tmp_path / n).write_text(open(os.path.join(mig, n)).read())
    with db.connect(raw_dsn) as c:
        assert db.migrate(c, tmp_path)[-1] == "0005_admin.sql"
        assert set(TABLES) <= tables(c)
    with db.connect(super_dsn) as su:
        su.execute(open(DOWN).read())
        assert not (set(TABLES) & tables(su))
        for col in ("member_id", "email_norm"):
            assert su.execute("SELECT count(*) AS n FROM information_schema.columns WHERE table_schema = 'consentvault'"
                              " AND table_name = 'member' AND column_name = %s", (col,)).fetchone()["n"] == 0
        assert "developer" not in su.execute("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint"
                                             " WHERE conname = 'member_role_check'").fetchone()["d"]
        su.execute("DELETE FROM consentvault.schema_migration WHERE name = '0005_admin.sql'")
    with db.connect(raw_dsn) as c:
        assert db.migrate(c, tmp_path) == ["0005_admin.sql"]
        assert set(TABLES) <= tables(c)


def test_the_down_file_refuses_while_any_admin_record_exists(vault):
    with vault.superuser() as su:
        vault.create_org("Acme", "boss@acme.example")
        with pytest.raises(psycopg.Error, match="refused"):
            su.execute(open(DOWN).read())
        su.execute("ROLLBACK")
        assert "audit_event" in tables(su)


def test_the_down_file_refuses_a_filtered_role(vault):
    with vault.operator() as o:  # the schema owner is bound by row security: it must get an error, not a count of zero
        with pytest.raises(psycopg.Error):
            o.execute(open(DOWN).read())
        o.execute("ROLLBACK")
    with vault.superuser() as su:
        assert "audit_event" in tables(su)
