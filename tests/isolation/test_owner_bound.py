"""A NOLOGIN, non-superuser schema owner, reached through a migrator login whose default role is the owner, migrates
once a superuser has made the group roles, and FORCE binds the owner's rights."""

import os
import uuid

import psycopg
import pytest

from consentvault import db
from consentvault.tenancy.tokens import TokenKey, mint_org_token, org_transaction


@pytest.fixture
def owner_dsn(pg_server):
    port = pg_server["port"]
    name, owner = "o_" + uuid.uuid4().hex[:10], "own_" + uuid.uuid4().hex[:10]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'CREATE DATABASE "{name}"')
        su.execute("DO $$ BEGIN"
                   " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_app') THEN CREATE ROLE consentvault_app NOLOGIN; END IF;"
                   " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_worker') THEN CREATE ROLE consentvault_worker NOLOGIN; END IF;"
                   " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_operator') THEN CREATE ROLE consentvault_operator NOLOGIN BYPASSRLS; END IF;"
                   " END $$")
        su.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_console')"
                   " THEN CREATE ROLE consentvault_console NOLOGIN; END IF; END $$")
        su.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_integrity')"
                   " THEN CREATE ROLE consentvault_integrity NOLOGIN; END IF; END $$")
        su.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_records_jobs')"
                   " THEN CREATE ROLE consentvault_records_jobs NOLOGIN; END IF; END $$")
        for group in ("consentvault_isolation_self_test", "consentvault_restore_drill"):
            su.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{group}')"
                       f" THEN CREATE ROLE {group} NOLOGIN; END IF; END $$")
        su.execute(f'CREATE ROLE "{owner}" NOLOGIN IN ROLE consentvault_operator')
        su.execute(f'CREATE ROLE "{owner}_m" LOGIN IN ROLE "{owner}"')
        su.execute(f'ALTER ROLE "{owner}_m" SET role = \'{owner}\'')
        su.execute(f'ALTER DATABASE "{name}" OWNER TO "{owner}"')
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/{name}", autocommit=True) as su:
        su.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    return f"postgresql://{owner}_m@127.0.0.1:{port}/{name}"


def test_a_non_superuser_owner_migrates_and_is_bound_by_row_level_security(owner_dsn):
    key = TokenKey("own-k", os.urandom(32))
    with db.connect(owner_dsn) as owner:
        assert owner.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
                             ).fetchone() == {"rolsuper": False, "rolbypassrls": False}
        assert db.migrate(owner) == [p.name for p in db.list_migrations(db.default_migrations_dir())]
        assert owner.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"] == 1  # home
        owner.execute("SELECT consentvault.install_token_key(%s, %s)", (key.key_id, key.secret))
        owner.execute("SELECT consentvault.enable_multi_tenant()")
        assert owner.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner.execute("INSERT INTO consentvault.organization (name) VALUES ('sneaky')")
        new_org = uuid.uuid4()
        with org_transaction(owner, mint_org_token(key, new_org, ["admin"], credential_id=None)):
            owner.execute("INSERT INTO consentvault.organization (org_id, name) VALUES (%s, 'created')", (new_org,))
            assert [r["name"] for r in owner.execute("SELECT name FROM consentvault.organization")] == ["created"]
        assert owner.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"] == 0
        ops = {r["proname"]: r["owner"] for r in owner.execute(
            "SELECT p.proname, pg_get_userbyid(p.proowner) AS owner FROM pg_proc p"
            " JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'"
            " AND p.proname IN ('resolve_credential', 'resolve_member', 'active_org_ids')")}
        assert set(ops.values()) == {"consentvault_operator"} and len(ops) == 3
        assert not owner.execute("SELECT has_schema_privilege('consentvault_operator', 'consentvault', 'CREATE') AS c"
                                 ).fetchone()["c"]
