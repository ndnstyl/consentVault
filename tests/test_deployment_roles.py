"""The compose init scripts create the role layout, and the roles behave as documented: a NOLOGIN owner owns the schema,
the migrator migrates as it, the operator console login owns nothing, the runtime role only appends, and nobody but a
superuser switches a vault trigger off."""

import os
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest

from conftest import _pg_bin
from consentvault import api, db

INITDB = Path(__file__).resolve().parents[1] / "docker" / "initdb"
SCRIPT = INITDB / "10-roles.sh"
GUARD = INITDB / "20-trigger-guard.sql"
LOGINS = ("consentvault_migrator", "consentvault_operator_login", "consentvault_runtime")


def test_init_scripts_make_a_nologin_owner_a_migrator_an_operator_login_and_a_runtime_role(pg_server):
    psql = _pg_bin() / "psql"
    if not psql.exists():
        pytest.skip("psql not found next to the PostgreSQL binaries")
    port = pg_server["port"]
    name = "d_" + uuid.uuid4().hex[:10]
    admin = f"postgresql://postgres@127.0.0.1:{port}/postgres"
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
        for role in LOGINS + ("consentvault_owner",):
            c.execute(f"DROP ROLE IF EXISTS {role}")  # earlier runs in this cluster
    env = {**os.environ, "POSTGRES_USER": "postgres", "POSTGRES_DB": name, "CONSENTVAULT_MIGRATOR_PASSWORD": "mig-pw",
           "CONSENTVAULT_OPERATOR_PASSWORD": "op-pw", "CONSENTVAULT_APP_PASSWORD": "app-pw", "PGHOST": "127.0.0.1",
           "PGPORT": str(port), "PATH": f"{psql.parent}{os.pathsep}{os.environ['PATH']}"}
    done = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    # the Docker entrypoint runs *.sql files the same way: psql as the superuser against POSTGRES_DB
    done = subprocess.run([str(psql), "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", name, "-f", str(GUARD)],
                          env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr

    with psycopg.connect(admin, autocommit=True) as c:
        owner = c.execute("SELECT rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'consentvault_owner'"
                          ).fetchone()
        assert owner == (False, False, False)
        with pytest.raises(psycopg.OperationalError, match="not permitted to log in"):
            psycopg.connect(f"postgresql://consentvault_owner@127.0.0.1:{port}/{name}").close()

    with db.connect(f"postgresql://consentvault_migrator@127.0.0.1:{port}/{name}") as m:
        assert db.migrate(m) == [p.name for p in db.list_migrations(db.default_migrations_dir())]
        assert m.execute("SELECT session_user AS s, current_user AS c").fetchone() == {
            "s": "consentvault_migrator", "c": "consentvault_owner"}
        assert m.execute("SELECT count(*) AS n FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                         " WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p', 'S', 'v')"
                         " AND pg_get_userbyid(c.relowner) <> 'consentvault_owner'").fetchone()["n"] == 0
        # FORCE row-level security binds the owner's rights too: in multi mode with no tenant token it sees no organisation
        assert m.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"] == 1
        m.execute("SELECT consentvault.enable_multi_tenant()")
        assert m.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="trigger guard"):
            m.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
    with db.connect(f"postgresql://consentvault_operator_login@127.0.0.1:{port}/{name}") as o:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            o.execute("ALTER TABLE consentvault.contact_key DISABLE TRIGGER contact_key_hold_guard")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            o.execute("DELETE FROM consentvault.contact_key")
    with db.connect(f"postgresql://consentvault_runtime@127.0.0.1:{port}/{name}") as app:
        assert app.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
        with pytest.raises(psycopg.Error):
            app.execute("TRUNCATE consentvault.event")
        with pytest.raises(psycopg.Error):
            app.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
    # the multi-tenant start check refuses while the migration run is still open: the guards unpinned, the migration
    # login able to log in. The deployment closes it as the superuser (docs/deployment.md); then the layout passes.
    runtime = f"postgresql://consentvault_runtime@127.0.0.1:{port}/{name}"
    with pytest.raises(api.StartupRefusedError, match="not pinned"):
        api.startup_check(runtime)
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/{name}", autocommit=True) as su:
        su.execute("SELECT consentvault_guard.pin_guards()")
    with pytest.raises(api.StartupRefusedError, match="migration login consentvault_migrator"):
        api.startup_check(runtime)
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("ALTER ROLE consentvault_migrator NOLOGIN")
    api.startup_check(runtime)
