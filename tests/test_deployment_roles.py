"""The compose init script creates the owner and runtime roles, and the roles behave as documented."""

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest

from conftest import _pg_bin
from consentvault import db

SCRIPT = Path(__file__).resolve().parents[1] / "docker" / "initdb" / "10-roles.sh"


def test_init_script_makes_an_owner_that_migrates_and_a_runtime_role_that_only_appends(pg_server):
    psql = _pg_bin() / "psql"
    if not psql.exists():
        pytest.skip("psql not found next to the PostgreSQL binaries")
    port = pg_server["port"]
    name = "d_" + uuid.uuid4().hex[:10]
    admin = f"postgresql://postgres@127.0.0.1:{port}/postgres"
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
        for role in ("consentvault_owner", "consentvault_runtime"):
            c.execute(f"DROP ROLE IF EXISTS {role}")  # earlier runs in this cluster
    env = {**os.environ, "POSTGRES_USER": "postgres", "POSTGRES_DB": name, "CONSENTVAULT_OWNER_PASSWORD": "owner-pw",
           "CONSENTVAULT_APP_PASSWORD": "app-pw", "PGHOST": "127.0.0.1", "PGPORT": str(port),
           "PATH": f"{psql.parent}{os.pathsep}{os.environ['PATH']}"}
    done = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr

    with db.connect(f"postgresql://consentvault_owner@127.0.0.1:{port}/{name}") as owner:
        assert db.migrate(owner) == ["0001_init.sql"]
    with db.connect(f"postgresql://consentvault_runtime@127.0.0.1:{port}/{name}") as app:
        assert app.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
        with pytest.raises(psycopg.Error):
            app.execute("TRUNCATE consentvault.event")
        with pytest.raises(psycopg.Error):
            app.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
