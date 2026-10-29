import os
import shutil
import socket
import subprocess
import tempfile
import uuid
from pathlib import Path

import psycopg
import pytest

from consentvault import db


def _pg_bin() -> Path:
    env = os.environ.get("PG_BIN")
    if env:
        return Path(env)
    if shutil.which("pg_config"):
        out = subprocess.run(["pg_config", "--bindir"], capture_output=True, text=True, check=True)
        return Path(out.stdout.strip())
    found = shutil.which("initdb")
    if found:
        return Path(found).parent
    raise RuntimeError("PostgreSQL binaries not found: set PG_BIN, or put pg_config or initdb on PATH")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def pg_server():
    bindir = _pg_bin()
    root = Path(tempfile.mkdtemp(prefix="consentvault-pg-"))
    data = root / "data"
    port = _free_port()
    subprocess.run(
        [str(bindir / "initdb"), "-D", str(data), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--locale=C"],
        check=True, capture_output=True,
    )
    started = False
    try:
        subprocess.run(
            [str(bindir / "pg_ctl"), "start", "-w", "-t", "60", "-D", str(data), "-l", str(root / "pg.log"),
             "-o", f"-p {port} -k {root} -c listen_addresses=127.0.0.1 -c fsync=off"],
            check=True, capture_output=True,
        )
        started = True
        yield {"port": port}
    finally:
        if started:
            subprocess.run(
                [str(bindir / "pg_ctl"), "stop", "-m", "immediate", "-w", "-D", str(data)],
                check=True, capture_output=True,
            )
        shutil.rmtree(root, ignore_errors=True)


def _dsn(port: int, dbname: str) -> str:
    return f"postgresql://postgres@127.0.0.1:{port}/{dbname}"


@pytest.fixture
def raw_dsn(pg_server):
    """A fresh empty database."""
    name = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(_dsn(pg_server["port"], "postgres"), autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    return _dsn(pg_server["port"], name)


@pytest.fixture
def dsn(raw_dsn):
    """A fresh database with migrations applied."""
    with db.connect(raw_dsn) as c:
        db.migrate(c)
    return raw_dsn


@pytest.fixture
def app_dsn(dsn, pg_server):
    """A DSN for a login role that is only a member of the runtime group role, the way a deployment runs."""
    role = "app_" + uuid.uuid4().hex[:10]
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(f'CREATE ROLE "{role}" LOGIN IN ROLE consentvault_app')
    return f"postgresql://{role}@127.0.0.1:{pg_server['port']}/{dsn.rsplit('/', 1)[1]}"


@pytest.fixture
def app_conn(app_dsn):
    c = db.connect(app_dsn)
    yield c
    c.close()


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    yield c
    c.close()


@pytest.fixture
def disclosure(conn):
    from consentvault import disclosure as d

    return d.register(conn, "I agree to be contacted by text.", "test-form", "en", ["sms"], ["marketing"])
