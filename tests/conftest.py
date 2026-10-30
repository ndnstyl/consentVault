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


def _dsn(port: int, dbname: str, user: str = "postgres") -> str:
    return f"postgresql://{user}@127.0.0.1:{port}/{dbname}"


OWNER_ROLE = "cv_test_owner"  # NOLOGIN: owns the database, the schema and everything the migrations make
MIGRATOR_ROLE = "cv_test_migrator"  # LOGIN, a member of the owner: migrations run under SET ROLE to the owner
OPERATOR_ROLE = "cv_test_console"  # LOGIN, a member of consentvault_console: the operator console's connection
TRIGGER_GUARD = Path(__file__).resolve().parents[1] / "docker" / "initdb" / "20-trigger-guard.sql"


def ensure_roles(port: int) -> None:
    """The cluster-wide roles a deployment's init script makes (docker/initdb/10-roles.sh), made as the superuser.

    The schema owner cannot log in and is neither a superuser nor BYPASSRLS (the tenancy migration refuses one); it is a
    member of consentvault_operator only so the migration can hand that role its functions. The migrator logs in and is
    a member of the owner whose login default is SET ROLE to the owner; the operator console logs in as a member of consentvault_console and owns nothing.
    """
    with psycopg.connect(_dsn(port, "postgres"), autocommit=True) as su:
        su.execute(
            "DO $$ BEGIN"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_app') THEN CREATE ROLE consentvault_app NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_worker') THEN CREATE ROLE consentvault_worker NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_operator') THEN CREATE ROLE consentvault_operator NOLOGIN BYPASSRLS; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_console') THEN CREATE ROLE consentvault_console NOLOGIN; END IF;"
            f" IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{OWNER_ROLE}') THEN CREATE ROLE {OWNER_ROLE} NOLOGIN IN ROLE consentvault_operator; END IF;"
            f" IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATOR_ROLE}') THEN CREATE ROLE {MIGRATOR_ROLE} LOGIN IN ROLE {OWNER_ROLE};"
            f"   ALTER ROLE {MIGRATOR_ROLE} SET role = '{OWNER_ROLE}'; END IF;"
            f" IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{OPERATOR_ROLE}') THEN CREATE ROLE {OPERATOR_ROLE} LOGIN IN ROLE consentvault_console; END IF;"
            " END $$")


def create_vault_database(port: int, name: str) -> None:
    """A database owned by the NOLOGIN owner, with the trigger guard installed by the superuser (as 20-trigger-guard.sql
    is at init)."""
    with psycopg.connect(_dsn(port, "postgres"), autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}" OWNER {OWNER_ROLE}')
    with psycopg.connect(_dsn(port, name), autocommit=True) as su:
        su.execute(TRIGGER_GUARD.read_text(encoding="utf-8"))


@pytest.fixture
def raw_dsn(pg_server):
    """A fresh empty database owned by the NOLOGIN schema owner; the DSN connects as the migrator."""
    port = pg_server["port"]
    ensure_roles(port)
    name = "t_" + uuid.uuid4().hex[:12]
    create_vault_database(port, name)
    return _dsn(port, name, MIGRATOR_ROLE)


@pytest.fixture
def super_dsn(raw_dsn):
    """The same database as the superuser: for out-of-band inspection and down migrations, never for the vault."""
    return raw_dsn.replace(f"{MIGRATOR_ROLE}@", "postgres@", 1)


def operator_dsn_for(dsn: str) -> str:
    """The operator console's login on the same database as ``dsn`` (the migrator's).

    A lane suite that applies only a subset of the migrations, without the role layout (0019), has no console grants:
    there the operator's connection is the migrator's, acting with the owner's rights as it did before the layout."""
    with psycopg.connect(dsn) as c:
        has_layout = c.execute("SELECT to_regclass('consentvault.schema_migration') IS NOT NULL AND EXISTS ("
                               " SELECT 1 FROM consentvault.schema_migration WHERE name = '0019_role_layout.sql')"
                               ).fetchone()[0]
    if not has_layout:
        return dsn
    rest = dsn.split("@", 1)[1]
    return f"postgresql://{OPERATOR_ROLE}@{rest}"


def superuser_of(conn: psycopg.Connection) -> psycopg.Connection:
    """A superuser connection to the database ``conn`` is on. With the trigger guard installed, only a superuser can
    switch a vault trigger off, so a test that simulates tampering below the triggers does it as one."""
    return db.connect(f"postgresql://postgres@{conn.info.host}:{conn.info.port}/{conn.info.dbname}")


@pytest.fixture
def dsn(raw_dsn):
    """A fresh database with migrations applied by the migrator (under SET ROLE to the schema owner)."""
    with db.connect(raw_dsn) as c:
        db.migrate(c)
    pin_as_superuser(raw_dsn)
    return raw_dsn


def pin_as_superuser(dsn: str) -> None:
    """Pin the guards the migrations made, as a deployment does after every migration run: pinning is a superuser's."""
    with psycopg.connect(dsn.replace(f"{MIGRATOR_ROLE}@", "postgres@", 1), autocommit=True) as su:
        su.execute("SELECT consentvault_guard.pin_guards()")


@pytest.fixture(autouse=True)
def _suite_migration_login(request, monkeypatch):
    """The suite keeps its migration login so tests can act as the schema owner; a deployment removes it after the
    migration run and the API refuses to start while one can log in. Every test but those marked migration_login_check
    sees the start check skip this one login by name (and only it)."""
    if request.node.get_closest_marker("migration_login_check"):
        return
    from consentvault import api

    real = api._migration_logins
    monkeypatch.setattr(api, "_migration_logins", lambda conn: [r for r in real(conn) if r != MIGRATOR_ROLE])


@pytest.fixture
def app_dsn(dsn, pg_server):
    """A DSN for a login role that is only a member of the runtime group role, the way a deployment runs."""
    role = "app_" + uuid.uuid4().hex[:10]
    with psycopg.connect(_dsn(pg_server["port"], "postgres"), autocommit=True) as su:
        su.execute(f'CREATE ROLE "{role}" LOGIN IN ROLE consentvault_app')
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


# ---- the run report the checkpoint's traceability stage reads ---------------------------------------------------------------
# With CONSENTVAULT_RUN_REPORT_OUT set (scripts/checkpoint.sh sets it for the python suite), the session writes every test's
# outcome there at the end: {"exitstatus": int, "tests": {"<node id>": "passed" | "failed" | "skipped"}}. The traceability
# test (CONSENTVAULT_RUN_REPORT_IN) fails any mapped test that did not pass in that run unless its requirement names who
# proves it elsewhere and the receipt that shows it.
RUN_REPORT_OUT = "CONSENTVAULT_RUN_REPORT_OUT"
_RUN_OUTCOMES: dict[str, str] = {}


def pytest_runtest_logreport(report):
    if report.when == "call" or report.outcome != "passed":
        prior = _RUN_OUTCOMES.get(report.nodeid)
        if prior != "failed":
            _RUN_OUTCOMES[report.nodeid] = report.outcome


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get(RUN_REPORT_OUT)
    if not out:
        return
    import json

    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"exitstatus": int(exitstatus), "tests": _RUN_OUTCOMES}, sort_keys=True))
