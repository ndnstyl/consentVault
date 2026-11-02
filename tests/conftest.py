import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import psycopg
import psycopg.rows
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


OWNER_FILE = "owner.pid"
CLUSTER_PREFIXES = ("consentvault-pg-", "consentvault-pgsetup-", "cv-roundtrip-")
LEGACY_STALE_SECONDS = 2 * 3600


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def claim_cluster(root: Path) -> None:
    """Mark a throwaway cluster folder with the pid of the test process that owns it. pg_ctl daemonizes the server, so a
    test run killed before its teardown leaves the server running with no owner; the next run's sweep stops it by this mark."""
    (root / OWNER_FILE).write_text(str(os.getpid()))


def _legacy_clients(data: Path) -> int | None:
    """Client connections on an unmarked cluster's server (left by a run older than the owner mark), or None if unreachable."""
    lines = (data / "postmaster.pid").read_text().splitlines()
    port, sockdir = lines[3].strip(), lines[4].strip()
    try:
        with psycopg.connect(host=sockdir, port=port, user="postgres", dbname="postgres", connect_timeout=5) as su:
            return su.execute("SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'"
                              " AND pid <> pg_backend_pid()").fetchone()[0]
    except psycopg.Error:
        return None


def sweep_stale_clusters(bindir: Path, tmp: Path | None = None, *, now: float | None = None) -> list[str]:
    """Stop and delete every throwaway cluster whose owning test process is gone. A folder with an owner mark is stale when that
    process no longer exists; an unmarked folder (from before the mark) only when it is over two hours old and its server, if
    running, has no client connections. A server that will not stop is a loud error naming its folder. Returns what was removed."""
    tmp = Path(tmp or tempfile.gettempdir())
    now = time.time() if now is None else now
    removed = []
    for root in sorted(p for prefix in CLUSTER_PREFIXES for p in tmp.glob(prefix + "*") if p.is_dir()):
        data, mark = root / "data", root / OWNER_FILE
        pidfile = data / "postmaster.pid"
        try:
            running = pidfile.exists() and _alive(int(pidfile.read_text().splitlines()[0]))
            if mark.exists():
                if _alive(int(mark.read_text().strip() or "0")):
                    continue
            elif now - root.stat().st_mtime < LEGACY_STALE_SECONDS or (running and _legacy_clients(data) != 0):
                continue
        except (OSError, ValueError, IndexError):
            continue  # loud-failure-exempt: a folder mid-creation or mid-removal by its own live run is not ours to judge
        if running:
            r = subprocess.run([str(bindir / "pg_ctl"), "stop", "-m", "immediate", "-w", "-t", "30", "-D", str(data)],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0 and pidfile.exists():
                raise RuntimeError(f"a stale test postgres in {root} (its test run is gone) would not stop: "
                                   f"pg_ctl exit {r.returncode}: {(r.stdout + r.stderr).strip()}")
        _remove_cluster_folder(root)
        removed.append(str(root))
    if removed:
        print(f"stopped and removed {len(removed)} stale test postgres cluster(s): {removed}", file=sys.stderr)
    return removed


START_DEADLINE_SECONDS = 60
START_ATTEMPTS = 2


def _show_log(root: Path, why: str) -> str:
    """Print the server log to stderr (it is deleted with the folder right after) and return its text."""
    log = root / "pg.log"
    text = log.read_text(errors="replace") if log.exists() else "(no server log was written)"
    print(f"--- postgres start failed ({why}); server log {log} ---\n{text}\n--- end of server log ---", file=sys.stderr)
    return text


def start_cluster(bindir: Path, root: Path, data: Path, *, deadline: int = START_DEADLINE_SECONDS,
                  attempts: int = START_ATTEMPTS, pick_port=None, run=subprocess.run) -> int:
    """Start the throwaway server and return its port. A free port is picked, then used by the server a moment later,
    so another suite can take it in between: a start that fails because the address is taken is retried on a new port
    (``attempts`` times in all). Any failure prints the server log and the tool's own output to stderr before the folder
    is deleted, and the error names the port, the elapsed time and the deadline."""
    pick_port = pick_port or _free_port
    last = ""
    for attempt in range(1, attempts + 1):
        port = pick_port()
        t0 = time.monotonic()
        try:
            run([str(bindir / "pg_ctl"), "start", "-w", "-t", str(deadline), "-D", str(data), "-l", str(root / "pg.log"),
                 "-o", f"-p {port} -k {root} -c listen_addresses=127.0.0.1 -c fsync=off"],
                check=True, capture_output=True, text=True, timeout=deadline + 30)
            return port
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - t0
            _show_log(root, f"no answer within {deadline + 30}s")
            raise RuntimeError(f"postgres did not start on port {port} within the {deadline}s startup deadline "
                               f"(pg_ctl itself gave no answer after {elapsed:.1f}s, attempt {attempt}/{attempts})") from exc
        except subprocess.CalledProcessError as exc:
            elapsed = time.monotonic() - t0
            log = _show_log(root, f"pg_ctl exit {exc.returncode}")
            tool = f"{exc.stdout or ''}{exc.stderr or ''}".strip()
            print(f"pg_ctl output: {tool}", file=sys.stderr)
            taken = "Address already in use" in log or "could not bind" in log or "Address already in use" in tool
            last = (f"postgres failed to start on port {port} after {elapsed:.1f}s (attempt {attempt}/{attempts}, "
                    f"startup deadline {deadline}s): {tool or 'no pg_ctl output'}")
            if "did not start in time" in tool or "timed out" in tool:
                last += f"; it was still not accepting connections at the {deadline}s startup deadline"
            if not taken:
                break
            (root / "pg.log").unlink(missing_ok=True)
    raise RuntimeError(last)


def _remove_cluster_folder(root: Path, attempts: int = 5) -> None:
    """Delete a stopped cluster's folder. An immediate stop returns once the postmaster is gone, while its last backends can
    still be writing, so a single pass can leave gigabytes behind; retry, then fail naming the folder."""
    for attempt in range(attempts):
        shutil.rmtree(root, ignore_errors=True)
        if not root.exists():
            return
        time.sleep(1 + attempt)
    raise RuntimeError(f"the test postgres folder {root} could not be removed after {attempts} attempts")


def _teardown_on_terminate():
    """A run stopped with SIGTERM or SIGHUP (a timeout, a closed terminal) unwinds as an interrupt, so the session teardown still
    stops the server. SIGKILL cannot be caught: the next run's sweep stops what it left. Returns the restore call."""
    previous = {}

    def interrupt(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")

    for sig in (signal.SIGTERM, signal.SIGHUP):
        if signal.getsignal(sig) in (signal.SIG_DFL, None):
            previous[sig] = signal.signal(sig, interrupt)

    def restore():
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return restore


@pytest.fixture(scope="session")
def pg_server():
    bindir = _pg_bin()
    sweep_stale_clusters(bindir)
    root = Path(tempfile.mkdtemp(prefix="consentvault-pg-"))
    claim_cluster(root)
    data = root / "data"
    started = False
    restore = _teardown_on_terminate()
    try:
        try:
            subprocess.run(
                [str(bindir / "initdb"), "-D", str(data), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--locale=C"],
                check=True, capture_output=True, text=True, timeout=120)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            print(f"initdb failed: {getattr(exc, 'stderr', '') or exc}", file=sys.stderr)
            raise
        port = start_cluster(bindir, root, data)
        started = True
        yield {"port": port}
    finally:
        if started:
            subprocess.run(
                [str(bindir / "pg_ctl"), "stop", "-m", "immediate", "-w", "-D", str(data)],
                check=True, capture_output=True,
            )
        _remove_cluster_folder(root)
        restore()


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
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_integrity') THEN CREATE ROLE consentvault_integrity NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_records_jobs') THEN CREATE ROLE consentvault_records_jobs NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_isolation_self_test') THEN CREATE ROLE consentvault_isolation_self_test NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_restore_drill') THEN CREATE ROLE consentvault_restore_drill NOLOGIN; END IF;"
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


@pytest.fixture(autouse=True)
def _no_stray_migration_login(request):
    """A login role that is a member of the shared schema-owner role reads, to every later start check, as a migration login
    left open ("the migration login ... can still log in"). Roles live in the cluster, not the database, so one test that
    leaves one behind breaks whichever unrelated test starts a server next. After each test that used the cluster, any such
    role other than the suite's own migrator is dropped and the test that left it is failed BY NAME, so the cause is the test
    that made the role, never a bystander."""
    yield
    if "pg_server" not in request.node.fixturenames:
        return
    port = request.getfixturevalue("pg_server")["port"]
    with psycopg.connect(_dsn(port, "postgres"), autocommit=True, row_factory=psycopg.rows.dict_row) as su:
        stray = [r["rolname"] for r in su.execute(
            "SELECT m.rolname FROM pg_roles m JOIN pg_auth_members a ON a.member = m.oid JOIN pg_roles o ON o.oid = a.roleid"
            " WHERE o.rolname = %s AND m.rolcanlogin AND m.rolname <> %s", (OWNER_ROLE, MIGRATOR_ROLE)).fetchall()]
        for name in stray:
            su.execute(f'DROP ROLE "{name}"')
    assert not stray, f"{request.node.nodeid} left login role(s) {stray} on the schema owner; every later server start would refuse"


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


def pytest_collection_modifyitems(config, items):
    """Tests marked contract_pending (written before their feature) run only when asked for by name, whatever other -m
    expression a script passes (CI passes -m "not network", which would otherwise re-include them)."""
    if "contract_pending" in (config.getoption("-m") or ""):
        return
    dropped = [i for i in items if i.get_closest_marker("contract_pending")]
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = [i for i in items if not i.get_closest_marker("contract_pending")]
