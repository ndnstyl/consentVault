"""pytest plugin: runs the product's own suites against the self-host stack's Postgres image instead of a locally
installed server. Loaded by run_suites.sh with ``-p tests.selfhost.suites_plugin``.

The suites' ``pg_server`` fixture starts a local postgres from PG_BIN. This plugin answers that fixture with the
throwaway ``db-suites`` service of deploy/selfhost/docker-compose.yml (same pinned image as the stack's db) and
changes nothing else, so every test body runs exactly as shipped. Each test makes its own database (``t_*``); the
plugin drops them at session start and end (module-scoped fixtures share a database across tests, so not sooner).
"""

import os

import psycopg
import pytest


def _drop_test_databases(port: int) -> int:
    dropped = 0
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True, connect_timeout=10) as c:
        for (name,) in c.execute("SELECT datname FROM pg_database WHERE datname LIKE 't\\_%'").fetchall():
            c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            dropped += 1
    return dropped


_checked: list = []  # the other-client check runs once, before this session's own tests connect


@pytest.hookimpl(tryfirst=True)
def pytest_fixture_setup(fixturedef, request):
    if fixturedef.argname != "pg_server":
        return None
    inside = os.environ.get("SUITES_DB_PORT")  # set when the suites run in the stack's own network (the only supported way)
    if not inside:
        raise AssertionError("SUITES_DB_PORT is not set: run the suites through the `suites` service of deploy/selfhost/docker-compose.yml; "
                             "the throwaway database publishes no host port, so no other process can share its roles")
    port = int(inside)
    first_call = not _checked
    _checked.append(True)
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", connect_timeout=10) as c:
        version = c.execute("SHOW server_version").fetchone()[0]
        others = c.execute("SELECT pid, usename, application_name, client_addr::text FROM pg_stat_activity"
                           " WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()").fetchall()
    if others and first_call:
        raise AssertionError(f"another client is connected to the suites database ({others}); the suite's roles are cluster-wide, "
                             "so a second runner on this database makes the stray-login guard fail unrelated tests")
    if not version.startswith("17."):
        raise AssertionError(f"the suites expected the stack's PostgreSQL 17 image, got {version}")
    _drop_test_databases(port)
    fixturedef.addfinalizer(lambda: _drop_test_databases(port))
    result = {"port": port}
    fixturedef.cached_result = (result, fixturedef.cache_key(request), None)
    return result
