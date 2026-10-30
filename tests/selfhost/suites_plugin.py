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

from .conftest import load_settings


def _drop_test_databases(port: int) -> int:
    dropped = 0
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True, connect_timeout=10) as c:
        for (name,) in c.execute("SELECT datname FROM pg_database WHERE datname LIKE 't\\_%'").fetchall():
            c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            dropped += 1
    return dropped


@pytest.hookimpl(tryfirst=True)
def pytest_fixture_setup(fixturedef, request):
    if fixturedef.argname != "pg_server":
        return None
    inside = os.environ.get("SUITES_DB_PORT")  # set when the suites run in the stack's own network (the supported way)
    port = int(inside) if inside else int(load_settings()["SUITES_DB_PORT"])
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", connect_timeout=10) as c:
        version = c.execute("SHOW server_version").fetchone()[0]
    if not version.startswith("17."):
        raise AssertionError(f"the suites expected the stack's PostgreSQL 17 image, got {version}")
    _drop_test_databases(port)
    fixturedef.addfinalizer(lambda: _drop_test_databases(port))
    result = {"port": port}
    fixturedef.cached_result = (result, fixturedef.cache_key(request), None)
    return result
