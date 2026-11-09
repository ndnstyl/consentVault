"""Fixtures for the pure-projection tests (specs/capture-everything/pure-projection.md, draft 6).

Every fixture here is lazy: the throwaway database, the vault and the confirmation stack are built on first use inside the test,
so a test begins with its MISSING FEATURE precondition (support.need_*) and fails there, cheaply and with a plain name, before
any database is made. A failure that does not start with "MISSING FEATURE" is a defect in the test or a regression.
"""

import pytest

from admin.conftest import vault  # noqa: F401  (the multi-mode vault the world is built on; reached only through getfixturevalue)
from test_seal import _tsa_server, tsa  # noqa: F401  (the throwaway timestamp authority the seal tests use)
from contract_world.confirm import build_stack, arm
from contract_world.fixtures import Lazy
from contract_world.world import World
from isolation.cloud_harness import Cloud
from isolation.harness import build_tenancy


def pytest_configure(config):
    config.addinivalue_line("markers", "spec_item(*ids): the spec item(s) of pure-projection.md this test answers (read by make_index.py)")


def _loader_role(request) -> int:
    """The cluster-wide loader role migration 0084 refuses to apply without (as 0019 does for the console). The suite's shared
    ``ensure_roles`` does not make it, so the first fixture build here does, before the database is migrated. Returns the port."""
    import psycopg

    port = request.getfixturevalue("pg_server")["port"]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_loader')"
                   " THEN CREATE ROLE consentvault_loader NOLOGIN; END IF; END $$")
    return port


def _cutover_orgs(superuser, org_ids) -> None:
    """The design's cutover is per organisation by watermark row: the old fold is off for an organisation once its row exists. Each
    organisation the fixtures create gets its row (head 0: the old fold finished nothing here), when the table exists."""
    with superuser() as su:
        if su.execute("SELECT to_regclass('consentvault.effect_watermark') IS NOT NULL AS t").fetchone()["t"]:
            for org_id in org_ids:
                su.execute("INSERT INTO consentvault.effect_watermark (org_id, head_seq) VALUES (%s, 0) ON CONFLICT DO NOTHING", (str(org_id),))


def _build_cloud(request, tmp_path):
    cloud = Cloud(build_tenancy(request.getfixturevalue("dsn") if _loader_role(request) else None,
                                request.getfixturevalue("pg_server")["port"]), str(tmp_path / "evidence"))
    _cutover_orgs(cloud.t.superuser, [cloud.a.org.org_id, cloud.b.org.org_id])
    return cloud


def _build_world(request, tmp_path):
    world = World(request.getfixturevalue("vault") if _loader_role(request) else None, tmp_path)
    _cutover_orgs(world.vault.superuser, [world.a.org_id, world.b.org_id])
    return world


@pytest.fixture
def cloud(request, tmp_path):
    """The multi-tenant HTTP door over two synthetic organisations (isolation harness), built on first use."""
    lazy = Lazy(lambda: _build_cloud(request, tmp_path))
    yield lazy
    built = object.__getattribute__(lazy, "_obj")
    if built is not None:
        built.close()


@pytest.fixture
def world(request, tmp_path):
    return Lazy(lambda: _build_world(request, tmp_path))


@pytest.fixture
def stack(world):
    lazy = Lazy(lambda: build_stack(world), needs=[world])
    world._after(lazy._get)
    return lazy


@pytest.fixture
def armed(world, stack):
    """Rules on, accounts connected, before the test's first grant (a rule never sends for older grants)."""
    def make():
        st = stack._get()
        res = arm(st, world._get().a)
        assert res.stack is st
        return res
    lazy = Lazy(make, needs=[world])
    world._after(lazy._get)
    return lazy
