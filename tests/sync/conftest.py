import pytest

from isolation.harness import build_tenancy

from .support import SyncEnv


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def env(tenancy, pg_server):
    return SyncEnv(tenancy, pg_server["port"])
