"""Fixtures for the erasure, offboarding, hold, legal-process and restore suites: two synthetic organisations."""

import pytest

from isolation.harness import build_tenancy

from .support import Env


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def env(tenancy, tmp_path):
    return Env(tenancy, tmp_path)
