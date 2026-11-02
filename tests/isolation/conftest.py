"""Isolation harness: a fresh vault with two synthetic organisations per test."""

import pytest

from .harness import build_tenancy


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])
