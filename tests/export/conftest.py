import pytest

import tsa as tsa_mod
from consentvault import db

from .support import build_empty_tenancy, pinned_migrations, populate


@pytest.fixture(scope="module")
def throwaway_tsa(tmp_path_factory):
    tsa = tsa_mod.build(tmp_path_factory.mktemp("tsa"))
    if tsa is None:
        pytest.skip("this openssl cannot run 'ts -reply' / 'ts -verify'; seal verification not tested")
    return tsa


@pytest.fixture
def pinned_dsn(raw_dsn, tmp_path):
    with db.connect(raw_dsn) as c:
        db.migrate(c, pinned_migrations(tmp_path / "migrations"))
    return raw_dsn


@pytest.fixture
def world(pinned_dsn, pg_server, throwaway_tsa):
    """Two organisations, each with sealed events for the same phone number."""
    t = build_empty_tenancy(pinned_dsn, pg_server["port"])
    populate(t, t.a, throwaway_tsa)
    populate(t, t.b, throwaway_tsa)
    return t
