"""Billing test fixtures: two synthetic organisations in a multi-tenant vault and a Stripe that never leaves memory."""

import pytest

from isolation.harness import build_tenancy

from .fakes import FakeStripe
from .schema import apply_billing_schema


@pytest.fixture
def dsn(raw_dsn):
    """The billing schema only (see schema.py), applied by the schema owner."""
    apply_billing_schema(raw_dsn)
    return raw_dsn


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def stripe():
    return FakeStripe()
