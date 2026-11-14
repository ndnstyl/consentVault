"""Billing test fixtures: two synthetic organisations in a multi-tenant vault and a Stripe that never leaves memory."""

import pytest

from isolation.harness import build_tenancy

from .fakes import FakeStripe
from .schema import apply_billing_schema


@pytest.fixture(autouse=True)
def no_records_tables(monkeypatch):
    """Billing runs on a partial schema with no contact-record tables, so the writer that fills them is switched off here and
    nowhere else; no billing assertion depends on it."""
    monkeypatch.setattr("consentvault.records.write_event_records", lambda *a, **k: "00000000-0000-0000-0000-000000000000")
    monkeypatch.setattr("consentvault.confirmations.enqueue_confirmation_intents", lambda *a, **k: 0)  # same reason: no confirmation tables
    monkeypatch.setattr("consentvault.sync.outbox._echo_targets", lambda conn: set())  # same reason: no connector migration


@pytest.fixture(autouse=True)
def fresh_days(request):
    """The billing modules name the day at import (NOW, TODAY, YESTERDAY); the database stamps its own UTC day when a test runs.
    A suite that crosses UTC midnight between collection and a test would compare a stale day with the database's, so each
    test reads them again at its start (the running module's names; a helper reads the same module)."""
    from datetime import date, datetime, timedelta, timezone

    from consentvault.billing.usage import closed_day

    now = datetime.now(timezone.utc)
    fresh = {"NOW": now, "YESTERDAY": closed_day(now), "TODAY": closed_day(now) + timedelta(days=1)}
    mod = request.module
    for name, value in fresh.items():
        current = getattr(mod, name, None)
        if isinstance(current, datetime) and isinstance(value, datetime) or (
                type(current) is date and type(value) is date):
            setattr(mod, name, value)
    yield


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
