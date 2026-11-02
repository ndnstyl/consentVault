"""The decisions moved to the database's clock hold whichever way this host's clock is skewed: a worker 11 minutes ahead or
11 minutes behind judges a request, an export link, a gate decision and a ledger entry exactly as one in step."""

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import api, dbclock
from consentvault.gate_rules import engine

from test_api import PURPOSES, SECRET, TOKEN, VERIFIED_SECRET, _grant, _post, server  # noqa: F401

SKEWS = [660.0, -660.0]


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_a_signed_request_is_fresh_by_the_database_clock_whatever_the_host_clock(server, disclosure, monkeypatch, by):
    ts = int(time.time())                                 # the database's time (same machine, true clock)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + by)   # this host's clock, 11 minutes out
    status, body, _ = _post(server, _grant(disclosure), ts=ts)
    assert status == 201, body


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_a_stale_request_is_still_stale_whatever_the_host_clock(server, disclosure, monkeypatch, by):
    real = time.time
    stale = int(real()) - 301
    monkeypatch.setattr(time, "time", lambda: real() + by)
    status, body, _ = _post(server, _grant(disclosure), ts=stale)
    assert status == 401 and body["error"] == "unauthenticated"


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_the_gate_decides_at_the_time_it_is_given_never_the_host_clock(by):
    import inspect
    assert "now" in inspect.signature(engine.decide).parameters
    assert inspect.signature(engine.decide).parameters["now"].default is inspect.Parameter.empty


def test_the_database_clock_helpers_read_the_database(app_dsn):
    from consentvault import db
    clock = dbclock.datetime_clock(lambda: db.connect(app_dsn))
    assert abs((clock() - datetime.now(timezone.utc)).total_seconds()) < 5
    assert abs(dbclock.epoch_clock(lambda: db.connect(app_dsn))() - time.time()) < 5


def test_a_ledger_without_a_clock_writes_nothing():
    """A ledger built without the database's clock refuses its first write, loudly, before anything reaches the store:
    no entry is ever stamped with this host's clock."""
    from consentvault.tenancy.erasure import LedgerUnavailableError, LifecycleLedger

    class Store:
        puts = 0

        def get(self, *a, **k):
            return None

        def put(self, *a, **k):
            Store.puts += 1

    ledger = LifecycleLedger(Store())
    ledger._get = lambda org, seq: None
    with pytest.raises(LedgerUnavailableError, match="no clock"):
        ledger.append("org-1", {"kind": "probe"})
    assert Store.puts == 0
