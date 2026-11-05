"""No error is ever a final reason (one-door.md, addendum point 1). Only the reader's own refusal is final; every database,
store and key error leaves the post unfinished, and the next run projects it. There is no list of error codes to get wrong:
the same stop is retried whatever the code of the fault that hit it (the codes the third review round found classed final)."""

import psycopg
import pytest

from consentvault import door

CODES = [psycopg.errors.QueryCanceled, psycopg.errors.LockNotAvailable, psycopg.errors.DiskFull, psycopg.errors.OutOfMemory,
         psycopg.errors.IdleInTransactionSessionTimeout, psycopg.errors.IdleSessionTimeout,
         psycopg.errors.TransactionResolutionUnknown, psycopg.errors.IoError, psycopg.errors.ConfigurationLimitExceeded,
         psycopg.errors.ProtocolViolation, psycopg.errors.CannotConnectNow, psycopg.errors.TooManyConnections,
         psycopg.errors.CrashShutdown, psycopg.errors.SerializationFailure, psycopg.errors.DeadlockDetected,
         psycopg.errors.ProgramLimitExceeded, FileNotFoundError, TimeoutError, TypeError, ValueError]

STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["*"], "method": "keyword", "origin": "consumer"}


def _events(conn, contact):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (contact,)).fetchone()["n"]


def test_there_is_no_list_of_error_codes_and_no_decision_that_an_error_is_final():
    assert not hasattr(door, "retryable")
    assert not hasattr(door, "PASSING_SQLSTATES")


@pytest.mark.parametrize("cls", CODES, ids=[c.__name__ for c in CODES])
def test_a_stop_that_meets_any_error_once_lands_on_the_next_run(cls, conn, monkeypatch):
    calls = {"n": 0}
    real = door.SingleBackend.apply

    def apply(self, c, enter, fields, link):
        calls["n"] += 1
        if calls["n"] == 1:
            raise cls("x")
        return real(self, c, enter, fields, link)

    monkeypatch.setattr(door.SingleBackend, "apply", apply)
    contact = "+12125550191"
    with pytest.raises(Exception):   # the caller in this process is told what stopped the post
        door.submit(conn, intake="system_stop", region="US", allowed_purposes=None, payload=dict(STOP, contact=contact))
    assert _events(conn, contact) == 0
    outcomes = door.rebuild(conn)
    assert [o.retry for o in outcomes] == [False]
    assert _events(conn, contact) == 1
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE name = 'event_not_derived'").fetchone()["n"] == 0
    door.rebuild(conn)
    assert _events(conn, contact) == 1


def test_a_post_that_always_meets_an_error_stays_unfinished_on_every_run_and_is_never_marked_final(conn, monkeypatch):
    def apply(self, c, enter, fields, link):
        raise psycopg.errors.QueryCanceled("x")

    monkeypatch.setattr(door.SingleBackend, "apply", apply)
    with pytest.raises(Exception):
        door.submit(conn, intake="system_stop", region="US", allowed_purposes=None, payload=dict(STOP, contact="+12125550192"))
    for _ in range(3):
        outcomes = door.rebuild(conn)
        assert [(o.retry, o.reason) for o in outcomes] == [(True, "QueryCanceled")]
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE name = 'event_not_derived'").fetchone()["n"] == 0
