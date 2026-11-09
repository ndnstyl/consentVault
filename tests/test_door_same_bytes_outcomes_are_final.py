"""An outcome that repeats on the same bytes is a final reason, and a stop is never held behind another post (one-door review
round 5, gates 2 and 3). A junk contact, a capture time past the skew bound at arrival: stored with their plain reason, no attempt
row, no halt. A stop behind a post that is only waiting for a retry still records at once."""

import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from consentvault import cli, door, ledger

STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}
GRANT = {"event_type": "grant", "checked": True, "channels": ["sms"], "purposes": ["marketing"], "disclosure_sha256": "a" * 64}
S = "+12125550177"


def _n(conn, contact):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (contact,)).fetchone()["n"]


def _attempts(conn):
    return conn.execute("SELECT count(*) AS n FROM consentvault.projection_attempt").fetchone()["n"]


def test_a_junk_contact_is_a_final_reason_and_a_later_stop_records_at_once(conn):
    with pytest.raises(Exception):
        door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(GRANT, contact="call me at the front desk"))
    door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=S))
    assert _n(conn, S) == 1                                  # live, at once
    outs = door.rebuild(conn)
    assert _n(conn, S) == 1 and not [o for o in outs if o.retry]
    assert _attempts(conn) == 0
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE name='event_not_derived'").fetchone()["n"] == 1


def test_the_rebuild_exits_zero_once_the_junk_post_is_final(dsn, conn, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    with pytest.raises(Exception):
        door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(GRANT, contact="not a number"))
    assert cli.main(["projection-rebuild"]) == 0


def test_a_capture_time_past_the_bound_at_arrival_is_final_whenever_it_is_projected(conn, monkeypatch):
    monkeypatch.setattr(ledger, "MAX_CAPTURE_SKEW", timedelta(seconds=1))
    cap = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    with pytest.raises(Exception):
        door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=S, captured_at=cap))
    door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact="+12125550178"))
    assert _n(conn, "+12125550178") == 1 and _attempts(conn) == 0
    assert not [o for o in door.rebuild(conn) if o.retry]


def test_a_stop_is_not_held_behind_a_post_that_is_only_waiting_for_a_retry(conn, monkeypatch):
    real = door.read_view
    bad = set()

    def flaky(writer, c, org, post_id, *a, **k):
        if post_id in bad:
            raise psycopg.errors.SerializationFailure("x")
        return real(writer, c, org, post_id, *a, **k)

    monkeypatch.setattr(door, "read_view", flaky)

    def crash(*a, **k):
        raise RuntimeError("crash between the answer and the projection")

    with monkeypatch.context() as m:
        m.setattr(door, "project_post", crash)
        with pytest.raises(RuntimeError):
            door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact="+12125550179"))
    bad.add(conn.execute("SELECT post_id::text AS p FROM consentvault.raw_post ORDER BY seq DESC LIMIT 1").fetchone()["p"])
    door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=S))
    assert _n(conn, S) == 1                                  # the live stop is recorded behind the faulted post
    assert _n(conn, "+12125550179") == 0
    bad.clear()
    door.rebuild(conn)
    assert _n(conn, "+12125550179") == 1 and _n(conn, S) == 1
