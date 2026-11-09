"""The capture-time skew check compares against the post's stored arrival time, not the clock at projection (one-door review round
4, gate 3). Whether a post is in the history must not depend on when the projection runs."""

import time
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import door, ledger

X, Y = "+12125550171", "+12125550172"
STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}


def _store_without_projecting(conn, monkeypatch, contact, captured_at):
    def crash(*a, **k):
        raise RuntimeError("crash between the answer and the projection")

    with monkeypatch.context() as m:
        m.setattr(door, "project_post", crash)
        with pytest.raises(RuntimeError):
            door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"],
                        payload=dict(STOP, contact=contact, captured_at=captured_at.isoformat()))


def _n(conn, contact):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (contact,)).fetchone()["n"]


def test_a_late_projection_judges_the_capture_time_against_the_arrival(conn, monkeypatch):
    monkeypatch.setattr(ledger, "MAX_CAPTURE_SKEW", timedelta(seconds=1))
    now = datetime.now(timezone.utc)
    _store_without_projecting(conn, monkeypatch, Y, now + timedelta(seconds=0.4))   # inside the skew bound at arrival
    _store_without_projecting(conn, monkeypatch, X, now + timedelta(seconds=1.7))   # beyond it
    time.sleep(1.2)   # by the projection clock the first one would now look inside the bound
    door.rebuild(conn)
    assert (_n(conn, X), _n(conn, Y)) == (0, 1)


def test_the_ledger_append_takes_the_arrival_to_compare_against(conn):
    now = datetime.now(timezone.utc)
    with pytest.raises(ledger.ClockSkewError):
        ledger.record_event(conn, contact=X, event_type="revoke", channels=["sms"], purposes=["marketing"], method="keyword",
                            origin="consumer", captured_at=now, arrived_at=now - timedelta(minutes=10))
