"""The live catch-up retries a faulted earlier post at most once per interval (one-door review round 4). A fault that always
repeats must not cost a re-projection and a permanent attempt row on every later request; the rebuild job handles the rest."""

import time

import psycopg
import pytest

from consentvault import door

X, Y, Z = "+12125550191", "+12125550192", "+12125550193"
STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}


def _store_without_projecting(conn, monkeypatch, contact):
    def crash(*a, **k):
        raise RuntimeError("crash between the answer and the projection")

    with monkeypatch.context() as m:
        m.setattr(door, "project_post", crash)
        with pytest.raises(RuntimeError):
            door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=contact))
    return conn.execute("SELECT post_id::text AS p FROM consentvault.raw_post ORDER BY seq DESC LIMIT 1").fetchone()["p"]


def _attempts(conn, post):
    return conn.execute("SELECT count(*) AS n FROM consentvault.projection_attempt WHERE post_id = %s", (post,)).fetchone()["n"]


def _live(conn, contact):
    return door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=contact))


def test_an_always_failing_earlier_post_is_tried_once_per_interval_on_the_live_path(conn, monkeypatch):
    bad = set()
    real = door.read_view

    def flaky(writer, c, org, post_id, *a, **k):
        if post_id in bad:
            raise psycopg.errors.SerializationFailure("x")
        return real(writer, c, org, post_id, *a, **k)

    monkeypatch.setattr(door, "read_view", flaky)
    monkeypatch.setattr(door, "LIVE_RETRY_INTERVAL_SECONDS", 1.0)
    a_post = _store_without_projecting(conn, monkeypatch, X)
    bad.add(a_post)
    _live(conn, Y)
    assert _attempts(conn, a_post) == 1
    _live(conn, Z)
    _live(conn, "+12125550194")
    assert _attempts(conn, a_post) == 1   # three live requests inside the interval, one attempt
    time.sleep(1.2)
    _live(conn, "+12125550195")
    assert _attempts(conn, a_post) == 2   # the interval passed: tried again once
    door.rebuild(conn)
    assert _attempts(conn, a_post) == 3   # the rebuild is never held back by the live interval
    bad.clear()
    door.rebuild(conn)
    n = conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (X,)).fetchone()["n"]
    assert n == 1
