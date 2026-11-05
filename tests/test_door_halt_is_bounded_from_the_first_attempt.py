"""The halt behind a faulted post is bounded by the time since its first recorded attempt, not by its arrival (one-door.md,
addendum point 3). A post that arrived long ago and met its first error only now holds the posts behind it for the whole bound;
once the bound has passed since that first attempt, the posts behind it project, and the faulted post is still tried on every run."""

import time

import psycopg
import pytest

from consentvault import door

X, Y = "+12125550181", "+12125550182"
STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}
BOUND = 1.0


def _store_without_projecting(conn, monkeypatch, contact):
    def crash(*a, **k):
        raise RuntimeError("crash between the answer and the projection")

    with monkeypatch.context() as m:
        m.setattr(door, "project_post", crash)
        with pytest.raises(RuntimeError):
            door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=contact))
    return conn.execute("SELECT post_id::text AS p FROM consentvault.raw_post ORDER BY seq DESC LIMIT 1").fetchone()["p"]


def _n(conn, contact):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type='revoke' AND contact_norm=%s",
                        (contact,)).fetchone()["n"]


def test_the_halt_counts_from_the_first_attempt_so_a_post_that_arrived_long_ago_still_holds_the_posts_behind_it_for_the_bound(conn, monkeypatch):
    bad = set()
    real = door.read_view

    def flaky(writer, c, org, post_id, *a, **k):
        if post_id in bad:
            raise psycopg.errors.SerializationFailure("x")
        return real(writer, c, org, post_id, *a, **k)

    monkeypatch.setattr(door, "read_view", flaky)
    a_post = _store_without_projecting(conn, monkeypatch, X)
    bad.add(a_post)
    time.sleep(BOUND + 0.3)   # the faulted post is older than the bound before anything has tried it
    _store_without_projecting(conn, monkeypatch, Y)
    monkeypatch.setattr(door, "HALT_CAP_SECONDS", BOUND)

    first = door.rebuild(conn)   # the first attempt on the faulted post: the bound has not started to run out
    assert (_n(conn, X), _n(conn, Y)) == (0, 0)
    assert [(o.retry, o.halts) for o in first] == [(True, True), (True, False)]
    assert first[1].reason == "waiting_for_an_earlier_post"   # the post behind it is named as unfinished, never skipped silently

    time.sleep(BOUND + 0.2)   # now the bound has passed since the first recorded attempt
    second = door.rebuild(conn)
    assert (_n(conn, X), _n(conn, Y)) == (0, 1)   # the post behind went ahead; the faulted one was tried again and is still unfinished
    assert [(o.post_id == a_post, o.retry) for o in second] == [(True, True), (False, False)]

    bad.clear()
    door.rebuild(conn)
    assert (_n(conn, X), _n(conn, Y)) == (1, 1)
    attempts = conn.execute("SELECT count(*) AS n FROM consentvault.projection_attempt WHERE post_id = %s", (a_post,)).fetchone()["n"]
    assert attempts == 2
