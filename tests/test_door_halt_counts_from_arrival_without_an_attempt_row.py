"""When no attempt row can be written, the halt behind a faulted post is counted from the post's arrival, not from zero forever
(one-door review round 4, gate 2)."""

import time

import psycopg
import pytest

from consentvault import door

X, Y = "+12125550151", "+12125550152"
STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}


def _payload(contact, disclosure):
    # a post behind a faulted one waits only when it is not a stop: the post behind is a grant when a disclosure is given
    if disclosure is None:
        return dict(STOP, contact=contact)
    return {"contact": contact, "event_type": "grant", "checked": True, "channels": ["sms"], "purposes": ["marketing"],
            "method": "checkbox", "origin": "consumer", "disclosure_sha256": disclosure}


def _store_without_projecting(conn, monkeypatch, contact, disclosure=None):
    def crash(*a, **k):
        raise RuntimeError("crash between the answer and the projection")

    with monkeypatch.context() as m:
        m.setattr(door, "project_post", crash)
        with pytest.raises(RuntimeError):
            door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=_payload(contact, disclosure))


def _n(conn, contact):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (contact,)).fetchone()["n"]


def test_the_halt_ends_after_the_bound_from_arrival_when_attempts_cannot_be_recorded(conn, monkeypatch, disclosure):
    real = door.read_view

    def flaky(writer, c, org, post_id, *a, **k):
        if post_id == bad[0]:
            raise psycopg.errors.SerializationFailure("x")
        return real(writer, c, org, post_id, *a, **k)

    monkeypatch.setattr(door, "read_view", flaky)
    monkeypatch.setattr(door, "_attempt", lambda *a, **k: None)   # the attempt insert keeps failing
    monkeypatch.setattr(door, "HALT_CAP_SECONDS", 1.0)
    _store_without_projecting(conn, monkeypatch, X)
    bad = [conn.execute("SELECT post_id::text AS p FROM consentvault.raw_post ORDER BY seq DESC LIMIT 1").fetchone()["p"]]
    _store_without_projecting(conn, monkeypatch, Y, disclosure)
    door.rebuild(conn)
    assert (_n(conn, X), _n(conn, Y)) == (0, 0)   # inside the bound the post behind waits
    time.sleep(1.3)
    door.rebuild(conn)
    assert (_n(conn, X), _n(conn, Y)) == (0, 1)   # past the bound, counted from arrival, it goes ahead
