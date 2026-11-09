"""A memory or recursion error inside the pure reader is an attempt, never a final reason (one-door review round 4, gate 2)."""

import pytest

from consentvault import door

STOP = {"contact": "+12125550161", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword",
        "origin": "consumer"}


@pytest.mark.parametrize("exc", [MemoryError, RecursionError])
def test_a_resource_error_in_the_reader_is_an_attempt_and_the_post_is_tried_again(conn, monkeypatch, exc):
    real = door.SingleBackend.prepare
    calls = {"n": 0}

    def prepare(self, c, payload, body, auth):
        calls["n"] += 1
        if calls["n"] == 1:
            raise exc("x")
        return real(self, c, payload, body, auth)

    monkeypatch.setattr(door.SingleBackend, "prepare", prepare)
    with pytest.raises(exc):
        door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=STOP)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.projection_outcome WHERE outcome = 'event_not_derived'").fetchone()["n"] == 0
    assert conn.execute("SELECT count(*) AS n FROM consentvault.projection_attempt").fetchone()["n"] == 1
    door.rebuild(conn)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (STOP["contact"],)).fetchone()["n"] == 1
