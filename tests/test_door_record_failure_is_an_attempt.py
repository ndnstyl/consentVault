"""A non-database error while recording a post's outcome does not escape and stop the organisation's run (one-door review round 4,
gate 2): the post's event is already written, the failed record is logged by name, and the next run records it."""

from consentvault import door
from consentvault.rawpost import RawPostWriter

A, B = "+12125550141", "+12125550142"
STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}


def test_a_plain_error_while_recording_an_outcome_does_not_stop_the_run(conn, monkeypatch):
    calls = {"n": 0}
    real = RawPostWriter.append_facts

    def broken(self, *a, **k):
        calls["n"] += 1
        raise KeyError("not a database error")

    monkeypatch.setattr(RawPostWriter, "append_facts", broken)
    ev = door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=A))
    assert ev is not None and calls["n"] >= 1   # the stop was written and the caller was answered
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (A,)).fetchone()["n"] == 1
    monkeypatch.setattr(RawPostWriter, "append_facts", real)
    door.rebuild(conn)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm=%s", (A,)).fetchone()["n"] == 1
