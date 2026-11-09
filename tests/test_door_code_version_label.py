"""The projection's code version label changes when its behaviour does, so outcomes from before and after can be told apart
(one-door review round 4, gate 5)."""

from consentvault import door

STOP = {"contact": "+12125550131", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword",
        "origin": "consumer"}


def test_the_label_is_past_the_one_the_earlier_rounds_shipped():
    assert door.CODE_VERSION != "door-1" and door.CODE_VERSION.startswith("door-")


def test_an_attempt_carries_the_current_label(conn, monkeypatch):
    def broken(self, *a, **k):
        raise MemoryError("x")

    monkeypatch.setattr(door.SingleBackend, "prepare", broken)
    try:
        door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=STOP)
    except MemoryError:
        pass
    assert [r["code_version"] for r in conn.execute("SELECT code_version FROM consentvault.projection_attempt").fetchall()] == [door.CODE_VERSION]
