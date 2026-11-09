"""A post stored behind an unfinished earlier post is answered by name: stored, waiting (one-door.md, addendum point 5). The
library returns ``StoredWaiting`` and the command line prints it with exit 0; neither says the request is invalid, and the post
is projected after the earlier one by the next run."""

import json

import psycopg
import pytest

from consentvault import cli, door
from consentvault.capture import revoke

CONTACT_A, CONTACT_B, CONTACT_C = "+12125550141", "+12125550142", "+12125550143"
STOP = {"event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}


def _grant(contact, disclosure):
    return {"contact": contact, "event_type": "grant", "checked": True, "channels": ["sms"], "purposes": ["marketing"],
            "method": "checkbox", "origin": "consumer", "disclosure_sha256": disclosure}


def _n(conn, contact):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm = %s", (contact,)).fetchone()["n"]


def _unfinished_earlier_post(conn, monkeypatch):
    real = door.SingleBackend.apply
    state = {"down": True}

    def apply(self, c, enter, fields, link):
        if state["down"]:
            raise psycopg.errors.LockNotAvailable("x")
        return real(self, c, enter, fields, link)

    monkeypatch.setattr(door.SingleBackend, "apply", apply)
    with pytest.raises(psycopg.errors.LockNotAvailable):
        door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=dict(STOP, contact=CONTACT_A))
    return state


def test_the_library_answers_stored_waiting_by_name_and_never_invalid(conn, monkeypatch, disclosure):
    state = _unfinished_earlier_post(conn, monkeypatch)
    answer = door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=_grant(CONTACT_B, disclosure))
    assert isinstance(answer, door.StoredWaiting)
    assert answer.as_dict()["stored"] is True and answer.as_dict()["waiting"] is True and answer.reason == "waiting_for_an_earlier_post"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 2
    assert (_n(conn, CONTACT_A), _n(conn, CONTACT_B)) == (0, 0)
    state["down"] = False
    door.rebuild(conn)
    assert (_n(conn, CONTACT_A), _n(conn, CONTACT_B)) == (1, 1)


def test_the_command_line_prints_stored_waiting_and_exits_zero(dsn, conn, monkeypatch, capsys, disclosure):
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    _unfinished_earlier_post(conn, monkeypatch)
    capsys.readouterr()
    assert cli.main(["capture", "--contact", CONTACT_C, "--checked", "--disclosure", disclosure, "--channel", "sms",
                     "--purpose", "marketing"]) == 0
    printed = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert printed["stored"] is True and printed["waiting"] is True and printed["reason"] == "waiting_for_an_earlier_post"
    assert "event_id" not in printed
    assert _n(conn, CONTACT_C) == 0
