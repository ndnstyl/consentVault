"""On the single-company path a failed derive leaves no claim, so the safe resend records its event."""
import time

from consentvault import api
from consentvault.errors import LedgerError
from test_api import _post, _posts, _facts, server  # noqa: F401

STOP = {"contact": "+12125550142", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword"}


def test_a_ledger_failure_leaves_no_claim_and_the_resend_records_exactly_one_event(server, conn, monkeypatch):
    real = api.record_event
    n = {"c": 0}

    def fails_once(*a, **k):
        n["c"] += 1
        if n["c"] == 1:
            raise LedgerError("the ledger could not record the event")
        return real(*a, **k)
    monkeypatch.setattr(api, "record_event", fails_once)
    h = {"X-ConsentVault-Request-Id": "stop-9"}
    now = int(time.time())
    assert _post(server, STOP, ts=now - 5, headers=h)[0] == 201
    server.settle()
    count = lambda t, tbl: conn.execute(f"SELECT count(*) AS n FROM consentvault.{tbl}" + t).fetchone()["n"]
    assert count(" WHERE event_type = 'revoke'", "event") == 0
    assert count("", "seen_request") == 0
    assert _facts(conn, _posts(conn)[-1]["post_id"])["event_not_derived"].startswith("LedgerError")
    assert _post(server, STOP, ts=now - 4, headers=h)[0] == 201  # the documented safe resend
    server.settle()
    assert count(" WHERE event_type = 'revoke'", "event") == 1
    assert count("", "seen_request") == 1
