"""Edge -> API seam: the real worker logic under node, forwarding into a live ``consentvault serve`` thread."""

import hashlib
import json
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path

import pytest

from consentvault import api, disclosure
from consentvault.gate import may_contact

HARNESS = Path(__file__).parent / "support" / "edge_harness.mjs"
SECRET = "e2e-shared-secret"
TEXT = "I agree to be contacted by text about my account. Reply STOP to end."
SHA = hashlib.sha256(TEXT.encode()).hexdigest()
PHONE = "+15555550100"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


@pytest.fixture
def live(dsn, app_dsn):
    settings = api.ApiSettings(dsn=app_dsn, secret=SECRET, token="t", purposes=("marketing",), default_region="US")
    srv = api.make_server(settings, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=10)


def _widget(checked, **over):
    body = {"contact": PHONE, "checked": checked, "disclosure_sha256": SHA,
            "channels": ["sms"], "purposes": ["marketing"], "page_url": "https://www.example.com/signup",
            "session": "sess-e2e"}
    body.update(over)
    return json.dumps(body)


def _run_edge(live_url, requests):
    proc = subprocess.run(
        ["node", str(HARNESS)], input=json.dumps({"live_url": live_url, "secret": SECRET, "requests": requests}),
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["results"]


def test_checked_box_becomes_a_grant_and_unchecked_never_does(live, conn):
    disclosure.register(conn, TEXT, "e2e", "en", ["sms"], ["marketing"])
    checked_raw = _widget(True)
    unchecked_raw = _widget(False, contact="+15555550101")
    ok, no = _run_edge(live, [{"body": checked_raw, "ip": "203.0.113.9"},
                              {"body": unchecked_raw, "ip": "203.0.113.9"}])

    assert ok["status"] == 200 and ok["body"]["recorded"] is True
    assert no["status"] == 422 and no["body"]["error"] == "unchecked"
    assert no["forwarded"] is None  # the worker never even called the vault

    rows = conn.execute("SELECT * FROM consentvault.event ORDER BY seq").fetchall()
    assert len(rows) == 1
    ev = rows[0]
    sent = ok["forwarded"]["body"]
    assert ev["event_type"] == "grant" and ev["contact_norm"] == PHONE
    assert ev["disclosure_sha256"] == SHA
    assert ev["edge_received_at"] == datetime.fromisoformat(sent["edge_received_at"].replace("Z", "+00:00"))
    assert "received_at" not in sent  # the vault stamps its own receipt time
    assert ev["payload_sha256"] == hashlib.sha256(checked_raw.encode()).hexdigest() == ok["body"]["payload_sha256"]
    assert (ev["client_ip"], ev["user_agent"], ev["session_ref"], ev["source"]) == (
        "203.0.113.9", "e2e/1", "sess-e2e", "e2e-form")
    held = conn.execute("SELECT body FROM consentvault.disclosure WHERE sha256 = %s", (SHA,)).fetchone()
    assert held["body"] == TEXT

    assert may_contact(conn, PHONE, "sms", "marketing", region="US").allowed
    assert not may_contact(conn, "+15555550101", "sms", "marketing", region="US").allowed


def test_wording_is_refused_at_the_edge_and_an_unregistered_hash_at_the_vault(live, conn):
    other = hashlib.sha256(b"wording nobody registered").hexdigest()
    with_text, unknown = _run_edge(live, [
        {"body": _widget(True, disclosure_text=TEXT), "ip": "203.0.113.9"},
        {"body": _widget(True, disclosure_sha256=other), "ip": "203.0.113.9"},
    ])
    assert with_text["status"] == 400 and with_text["body"]["error"] == "disclosure_text_refused"
    assert with_text["forwarded"] is None
    assert unknown["status"] == 502 and unknown["body"]["recorded"] is False
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
    assert conn.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 0
