"""Edge -> API seam: the real worker logic under node, forwarding into a live ``consentvault serve`` thread."""

import base64
import hashlib
import json
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path

import pytest

from consentvault import api, disclosure
from consentvault.gate import contact_facts

HARNESS = Path(__file__).parent / "support" / "edge_harness.mjs"
SECRET = "e2e-shared-secret"
TEXT = "I agree to be contacted by text about my account. Reply STOP to end."
SHA = hashlib.sha256(TEXT.encode()).hexdigest()
PHONE = "+15555550100"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


class Live(str):
    pass


def _settle(live):
    live.srv.drain(30)


@pytest.fixture
def live(dsn, app_dsn):
    settings = api.ApiSettings(dsn=app_dsn, secret=SECRET, token="t", purposes=("marketing",), default_region="US")
    srv = api.make_server(settings, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        url = Live(f"http://127.0.0.1:{srv.server_address[1]}")
        url.srv = srv
        yield url
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


def _envelope_body(result):
    import base64
    return base64.b64decode(result["forwarded"]["body"]["body_b64"])


def test_the_edge_stores_both_posts_and_only_the_checked_box_becomes_a_grant(live, conn):
    disclosure.register(conn, TEXT, "e2e", "en", ["sms"], ["marketing"])
    checked_raw = _widget(True)
    unchecked_raw = _widget(False, contact="+15555550101")
    ok, no = _run_edge(live, [{"body": checked_raw, "ip": "203.0.113.9"},
                              {"body": unchecked_raw, "ip": "203.0.113.9"}])
    _settle(live)

    assert ok["status"] == 201 and ok["body"]["stored"] is True
    assert no["status"] == 201 and no["body"]["stored"] is True
    # the edge forwards the browser's exact bytes; the unchecked post is stored whole and is not made a grant
    assert _envelope_body(ok) == checked_raw.encode() and _envelope_body(no) == unchecked_raw.encode()

    posts = conn.execute("SELECT * FROM consentvault.raw_post ORDER BY seq").fetchall()
    # the post is the signed envelope exactly as received; the browser's bytes are inside it
    inner = [base64.b64decode(json.loads(bytes(p["body_ct"]))["body_b64"]) for p in posts]
    assert inner == [checked_raw.encode(), unchecked_raw.encode()]
    assert [p["body_sha256"] for p in posts] == [ok["body"]["body_sha256"], no["body"]["body_sha256"]]
    assert all(p["intake"] == "edge_single" for p in posts)
    assert posts[0]["edge_received_at"] is not None
    consent = [json.loads(bytes(r["values_ct"])) for r in conn.execute(
        "SELECT values_ct FROM consentvault.raw_post_field WHERE field = 'consent' ORDER BY (SELECT seq FROM consentvault.raw_post p"
        " WHERE p.post_id = raw_post_field.post_id)").fetchall()]
    assert consent == [["true"], ["false"]]

    rows = conn.execute("SELECT * FROM consentvault.event ORDER BY seq").fetchall()
    assert len(rows) == 1
    ev = rows[0]
    assert ev["event_type"] == "grant" and ev["contact_norm"] == PHONE and ev["disclosure_sha256"] == SHA
    assert (ev["client_ip"], ev["user_agent"], ev["session_ref"], ev["source"]) == ("203.0.113.9", "e2e/1", "sess-e2e", "e2e-form")
    assert ev["payload_sha256"] == hashlib.sha256(checked_raw.encode()).hexdigest()
    held = conn.execute("SELECT body FROM consentvault.disclosure WHERE sha256 = %s", (SHA,)).fetchone()
    assert held["body"] == TEXT

    assert [line["event_type"] for line in contact_facts(conn, PHONE, region="US").history] == ["grant"]
    assert contact_facts(conn, "+15555550101", region="US").status == "no_record_found"


def test_wording_text_and_an_unregistered_hash_are_stored_and_make_no_grant(live, conn):
    other = hashlib.sha256(b"wording nobody registered").hexdigest()
    with_text, unknown = _run_edge(live, [
        {"body": _widget(True, disclosure_text=TEXT), "ip": "203.0.113.9"},
        {"body": _widget(True, disclosure_sha256=other), "ip": "203.0.113.9"},
    ])
    _settle(live)
    assert with_text["status"] == 201 and unknown["status"] == 201
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 2
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
    assert conn.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 0
    wording = json.loads(bytes(conn.execute("SELECT values_ct FROM consentvault.raw_post_field WHERE field = 'wording'"
                                            " AND state = 'sent'").fetchone()["values_ct"]))
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post_field WHERE field = 'wording' AND state = 'not_sent'"
                        ).fetchone()["n"] == 1  # the hash-only post reads not sent
    assert json.loads(wording[0]) == TEXT  # the wording as sent, byte for byte, in its own labelled field
