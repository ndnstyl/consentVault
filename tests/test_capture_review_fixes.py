"""The review of the capture size hotfix: the signature allowance, chunk framing, the inner body of an envelope, and a grant
stored before the hostname check existed. No database: every refusal here happens before the store is reached."""

import hashlib
import hmac
import http.client
import io
import json
import threading
import time
from types import SimpleNamespace

import pytest

from consentvault import api, door, edge_envelope
from consentvault.capture_http import BodyTooLarge, read_any_body

CAP = 64 * 1024
SECRET = "edge-secret"  # gitleaks:allow (test constant)


class FakeHandler:
    def __init__(self, data: bytes, headers: dict):
        self.rfile = io.BytesIO(data)
        self.headers = _Headers(headers)


class _Headers(dict):
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


def _bad_chunking():
    from consentvault.capture_http import BadChunking
    return BadChunking


# ---- finding 4: every byte read counts, a chunk is followed by CRLF ------------------------------------------------------
def test_chunk_extensions_are_counted_against_the_limit():
    unit = b"1;" + b"x" * 60000 + b"\r\na\r\n"
    data = unit * 300 + b"0\r\n\r\n"      # about 18 MB of wire for 300 bytes of body
    h = FakeHandler(data, {"Transfer-Encoding": "chunked"})
    with pytest.raises(BodyTooLarge):
        read_any_body(h)
    assert h.rfile.tell() < 4 * CAP, f"read {h.rfile.tell()} bytes for a 64 KiB limit"


def test_trailer_lines_are_counted_against_the_limit():
    data = b"1\r\na\r\n0\r\n" + (b"x" * 60000 + b"\r\n") * 300 + b"\r\n"
    h = FakeHandler(data, {"Transfer-Encoding": "chunked"})
    with pytest.raises(BodyTooLarge):
        read_any_body(h)
    assert h.rfile.tell() < 4 * CAP


def test_junk_after_a_chunk_is_refused_not_skipped():
    data = b"1\r\na" + b"x" * 60000 + b"\r\n0\r\n\r\n"
    h = FakeHandler(data, {"Transfer-Encoding": "chunked"})
    with pytest.raises(_bad_chunking()):
        read_any_body(h)
    assert h.rfile.tell() < 4 * CAP


def _cloud(settings_over=None):
    settings = SimpleNamespace(allowed_hosts=("127.0.0.1", "localhost"), edge_signing_secret=SECRET, dsn="postgresql://unreachable.invalid/none",
                               edge_timestamp_window_s=300, **(settings_over or {}))
    handler = type("H", (api._CloudHandler,), {"settings": settings, "pipeline": None, "writer": None})
    srv = api.SafeHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


@pytest.fixture
def cloud():
    srv, t = _cloud()
    yield ("127.0.0.1", srv.server_address[1])
    srv.shutdown()
    srv.server_close()
    t.join(timeout=10)


def _post(base, body, headers):
    conn = http.client.HTTPConnection(*base, timeout=10)
    conn.request("POST", "/v1/events", body=body, headers=headers)
    res = conn.getresponse()
    raw = res.read()
    conn.close()
    return res.status, (json.loads(raw) if raw else {})


def test_junk_after_a_chunk_is_answered_400_over_http(cloud):
    conn = http.client.HTTPConnection(*cloud, timeout=10)
    conn.putrequest("POST", "/v1/events")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(b"1\r\naXX\r\n0\r\n\r\n")
    res = conn.getresponse()
    assert res.status == 400
    conn.close()


# ---- finding 2: the larger allowance needs a signature that verifies --------------------------------------------------------
def test_a_bad_signature_does_not_buy_the_envelope_allowance(cloud):
    body = b"x" * (CAP + 10)
    status, answer = _post(cloud, body, {"X-ConsentVault-Signature": "deadbeef", "X-ConsentVault-Timestamp": str(int(time.time()))})
    assert status == 413 and answer["stored"] is False


def _sign(body: bytes, ts: str) -> str:
    return hmac.new(SECRET.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


# ---- finding 5: the browser body inside a verified envelope is capped too ------------------------------------------------------
def test_an_inner_body_over_64_kib_inside_a_signed_envelope_is_refused(cloud):
    import base64
    inner = b"y" * (CAP + 1)
    env = json.dumps({"method": "POST", "path": "/capture", "query": "", "headers": [["x-consentvault-site-key", "cv_site_x"]],
                      "body_b64": base64.b64encode(inner).decode(), "body_sha256": hashlib.sha256(inner).hexdigest(),
                      "body_bytes": len(inner), "edge_facts": {}}).encode()
    assert len(env) < 192 * 1024
    ts = str(int(time.time()))
    status, answer = _post(cloud, env, {"X-ConsentVault-Signature": _sign(env, ts), "X-ConsentVault-Timestamp": ts})
    assert status == 413 and answer["stored"] is False


# ---- finding 3: a grant stored before the hostname check existed -----------------------------------------------------------------
def _legacy_view(answer):
    import base64
    env = json.dumps({"method": "POST", "path": "/capture", "query": "", "headers": [["x-consentvault-site-key", "cv_site_x"], ["origin", "https://example.test"]],
                      "body_b64": base64.b64encode(b"{}").decode(), "body_sha256": hashlib.sha256(b"{}").hexdigest(),
                      "body_bytes": 2, "edge_facts": {"bot_check_answer": answer}}).encode()
    facts = {("vault", "tenant"): True, ("vault", "site_key_state"): "active", ("vault", "edge_timestamp"): "fresh",
             ("vault", "credential"): {"state": "verified", "credential_id": "c", "scopes": ["capture"], "via": "edge"},
             ("vault", "origin_on_list"): True, ("edge", "bot_check_answer"): answer, ("vault", "request_key"): "replay:x:y"}
    return door.PostView("org", "post", 1, "edge_site_key", env, facts, "POST", "/capture", 0.0)


@pytest.mark.parametrize("answer,reason", [({"success": True, "hostname": "example.test"}, None),
                                           ({"success": True, "hostname": "attacker.test"}, "bot_check_hostname_not_allowed")])
def test_a_post_stored_before_the_hostname_check_is_judged_from_its_stored_answer(monkeypatch, answer, reason):
    from consentvault.tenancy import site_keys

    owner = SimpleNamespace(allowed_origins=("https://example.test",))
    monkeypatch.setattr(site_keys, "resolve_site_key", lambda conn, key: owner)
    view = door.with_hostname_check(None, _legacy_view(answer))
    assert door.auth_from_facts(view.facts).reason == reason
