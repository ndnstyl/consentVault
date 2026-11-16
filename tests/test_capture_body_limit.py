"""A public capture body is capped at 64 KiB and a GET on a capture route is refused, both before anything is read or stored
(security probe 2026-11-16). No database: every refusal here happens before the store is reached."""

import http.client
import io
import json
import threading
from types import SimpleNamespace

import pytest

from consentvault import api
from consentvault.capture_http import BodyTooLarge, MAX_BODY_BYTES, MAX_SIGNED_BODY_BYTES, body_limit, read_any_body

CAP = 64 * 1024


class FakeHandler:
    def __init__(self, data: bytes, headers: dict):
        self.rfile = io.BytesIO(data)
        self.headers = {k: v for k, v in headers.items()}
        self.headers = _Headers(headers)


class _Headers(dict):
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default

    def items(self):
        return list(super().items())


def chunked(*sizes: int, tail: bool = True) -> bytes:
    out = b""
    for n in sizes:
        out += f"{n:x}\r\n".encode() + b"a" * n + b"\r\n"
    return out + (b"0\r\n\r\n" if tail else b"")


def test_the_caps_are_what_was_ruled():
    assert MAX_BODY_BYTES == CAP
    assert MAX_SIGNED_BODY_BYTES > CAP  # the edge's envelope carries the body in base64 with headers and facts


def test_a_declared_length_over_the_cap_is_refused_without_reading_a_byte():
    h = FakeHandler(b"x" * (CAP + 1), {"Content-Length": str(CAP + 1)})
    with pytest.raises(BodyTooLarge):
        read_any_body(h)
    assert h.rfile.tell() == 0


def test_a_body_of_exactly_the_cap_is_read_whole():
    body, facts = read_any_body(FakeHandler(b"x" * CAP, {"Content-Length": str(CAP)}))
    assert len(body) == CAP and facts == []


def test_a_chunked_body_over_the_cap_is_refused_before_the_chunk_that_crosses_it_is_read():
    data = chunked(32 * 1024, 32 * 1024, 30000)
    h = FakeHandler(data, {"Transfer-Encoding": "chunked"})
    with pytest.raises(BodyTooLarge):
        read_any_body(h)
    assert h.rfile.tell() < len(data) - 30000, "the crossing chunk was not read"


def test_a_chunk_that_claims_to_be_huge_is_refused_without_reading_it():
    h = FakeHandler(b"7fffffff\r\n" + b"a" * 100, {"Transfer-Encoding": "chunked"})
    with pytest.raises(BodyTooLarge):
        read_any_body(h)
    assert h.rfile.tell() <= len(b"7fffffff\r\n")


def test_a_chunked_body_at_the_cap_is_read_whole():
    body, facts = read_any_body(FakeHandler(chunked(32 * 1024, 32 * 1024), {"Transfer-Encoding": "chunked"}))
    assert len(body) == CAP and facts == []


def test_an_edge_signed_request_may_carry_the_envelope_but_no_more():
    plain = FakeHandler(b"", {})
    signed = FakeHandler(b"", {"X-ConsentVault-Signature": "abc"})
    assert body_limit(plain) == MAX_BODY_BYTES
    assert body_limit(signed) == MAX_SIGNED_BODY_BYTES
    h = FakeHandler(b"x" * (MAX_SIGNED_BODY_BYTES + 1), {"Content-Length": str(MAX_SIGNED_BODY_BYTES + 1)})
    with pytest.raises(BodyTooLarge):
        read_any_body(h, MAX_SIGNED_BODY_BYTES)


def _call(base, method, path, body=None, headers=None):
    host, port = base
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    res = conn.getresponse()
    raw = res.read()
    conn.close()
    return res.status, (json.loads(raw) if raw else {}), dict(res.getheaders())


@pytest.fixture
def single():
    settings = api.ApiSettings(dsn="postgresql://unreachable.invalid/none", secret="s", token="t", purposes=("marketing",))  # gitleaks:allow (test constant)
    srv = api.make_server(settings, "127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield ("127.0.0.1", srv.server_address[1])
    srv.shutdown()
    srv.server_close()
    t.join(timeout=10)


@pytest.fixture
def cloud_handler():
    settings = SimpleNamespace(allowed_hosts=("127.0.0.1", "localhost"), edge_signing_secret=None)
    handler = type("H", (api._CloudHandler,), {"settings": settings, "pipeline": None, "writer": None})
    srv = api.SafeHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield ("127.0.0.1", srv.server_address[1])
    srv.shutdown()
    srv.server_close()
    t.join(timeout=10)


@pytest.fixture(params=["single", "cloud"])
def server(request, single, cloud_handler):
    return single if request.param == "single" else cloud_handler


@pytest.mark.parametrize("path", ["/v1/events", "/v1/capture", "/v1/capture/x?a=1"])
def test_a_get_on_a_capture_route_is_refused_with_405_and_nothing_is_stored(server, path):
    status, answer, headers = _call(server, "GET", path)
    assert status == 405
    assert headers.get("Allow") == "POST, OPTIONS"
    assert answer.get("stored") is False


def test_a_body_over_the_cap_is_answered_413_before_it_is_stored(server):
    status, answer, _ = _call(server, "POST", "/v1/events", body=b"x" * (CAP + 1), headers={"Origin": "https://a.example"})
    assert status == 413
    assert answer["stored"] is False and answer["error"] == "too_large"


def test_a_chunked_body_over_the_cap_is_answered_413(server):
    host, port = server
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.putrequest("POST", "/v1/events")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    for _ in range(3):
        conn.send(f"{32 * 1024:x}\r\n".encode() + b"a" * (32 * 1024) + b"\r\n")
    res = conn.getresponse()
    assert res.status == 413
    conn.close()
