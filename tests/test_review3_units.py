"""Third review: the request key follows the body, header reads are bounded, and a text is not a verification."""
import io
import socket
import threading
from http.server import HTTPServer

from consentvault import capture_http
from consentvault.capture_http import StoreRefusedRequests, _Chained, request_key
from consentvault.gate_rules import engine
from consentvault import ledger


def test_the_same_request_id_on_a_different_body_is_a_different_request():
    h = [("X-ConsentVault-Request-Id", "contact-42")]
    assert request_key(h, None, None, b"grant") != request_key(h, None, None, b"stop")
    assert request_key(h, None, None, b"stop") == request_key(h, "sig-b", None, b"stop")
    assert request_key([], None, "edge-1", b"a") != request_key([], None, "edge-1", b"b")


def test_a_request_with_no_identity_is_not_de_duplicated():
    assert request_key([], None, None, b"x") is None


def test_a_header_block_over_a_megabyte_streams_to_disk_not_memory():
    import tempfile

    head = tempfile.SpooledTemporaryFile(max_size=capture_http.HEAD_IN_MEMORY_BYTES)
    chained = _Chained(head, io.BytesIO(b"body"))
    head.seek(0, io.SEEK_END)
    head.write(b"x" * (capture_http.HEAD_IN_MEMORY_BYTES + 10))
    assert head._rolled
    chained = _Chained(head, io.BytesIO(b"body"))
    assert len(chained.head_bytes()) == capture_http.HEAD_IN_MEMORY_BYTES + 10
    assert chained.read().endswith(b"body")


def test_the_handler_gives_up_on_a_silent_socket():
    assert 0 < StoreRefusedRequests.timeout <= 120
    assert capture_http.MAX_HEAD_BYTES <= 64 * 1024 * 1024


def test_a_stalled_header_read_is_closed_at_the_timeout(monkeypatch):
    monkeypatch.setattr(StoreRefusedRequests, "timeout", 0.3)

    class H(StoreRefusedRequests, __import__("http.server", fromlist=["x"]).BaseHTTPRequestHandler):
        def _capture(self):  # pragma: no cover - never reached
            raise AssertionError("a request that never finished must not be handled")

        def _is_capture_target(self):
            return True

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.handle_request)
    t.start()
    c = socket.create_connection(srv.server_address, timeout=5)
    c.sendall(b"POST /v1/events HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n")  # never finishes the header block
    t.join(5)
    assert not t.is_alive(), "the server stayed blocked on a socket that went quiet"
    c.close()
    srv.server_close()


def test_a_text_is_in_no_verified_list():
    assert "inbound_keyword" not in ledger.VERIFIED
    assert "inbound_keyword" not in engine.VERIFIED
