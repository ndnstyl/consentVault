"""What the HTTP intakes share: read any body, name the headers as presented, answer with a receipt, track what runs after.

Nothing here judges a request. A body of any size and any content type is read whole (length-prefixed or chunked); a
length header that cannot be read or a body that ends short is a fact beside the post, never a reason to refuse it.
``Downstream`` counts the work that runs after an answer is sent, so a test (or a shutdown) can wait for it.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from typing import Iterator

from .errors import ConsentVaultError
from .rawpost import Fact, StoredPost

PERMISSION_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
READ_CHUNK = 1 << 20


class DownstreamNotIdle(ConsentVaultError):
    """Work that follows an answer did not finish inside the wait."""


class Downstream:
    """A count of in-flight after-the-answer work with a condition to wait on it."""

    def __init__(self) -> None:
        self._n = 0
        self._cv = threading.Condition()

    @contextmanager
    def track(self) -> Iterator[None]:
        with self._cv:
            self._n += 1
        try:
            yield
        finally:
            with self._cv:
                self._n -= 1
                self._cv.notify_all()

    def drain(self, timeout: float = 60.0) -> None:
        """Block until nothing is in flight. Raises ``DownstreamNotIdle`` at the deadline (never a silent return)."""
        deadline = time.monotonic() + timeout
        with self._cv:
            while self._n > 0:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise DownstreamNotIdle(f"{self._n} unit(s) of work after an answer did not finish in {timeout} seconds")
                self._cv.wait(left)


class _Chained:
    """A reader that yields ``head`` first and then the rest of the original stream (the header block read ahead of the library)."""

    def __init__(self, head: bytes, rest) -> None:
        import io

        self._head, self._rest = io.BytesIO(head), rest

    def read(self, n: int = -1) -> bytes:
        got = self._head.read(n)
        if n is not None and 0 <= n and len(got) == n:
            return got
        more = self._rest.read(-1 if n is None or n < 0 else n - len(got))
        return got + more

    def readline(self, limit: int = -1) -> bytes:
        got = self._head.readline(limit)
        if got.endswith(b"\n") or (limit >= 0 and len(got) >= limit):
            return got
        return got + self._rest.readline(-1 if limit < 0 else limit - len(got))

    def close(self) -> None:
        self._rest.close()


MAX_HEAD_LINES = 1_000_000
MAX_LINE_BYTES = 256 * 1024 * 1024


def _read_full_line(rfile, first: bytes) -> bytes:
    """A line the library would have cut at 64 KiB, read to its end."""
    out = bytearray(first)
    while not out.endswith(b"\n") and len(out) < MAX_LINE_BYTES:
        more = rfile.readline(65537)
        if not more:
            break
        out += more
    return bytes(out)


class StoreRefusedRequests:
    """For a ``BaseHTTPRequestHandler``: the standard library refuses some requests before any handler runs (a request line over
    64 KiB, more than 100 headers, a line that does not parse, a version it does not speak, a method it has no ``do_`` for).
    On a capture path, and for anything that did not parse at all, those are stored as received instead and answered with the
    receipt: the whole request line, every header line and the body are read off the socket first, so nothing the library would
    have discarded is lost. A subclass names ``_capture`` (the storing method) and ``_is_capture_target`` (whether the path is a
    capture path)."""

    _parsing = False
    _extra_facts: tuple = ()

    def handle_one_request(self):
        import email.parser

        try:
            line = self.rfile.readline(65537)
            self._extra_facts = ()
            if not line:
                self.close_connection = True
                return
            overlong = len(line) > 65536
            if overlong:
                line = _read_full_line(self.rfile, line)
            # read the header block ourselves, whole, before the library sees any of it
            head = bytearray()
            for _ in range(MAX_HEAD_LINES):
                h = _read_full_line(self.rfile, self.rfile.readline(65537))
                head += h
                if h in (b"\r\n", b"\n", b""):
                    break
            self._original_rfile = self.rfile
            self.rfile = _Chained(bytes(head), self.rfile)
            self.raw_requestline = line[:65537] if not overlong else line
            if overlong:
                self.requestline = self.request_version = self.command = ""
                self.headers = email.parser.BytesParser().parsebytes(bytes(head), headersonly=True)
                self._store_refused(414, line)
                return
            self._parsing = True
            try:
                parsed = self.parse_request()
            finally:
                self._parsing = False
            if not parsed:
                return  # send_error stored it, from the header block read above
            method = getattr(self, "do_" + self.command, None)
            if method is None:
                if self._is_capture_target():
                    self._extra_facts = (Fact("vault", "method_without_a_handler", self.command),)
                    self._capture()
                else:
                    self.send_error(501, "Unsupported method (%r)" % self.command)
                    return
            else:
                method()
            self.wfile.flush()
        except TimeoutError:
            self.log_error("Request timed out")
            self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        if self._parsing and code in (400, 414, 431, 501, 505):
            self._parsing = False
            import email.parser

            head = getattr(self.rfile, "_head", None)
            raw_head = head.getvalue() if head is not None else b""
            self.headers = email.parser.BytesParser().parsebytes(raw_head, headersonly=True)
            self._store_refused(code, bytes(getattr(self, "raw_requestline", b"") or b""))
            return
        super().send_error(code, message, explain)

    def _store_refused(self, code: int, line: bytes) -> None:
        """Store a request the standard library refused before dispatch: the whole request line, every header line it was sent,
        and the body; the refusal is a fact."""
        import base64

        tokens = line.decode("latin-1").split()
        self.command = (tokens[0] if tokens else "") or "UNKNOWN"
        self.path = tokens[1] if len(tokens) > 1 else ""
        self._extra_facts = (Fact("vault", "refused_by_the_http_server", {"status": code}),
                             Fact("vault", "raw_request_line_b64", base64.b64encode(line[:65536]).decode("ascii")),
                             Fact("vault", "raw_request_line_bytes", len(line)))
        self.close_connection = True
        self.rfile = self._original_rfile  # the whole header block is already read: what follows is the body
        self._capture()


REQUEST_ID_HEADER = "x-consentvault-request-id"


def request_key(headers, signature: str | None = None, edge_request_id: str | None = None) -> str | None:
    """The identity of one request, for the permanent seen-request record: the id the edge minted for it, else the signature it
    was signed with, else a request id header the sender (or the gateway) put on it. None when it carries none of them (a bearer
    request with no id is not de-duplicated). Never derived from the body."""
    if edge_request_id:
        return "edge:" + edge_request_id
    given = next((v for n, v in headers if n.lower() == REQUEST_ID_HEADER and v), None)
    if given:
        return "id:" + given
    return "sig:" + signature if signature else None


def is_capture_path(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


# The edge gateway's own service credentials for the hop to the vault: they are the gateway's, not the sender's, and a
# credential never goes into the evidence. Their presence is recorded as a fact.
TRANSPORT_CREDENTIAL_HEADERS = ("cf-access-client-id", "cf-access-client-secret")


def request_headers(handler) -> tuple[tuple[str, str], ...]:
    """Every header name and value as the server presented them, in order, repeats kept, except the gateway's own
    service credentials for the hop to the vault (``TRANSPORT_CREDENTIAL_HEADERS``)."""
    return tuple((k, v) for k, v in handler.headers.items() if k.lower() not in TRANSPORT_CREDENTIAL_HEADERS)


def transport_credentials_removed(handler) -> bool:
    return any(handler.headers.get(h) is not None for h in TRANSPORT_CREDENTIAL_HEADERS)


def is_preflight(handler) -> bool:
    return handler.command == "OPTIONS" and handler.headers.get("Access-Control-Request-Method") is not None


def read_any_body(handler) -> tuple[bytes, list[Fact]]:
    """The whole request body. Never refuses: an unreadable or missing length gives an empty or short body and a fact."""
    facts: list[Fact] = []
    te = (handler.headers.get("Transfer-Encoding") or "").lower()
    raw_len = handler.headers.get("Content-Length")
    rfile = handler.rfile
    if "chunked" in te:
        out = bytearray()
        for _ in range(1 << 31):  # ends at the zero-size chunk or the end of the stream
            line = rfile.readline(65537)
            if not line:
                facts.append(Fact("vault", "body_short_read", "chunked body ended before its last chunk"))
                break
            try:
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:  # loud-failure-exempt: recorded as the fact body_short_read beside the post; the bytes read so far are kept
                facts.append(Fact("vault", "body_short_read", "a chunk size could not be read"))
                break
            if size == 0:
                for _ in range(1000):  # trailer lines, up to the blank line
                    if rfile.readline(65537) in (b"\r\n", b"\n", b""):
                        break
                break
            chunk = _read_exact(rfile, size)
            out += chunk
            if len(chunk) < size:
                facts.append(Fact("vault", "body_short_read", f"chunk of {size} bytes ended after {len(chunk)}"))
                break
            rfile.readline(65537)  # the CRLF after the chunk
        return bytes(out), facts
    if raw_len is None:
        return b"", facts
    try:
        length = int(raw_len)
        if length < 0:
            raise ValueError("negative length")
    except ValueError:  # loud-failure-exempt: recorded as the fact content_length_unreadable beside the post (the header itself is stored whole)
        facts.append(Fact("vault", "content_length_unreadable", raw_len))
        return b"", facts
    body = _read_exact(rfile, length)
    if len(body) < length:
        facts.append(Fact("vault", "body_short_read", f"Content-Length {length}, received {len(body)}"))
    return body, facts


def _read_exact(rfile, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        piece = rfile.read(min(READ_CHUNK, n - len(out)))
        if not piece:
            break
        out += piece
    return bytes(out)


def cors_headers(handler) -> dict[str, str]:
    """The permission headers every capture answer carries so a browser can read it: the request's origin echoed (or *)."""
    origin = handler.headers.get("Origin")
    out = {"Access-Control-Allow-Origin": origin or "*", "Vary": "Origin"}
    wanted = handler.headers.get("Access-Control-Request-Headers")
    out["Access-Control-Allow-Methods"] = handler.headers.get("Access-Control-Request-Method") or PERMISSION_METHODS
    out["Access-Control-Allow-Headers"] = wanted or "*"
    out["Access-Control-Expose-Headers"] = "X-Request-Id"
    return out


def stored_answer(stored: StoredPost) -> tuple[int, dict]:
    return 201, stored.answer()


def unavailable_answer() -> tuple[int, dict]:
    return 503, {"stored": False, "error": "store_unavailable",
                 "detail": "the record store could not be written; nothing was stored; send again"}


def json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True).encode("utf-8")
