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


def is_capture_path(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def request_headers(handler) -> tuple[tuple[str, str], ...]:
    """Every header name and value as the server presented them, in order, repeats kept."""
    return tuple((k, v) for k, v in handler.headers.items())


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
