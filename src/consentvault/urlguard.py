"""One check in front of every outbound URL open: the scheme and the host must be the expected ones, or nothing is sent."""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .safelog import bounded_http_error
from .errors import ConsentVaultError


class UrlRefusedError(ConsentVaultError):
    """The URL is not one this call may open (wrong scheme, wrong host, or no host)."""


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_url(url: str, *, schemes=("https",), host_pattern: str | None = None, loopback_http: bool = False,
                http_hosts=()) -> str:
    """Return ``url`` when its scheme is in ``schemes`` (and, if ``host_pattern`` is given, its host matches it fully);
    plain http is also allowed to a loopback host when ``loopback_http`` is set. Anything else raises."""
    if "\\" in url or any(ord(c) < 33 for c in url):
        raise UrlRefusedError("the URL holds a backslash, a space or a control character")
    parts = urllib.parse.urlparse(url)
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UrlRefusedError("the URL carries a user name or password")
    host = (parts.hostname or "").lower()
    if not host:
        raise UrlRefusedError(f"the URL has no host: {url!r}; expected one of {tuple(schemes)}")
    scheme_ok = parts.scheme in schemes or (parts.scheme == "http" and ((loopback_http and _loopback(host)) or host in http_hosts))
    if not scheme_ok:
        raise UrlRefusedError(f"the URL scheme {parts.scheme!r} is not allowed here (allowed: {tuple(schemes)})")
    if host_pattern is not None and not re.fullmatch(host_pattern, host):
        raise UrlRefusedError(f"the URL host {host!r} is not an expected host for this call")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[override]
        return None  # a 3xx answer surfaces as an HTTPError; nothing follows it, so no header or body leaves for a new place


def _tracked_handlers(socks: list):
    """HTTP and HTTPS handlers that remember every socket they open, so the deadline can close it."""
    class Plain(http.client.HTTPConnection):
        def connect(self):
            super().connect()
            socks.append(self.sock)

    class Secure(http.client.HTTPSConnection):
        def connect(self):
            super().connect()
            socks.append(self.sock)

    class PlainHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(Plain, req)

    class SecureHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Secure, req, context=self._context)

    return PlainHandler(), SecureHandler()


MAX_BODY_BYTES = 16 * 1024 * 1024
WORKER_NAME = "urlguard-open"


class BoundedResponse:
    """What ``open_no_redirect`` returns: the status, headers and the whole body, already read inside the deadline."""

    def __init__(self, status: int, headers, body: bytes, url: str):
        self.status, self.headers, self.url, self._body, self._pos = status, headers, url, body, 0

    def getcode(self) -> int:
        return self.status

    def read(self, n: int = -1) -> bytes:
        end = len(self._body) if n is None or n < 0 else self._pos + n
        chunk, self._pos = self._body[self._pos:end], min(end, len(self._body))
        return chunk

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


def _close_all(socks: list) -> None:
    for sk in list(socks):
        try:
            sk.shutdown(socket.SHUT_RDWR)
        except OSError:  # loud-failure-exempt: the peer already closed it; the next line closes our end either way
            pass
        try:
            sk.close()
        except OSError:  # loud-failure-exempt: closing an already-closed socket
            pass


def open_no_redirect(req: urllib.request.Request, *, timeout: float, schemes=("https",), loopback_http: bool = True,
                     http_hosts=(), host_pattern: str | None = None, proxy: bool = True) -> BoundedResponse:
    """The one way an outbound request leaves this code. It checks the URL itself (``schemes``; plain http only to a
    loopback host or one of ``http_hosts``; no user name, backslash or control character), never follows a redirect (a
    3xx answer raises ``HTTPError``), reads the whole answer within ONE overall deadline of ``timeout`` seconds, and at
    that deadline closes the socket so the reader stops at once and no thread outlives the call. ``proxy=False`` skips the
    environment proxy (the link-local credentials endpoint only)."""
    require_url(req.full_url, schemes=schemes, loopback_http=loopback_http, http_hosts=http_hosts, host_pattern=host_pattern)
    deadline = time.monotonic() + timeout
    box: dict = {}
    socks: list = []

    def work() -> None:
        plain, secure = _tracked_handlers(socks)
        handlers = [_NoRedirect, plain, secure] + ([] if proxy else [urllib.request.ProxyHandler({})])
        opener = urllib.request.build_opener(*handlers)  # built per call so the proxy settings are read at call time
        try:
            resp = opener.open(req, timeout=timeout)
            try:
                chunks, size = [], 0
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"the call to {sink(req.full_url)} passed its {timeout}s deadline")
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    chunks.append(chunk); size += len(chunk)
                    if size > MAX_BODY_BYTES:
                        raise OSError("the answer is larger than the allowed size")
                box["ok"] = BoundedResponse(resp.status, resp.headers, b"".join(chunks), resp.geturl())
            finally:
                resp.close()
        except urllib.error.HTTPError as exc:
            box["err"] = bounded_http_error(exc, MAX_BODY_BYTES)
        except BaseException as exc:  # carried to the caller thread and raised there
            box["err"] = exc  # carry-to-raise: re-raised unchanged by the calling thread

    worker = threading.Thread(target=work, daemon=True, name=WORKER_NAME)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        _close_all(socks)
        worker.join(2.0)
        raise TimeoutError(f"the call to {sink(req.full_url)} passed its {timeout}s deadline")
    if "err" in box:
        raise box["err"]
    return box["ok"]


def sink(url: str) -> str:
    parts = urllib.parse.urlparse(url)
    return f"{parts.scheme}://{parts.hostname}"
