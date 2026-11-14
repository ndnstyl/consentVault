"""The confirmation service in the cloud server and its jobs (marketing/specs/confirmations-go-live).

Two settings turn it on, both or neither:

    CONSENTVAULT_CONFIRMATIONS_API_BASE    the public base the text provider posts to, ``https://<host>`` with nothing after
                                           it (``https://api.consentvault.ai``). Every sending account's stored
                                           ``inbound_url`` is built from it, and the signature is checked over that stored
                                           address (confirmations.md section 9).
    CONSENTVAULT_CONFIRMATIONS_EDGE_CNAME  the edge name each organisation points its wording link host at
                                           (``edge.consentvault.ai``).

Neither set: no service, and every ``/v1/confirmations/*`` portal route answers 503 by name, as before. One without the
other, or a malformed value: the start is refused with a ``ConfigError`` naming the setting. Both set: the service exists,
and still sends nothing until an organisation has a connected sending account and an enabled rule.

``ConfirmationDoor`` is the route object the server mounts beside the admin routes: the provider door
``POST /v1/confirmations/inbound/<key>`` and the two public pages ``GET /c/r/<token>`` and ``GET``/``POST /c/stop/<token>``.
The pages are looked up on the organisation's own link host, which the vault cannot read from ``Host`` (the tunnel presents
``localhost``): the edge sends it as ``X-ConsentVault-Link-Host``, set from the request's own host name after dropping any
copy the client sent. The origin is reachable only through the edge's Access token, so no one else can set it.
"""

from __future__ import annotations

import re
from typing import Callable, Mapping, Optional
from urllib.parse import urlsplit

from ..errors import ConfigError
from .core import Reply
from .public import PATH as PUBLIC_PATH
from .public import _page

ENV_API_BASE = "CONSENTVAULT_CONFIRMATIONS_API_BASE"
ENV_EDGE_CNAME = "CONSENTVAULT_CONFIRMATIONS_EDGE_CNAME"
LINK_HOST_HEADER = "X-ConsentVault-Link-Host"

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")
INBOUND_PATH = re.compile(r"^/v1/confirmations/inbound/([A-Za-z0-9_-]{1,128})$")


def _host_ok(host: str) -> bool:
    return len(host) <= 253 and bool(_HOST.match(host))


def confirmation_settings(env: Mapping[str, str]) -> Optional[tuple[str, str]]:
    """``(api_base, edge_cname)``, or None when neither is set. Raises ``ConfigError`` naming the setting otherwise."""
    base = (env.get(ENV_API_BASE) or "").strip()
    cname = (env.get(ENV_EDGE_CNAME) or "").strip().lower()
    if not base and not cname:
        return None
    if not base or not cname:
        missing = ENV_API_BASE if not base else ENV_EDGE_CNAME
        raise ConfigError(f"confirmation messages are half configured: {missing} is not set (set both "
                          f"{ENV_API_BASE} and {ENV_EDGE_CNAME}, or neither); nothing was started")
    parts = urlsplit(base.rstrip("/"))
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port or parts.path
            or parts.query or parts.fragment or not _host_ok(parts.hostname) or base.rstrip("/") != f"https://{parts.netloc}"):
        raise ConfigError(f"{ENV_API_BASE} must be https://<host> with nothing after the host; nothing was started")
    if not _host_ok(cname):
        raise ConfigError(f"{ENV_EDGE_CNAME} must be a host name (for example edge.consentvault.ai); nothing was started")
    return f"https://{parts.hostname.lower()}", cname


def build_service(env: Mapping[str, str], *, connect, token_key, custody, clock: Callable[[], float]):
    """The ``ConfirmationService`` for these settings, or None when they are off. The clock is the caller's one clock: the
    server hands the same callable to the admin app."""
    settings = confirmation_settings(env)
    if settings is None:
        return None
    from .service import ConfirmationService

    api_base, edge_cname = settings
    return ConfirmationService(connect=connect, token_key=token_key, custody=custody, clock=clock, api_base=api_base,
                               edge_cname=edge_cname)


def _header(headers: Mapping[str, str], name: str) -> str:
    want = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == want:
            return str(v)
    return ""


class ConfirmationDoor:
    """The provider door and the two public pages, answered by the service. Mounted only when the service is on."""

    def __init__(self, service, api_base: str):
        self._service = service
        self._api_base = api_base.rstrip("/")

    def handles(self, method: str, path: str) -> bool:
        if method == "POST" and INBOUND_PATH.match(path or ""):
            return True
        m = PUBLIC_PATH.match(path or "")
        return m is not None and (method == "GET" or (method == "POST" and m.group(1) == "stop"))

    def handle(self, method: str, path: str, *, body: bytes = b"", headers: Optional[Mapping[str, str]] = None, **_) -> Reply:
        headers = dict(headers or {})
        m = INBOUND_PATH.match(path or "")
        if method == "POST" and m:
            # The address the provider was given; the service checks the signature over the address STORED on the account.
            res = self._service.handle_inbound(m.group(1), headers=headers, body=body or b"", url=self._api_base + path)
            return res if res.payload is not None or res.raw is not None else Reply(res.status, {}, headers=res.headers)
        host = _header(headers, LINK_HOST_HEADER).strip().lower()
        if not host:
            # Never read Host: behind the tunnel it is localhost, and a page is found only on its organisation's own host.
            return _page("Not found", "<p>Not found.</p>", 404)
        return self._service.handle_public(method, path, host=host, headers=headers, body=body or b"")
