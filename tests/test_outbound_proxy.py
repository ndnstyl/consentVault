"""Every outbound HTTP client honors HTTPS_PROXY (the cloud reaches the internet only through an explicit proxy), and
the container credentials endpoint, which is link-local, never goes through it.

A local proxy stand-in records the CONNECT each client sends and refuses it; the client then fails, which is expected:
what is checked is that the request reached the proxy and named the right upstream.
"""

import re
import socket
import threading
from pathlib import Path

import pytest

UPSTREAM = "upstream.example"
HTTPS_URL = "https" + f"://{UPSTREAM}/path"
SES_HOST = "email.us-east-1.amazonaws.com"
SES_URL = "https" + f"://{SES_HOST}/v2/x"
SNS_HOST = "sns.us-east-1.amazonaws.com"
HOSTS = {"stripe": "api.stripe.com", "email sender": SES_HOST, "alarm relay": SNS_HOST}


def _change():
    from datetime import datetime, timezone
    from consentvault.adapters import PermissionChange
    return PermissionChange(contact_norm="+15555550100", contact_kind="phone", channel="sms", purpose="marketing",
                            allowed=False, reason="stop received", event_id="e-1", changed_at=datetime(2026, 1, 2, tzinfo=timezone.utc))


class Proxy:
    def __init__(self):
        self.seen: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError as exc:  # loud-failure-exempt: the listening socket was closed by close(); the server ends
                self.seen.append(f"closed {type(exc).__name__}")
                return
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except OSError as exc:  # loud-failure-exempt: recorded in seen, which every test asserts on
                    self.seen.append(f"error {exc}")
                self.seen.append(data.split(b"\r\n", 1)[0].decode("latin-1"))
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

    def close(self):
        self._stop = True
        self.sock.close()
        self.thread.join(timeout=5)


@pytest.fixture
def proxy(monkeypatch):
    p = Proxy()
    url = f"http://127.0.0.1:{p.port}"
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(name, url)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    import urllib.request
    # urlopen builds its default opener once per process and reads the proxy settings then (in a task, at start);
    # each test starts its own proxy, so the cached opener is dropped
    monkeypatch.setattr(urllib.request, "_opener", None)
    yield p
    p.close()


def _try(fn):
    try:
        fn()
    except Exception as exc:  # loud-failure-exempt: the proxy refuses every tunnel; the caller asserts on what it saw
        return exc
    return None


def _clients():
    from consentvault.billing.stripe_client import urllib_transport as stripe
    from consentvault.providers.anchors import _urllib_post as anchor_post
    from consentvault.providers.evidence import urllib_s3_transport
    from consentvault.providers.identity import HttpJwksFetcher
    from consentvault.providers.keys import UrllibBaoTransport
    from consentvault.sync.connectors.webhook import EgressTransport, PushRequest

    from consentvault.adapters.webhook import WebhookCrmAdapter
    from consentvault.anchor import _post as anchor_sink_post
    from consentvault.notify.ses import HttpRequest, urllib_transport as ses_transport
    from consentvault.seal import _post as seal_post

    return {
        "stripe": lambda: stripe("GET", "https" + "://api.stripe.com/path", None, {}),
        "s3 evidence store and KMS/STS signer transport": lambda: urllib_s3_transport()("GET", HTTPS_URL, {}, b""),
        "anchor webhook": lambda: anchor_post(HTTPS_URL, {}, b"x"),
        "WorkOS JWKS": lambda: HttpJwksFetcher(HTTPS_URL)(),
        "OpenBao": lambda: UrllibBaoTransport("https" + f"://{UPSTREAM}", "t")("GET", "/v1/x", None),
        "timestamp authority": lambda: seal_post(HTTPS_URL, b"x", 0, 0.0),
        "anchor sink": lambda: anchor_sink_post(HTTPS_URL, "{}"),
        "email sender": lambda: ses_transport(HttpRequest("POST", SES_URL, {}, b"x")),
        "alarm relay": lambda: __import__("consentvault.alarm_relay", fromlist=["x"]).SnsTopic(
            "arn:aws:sns:us-east-1:123456789012:cv-alerts", "us-east-1", _Aws()).publish("s", "m"),
        "CRM webhook adapter": lambda: WebhookCrmAdapter(HTTPS_URL, "s").push_permission_change(_change()),
        "sync egress": lambda: EgressTransport(HTTPS_URL, "s").send(
            PushRequest(target_url=HTTPS_URL, body=b"{}", headers={})),
    }


class _Aws:
    def get(self):
        from datetime import datetime, timedelta, timezone

        from consentvault.providers.rds_iam import AwsCredentials
        return AwsCredentials("ASIAFAKE", "secret", "token", datetime.now(timezone.utc) + timedelta(hours=1))


@pytest.mark.parametrize("name", list(_clients()))
def test_every_outbound_client_goes_through_the_configured_proxy(proxy, name):
    _try(_clients()[name])
    host = HOSTS.get(name, UPSTREAM)  # the Stripe and email clients refuse any other host
    assert any(line.startswith(f"CONNECT {host}:443") for line in proxy.seen), (name, proxy.seen)


def test_no_client_switches_proxies_off_except_the_link_local_credentials_endpoint():
    src = Path(__file__).resolve().parents[1] / "src" / "consentvault"
    hits = sorted(str(p.relative_to(src)) for p in src.rglob("*.py")
                  if re.search(r"ProxyHandler\(\s*\{\s*\}\s*\)", p.read_text(encoding="utf-8")))
    assert hits == ["urlguard.py"]  # the one opener, and only when a caller asks proxy=False (the link-local credentials endpoint)
    raw = [str(p.relative_to(src)) for p in src.rglob("*.py")
           if re.search(r"HTTPSConnection|HTTPConnection\(|socket\.create_connection", p.read_text(encoding="utf-8"))]
    # urlguard.py subclasses the connection classes only to remember the socket for its deadline; urllib's own handlers
    # still choose the host (the proxy when one is set), which the behaviour tests above prove with a CONNECT.
    assert raw == ["urlguard.py"], "a client that opens its own connection would bypass the proxy"


def test_the_container_credentials_endpoint_never_goes_through_the_proxy(proxy):
    from consentvault.providers.rds_iam import urllib_fetch

    exc = _try(lambda: urllib_fetch(timeout_s=0.5)("http://127.0.0.1:9/v2/credentials/x", {}))
    assert exc is not None and proxy.seen == []


# Every module that can open a connection is named here. A new client that calls urlopen or builds its own opener is
# not on the list, so this test fails until the client goes through consentvault.urlguard.open_no_redirect.
_PENDING_OWNER_FIX: set = set()


def test_no_module_opens_urls_except_through_the_shared_opener():
    src = Path(__file__).resolve().parents[1] / "src" / "consentvault"
    offenders = set()
    for p in src.rglob("*.py"):
        if p.name == "urlguard.py":
            continue
        code = "\n".join(line.split("#", 1)[0] for line in p.read_text(encoding="utf-8").splitlines())
        if re.search(r"\burlopen\b|\bbuild_opener\b|\burllib3\b|\brequests\.|\bhttpx\b|\baiohttp\b", code):
            offenders.add(str(p.relative_to(src)))
    assert offenders == _PENDING_OWNER_FIX, sorted(offenders)


def test_the_credentials_fetch_refuses_any_host_that_is_not_an_exact_metadata_host():
    from consentvault import urlguard
    from consentvault.providers.rds_iam import urllib_fetch

    for url in ("https://example.com/v2/credentials/x", "https://169.254.170.2.evil.example/x", "http://example.com/x",
                "https://169.254.170.2\\evil/x", "http://169.254.170.3/x"):
        with pytest.raises(urlguard.UrlRefusedError):
            urllib_fetch(timeout_s=0.5)(url, {})
