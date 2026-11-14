"""Hardening found by the security gate: constant-time digest checks, composed SQL for dynamic identifiers, URL schemes."""
import hmac

import pytest
from psycopg import sql

from consentvault import evidence, ledger, seal
from consentvault.tenancy import admin_policy, offboard

HOSTILE = 'evil"); SELECT pg_sleep(60);--'


class _Spy:
    def __init__(self, monkeypatch):
        self.calls = 0
        real = hmac.compare_digest

        def spy(a, b):
            self.calls += 1
            return real(a, b)

        monkeypatch.setattr(hmac, "compare_digest", spy)


def test_seal_binds_event_uses_compare_digest(monkeypatch):
    spy = _Spy(monkeypatch)
    version = max(seal.SEAL_HASH_VERSIONS)
    cols = seal.SEAL_HASH_VERSIONS[version]
    row = {c: "x" for c in cols}
    try:
        good = seal._digest_columns(row, cols).hex()
    except seal.SealError:
        pytest.skip("synthetic row not digestible")
    assert seal.seal_binds_event(row, version, cols, good)
    assert not seal.seal_binds_event(row, version, cols, "0" * 64)
    assert spy.calls >= 2


@pytest.mark.parametrize("mod", [evidence, admin_policy, offboard, seal])
def test_digest_checks_import_hmac(mod):
    assert mod.hmac is hmac


def test_event_insert_composes_identifiers():
    q = ledger._insert_event_sql(["contact_fp", HOSTILE])
    assert isinstance(q, sql.Composable)
    text = q.as_string(None)
    assert '"evil""); SELECT pg_sleep(60);--"' in text
    assert text.count("%s") == 2


def test_export_update_composes_identifiers():
    q = evidence._update_sql(["status", HOSTILE])
    text = q.as_string(None)
    assert '"evil""); SELECT pg_sleep(60);--" = %s' in text
    assert text.count("%s") == 3  # two columns and the export id


from consentvault import anchor, urlguard  # noqa: E402
from consentvault.billing import stripe_client  # noqa: E402
from consentvault.notify import ses  # noqa: E402


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://api.stripe.com/", "http://api.stripe.com/", "https://evil.example/",
                                 "https://api.stripe.com.evil.example/", "https:///nohost"])
def test_stripe_transport_refuses_unexpected_urls(url):
    with pytest.raises(urlguard.UrlRefusedError):
        stripe_client.urllib_transport("GET", url, None, {})


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://email.us-east-1.amazonaws.com/", "https://email.us-east-1.amazonaws.com.evil.example/",
                                 "https://evil.example/"])
def test_ses_transport_refuses_unexpected_urls(url):
    with pytest.raises(urlguard.UrlRefusedError):
        ses.urllib_transport(ses.HttpRequest("POST", url, {}, b""))


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://example.com/hook", "ftp://example.com/"])
def test_anchor_webhook_refuses_unexpected_urls(url):
    with pytest.raises(urlguard.UrlRefusedError):
        anchor._post(url, "{}")


def test_tsa_post_refuses_other_schemes():
    from consentvault import seal
    with pytest.raises(urlguard.UrlRefusedError):
        seal._post("file:///etc/passwd", b"x", 0, 0.0)


def test_guard_allows_expected():
    assert urlguard.require_url("https://api.stripe.com/v1/x", host_pattern=r"api\.stripe\.com")
    assert urlguard.require_url("http://127.0.0.1:9/", loopback_http=True)
    assert urlguard.require_url("http://[::1]:9/", loopback_http=True)
    with pytest.raises(urlguard.UrlRefusedError):
        urlguard.require_url("http://10.0.0.1/", loopback_http=True)


from consentvault.tenancy import admin_base  # noqa: E402


def test_offboard_step_composes_identifiers():
    text = offboard._step_sql(["a", HOSTILE]).as_string(None)
    assert '"evil""); SELECT pg_sleep(60);--" = %s' in text
    assert text.count("%s") == 3 + 2  # name, value, two columns, request id


def test_offboard_record_composes_identifiers():
    text = offboard._record_sql(["a", HOSTILE]).as_string(None)
    assert '"evil""); SELECT pg_sleep(60);--"' in text
    assert text.count("%s") == 3 + 2


def test_next_version_composes_the_table_name():
    text = admin_policy._next_version_sql(HOSTILE).as_string(None)
    assert 'consentvault."evil""); SELECT pg_sleep(60);--"' in text


@pytest.mark.parametrize("key_cols,key_types", [((HOSTILE, "_k2"), ("text", "text")), (("_k1", "_k2"), ("text; SELECT 1", "text"))])
def test_paginate_refuses_a_hostile_identifier_or_type(key_cols, key_types):
    with pytest.raises(ValueError):
        admin_base.paginate(None, endpoint="x", select_sql="SELECT 1", params=[], key_cols=key_cols, key_types=key_types,
                            descending=True, limit=None, cursor=None, shape=dict)


def test_length_helper():
    from consentvault.lengths import is_bytes_of_len
    assert is_bytes_of_len(b"x" * 32, 32)
    assert not is_bytes_of_len(b"x" * 31, 32)
    assert not is_bytes_of_len("x" * 32, 32)
    assert not is_bytes_of_len(None, 32)


import http.server  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402
from datetime import date, timedelta  # noqa: E402
from pathlib import Path  # noqa: E402


class _Servers:
    """A target that records hits, and a first server that answers every request with a redirect to a given Location."""

    def __init__(self, status, location_of):
        self.hits, self.seen_headers, self.first_hits = [], [], []
        outer = self

        class Target(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                outer.hits.append(self.path); outer.seen_headers.append(dict(self.headers))
                self.send_response(200); self.end_headers()
            do_GET = do_POST

            def log_message(self, *a):
                pass

        self.target = http.server.HTTPServer(("127.0.0.1", 0), Target)
        tp = self.target.server_address[1]

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                outer.first_hits.append(self.path)
                self.send_response(status); self.send_header("Location", location_of(tp)); self.end_headers()
            do_GET = do_POST

            def log_message(self, *a):
                pass

        self.first = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        self.url = f"http://127.0.0.1:{self.first.server_address[1]}/start"
        for s in (self.target, self.first):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def close(self):
        for s in (self.target, self.first):
            s.shutdown(); s.server_close()


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("where", ["other_host_http", "other_port"])
def test_no_client_follows_a_redirect(status, where):
    loc = (lambda tp: f"http://localhost:{tp}/landed") if where == "other_host_http" else (lambda tp: f"http://127.0.0.1:{tp}/landed")
    srv = _Servers(status, loc)
    try:
        req = urllib.request.Request(srv.url, data=b"x", method="POST", headers={"Authorization": "Bearer sk_test_secret"})
        with pytest.raises(urllib.error.HTTPError) as ei:
            urlguard.open_no_redirect(req, timeout=5)
        assert ei.value.code == status
        assert srv.hits == [], "the redirect target must never be contacted"
        assert srv.seen_headers == []
        with pytest.raises(Exception):
            anchor._post(srv.url, "{}")
        from consentvault import seal as seal_mod
        with pytest.raises(Exception):
            seal_mod._post(srv.url, b"x", 0, 0.0)
        assert srv.hits == []
    finally:
        srv.close()


def test_stripe_transport_returns_a_redirect_as_a_status_and_follows_nothing(monkeypatch):
    srv = _Servers(302, lambda tp: f"http://localhost:{tp}/landed")
    try:
        monkeypatch.setattr(stripe_client, "require_url", lambda url, **kw: url)
        monkeypatch.setattr(urlguard, "require_url", lambda url, **kw: url)  # the loopback test server stands in for the Stripe host
        status, _ = stripe_client.urllib_transport("GET", srv.url, None, {"Authorization": "Bearer sk_test_secret"})
        assert status == 302 and srv.hits == []
    finally:
        srv.close()


@pytest.mark.parametrize("url", [
    "HTTPS://evil.example/", "FILE:///etc/passwd", "HtTp://api.stripe.com/",
    "https://user@api.stripe.com/", "https://user:pw@api.stripe.com/", "https://api.stripe.com@evil.example/",
    "https://evil.example\\@api.stripe.com/", "https://api.stripe.com\\.evil.example/", "https://api.stripe.com/ x", "https://api.stripe.com/\n",
])
def test_stripe_pattern_refuses_tricky_urls(url):
    with pytest.raises(urlguard.UrlRefusedError):
        urlguard.require_url(url, host_pattern=r"api\.stripe\.com")


def test_an_uppercase_scheme_is_judged_by_its_lowercase_form():
    assert urlguard.require_url("HTTPS://api.stripe.com/v1", host_pattern=r"api\.stripe\.com")
    assert urlguard.require_url("HTTPS://API.STRIPE.COM/v1", host_pattern=r"api\.stripe\.com")


def _gate_eval(tmp_path, results, entries):
    rep = tmp_path / "bandit.json"
    rep.write_text(json.dumps({"results": [{"test_id": "B608", "issue_severity": "MEDIUM", "filename": f"/r/{f}", "line_number": n,
                                            "issue_text": "x"} for f, n in results]}))
    al = tmp_path / "allow.json"
    al.write_text(json.dumps({"entries": entries}))
    lib = Path(__file__).resolve().parents[1] / "scripts" / "security" / "gate_lib.py"
    return subprocess.run([sys.executable, str(lib), "evaluate", "bandit", str(rep), "--allowlist", str(al), "--root", "/r"],
                          capture_output=True, text=True)


def _entry(**kw):
    e = {"tool": "bandit", "id": "B608", "path": "src/a.py", "reason": "constant fragments only, bound params",
         "expires": str(date.today() + timedelta(days=30))}
    e.update(kw)
    return e


def test_an_allowlist_entry_with_a_count_does_not_cover_a_new_finding_in_the_same_file(tmp_path):
    ok = _gate_eval(tmp_path, [("src/a.py", 10), ("src/a.py", 20)], [_entry(count=2)])
    assert ok.returncode == 0, ok.stdout
    planted = _gate_eval(tmp_path, [("src/a.py", 10), ("src/a.py", 20), ("src/a.py", 99)], [_entry(count=2)])
    assert planted.returncode == 1 and "src/a.py:" in planted.stdout and '"accepted": 2' in planted.stdout


def test_a_zero_or_non_integer_count_is_an_invalid_entry(tmp_path):
    lib = Path(__file__).resolve().parents[1] / "scripts" / "security" / "gate_lib.py"
    for bad in (0, "2", -1):
        al = tmp_path / "a.json"
        al.write_text(json.dumps({"entries": [_entry(count=bad)]}))
        r = subprocess.run([sys.executable, str(lib), "check-allowlist", str(al)], capture_output=True, text=True)
        assert r.returncode != 0 and "count" in (r.stdout + r.stderr)


def test_the_repository_allowlist_pins_a_count_on_every_entry():
    p = Path(__file__).resolve().parents[1] / "scripts" / "security" / "allowlist.json"
    entries = json.loads(p.read_text())["entries"]
    assert entries and all(isinstance(e.get("count"), int) and e["count"] > 0 for e in entries)


# ---- round three: egress and CRM adapter redirects, SES, per-call deadline, allowlist strictness -------------------

import time  # noqa: E402
import socket  # noqa: E402
from consentvault.adapters.webhook import WebhookCrmAdapter, AdapterError  # noqa: E402
from consentvault.sync.connectors import webhook as sync_webhook  # noqa: E402


def test_the_egress_transport_never_follows_a_redirect_with_its_bearer_secret():
    srv = _Servers(302, lambda tp: f"http://127.0.0.1:{tp}/landed")
    try:
        t = sync_webhook.EgressTransport("https://egress.example.test", "door-secret", timeout=5)
        t.egress_url = srv.url.rsplit("/", 1)[0]  # the loopback server stands in for the Worker; same default opener
        try:
            t.send(sync_webhook.PushRequest(target_url="https://r.example/x", body=b"{}", headers={}))
        except sync_webhook.TransportError:
            pass
        assert srv.first_hits and srv.hits == [] and srv.seen_headers == []
    finally:
        srv.close()


def test_the_crm_webhook_adapter_never_follows_a_redirect():
    from datetime import datetime, timezone
    from consentvault.adapters import PermissionChange
    change = PermissionChange(contact_norm="+15555550100", contact_kind="phone", channel="sms", purpose="marketing",
                              allowed=False, reason="stop received", event_id="e-1", changed_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
    srv = _Servers(302, lambda tp: f"http://127.0.0.1:{tp}/landed")
    try:
        with pytest.raises(AdapterError):
            WebhookCrmAdapter(srv.url, "s3cret", timeout=5).push_permission_change(change)
        assert srv.first_hits, "the adapter must reach the first server"
        assert srv.hits == [] and srv.seen_headers == []
    finally:
        srv.close()


def test_ses_transport_never_follows_a_redirect(monkeypatch):
    srv = _Servers(302, lambda tp: f"http://127.0.0.1:{tp}/landed")
    try:
        monkeypatch.setattr(ses, "require_url", lambda url, **kw: url)
        monkeypatch.setattr(urlguard, "require_url", lambda url, **kw: url)
        r = ses.urllib_transport(ses.HttpRequest("POST", srv.url, {"Authorization": "AWS4 secret"}, b"x"))
        assert r.status == 302 and srv.hits == []
    finally:
        srv.close()


class _Trickle:
    def __init__(self, in_headers):
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(5)
        self.port = self.sock.getsockname()[1]; self.stop = False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self.feed, args=(c,), daemon=True).start()

    def feed(self, c):
        try:
            c.recv(4096)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            for _ in range(400):
                if self.stop:
                    break
                c.sendall(b"x"); time.sleep(0.25)
        except OSError:
            pass
        finally:
            c.close()


def test_a_trickling_server_cannot_hold_a_call_past_its_deadline():
    srv = _Trickle(False)
    try:
        t0 = time.monotonic()
        with pytest.raises((TimeoutError, urllib.error.URLError, OSError)):
            r = urlguard.open_no_redirect(urllib.request.Request(f"http://127.0.0.1:{srv.port}/"), timeout=1.0)
            r.read()
        assert time.monotonic() - t0 < 3.0
    finally:
        srv.stop = True


def _allow_run(tmp_path, entry, results=(("src/a.py", 10),)):
    return _gate_eval(tmp_path, list(results), [entry])


def test_an_allowlist_entry_without_a_count_or_without_a_path_is_invalid(tmp_path):
    lib = Path(__file__).resolve().parents[1] / "scripts" / "security" / "gate_lib.py"
    for drop in ("count", "path"):
        e = _entry(count=1)
        e.pop(drop, None)
        al = tmp_path / f"no_{drop}.json"
        al.write_text(json.dumps({"entries": [e]}))
        r = subprocess.run([sys.executable, str(lib), "check-allowlist", str(al)], capture_output=True, text=True)
        assert r.returncode != 0 and drop in (r.stdout + r.stderr)
        r = _gate_eval(tmp_path, [("src/a.py", 10)], [e])
        assert r.returncode == 1, f"an entry with no {drop} must not suppress anything"


def test_an_allowlist_path_is_matched_exactly_not_as_a_substring(tmp_path):
    r = _gate_eval(tmp_path, [("src/a.py", 10)], [_entry(path="src/a.p", count=1)])
    assert r.returncode == 1
    r = _gate_eval(tmp_path, [("vendor/src/a.py", 10)], [_entry(path="src/a.py", count=1)])
    assert r.returncode == 1
    r = _gate_eval(tmp_path, [("src/a.py", 10)], [_entry(path="src/a.py", count=1)])
    assert r.returncode == 0


# ---- round four: socket closed at the deadline, the shared opener for every provider, duplicate allowlist rows ------

def _workers():
    return [t.name for t in threading.enumerate() if t.name.startswith("urlguard-open")]


def _seen_worker_midcall():
    seen = []
    stop = time.monotonic() + 0.9
    while time.monotonic() < stop:
        if _workers():
            seen.append(1); break
        time.sleep(0.02)
    return seen


def test_no_worker_thread_outlives_the_deadline_on_a_trickling_server():
    srv = _Trickle(False)
    try:
        watcher = []
        th = threading.Thread(target=lambda: watcher.extend(_seen_worker_midcall()))
        th.start()
        with pytest.raises((TimeoutError, OSError)):
            urlguard.open_no_redirect(urllib.request.Request(f"http://127.0.0.1:{srv.port}/"), timeout=1.0)
        th.join()
        assert watcher, "the call must run in a worker named urlguard-open"
        deadline = time.monotonic() + 2.0
        while _workers() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _workers() == [], "the socket must be closed at the deadline so the reader stops at once"
    finally:
        srv.stop = True


class _TrickleHeaders(_Trickle):
    def feed(self, c):
        try:
            c.recv(4096)
            for ch in b"HTTP/1.1 200 OK\r\nX-A: " + b"y" * 300:
                if self.stop:
                    break
                c.sendall(bytes([ch])); time.sleep(0.2)
        except OSError:
            pass
        finally:
            c.close()


def test_no_worker_thread_outlives_the_deadline_when_the_headers_trickle():
    srv = _TrickleHeaders(True)
    try:
        watcher = []
        th = threading.Thread(target=lambda: watcher.extend(_seen_worker_midcall()))
        th.start()
        with pytest.raises((TimeoutError, OSError)):
            urlguard.open_no_redirect(urllib.request.Request(f"http://127.0.0.1:{srv.port}/"), timeout=1.0)
        th.join()
        assert watcher
        deadline = time.monotonic() + 3.0
        while _workers() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _workers() == []
    finally:
        srv.stop = True


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "http://example.com/x", "HTTP://example.com/",
                                 "https://user:pw@example.com/", "https://example.com\\@evil.example/", "https://example.com\\evil/", "data:text/plain,hi"])
def test_the_shared_opener_checks_the_url_itself(url):
    with pytest.raises(urlguard.UrlRefusedError):
        urlguard.open_no_redirect(urllib.request.Request(url), timeout=1.0)


def test_the_shared_opener_allows_loopback_http_and_named_hosts():
    srv = _Servers(200, lambda tp: "")
    try:
        r = urlguard.open_no_redirect(urllib.request.Request(srv.url.replace("/start", "/x")), timeout=3.0)
        assert r.status == 302 or r.status == 200
    except urllib.error.HTTPError as exc:
        assert exc.code == 200 or exc.code >= 300
    finally:
        srv.close()
    with pytest.raises(urlguard.UrlRefusedError):
        urlguard.open_no_redirect(urllib.request.Request("http://169.254.170.2/x"), timeout=1.0)
    assert urlguard.require_url("http://169.254.170.2/x", http_hosts=("169.254.170.2",))


def _redir():
    return _Servers(302, lambda tp: f"http://127.0.0.1:{tp}/landed")


def test_openbao_transport_follows_no_redirect():
    from consentvault.providers.keys import UrllibBaoTransport
    srv = _redir()
    try:
        status, _ = UrllibBaoTransport(srv.url.rsplit("/", 1)[0], "tok", timeout_s=5)("GET", "/v1/x", None)
        assert status == 302
        assert srv.first_hits and srv.hits == [] and srv.seen_headers == []
    finally:
        srv.close()


def test_anchor_provider_post_follows_no_redirect():
    from consentvault.providers.anchors import _urllib_post
    srv = _redir()
    try:
        assert _urllib_post(srv.url, {"X-ConsentVault-Signature": "s"}, b"x") == 302
        assert srv.first_hits and srv.hits == []
    finally:
        srv.close()


def test_container_credentials_fetch_follows_no_redirect():
    from consentvault.providers.rds_iam import urllib_fetch
    srv = _redir()
    try:
        status, _ = urllib_fetch(5.0)(srv.url, {"Authorization": "tok"})
        assert status == 302 and srv.first_hits and srv.hits == []
    finally:
        srv.close()


def test_jwks_fetch_follows_no_redirect():
    from consentvault.providers.identity import HttpJwksFetcher
    srv = _redir()
    try:
        with pytest.raises(Exception):
            HttpJwksFetcher(srv.url, timeout_s=5)()
        assert srv.first_hits and srv.hits == []
    finally:
        srv.close()


def test_s3_transport_follows_no_redirect():
    from consentvault.providers.evidence import urllib_s3_transport
    srv = _redir()
    try:
        status, _, _ = urllib_s3_transport(5.0)("GET", srv.url, {"Authorization": "AWS4 secret"}, b"")
        assert status == 302 and srv.first_hits and srv.hits == [] and srv.seen_headers == []
    finally:
        srv.close()


def test_every_provider_opens_through_the_shared_opener():
    import inspect
    from consentvault.providers import anchors, evidence, identity, keys, rds_iam
    for mod in (anchors, evidence, identity, keys, rds_iam):
        src = inspect.getsource(mod)
        assert "open_no_redirect" in src and "build_opener" not in src, mod.__name__


def test_a_repeated_allowlist_row_for_the_same_tool_rule_and_file_is_invalid(tmp_path):
    lib = Path(__file__).resolve().parents[1] / "scripts" / "security" / "gate_lib.py"
    al = tmp_path / "dup.json"
    al.write_text(json.dumps({"entries": [_entry(count=1), _entry(count=1, reason="a second row for the very same file")]}))
    r = subprocess.run([sys.executable, str(lib), "check-allowlist", str(al)], capture_output=True, text=True)
    assert r.returncode != 0 and "more than one entry" in (r.stdout + r.stderr)
    al.write_text(json.dumps({"entries": [_entry(count=1), _entry(count=1, path="src/b.py")]}))
    assert subprocess.run([sys.executable, str(lib), "check-allowlist", str(al)], capture_output=True, text=True).returncode == 0
