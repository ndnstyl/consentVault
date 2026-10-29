import os
import socket
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import psycopg
import pytest

from consentvault import ledger, seal
from consentvault.errors import ConfigError


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _sh(args):
    subprocess.run([str(a) for a in args], check=True, capture_output=True)


class _TestTsa:
    """A local RFC 3161 authority: a self-signed CA, a TSA certificate with the timeStamping usage,
    and an HTTP server answering with `openssl ts -reply`."""

    def __init__(self, root: Path):
        self.root = root
        self.ossl = seal.openssl_path()
        self.mode = "normal"
        self._build_pki()
        self.decoy = self._sign_digest("ab" * 32)
        self.port = _free_port()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                try:
                    out = outer.reply(body)
                except subprocess.CalledProcessError as exc:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(exc).encode())
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                return None

        self.server = HTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.port}/"

    def _build_pki(self):
        r = self.root
        cnf = r / "openssl.cnf"
        cnf.write_text(
            "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=test authority\n"
            "[ca_ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\n"
            "[tsa_ext]\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\n"
            "[tsa]\ndefault_tsa=tsa_cfg\n"
            f"[tsa_cfg]\nserial={r / 'serial'}\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\n"
            "digests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\n"
        )
        (r / "serial").write_text("01\n")
        o = self.ossl
        _sh([o, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", r / "ca.key", "-out", r / "ca.pem",
             "-days", "2", "-config", cnf, "-extensions", "ca_ext"])
        _sh([o, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", r / "tsa.key", "-out", r / "tsa.csr",
             "-config", cnf])
        _sh([o, "x509", "-req", "-in", r / "tsa.csr", "-CA", r / "ca.pem", "-CAkey", r / "ca.key",
             "-CAcreateserial", "-out", r / "tsa.pem", "-days", "2", "-extfile", cnf, "-extensions", "tsa_ext"])
        self.cafile = r / "ca.pem"

    def _sign(self, query: Path) -> bytes:
        out = self.root / f"reply-{threading.get_ident()}.tsr"
        _sh([self.ossl, "ts", "-reply", "-config", self.root / "openssl.cnf", "-section", "tsa_cfg",
             "-queryfile", query, "-signer", self.root / "tsa.pem", "-inkey", self.root / "tsa.key",
             "-chain", self.cafile, "-out", out])
        return out.read_bytes()

    def _sign_digest(self, digest_hex: str) -> bytes:
        q = self.root / "decoy.tsq"
        _sh([self.ossl, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q])
        return self._sign(q)

    def reply(self, body: bytes) -> bytes:
        if self.mode == "wrong_digest":
            return self.decoy
        q = self.root / f"query-{threading.get_ident()}.tsq"
        q.write_bytes(body)
        return self._sign(q)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)


@pytest.fixture(scope="session")
def _tsa_server():
    root = Path(tempfile.mkdtemp(prefix="consentvault-tsa-"))
    server = _TestTsa(root)
    old = os.environ.get(seal.ENV_CAFILE)
    os.environ[seal.ENV_CAFILE] = str(server.cafile)
    try:
        yield server
    finally:
        if old is None:
            os.environ.pop(seal.ENV_CAFILE, None)
        else:
            os.environ[seal.ENV_CAFILE] = old
        server.close()
        for p in root.iterdir():
            p.unlink()
        root.rmdir()


@pytest.fixture
def tsa(_tsa_server):
    _tsa_server.mode = "normal"
    return _tsa_server


def _grant(conn, sha, contact="212-555-0101"):
    return ledger.record_event(
        conn, contact=contact, event_type="grant", channels=["sms"], purposes=["marketing"],
        method="checkbox", origin="consumer", disclosure_sha256=sha, region="US",
    )


def _seal_count(conn):
    return conn.execute("SELECT count(*) AS n FROM consentvault.seal").fetchone()["n"]


def _tamper(conn, sql, params=()):
    conn.execute("ALTER TABLE consentvault.event DISABLE TRIGGER event_append_only")
    try:
        conn.execute(sql, params)
    finally:
        conn.execute("ALTER TABLE consentvault.event ENABLE TRIGGER event_append_only")


def test_seal_then_verify_ok(conn, disclosure, tsa):
    ev = _grant(conn, disclosure)
    sealed = seal.seal_pending(conn, tsa.url, backoff=0)
    assert sealed == [ev.event_id]
    row = conn.execute("SELECT * FROM consentvault.seal").fetchone()
    assert row["tsa_url"] == tsa.url
    assert row["hash_version"] == seal.current_hash_version()
    assert "row_hash" in row["columns"]
    assert bytes(row["token"])[:1] == b"\x30"
    assert row["gen_time"] is not None and row["gen_time"].tzinfo is not None
    res = seal.verify(conn, ev.event_id)
    assert res.ok, res.reason
    assert conn.execute("SELECT verified_at FROM consentvault.seal").fetchone()["verified_at"] is not None
    assert seal.verify_all(conn) == (1, [])
    assert seal.seal_pending(conn, tsa.url, backoff=0) == []


def test_digest_covers_exactly_the_named_columns(conn, disclosure):
    ev = _grant(conn, disclosure)
    row = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (ev.event_id,)).fetchone()
    d = seal.digest(row, 1)
    assert len(d) == 32
    assert seal.digest(dict(row, source="changed"), 1) != d
    assert seal.digest(dict(row, unrelated_new_column="x"), 1) == d
    with pytest.raises(seal.SealError, match="no column"):
        seal.digest({k: v for k, v in row.items() if k != "row_hash"}, 1)
    with pytest.raises(seal.SealError, match="unknown seal hash_version"):
        seal.digest(row, 99)


def test_altered_row_fails_verify(conn, disclosure, tsa):
    ev = _grant(conn, disclosure)
    seal.seal_pending(conn, tsa.url, backoff=0)
    assert seal.verify(conn, ev.event_id).ok
    _tamper(conn, "UPDATE consentvault.event SET page_url = 'https://example.invalid/changed' WHERE event_id = %s",
            (ev.event_id,))
    res = seal.verify(conn, ev.event_id)
    assert not res.ok
    assert "digest mismatch" in res.reason
    checked, failures = seal.verify_all(conn)
    assert checked == 1 and [f.event_id for f in failures] == [ev.event_id]


def test_new_hash_version_leaves_old_seals_valid(conn, disclosure, tsa, monkeypatch):
    first = _grant(conn, disclosure, "212-555-0101")
    seal.seal_pending(conn, tsa.url, backoff=0)
    old = seal.current_hash_version()
    conn.execute("ALTER TABLE consentvault.event ADD COLUMN extra_note text")
    monkeypatch.setitem(seal.SEAL_HASH_VERSIONS, old + 1, seal.SEAL_HASH_VERSIONS[old] + ("extra_note",))
    second = _grant(conn, disclosure, "212-555-0102")
    assert seal.seal_pending(conn, tsa.url, backoff=0) == [second.event_id]
    versions = {str(r["event_id"]): r["hash_version"] for r in conn.execute("SELECT * FROM consentvault.seal")}
    assert versions == {first.event_id: old, second.event_id: old + 1}
    assert seal.verify_all(conn) == (2, [])
    _tamper(conn, "UPDATE consentvault.event SET extra_note = 'late edit' WHERE event_id = %s", (second.event_id,))
    checked, failures = seal.verify_all(conn)
    assert checked == 2 and [f.event_id for f in failures] == [second.event_id]


def test_unreachable_authority_raises_and_writes_nothing(conn, disclosure):
    _grant(conn, disclosure)
    dead = f"http://127.0.0.1:{_free_port()}/"
    with pytest.raises(seal.TsaUnreachableError, match="unreachable after 4 attempts"):
        seal.seal_pending(conn, dead, backoff=0)
    assert _seal_count(conn) == 0
    assert conn.execute("SELECT count(*) AS n FROM consentvault.unsealed_events").fetchone()["n"] == 1


def test_non_http_authority_url_refused(conn, disclosure):
    _grant(conn, disclosure)
    with pytest.raises(seal.SealError, match="http or https"):
        seal.seal_pending(conn, "file:///nonexistent", backoff=0)
    assert _seal_count(conn) == 0


def test_reply_for_a_different_digest_is_refused(conn, disclosure, tsa):
    _grant(conn, disclosure)
    tsa.mode = "wrong_digest"
    with pytest.raises(seal.TsaRefusedError):
        seal.seal_pending(conn, tsa.url, backoff=0)
    assert _seal_count(conn) == 0


def test_untrusted_authority_is_refused(conn, disclosure, tsa, tmp_path, monkeypatch):
    _grant(conn, disclosure)
    stranger = tmp_path / "stranger.pem"
    _sh([seal.openssl_path(), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", tmp_path / "k.key",
         "-out", stranger, "-days", "2", "-subj", "/CN=stranger"])
    monkeypatch.setenv(seal.ENV_CAFILE, str(stranger))
    with pytest.raises(seal.TsaRefusedError):
        seal.seal_pending(conn, tsa.url, backoff=0)
    assert _seal_count(conn) == 0


def test_verify_without_seal_reports_it(conn, disclosure):
    ev = _grant(conn, disclosure)
    res = seal.verify(conn, ev.event_id)
    assert not res.ok and "no seal" in res.reason


def test_cli_seal_and_verify_seals(dsn, conn, disclosure, tsa, monkeypatch, capsys):
    from consentvault import cli

    _grant(conn, disclosure)
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_TSA_URL", tsa.url)
    assert cli.main(["seal"]) == 0
    assert cli.main(["verify-seals"]) == 0
    _tamper(conn, "UPDATE consentvault.event SET source = 'tampered'")
    capsys.readouterr()
    assert cli.main(["verify-seals"]) == cli.EXIT_BROKEN
    assert "seal failed for event" in capsys.readouterr().err


@pytest.mark.network
def test_seal_against_public_authority(conn, disclosure):
    if os.environ.get("CONSENTVAULT_NETWORK_TESTS") != "1":
        pytest.skip("set CONSENTVAULT_NETWORK_TESTS=1 to seal against a real public authority")
    url = os.environ.get("CONSENTVAULT_TSA_URL")
    assert url, "CONSENTVAULT_NETWORK_TESTS=1 needs CONSENTVAULT_TSA_URL (and CONSENTVAULT_TSA_CAFILE if the system bundle lacks its root)"
    ev = _grant(conn, disclosure)
    assert seal.seal_pending(conn, url) == [ev.event_id]
    assert seal.verify(conn, ev.event_id).ok


def test_a_signing_time_outside_the_window_after_receipt_is_named():
    from datetime import datetime, timedelta, timezone
    received = datetime(2026, 1, 1, 12, 0, 0, 400000, tzinfo=timezone.utc)
    window = timedelta(hours=24)
    assert seal.check_gen_window(received.replace(microsecond=0), received, window) is None
    assert seal.check_gen_window(received + timedelta(hours=24), received, window) is None
    before = seal.check_gen_window(received - timedelta(seconds=2), received, window)
    assert before and "precedes the event's received_at" in before
    after = seal.check_gen_window(received + timedelta(hours=24, seconds=1), received, window)
    assert after and "more than" in after


def test_a_stamp_the_limit_cannot_meet_fails_verification_and_the_default_limit_passes(conn, disclosure, tsa):
    from datetime import timedelta
    ev = _grant(conn, disclosure)
    seal.seal_pending(conn, tsa.url, backoff=0)
    assert seal.verify(conn, ev.event_id).ok
    unmeetable = timedelta(seconds=-2)  # the signing time can never be two seconds before the receipt time
    res = seal.verify(conn, ev.event_id, unmeetable)
    assert not res.ok and "more than" in res.reason
    checked, failures = seal.verify_all(conn, unmeetable)
    assert checked == 1 and len(failures) == 1
    assert seal.verify_all(conn) == (1, [])


def test_an_event_left_unsealed_past_the_grace_period_is_a_failure(conn, disclosure, tsa):
    from datetime import timedelta
    ev = _grant(conn, disclosure)
    assert seal.verify_all(conn) == (0, [])  # inside the default one hour grace
    checked, failures = seal.verify_all(conn, unsealed_grace=timedelta(0))
    assert checked == 0 and [f.event_id for f in failures] == [ev.event_id]
    assert "no RFC 3161 timestamp seal" in failures[0].reason
    seal.seal_pending(conn, tsa.url, backoff=0)
    assert seal.verify_all(conn, unsealed_grace=timedelta(0)) == (1, [])


def test_the_unsealed_grace_period_is_configurable_and_defaults_to_one_hour():
    from consentvault import config

    assert config.load_config(env={}).unsealed_grace_seconds == 3600
    assert config.load_config(env={"CONSENTVAULT_UNSEALED_GRACE_SECONDS": "90"}).unsealed_grace_seconds == 90
    with pytest.raises(ConfigError):
        config.load_config(env={"CONSENTVAULT_UNSEALED_GRACE_SECONDS": "0"})


def test_seal_times_that_run_backwards_against_seq_fail(conn, disclosure, tsa):
    import time
    first = _grant(conn, disclosure, "212-555-0101")
    second = _grant(conn, disclosure, "212-555-0102")
    version = seal.current_hash_version()

    def stamp_now(event_id):
        row = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (event_id,)).fetchone()
        d = seal.digest(row, version)
        token, gen = seal.stamp(d.hex(), tsa.url, backoff=0)
        conn.execute(
            "INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token, gen_time)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (event_id, version, list(seal.SEAL_HASH_VERSIONS[version]), d, tsa.url, token, gen))

    stamp_now(second.event_id)  # the later event is stamped first
    time.sleep(1.1)
    stamp_now(first.event_id)
    checked, failures = seal.verify_all(conn)
    assert checked == 2
    assert [f.event_id for f in failures] == [second.event_id]
    assert "runs backwards against seq" in failures[0].reason


def test_stored_gen_time_must_match_the_token(conn, disclosure, tsa):
    ev = _grant(conn, disclosure)
    seal.seal_pending(conn, tsa.url, backoff=0)
    conn.execute("ALTER TABLE consentvault.seal DISABLE TRIGGER seal_guard")
    conn.execute("UPDATE consentvault.seal SET gen_time = gen_time + interval '3 hours'")
    conn.execute("ALTER TABLE consentvault.seal ENABLE TRIGGER seal_guard")
    res = seal.verify(conn, ev.event_id)
    assert not res.ok and "differs from the token" in res.reason


def test_a_runtime_role_seals_and_verifies_through_the_function_only(app_conn, conn, disclosure, tsa):
    ev = _grant(app_conn, disclosure)
    assert seal.seal_pending(app_conn, tsa.url, backoff=0) == [ev.event_id]
    assert seal.verify(app_conn, ev.event_id).ok
    assert conn.execute("SELECT verified_at FROM consentvault.seal").fetchone()["verified_at"] is not None
    with pytest.raises(psycopg.Error):
        app_conn.execute("UPDATE consentvault.seal SET verified_at = now()")
