"""The independent review's findings on the core record path, each shown failing before it was fixed."""

import base64
import hashlib
import json
import socket
import time

import pytest

from consentvault import api, edge_envelope, extract, rawpost
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy
from test_api import SECRET, _call, _facts, _grant, _post, _posts, server  # noqa: F401


def raw_exchange(base: str, data: bytes) -> bytes:
    host, port = base.replace("http://", "").split(":")
    with socket.create_connection((host, int(port)), timeout=30) as s:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        out = b""
        while chunk := s.recv(65536):
            out += chunk
    return out


# 1. a stale or already-seen request makes no consent event, for good; a repeated message is not a repeated request -----------

def _signed(server, payload, ts):
    """One signed request: its identity is its signature, so a different time is a different request."""
    return _post(server, payload, ts=ts)


def _permission(server, contact="%2B12125550101"):
    s, facts, _ = _call(server + f"/v1/permission?contact={contact}", headers={"Authorization": "Bearer test-bearer-token"})
    return facts


def _open_stops(server):
    """The stops on the record that no later consent post has lifted (the facts say; nothing here decides)."""
    return [x for x in _permission(server)["stops"] if not x["lifted_by_post_ids"]]


STOP = {"contact": "+12125550101", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword"}


def test_stop_then_a_start_text_then_a_byte_identical_stop_the_stop_stays_open_throughout_and_start_writes_no_event(server, disclosure, conn):
    now = int(time.time())
    assert _grant_first(server, disclosure, now - 60)
    assert _signed(server, STOP, now - 30)[0] == 201
    assert len(_open_stops(server)) == 1
    start = {"contact": "+12125550101", "event_type": "grant", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword",
             "contact_verification": "inbound_keyword", "inbound_message": "START", "checked": True, "disclosure_sha256": disclosure}
    from test_api import VERIFIED_SECRET
    posts, events = len(_posts(conn)), conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"]
    assert _post(server, start, secret=VERIFIED_SECRET, ts=now - 20)[0] == 201
    assert len(_posts(conn)) == posts + 1  # one raw post
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == events  # and no event
    assert _facts(conn, _posts(conn)[-1]["post_id"])["event_not_derived"] == "a_text_is_not_consent"
    assert len(_open_stops(server)) == 1
    assert _signed(server, STOP, now - 10)[0] == 201  # byte for byte the first stop, a new request: recorded
    assert len(_open_stops(server)) == 2
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type = 'revoke'").fetchone()["n"] == 2


def _grant_first(server, disclosure, ts):
    return _signed(server, _grant(disclosure), ts)[0] == 201


def test_stop_then_a_re_engagement_form_grant_then_a_byte_identical_stop_is_recorded_and_the_check_lists_each_in_order(server, disclosure, conn):
    now = int(time.time())
    assert _grant_first(server, disclosure, now - 80)
    assert _signed(server, STOP, now - 60)[0] == 201
    form = _grant(disclosure)
    form["contact_verification"] = "otp"  # the person confirmed their number on the customer's re-engagement form
    from test_api import VERIFIED_SECRET
    assert _post(server, form, secret=VERIFIED_SECRET, ts=now - 40)[0] == 201
    assert [x["event_type"] for x in _permission(server)["history"]] == ["grant", "revoke", "grant"]
    assert _signed(server, STOP, now - 20)[0] == 201
    facts = _permission(server)
    assert [x["event_type"] for x in facts["history"]] == ["grant", "revoke", "grant", "revoke"] and facts["lifts"] == []
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type = 'revoke'").fetchone()["n"] == 2


def test_a_web_grant_then_a_revoke_then_the_identical_grant_and_revoke_again_follow_the_person_each_time(server, disclosure, conn):
    now = int(time.time())
    grant = _grant(disclosure)
    for i, body in enumerate((grant, STOP, grant, STOP)):
        assert _signed(server, body, now - 40 + i * 5)[0] == 201
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type IN ('grant', 'revoke')").fetchone()["n"] == 4
    assert [x["event_type"] for x in _permission(server)["history"]] == ["grant", "revoke", "grant", "revoke"]
    assert [_facts(conn, p["post_id"]).get("event_derived") is not None for p in _posts(conn)] == [True] * 4


def test_the_very_same_signed_request_sent_again_is_one_request_even_after_the_replay_guard_forgets_it(server, disclosure, conn):
    payload = _grant(disclosure)
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    assert _call(server + "/v1/events", "POST", body, h)[0] == 201
    server.settle()
    from conftest import superuser_of
    with superuser_of(conn) as su:
        su.execute("DELETE FROM consentvault.replay_guard")  # as if ten minutes had passed
    before = conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"]
    assert _call(server + "/v1/events", "POST", body, h)[0] == 201
    server.settle()
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == before
    assert _facts(conn, _posts(conn)[-1]["post_id"])["event_not_derived"] == "request_seen_before"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event_source_post WHERE request_key IS NOT NULL").fetchone()["n"] == 1


def test_an_old_signed_request_makes_no_event_and_a_request_id_header_makes_a_resend_one_request(server, disclosure, conn):
    assert _post(server, _grant(disclosure), ts=int(time.time()) - 3600)[0] == 201
    assert _facts(conn, _posts(conn)[0]["post_id"])["event_not_derived"] == "not_authenticated:stale_timestamp"
    now = int(time.time())
    for i in range(2):  # two different signatures, one request id: one request
        assert _post(server, STOP, ts=now - 5 - i, headers={"X-ConsentVault-Request-Id": "r-1"})[0] == 201
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type = 'revoke'").fetchone()["n"] == 1


# 2. a large body is inside the chain ------------------------------------------------------------------------------------------

@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def evidence(tmp_path):
    return LocalAppendOnlyEvidenceStore(str(tmp_path / "ev"))


def big_post(tenancy, evidence):
    writer = rawpost.RawPostWriter(crypto=tenancy.crypto, store=evidence, receipts=ReceiptSigner.generate(key_id="k"))
    req = rawpost.RawRequest(intake="api", method="POST", path="/v1/events", query="", headers=(),
                             body=b"y" * (rawpost.INLINE_LIMIT_BYTES + 5))
    with tenancy.app() as app:
        return writer, writer.write(app, lambda c: org_transaction(c, tenancy.token(tenancy.a)), req)


def test_the_object_digest_is_in_the_chained_row_and_a_changed_digest_breaks_the_chain(tenancy, evidence):
    _, stored = big_post(tenancy, evidence)
    with tenancy.superuser() as su:
        assert su.execute("SELECT body_object_sha256 FROM consentvault.raw_post").fetchone()["body_object_sha256"]
        su.execute("ALTER TABLE consentvault.raw_post DISABLE TRIGGER raw_post_append_only")
        su.execute("UPDATE consentvault.raw_post SET body_object_sha256 = %s", ("e" * 64,))
        su.execute("ALTER TABLE consentvault.raw_post ENABLE TRIGGER raw_post_append_only")
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert [b["reason"] for b in rawpost.verify_raw_chain(app)] == ["row_hash does not recompute from the stored columns"]


def test_the_daily_check_reads_every_stored_body_back_and_a_changed_or_missing_one_is_a_break(tenancy, evidence, monkeypatch):
    writer, stored = big_post(tenancy, evidence)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert rawpost.verify_raw_bodies(app, evidence, tenancy.crypto) == []
        monkeypatch.setattr(evidence, "get", lambda org, key: b"z" * 100)
        assert [b["reason"] for b in rawpost.verify_raw_bodies(app, evidence, tenancy.crypto)] == \
            ["the stored body differs from the digest in the row"]
        from consentvault.providers.errors import EvidenceNotFoundError

        def gone(org, key):
            raise EvidenceNotFoundError("gone")
        monkeypatch.setattr(evidence, "get", gone)
        assert "cannot be read" in rawpost.verify_raw_bodies(app, evidence, tenancy.crypto)[0]["reason"]
        assert "no store was given" in rawpost.verify_raw_bodies(app, None)[0]["reason"]


def test_the_integrity_run_reports_a_raw_chain_break_and_a_missing_anchor(tenancy, evidence, tmp_path):
    from consentvault import db, integrity
    from isolation.harness import make_login_role

    big_post(tenancy, evidence)
    dsn = make_login_role(int(tenancy.app_dsn.rsplit(":", 1)[1].split("/")[0]), tenancy.app_dsn.rsplit("/", 1)[1], "consentvault_integrity")
    with db.connect(dsn) as c:
        assert integrity.verify_chain_every_org(c, store=evidence)[str(tenancy.a.org_id)] >= 3
    with tenancy.superuser() as su:
        su.execute("ALTER TABLE consentvault.raw_post DISABLE TRIGGER raw_post_append_only")
        su.execute("UPDATE consentvault.raw_post SET body_bytes = body_bytes + 1")
        su.execute("ALTER TABLE consentvault.raw_post ENABLE TRIGGER raw_post_append_only")
    with db.connect(dsn) as c, pytest.raises(integrity.IntegrityRunError) as e:
        integrity.verify_chain_every_org(c, store=evidence)
    assert "raw post seq 1" in str(e.value)


# 3. the standard library's own refusals are stored instead ----------------------------------------------------------------------

def test_requests_the_http_library_refuses_are_stored_as_received_and_answered_with_a_receipt(server, conn):
    cases = {
        "too many headers": b"POST /v1/events HTTP/1.1\r\nHost: localhost\r\n" + b"".join(b"X-%d: v\r\n" % i for i in range(150))
                            + b"Content-Length: 2\r\n\r\n{}",
        "a request line over 64 KiB": b"POST /v1/events/" + b"a" * 70000 + b" HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "a malformed request line": b"this is not http\r\n\r\n",
        "HEAD": b"HEAD /v1/events HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "an unknown method": b"BREW /v1/events HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc",
    }
    for name, data in cases.items():
        out = raw_exchange(server, data)
        server.settle()
        if name == "a malformed request line":  # no version: the library answers in the old bare style, with the receipt as the body
            assert b'"stored": true' in out
            continue
        assert out.startswith(b"HTTP/1.") and b" 201 " in out.split(b"\r\n", 1)[0] + b" ", (name, out[:80])
    posts = _posts(conn)
    assert len(posts) == len(cases)
    methods = [p["method"] for p in posts]
    assert methods[3:] == ["HEAD", "BREW"]
    assert bytes(posts[4]["body_ct"]) == b"abc"
    assert "refused_by_the_http_server" in _facts(conn, posts[0]["post_id"])
    # nothing the library would have discarded is lost: all 150 headers and the body of the first, the whole line of the second
    names = [n for n, _ in json.loads(bytes(posts[0]["headers_ct"]))]
    assert len([n for n in names if n.startswith("X-")]) == 150 and bytes(posts[0]["body_ct"]) == b"{}"
    assert bytes(posts[1]["path_ct"]) == b"/v1/events/" + b"a" * 70000
    assert rawpost.verify_raw_chain(conn) == []


def test_an_overlong_request_line_keeps_the_headers_and_body_that_follow_it(server, conn):
    out = raw_exchange(server, b"POST /v1/events/" + b"b" * 70000 + b" HTTP/1.1\r\nHost: localhost\r\nX-Keep: yes\r\nContent-Length: 5\r\n\r\nhello")
    server.settle()
    assert b" 201 " in out.split(b"\r\n", 1)[0] + b" "
    post, = _posts(conn)
    assert bytes(post["body_ct"]) == b"hello" and ["X-Keep", "yes"] in json.loads(bytes(post["headers_ct"]))


def test_the_path_is_kept_as_the_exact_bytes_received(server, conn):
    out = raw_exchange(server, b"POST /v1/events/caf\xe9/%00x?q=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
    server.settle()
    assert b" 201 " in out.split(b"\r\n", 1)[0] + b" "
    post, = _posts(conn)
    assert bytes(post["path_ct"]) == b"/v1/events/caf\xe9/%00x"


# 4. the signed envelope is stored exactly, and read strictly ---------------------------------------------------------------------

def _env(**over):
    env = {"method": "POST", "path": "/capture", "query": "", "headers": [["a", "b"]], "body_b64": base64.b64encode(b"{}").decode(),
           "body_sha256": hashlib.sha256(b"{}").hexdigest(), "body_bytes": 2, "edge_facts": {}}
    env.update(over)
    return json.dumps(env).encode()


@pytest.mark.parametrize("bad", [{"method": 5}, {"path": None}, {"query": 1}, {"headers": [["a"]]}, {"headers": {"a": "b"}},
                                 {"edge_facts": []}, {"body_b64": 7}, {"body_sha256": 9}])
def test_an_envelope_that_is_not_shaped_as_the_contract_says_is_unreadable_and_nothing_is_filled_in(bad):
    with pytest.raises(edge_envelope.EnvelopeUnreadable):
        edge_envelope.unpack(_env(**bad))
    missing = json.loads(_env())
    del missing["method"]
    with pytest.raises(edge_envelope.EnvelopeUnreadable):
        edge_envelope.unpack(json.dumps(missing).encode())


def test_a_signed_envelope_is_stored_byte_for_byte_whatever_shape_it_has(server, conn):
    odd = _env(method=5, extra={"keep": [1, 2]})
    ts = str(int(time.time()))
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, odd)}
    assert _call(server + "/v1/events", "POST", odd, h)[0] == 201
    server.settle()
    post, = _posts(conn)
    assert bytes(post["body_ct"]) == odd and "edge_envelope_unreadable" in _facts(conn, post["post_id"])


# 5. arrival facts are hashed into the row and stamped by the database clock ----------------------------------------------------

def test_a_changed_arrival_fact_breaks_the_chain_and_a_caller_cannot_set_a_fact_time(tenancy, evidence):
    import psycopg

    writer = rawpost.RawPostWriter(crypto=tenancy.crypto, store=evidence)
    req = rawpost.RawRequest(intake="api", method="POST", path="/", query="", headers=(), body=b"{}",
                             facts=(rawpost.Fact("edge", "client_ip", "203.0.113.9"),))
    with tenancy.app() as app:
        stored = writer.write(app, lambda c: org_transaction(c, tenancy.token(tenancy.a)), req)
    with tenancy.superuser() as su:
        su.execute("ALTER TABLE consentvault.raw_post_fact DISABLE TRIGGER raw_post_fact_append_only")
        su.execute("UPDATE consentvault.raw_post_fact SET name = 'client_ip_other'")
        su.execute("ALTER TABLE consentvault.raw_post_fact ENABLE TRIGGER raw_post_fact_append_only")
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert [b["reason"] for b in rawpost.verify_raw_chain(app)] == ["the facts known at arrival do not match the row's facts digest"]
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("INSERT INTO consentvault.raw_post_fact (org_id, post_id, fact_id, source, name, value_ct, recorded_at)"
                        " VALUES (%s, %s, gen_random_uuid(), 'edge', 'x', %s, '2001-01-01')",
                        (tenancy.a.org_id, stored.post_id, b"x"))


# 6. S3 anchors for the raw chain -------------------------------------------------------------------------------------------------

def test_the_raw_chain_head_is_published_to_an_object_lock_sink_in_its_own_folder(tenancy, evidence, monkeypatch):
    from consentvault import anchor as anchor_mod
    from consentvault.providers.anchors import S3ObjectLockAnchorSink

    big_post(tenancy, evidence)
    published = []
    monkeypatch.setattr(anchor_mod, "publish_s3", lambda target, org, record, **k: published.append((target, org, record)))
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, ("gate_read",))):
        rec = anchor_mod.anchor(app, "s3://bucket")
    assert [p[2].get("chain") for p in published] == [None, "raw_post"] and rec["raw_post"]["seq"] == 1

    class Store:
        enforces_retention = True
        keys = []

        def put(self, org, key, data, *, retain_until):
            Store.keys.append(key)

    S3ObjectLockAnchorSink(Store()).publish(str(tenancy.a.org_id), {"chain": "raw_post", "seq": 1, "row_hash": "a" * 64})
    S3ObjectLockAnchorSink(Store()).publish(str(tenancy.a.org_id), {"seq": 1, "row_hash": "a" * 64})
    assert Store.keys[0].startswith("anchors-raw_post/") and Store.keys[1].startswith("anchors/")


# 7. only the name parameter names a multipart field ------------------------------------------------------------------------------

def test_a_file_part_whose_filename_is_checked_is_not_the_consent_box():
    body = (b'--B\r\nContent-Disposition: form-data; name="upload"; filename="checked"\r\n\r\nfile bytes\r\n'
            b'--B\r\nContent-Disposition: form-data; name="checked"\r\n\r\non\r\n--B--\r\n')
    got = extract.multipart_occurrences(body, "multipart/form-data; boundary=B", ["checked", "upload"])
    assert got == {"checked": [b"on"], "upload": [b"file bytes"]}
    part_type = (b'--B\r\nContent-Disposition: form-data; name="upload"\r\nContent-Type: text/plain; name="checked"\r\n\r\nx\r\n'
                 b'--B\r\nContent-Disposition: form-data; name="checked"\r\n\r\non\r\n--B--\r\n')
    assert extract.multipart_occurrences(part_type, "multipart/form-data; boundary=B", ["checked"]) == {"checked": [b"on"]}
    only_file = b'--B\r\nContent-Disposition: form-data; filename="checked"\r\n\r\nx\r\n--B--\r\n'
    assert extract.multipart_occurrences(only_file, "multipart/form-data; boundary=B", ["checked"]) == {"checked": []}


# 8. a reading never written is an error, and each reading names its versions ----------------------------------------------------

def test_a_reading_that_was_never_written_raises_and_a_written_one_names_its_map_and_extractor_version(tenancy, evidence):
    from consentvault import intake

    writer = rawpost.RawPostWriter(crypto=tenancy.crypto, store=evidence)
    enter = lambda c: org_transaction(c, tenancy.token(tenancy.a))  # noqa: E731
    req = rawpost.RawRequest(intake="edge_site_key", method="POST", path="/", query="", headers=(), body=b'{"checked": true}')
    with tenancy.app() as app:
        stored = writer.write(app, enter, req)
        intake.read_after_commit(writer, app, enter, stored, req)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        key = writer.open_key(app, tenancy.a.org_id, stored.post_id)
        r = extract.read_stored_values(app, tenancy.a.org_id, stored.post_id, "consent", data_key=key)
        assert (r["map_version"], r["extractor_version"], r["values"]) == (0, extract.EXTRACTOR_VERSION, ["true"])
        with pytest.raises(extract.ReadingNotWritten):
            extract.read_stored_values(app, tenancy.a.org_id, stored.post_id, "no_such_field", data_key=key)
        with pytest.raises(extract.ReadingNotWritten):
            extract.read_stored_values(app, tenancy.a.org_id, stored.post_id, "consent", map_version=9, data_key=key)
