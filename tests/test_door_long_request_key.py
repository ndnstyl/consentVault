"""A signed stop with an oversized request-id header is stored and counted (one-door review round 4, gate 1). The request key is
indexed as a digest, never as the sender's text, and a failure to write the key row never undoes the post."""

import hashlib
import json
import secrets
import time

import psycopg

from consentvault import api
from consentvault.capture_http import REQUEST_ID_HEADER
from consentvault.rawpost import RawPostWriter
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _call, _serve


def _post(app_dsn, rid):
    s = api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET, default_region="US")
    gen = _serve(s)
    base = next(gen)
    body = json.dumps({"contact": "+12125550199", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                       "method": "keyword", "origin": "consumer"}).encode()
    ts = str(int(time.time()))
    h = {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body), REQUEST_ID_HEADER: rid}
    st, b, _ = _call(base + "/v1/events", "POST", body, h)
    base.settle()
    gen.close()
    return st, body


def test_a_twelve_thousand_character_request_id_is_stored_and_counted(app_dsn, conn):
    rid = secrets.token_hex(6000)
    before = conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"]
    st, _ = _post(app_dsn, rid)
    after = conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"]
    assert st == 201 and after == before + 1
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE contact_norm='+12125550199'").fetchone()["n"] == 1


def test_the_key_is_kept_as_a_sha256_and_never_as_the_senders_text(app_dsn, conn):
    rid = "plain-id-" + secrets.token_hex(8)
    _post(app_dsn, rid)
    keys = [r["request_key"] for r in conn.execute("SELECT request_key FROM consentvault.raw_post_request").fetchall()]
    keys += [r["request_key"] for r in conn.execute("SELECT request_key FROM consentvault.event_source_post WHERE request_key IS NOT NULL").fetchall()]
    assert keys and all(len(k) == 64 and all(ch in "0123456789abcdef" for ch in k) for k in keys)
    assert not any(rid in k for k in keys)


def test_a_failure_to_write_the_key_row_leaves_the_post_stored(app_dsn, conn, monkeypatch):
    def broken(conn_, org, post_id, key):
        raise psycopg.errors.ProgramLimitExceeded("index row too large")
    monkeypatch.setattr(RawPostWriter, "_write_request_key", staticmethod(broken))
    before = conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"]
    st, _ = _post(app_dsn, "short-id")
    after = conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"]
    assert st == 201 and after == before + 1


def test_the_digest_is_the_sha256_of_the_key():
    from consentvault.rawpost import request_key_digest
    assert request_key_digest("id:abc:def") == hashlib.sha256(b"id:abc:def").hexdigest()
