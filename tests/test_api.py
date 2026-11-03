import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import api
from consentvault.capture import capture

SECRET = "test-shared-secret"
TOKEN = "test-bearer-token"
VERIFIED_SECRET = "test-verified-grant-secret"


PURPOSES = ("marketing", "billing")


class Url(str):
    """The server's base address, which also waits for the work that follows an answer."""

    def settle(self):
        self.srv.drain(30)


def _serve(settings):
    srv = api.make_server(settings, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        url = Url(f"http://127.0.0.1:{srv.server_address[1]}")
        url.srv = srv
        yield url
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=10)


@pytest.fixture
def server(dsn, app_dsn):
    """The API as deployed: it talks to the database as the restricted runtime role."""
    yield from _serve(api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES,
                                      verified_secret=VERIFIED_SECRET, default_region="US"))  # gitleaks:allow (test constant)


def _call(url, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {}), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (json.loads(raw) if raw else {}), dict(e.headers)


def _post(server, payload, *, secret=SECRET, ts=None, signature=None, headers=None):
    body = json.dumps(payload).encode()
    ts = str(int(time.time())) if ts is None else str(ts)
    sig = signature if signature is not None else api.sign(secret, ts, body)
    h = {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: sig}
    h.update(headers or {})
    out = _call(server + "/v1/events", "POST", body, h)
    server.settle()
    return out


def _grant(sha, contact="+12125550101"):
    return {"contact": contact, "event_type": "grant", "checked": True, "channels": ["sms"],
            "purposes": ["marketing"], "disclosure_sha256": sha, "method": "checkbox", "origin": "consumer",
            "session_ref": "s-1"}


def _posts(conn):
    return conn.execute("SELECT * FROM consentvault.raw_post ORDER BY seq").fetchall()


def _facts(conn, post_id):
    return {r["name"]: json.loads(bytes(r["value_ct"])) for r in conn.execute(
        "SELECT name, value_ct FROM consentvault.raw_post_fact WHERE post_id = %s", (post_id,)).fetchall()}


def _events(conn):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"]


def _stored(status, body):
    assert status == 201 and body["stored"] is True and len(body["body_sha256"]) == 64, (status, body)
    return body


def test_a_bad_signature_is_stored_whole_with_the_result_as_a_fact_and_writes_no_event(server, disclosure, conn):
    payload = _grant(disclosure)
    status, body, _ = _post(server, payload, secret="wrong")
    _stored(status, body)
    post, = _posts(conn)
    assert bytes(post["body_ct"]) == json.dumps(payload).encode() and str(post["post_id"]) == body["post_id"]
    assert _facts(conn, post["post_id"])["request_signature"] == "bad_signature"
    assert _events(conn) == 0


def test_an_unsigned_post_is_stored_with_the_fact_unsigned(server, disclosure, conn):
    status, body, _ = _call(server + "/v1/events", "POST", b"{}", {"Content-Type": "application/json"})
    server.settle()
    _stored(status, body)
    assert _facts(conn, _posts(conn)[0]["post_id"])["request_signature"] == "unsigned"


def test_a_stale_timestamp_is_stored_with_the_fact_and_writes_no_event(server, disclosure, conn):
    status, body, _ = _post(server, _grant(disclosure), ts=int(time.time()) - 301)
    _stored(status, body)
    assert _facts(conn, _posts(conn)[0]["post_id"])["request_signature"] == "stale_timestamp" and _events(conn) == 0


def test_a_replayed_request_is_stored_again_with_the_fact_replay_and_makes_one_event_only(server, disclosure, conn):
    payload = _grant(disclosure)
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    first = _call(server + "/v1/events", "POST", body, h)
    server.settle()
    second = _call(server + "/v1/events", "POST", body, h)
    server.settle()
    assert first[0] == 201 and second[0] == 201 and first[1]["post_id"] != second[1]["post_id"]
    a, b = _posts(conn)
    assert _facts(conn, a["post_id"])["replay"] == "fresh" and _facts(conn, b["post_id"])["replay"] == "replay"
    assert _events(conn) == 1 and first[1]["body_sha256"] == second[1]["body_sha256"]


def test_a_valid_post_is_stored_first_and_also_recorded_as_an_event(server, disclosure, conn):
    status, body, headers = _post(server, _grant(disclosure))
    _stored(status, body)
    row = conn.execute("SELECT * FROM consentvault.event").fetchone()
    assert row["contact_norm"] == "+12125550101" and row["event_type"] == "grant" and row["payload_sha256"] is not None
    assert _facts(conn, _posts(conn)[0]["post_id"])["event_derived"] == str(row["event_id"])
    assert headers["Access-Control-Allow-Origin"] == "*" and body["receipt"]["seq"] == 1


def test_an_unchecked_box_is_stored_as_sent_and_is_not_made_a_grant(server, disclosure, conn):
    payload = _grant(disclosure)
    payload["checked"] = False
    status, body, _ = _post(server, payload)
    _stored(status, body)
    post, = _posts(conn)
    assert json.loads(bytes(post["body_ct"]))["checked"] is False
    consent = conn.execute("SELECT state, values_ct FROM consentvault.raw_post_field WHERE field = 'consent'").fetchone()
    assert consent["state"] == "sent" and json.loads(bytes(consent["values_ct"])) == ["false"]
    assert _events(conn) == 0 and _facts(conn, post["post_id"])["event_not_derived"] == "UncheckedConsentError"


def test_a_missing_box_is_stored_as_not_sent_and_the_event_records_why_it_is_not_a_grant(server, disclosure, conn):
    payload = _grant(disclosure)
    del payload["checked"]
    status, body, _ = _post(server, payload)
    _stored(status, body)
    assert conn.execute("SELECT state FROM consentvault.raw_post_field WHERE field = 'consent'").fetchone()["state"] == "not_sent"
    assert _facts(conn, _posts(conn)[0]["post_id"])["event_not_derived"] == "UncheckedConsentError"
    # a stop carries no box, so the events API map does not raise the missing-box alarm (a form's own map does)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.operator_alarm").fetchone()["n"] == 0


def test_stop_event_is_recorded(server, disclosure):
    _post(server, _grant(disclosure))
    status, body, _ = _post(server, {"contact": "+12125550101", "event_type": "revoke", "channels": ["sms"],
                                     "purposes": ["marketing"], "method": "keyword"})
    _stored(status, body)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    s, perm, _ = _call(server + "/v1/permission?contact=%2B12125550101&channel=sms&purpose=marketing", headers=auth)
    assert s == 200 and perm["allowed"] is False and perm["reason"] == "stopped:revoke"


@pytest.mark.parametrize("body", [b"", b"\x00\xff\xfe garbage", b"{broken", b"[1,2,3]", b'"just a string"', b"null"])
def test_any_body_is_stored_and_answered_with_a_receipt(server, conn, body):
    status, answer, _ = _call(server + "/v1/events", "POST", body, {"Content-Type": "application/octet-stream"})
    server.settle()
    _stored(status, answer)
    assert answer["body_bytes"] == len(body) and answer["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert bytes(_posts(conn)[0]["body_ct"]) == body and _events(conn) == 0


def test_a_body_over_the_old_one_mebibyte_limit_is_stored_whole(server, conn):
    body = b"x" * (3 * 1024 * 1024)
    status, answer, _ = _call(server + "/v1/events", "POST", body, {"Content-Type": "text/plain"})
    server.settle()
    _stored(status, answer)
    assert answer["body_bytes"] == len(body) and answer["unusual_size"] is True
    assert bytes(_posts(conn)[0]["body_ct"]) == body


def test_a_chunked_body_is_stored_whole(server, conn):
    import http.client

    host, port = server.replace("http://", "").split(":")
    c = http.client.HTTPConnection(host, int(port))
    c.putrequest("POST", "/v1/events")
    c.putheader("Transfer-Encoding", "chunked")
    c.endheaders()
    for part in (b"hello ", b"chunked ", b"world"):
        c.send(b"%x\r\n" % len(part) + part + b"\r\n")
    c.send(b"0\r\n\r\n")
    r = c.getresponse()
    answer = json.loads(r.read())
    server.settle()
    _stored(r.status, answer)
    assert bytes(_posts(conn)[0]["body_ct"]) == b"hello chunked world"


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE"])
def test_every_method_on_the_capture_path_is_a_post_that_is_stored(server, conn, method):
    status, answer, _ = _call(server + "/v1/events?a=1", method, b"x" if method != "GET" else None, {})
    server.settle()
    _stored(status, answer)
    post, = _posts(conn)
    assert post["method"] == method and post["path"] == "/v1/events"


def test_a_browser_permission_check_is_answered_for_any_origin_and_stored_as_a_preflight(server, conn):
    h = {"Origin": "https://anywhere.example", "Access-Control-Request-Method": "POST",
         "Access-Control-Request-Headers": "content-type, x-consentvault-site-key"}
    status, _, headers = _call(server + "/v1/events", "OPTIONS", None, h)
    server.settle()
    assert status == 204 and headers["Access-Control-Allow-Origin"] == "https://anywhere.example" and headers["Vary"] == "Origin"
    post, = _posts(conn)
    assert post["kind"] == "preflight" and post["method"] == "OPTIONS"


def test_a_host_that_is_not_on_the_list_is_stored_with_the_fact(server, disclosure, conn):
    status, body, _ = _post(server, _grant(disclosure), headers={"Host": "evil.example.net"})
    _stored(status, body)
    assert _facts(conn, _posts(conn)[0]["post_id"])["host_on_list"] is False


def test_headers_are_stored_in_order_with_repeats(server, conn):
    _call(server + "/v1/events", "POST", b"{}", {"X-Thing": "one", "Content-Type": "application/json"})
    server.settle()
    post, = _posts(conn)
    assert post["headers_presented_by"] == "vault-http" and post["intake"] == "api_single"




def test_permission_and_proof_need_the_bearer_token(server, disclosure, conn):
    capture(conn, contact="+12125550101", checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    q = "?contact=%2B12125550101&channel=sms&purpose=marketing"
    assert _call(server + "/v1/permission" + q)[0] == 401
    assert _call(server + "/v1/permission" + q, headers={"Authorization": "Bearer nope"})[0] == 401
    auth = {"Authorization": f"Bearer {TOKEN}"}
    s, perm, _ = _call(server + "/v1/permission" + q, headers=auth)
    assert s == 200 and perm["allowed"] is True
    s, proof, _ = _call(server + "/v1/proof?contact=%2B12125550101", headers=auth)
    assert s == 200 and proof["found"] is True and len(proof["timeline"]) == 1


def test_unknown_contact_fails_closed(server):
    auth = {"Authorization": f"Bearer {TOKEN}"}
    s, perm, _ = _call(server + "/v1/permission?contact=%2B12125550177&channel=sms&purpose=marketing", headers=auth)
    assert s == 200 and perm["allowed"] is False and perm["reason"] == "no_consent_on_record"
    s, proof, _ = _call(server + "/v1/proof?contact=%2B12125550177", headers=auth)
    assert s == 200 and proof["found"] is False


def test_host_allowlist_and_no_cors(server):
    auth = {"Authorization": f"Bearer {TOKEN}", "Host": "evil.example.net"}
    s, body, _ = _call(server + "/v1/proof?contact=%2B12125550101", headers=auth)
    assert s == 421 and body["error"] == "host_not_allowed"
    s, body, headers = _call(server + "/v1/proof", "OPTIONS", headers={"Origin": "https://example.com"})
    assert s == 405
    assert not any(k.lower().startswith("access-control") for k in headers)


def test_settings_require_secret_token_and_purposes(tmp_path):
    from consentvault.errors import ConfigError

    base = {"CONSENTVAULT_DSN": "postgresql://u@h/db"}
    with pytest.raises(ConfigError):
        api.load_api_settings(env=base)
    with pytest.raises(ConfigError, match="purpose list"):
        api.load_api_settings(env={**base, api.ENV_SECRET: "a", api.ENV_TOKEN: "b"})
    s = api.load_api_settings(env={**base, api.ENV_SECRET: "a", api.ENV_TOKEN: "b", "CONSENTVAULT_PURPOSES": "Marketing, billing"})
    assert s.allowed_hosts == api.DEFAULT_HOSTS and s.purposes == ("billing", "marketing")
    assert hashlib.sha256(b"x")  # keep import used




def test_edge_fields_are_accepted_and_recorded(server, conn, disclosure):
    payload = _grant(disclosure)
    payload.update({"edge_received_at": "2026-01-02T03:04:05.000Z", "payload_sha256": "ab" * 32, "bot_check": "none"})
    before = datetime.now(timezone.utc)
    status, body, _ = _post(server, payload)
    _stored(status, body)
    row = conn.execute("SELECT received_at, edge_received_at, payload_sha256 FROM consentvault.event").fetchone()
    assert row["edge_received_at"] == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert row["payload_sha256"] == "ab" * 32
    assert before - timedelta(seconds=5) <= row["received_at"] <= datetime.now(timezone.utc) + timedelta(seconds=5)


def test_a_caller_supplied_received_at_is_stored_in_the_body_and_never_used_as_the_vaults_clock(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["received_at"] = "2099-01-01T00:00:00Z"
    status, body, _ = _post(server, payload)
    _stored(status, body)
    assert json.loads(bytes(_posts(conn)[0]["body_ct"]))["received_at"] == "2099-01-01T00:00:00Z"
    ev = conn.execute("SELECT received_at FROM consentvault.event").fetchone()
    assert ev["received_at"] < datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert _posts(conn)[0]["received_at"] < datetime(2030, 1, 1, tzinfo=timezone.utc)


def test_a_captured_at_far_ahead_of_the_vaults_clock_is_stored_and_makes_no_event(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["captured_at"] = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
    payload["edge_received_at"] = payload["captured_at"]
    status, body, _ = _post(server, payload)
    _stored(status, body)
    post, = _posts(conn)
    assert json.loads(bytes(post["body_ct"]))["captured_at"] == payload["captured_at"]
    assert _facts(conn, post["post_id"])["event_not_derived"] == "ClockSkewError" and _events(conn) == 0
    assert conn.execute("SELECT decision_time_parsed FROM consentvault.raw_post_field WHERE field = 'decision_time'"
                        ).fetchone()["decision_time_parsed"].year >= 2035


def _own_stop(conn):
    from consentvault.ledger import record_event

    record_event(conn, contact="+12125550101", event_type="revoke", channels=["sms"], purposes=["marketing"],
                 method="keyword", origin="consumer")


def test_a_web_grant_does_not_lift_the_contacts_own_stop_and_opens_a_review(server, conn, disclosure):
    _own_stop(conn)
    payload = _grant(disclosure)
    payload["contact_verification"] = "none"
    status, body, _ = _post(server, payload)
    _stored(status, body)
    row = conn.execute("SELECT release_outcome, release_cause FROM consentvault.event WHERE event_type = 'release'"
                       ).fetchone()
    assert (row["release_outcome"], row["release_cause"]) == ("refused", "contact_control_unverified")
    review = conn.execute("SELECT kind, status, contact_norm FROM consentvault.review").fetchall()
    assert [(r["kind"], r["status"], r["contact_norm"]) for r in review] == [("release", "pending", "+12125550101")]


def test_an_otp_confirmed_grant_lifts_the_stop(server, conn, disclosure):
    _own_stop(conn)
    payload = _grant(disclosure)
    payload["contact_verification"] = "otp"
    status, body, _ = _post(server, payload, secret=VERIFIED_SECRET)
    _stored(status, body)
    assert conn.execute("SELECT contact_verification FROM consentvault.event WHERE event_type = 'grant'"
                        ).fetchone()["contact_verification"] == "otp"
    assert conn.execute("SELECT release_outcome FROM consentvault.event WHERE event_type = 'release'").fetchone()["release_outcome"] == "released"


def test_the_capture_edges_secret_cannot_claim_a_verified_contact_but_the_post_is_stored(server, conn, disclosure):
    _own_stop(conn)
    payload = _grant(disclosure)
    payload["contact_verification"] = "otp"
    status, body, _ = _post(server, payload)
    _stored(status, body)
    assert _events(conn) == 1
    assert _facts(conn, _posts(conn)[0]["post_id"])["event_not_derived"] == "verification_key_required"


def test_an_inbound_start_text_is_stored_and_never_a_grant_or_a_lift(server, conn, disclosure):
    _own_stop(conn)
    payload = _grant(disclosure)
    payload.update({"contact_verification": "inbound_keyword", "method": "keyword", "inbound_message": "START"})
    n = conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"]
    status, body, _ = _post(server, payload, secret=VERIFIED_SECRET)
    _stored(status, body)
    assert _facts(conn, _posts(conn)[0]["post_id"])["event_not_derived"] == "a_text_is_not_consent"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == n


def test_wording_on_the_wire_is_stored_exactly_as_sent_and_the_registered_wording_is_not_replaced(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["disclosure_text"] = "I agree to anything."
    status, body, _ = _post(server, payload)
    _stored(status, body)
    post, = _posts(conn)
    assert json.loads(bytes(post["body_ct"]))["disclosure_text"] == "I agree to anything."
    assert conn.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 1
    r = conn.execute("SELECT state FROM consentvault.raw_post_field WHERE field = 'wording'").fetchone()
    assert r is None or r["state"] == "not_sent"  # the events API map names no wording field: the text is kept in the post


def test_a_hash_the_operator_never_registered_is_stored_and_makes_no_event(server, conn):
    status, body, _ = _post(server, _grant("cd" * 32))
    _stored(status, body)
    assert _events(conn) == 0 and _facts(conn, _posts(conn)[0]["post_id"])["event_not_derived"] == "UnknownDisclosureError"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 0


def test_a_grant_beyond_its_disclosure_is_stored_and_makes_no_event(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["channels"] = ["sms", "artificial_voice"]
    status, body, _ = _post(server, payload)
    _stored(status, body)
    assert _events(conn) == 0 and _facts(conn, _posts(conn)[0]["post_id"])["event_not_derived"] == "GrantScopeError"


def test_purposes_are_lower_cased_in_the_event_and_kept_as_sent_in_the_post(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["purposes"] = ["Marketing"]
    status, body, _ = _post(server, payload)
    _stored(status, body)
    assert conn.execute("SELECT purposes FROM consentvault.event").fetchone()["purposes"] == ["marketing"]
    assert json.loads(bytes(_posts(conn)[0]["body_ct"]))["purposes"] == ["Marketing"]
    payload["purposes"] = ["lottery"]
    status, body, _ = _post(server, payload)
    _stored(status, body)
    assert _events(conn) == 1 and _facts(conn, _posts(conn)[1]["post_id"])["event_not_derived"] == "UnknownPurposeError"


def test_permission_answers_through_the_gate_including_stop_all(server, conn, disclosure):
    _post(server, _grant(disclosure))
    auth = {"Authorization": f"Bearer {TOKEN}"}
    q = "?contact=%2B12125550101&channel=sms&purpose=Marketing"
    s, perm, _ = _call(server + "/v1/permission" + q, headers=auth)
    assert s == 200 and perm["allowed"] is True and perm["reason"] == "granted" and perm["basis_event_ids"]
    status, _, _ = _post(server, {"contact": "+12125550101", "event_type": "revoke", "channels": ["sms"],
                                  "purposes": ["*"], "method": "keyword"})
    assert status == 201
    s, perm, _ = _call(server + "/v1/permission" + q, headers=auth)
    assert s == 200 and perm["allowed"] is False and perm["reason"] == "stopped:revoke"
    s, perm, _ = _call(server + "/v1/permission?contact=%2B12125550101&channel=sms&purpose=billing", headers=auth)
    assert s == 200 and perm["allowed"] is False and perm["reason"] == "stopped:revoke"


def test_permission_returns_the_named_denial_when_the_database_errors(raw_dsn):
    """An unmigrated database raises a psycopg error inside the gate; an unreachable one fails to connect."""
    auth = {"Authorization": f"Bearer {TOKEN}"}
    q = "?contact=%2B12125550101&channel=sms&purpose=marketing"
    for bad_dsn in (raw_dsn, "postgresql://nobody@127.0.0.1:1/none"):
        settings = api.ApiSettings(dsn=bad_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, default_region="US")
        for base in _serve(settings):
            s, perm, _ = _call(base + "/v1/permission" + q, headers=auth)
            assert perm["allowed"] is False and perm["reason"].startswith("database_unreachable:"), perm
            assert s in (200, 503)


def test_the_vault_being_unavailable_is_the_only_answer_that_says_nothing_was_stored(raw_dsn):
    settings = api.ApiSettings(dsn="postgresql://nobody@127.0.0.1:1/none", secret=SECRET, token=TOKEN, purposes=PURPOSES, default_region="US")
    for base in _serve(settings):
        status, body, _ = _call(base + "/v1/events", "POST", b"{}", {})
        assert status == 503 and body["stored"] is False and body["error"] == "store_unavailable"


def test_bad_edge_timestamp_and_payload_hash_are_stored_and_the_event_is_made_without_them(server, conn, disclosure):
    p = _grant(disclosure)
    p["edge_received_at"] = "yesterday"
    assert _post(server, p)[0] == 201
    assert _facts(conn, _posts(conn)[0]["post_id"])["event_not_derived"] == "bad_edge_received_at" and _events(conn) == 0
    p = _grant(disclosure)
    p["payload_sha256"] = "nothex"
    assert _post(server, p)[0] == 201 and _events(conn) == 1


def test_the_gateways_service_credentials_for_the_hop_are_not_stored_and_a_fact_says_so(server, conn):
    _call(server + "/v1/events", "POST", b"{}", {"cf-access-client-id": "id-1", "cf-access-client-secret": "secret-1",
                                                  "X-Other": "kept", "Content-Type": "application/json"})
    server.settle()
    post, = _posts(conn)
    names = [n.lower() for n, _ in json.loads(bytes(post["headers_ct"]))]
    assert "x-other" in names and "cf-access-client-secret" not in names and "cf-access-client-id" not in names
    assert b"secret-1" not in bytes(post["headers_ct"]) and _facts(conn, post["post_id"])["gateway_service_credentials_not_stored"] is True
