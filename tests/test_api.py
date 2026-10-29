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


def _serve(settings):
    srv = api.make_server(settings, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
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
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


def _post(server, payload, *, secret=SECRET, ts=None, signature=None, headers=None):
    body = json.dumps(payload).encode()
    ts = str(int(time.time())) if ts is None else str(ts)
    sig = signature if signature is not None else api.sign(secret, ts, body)
    h = {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: sig}
    h.update(headers or {})
    return _call(server + "/v1/events", "POST", body, h)


def _grant(sha, contact="+12125550101"):
    return {"contact": contact, "event_type": "grant", "checked": True, "channels": ["sms"],
            "purposes": ["marketing"], "disclosure_sha256": sha, "method": "checkbox", "origin": "consumer",
            "session_ref": "s-1"}


def test_bad_signature_is_401(server, disclosure):
    status, body, _ = _post(server, _grant(disclosure), secret="wrong")
    assert status == 401 and body["error"] == "bad_signature"


def test_unsigned_is_401(server, disclosure):
    status, body, _ = _call(server + "/v1/events", "POST", b"{}", {"Content-Type": "application/json"})
    assert status == 401 and body["error"] == "unsigned"


def test_stale_timestamp_is_refused(server, disclosure):
    status, body, _ = _post(server, _grant(disclosure), ts=int(time.time()) - 301)
    assert status == 401 and body["error"] == "stale_timestamp"


def test_replay_is_refused(server, disclosure):
    payload = _grant(disclosure)
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    first = _call(server + "/v1/events", "POST", body, h)
    second = _call(server + "/v1/events", "POST", body, h)
    assert first[0] == 201
    assert second[0] == 409 and second[1]["error"] == "replay"


def test_valid_post_records_an_event(server, disclosure, conn):
    status, body, headers = _post(server, _grant(disclosure))
    assert status == 201 and body["ok"] is True
    row = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (body["event_id"],)).fetchone()
    assert row["contact_norm"] == "+12125550101" and row["event_type"] == "grant"
    assert row["payload_sha256"] is not None
    assert not any(k.lower().startswith("access-control") for k in headers)


def test_unchecked_grant_is_refused_and_not_recorded(server, disclosure, conn):
    payload = _grant(disclosure)
    payload["checked"] = False
    status, body, _ = _post(server, payload)
    assert status == 422 and body["error"] == "UncheckedConsentError"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


def test_stop_event_is_recorded(server, disclosure):
    _post(server, _grant(disclosure))
    status, body, _ = _post(server, {"contact": "+12125550101", "event_type": "revoke", "channels": ["sms"],
                                     "purposes": ["marketing"], "method": "keyword"})
    assert status == 201
    auth = {"Authorization": f"Bearer {TOKEN}"}
    s, perm, _ = _call(server + "/v1/permission?contact=%2B12125550101&channel=sms&purpose=marketing", headers=auth)
    assert s == 200 and perm["allowed"] is False and perm["reason"] == "stopped:revoke"


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
    assert status == 201, body
    row = conn.execute("SELECT received_at, edge_received_at, payload_sha256 FROM consentvault.event WHERE event_id = %s::uuid",
                       (body["event_id"],)).fetchone()
    assert row["edge_received_at"] == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert row["payload_sha256"] == "ab" * 32
    assert before - timedelta(seconds=5) <= row["received_at"] <= datetime.now(timezone.utc) + timedelta(seconds=5)


def test_the_vault_stamps_received_at_and_refuses_a_caller_supplied_one(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["received_at"] = "2099-01-01T00:00:00Z"
    status, body, _ = _post(server, payload)
    assert status == 400 and body["error"] == "unknown_fields"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


def test_a_captured_at_far_ahead_of_the_vaults_clock_is_refused(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["captured_at"] = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
    payload["edge_received_at"] = payload["captured_at"]
    status, body, _ = _post(server, payload)
    assert status == 422 and body["error"] == "ClockSkewError"


def _own_stop(conn):
    from consentvault.ledger import record_event

    record_event(conn, contact="+12125550101", event_type="revoke", channels=["sms"], purposes=["marketing"],
                 method="keyword", origin="consumer")


def test_a_web_grant_does_not_lift_the_contacts_own_stop_and_opens_a_review(server, conn, disclosure):
    _own_stop(conn)
    payload = _grant(disclosure)
    payload["contact_verification"] = "none"
    status, body, _ = _post(server, payload)
    assert status == 201, body
    assert body["release"] == {"released_channels": [], "refusals": {"contact_control_unverified": ["sms"]}}
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
    assert status == 201, body
    assert body["release"] == {"released_channels": ["sms"], "refusals": {}}
    assert conn.execute("SELECT contact_verification FROM consentvault.event WHERE event_type = 'grant'"
                        ).fetchone()["contact_verification"] == "otp"


def test_the_capture_edges_secret_cannot_claim_a_verified_contact(server, conn, disclosure):
    _own_stop(conn)
    payload = _grant(disclosure)
    payload["contact_verification"] = "otp"
    status, body, _ = _post(server, payload)
    assert status == 403 and body["error"] == "verification_key_required"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 1


def test_an_inbound_start_keyword_grant_lifts_the_stop_only_for_a_start_message(server, conn, disclosure):
    _own_stop(conn)
    payload = _grant(disclosure)
    payload.update({"contact_verification": "inbound_keyword", "method": "keyword", "inbound_message": "what is this"})
    status, body, _ = _post(server, payload, secret=VERIFIED_SECRET)
    assert status == 422 and body["error"] == "InvalidEventError"
    payload["inbound_message"] = "START"
    status, body, _ = _post(server, payload, secret=VERIFIED_SECRET)
    assert status == 201, body
    assert body["release"]["released_channels"] == ["sms"]


def test_a_verification_claim_without_the_inbound_message_is_refused(server, disclosure):
    payload = _grant(disclosure)
    payload.update({"contact_verification": "inbound_keyword", "method": "keyword"})
    status, body, _ = _post(server, payload, secret=VERIFIED_SECRET)
    assert status == 422 and body["error"] == "InvalidEventError"


def test_wording_on_the_wire_is_refused(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["disclosure_text"] = "I agree to anything."
    status, body, _ = _post(server, payload)
    assert status == 400 and body["error"] == "disclosure_text_refused"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
    assert conn.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 1


def test_a_hash_the_operator_never_registered_is_422(server, conn):
    status, body, _ = _post(server, _grant("cd" * 32))
    assert status == 422 and body["error"] == "UnknownDisclosureError"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
    assert conn.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 0


def test_grant_beyond_its_disclosure_is_422(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["channels"] = ["sms", "artificial_voice"]
    status, body, _ = _post(server, payload)
    assert status == 422 and body["error"] == "GrantScopeError"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


def test_purposes_are_lower_cased_and_must_be_on_the_configured_list(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["purposes"] = ["Marketing"]
    status, body, _ = _post(server, payload)
    assert status == 201, body
    assert conn.execute("SELECT purposes FROM consentvault.event").fetchone()["purposes"] == ["marketing"]
    payload["purposes"] = ["lottery"]
    status, body, _ = _post(server, payload)
    assert status == 422 and body["error"] == "UnknownPurposeError"


def test_a_captured_at_in_the_future_is_422(server, conn, disclosure):
    payload = _grant(disclosure)
    payload["captured_at"] = "2099-01-01T00:00:00Z"
    status, body, _ = _post(server, payload)
    assert status == 422 and body["error"] == "ClockSkewError"


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


def test_bad_edge_timestamp_and_payload_hash_are_400(server, disclosure):
    p = _grant(disclosure)
    p["edge_received_at"] = "yesterday"
    assert _post(server, p)[1]["error"] == "bad_edge_received_at"
    p = _grant(disclosure)
    p["payload_sha256"] = "nothex"
    assert _post(server, p)[1]["error"] == "bad_payload_sha256"
