"""Wave 2 hardening over the real multi-tenant server: edge captures find their organisation by site key hash (e),
checklist results answer the gate and the proof instead of "unavailable" (f), and the portal reads the contract
follow-ups add (g). Loopback only."""

import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import pytest

from consentvault.tenancy.admin_base import ROLE_SCOPES
from consentvault.tenancy.site_keys import hash_site_key, resolve_site_key
from consentvault.tenancy.tokens import org_transaction

from admin.support import FakeIdentity

from .cloud_harness import Cloud, approve_policy, policy_rules
from .test_route_wiring import OPERATOR, Wired, _j

EDGE_SECRET = b"test-only-edge-signing-secret-0123456789"
X = "+15555550177"


@pytest.fixture
def hw(tenancy, tmp_path, pg_server):
    cloud = Cloud(tenancy, str(tmp_path / "evidence"))
    w = Wired(cloud, tmp_path, pg_server, edge_signing_secret=EDGE_SECRET)
    yield w
    w.close()
    cloud.close()


def _site_key(w, co, *, retire=False, revoke=False) -> str:
    key = "cv_site_" + secrets.token_urlsafe(18)
    t = w.t
    with t.operator() as o, org_transaction(o, t.admin_token(co.org.org_id)):
        cid = o.execute("INSERT INTO consentvault.credential (org_id, source_id, kind, scope, site_key_id, site_key_hash)"
                        " VALUES (%s, %s, 'edge_site_key', ARRAY['capture'], %s, %s) RETURNING credential_id",
                        (co.org.org_id, co.org.source_id, key, hash_site_key(key))).fetchone()["credential_id"]
        if revoke:
            o.execute("UPDATE consentvault.credential SET revoked_at = now() WHERE credential_id = %s", (cid,))
        if retire:
            o.execute("UPDATE consentvault.capture_source SET status = 'retired', retired_at = now()"
                      " WHERE org_id = %s AND source_id = %s", (co.org.org_id, co.org.source_id))
    return key


def _edge_body(co, key, **extra) -> dict:
    """What a browser's widget posts to the edge (the browser's own JSON; ``extra`` adds or overrides a field as sent)."""
    return {"contact": X, "checked": True, "disclosure_sha256": co.wording, "channels": ["sms"], "purposes": ["marketing"],
            "page_url": "https://example.test/signup", "session": "s-1", **extra}


def _envelope(key, browser, *, raw_body: bytes | None = None, origin="https://example.test", facts=None, extra_headers=()) -> bytes:
    """The one signed envelope the capture edge forwards: the browser's request, exact bytes and headers, with the edge's facts."""
    import base64

    raw = raw_body if raw_body is not None else json.dumps(browser).encode()
    headers = [["content-type", "application/json"], ["origin", origin], ["user-agent", "ua"],
               ["x-consentvault-site-key", key], *[list(h) for h in extra_headers]]
    edge_facts = {"client_ip": "203.0.113.9", "edge_received_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                  "bot_check_answer": {"success": True, "hostname": "example.test"}, **(facts or {})}
    return json.dumps({"method": "POST", "path": "/capture", "query": "", "headers": headers,
                       "body_b64": base64.b64encode(raw).decode(), "body_sha256": hashlib.sha256(raw).hexdigest(),
                       "body_bytes": len(raw), "edge_facts": edge_facts}).encode()


def _edge_post(w, data: bytes, *, secret=EDGE_SECRET, ts=None, sig=None):
    stamp = str(int(time.time())) if ts is None else str(ts)
    signature = sig or hmac.new(secret, stamp.encode() + b"." + data, hashlib.sha256).hexdigest()
    req = urllib.request.Request(w.base + "/v1/events", data=data, method="POST", headers={
        "Content-Type": "application/json", "X-ConsentVault-Timestamp": stamp, "X-ConsentVault-Signature": signature})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            out = r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:  # loud-failure-exempt: a non-2xx answer is returned to the test to assert on
        out = e.code, json.loads(e.read())
    w.server.drain(30)
    return out


def _events_of(w, org):
    with w.t.superuser() as su:
        return su.execute("SELECT event_id, source_id, org_id FROM consentvault.event WHERE org_id = %s AND source_id = %s"
                          " AND channels = ARRAY['sms']::text[] ORDER BY seq DESC", (org.org_id, org.source_id)).fetchall()


def _posts_of(w, org):
    from .cloud_harness import raw_posts
    return raw_posts(w.t, org.org_id)


def _facts(w, row):
    from .cloud_harness import facts_of
    return facts_of(w.t, row)


# ---- (e) site key to organisation ----------------------------------------------------------------------------------
def test_an_edge_capture_lands_in_the_organisation_its_site_key_belongs_to(hw):
    a, b = hw.cloud.a, hw.cloud.b
    key = _site_key(hw, a)
    before_a, before_b = len(_events_of(hw, a.org)), len(_events_of(hw, b.org))
    posts_a, posts_b = len(_posts_of(hw, a.org)), len(_posts_of(hw, b.org))
    status, body = _edge_post(hw, _envelope(key, _edge_body(a, key)))
    assert status == 201 and body["stored"] is True, body
    assert len(_events_of(hw, a.org)) == before_a + 1 and len(_events_of(hw, b.org)) == before_b
    assert len(_posts_of(hw, a.org)) == posts_a + 1 and len(_posts_of(hw, b.org)) == posts_b
    assert body["receipt"]["org_id"] == str(a.org.org_id)
    post = _posts_of(hw, a.org)[-1]
    assert (post["intake"], post["headers_presented_by"]) == ("edge_site_key", "vault-http")  # the signed envelope, as received
    facts = _facts(hw, post)
    assert facts["site_key_state"] == "active" and facts["edge_envelope_signature"] == "verified"
    assert facts["client_ip"] == "203.0.113.9" and facts["origin_on_list"] in (True, False)


def test_the_brands_come_from_the_source_when_the_browser_sends_none(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    status, answer = _edge_post(hw, _envelope(key, _edge_body(a, key)))
    assert status == 201 and _facts(hw, _posts_of(hw, a.org)[-1])["event_derived"]
    with hw.t.superuser() as su:
        ev = su.execute("SELECT brand_ids FROM consentvault.event WHERE org_id = %s ORDER BY seq DESC LIMIT 1",
                        (a.org.org_id,)).fetchone()
    assert [str(x) for x in ev["brand_ids"]] == [str(a.org.brand_id)]


def test_a_site_key_never_reaches_another_organisations_source_or_brand(hw):
    a, b = hw.cloud.a, hw.cloud.b
    key = _site_key(hw, a)
    before_b = len(_posts_of(hw, b.org))
    status, body = _edge_post(hw, _envelope(key, _edge_body(a, key, source_id=str(b.org.source_id), brand_ids=[str(b.org.brand_id)])))
    assert status == 201 and body["receipt"]["org_id"] == str(a.org.org_id)
    # the browser's own words are stored as sent; the event uses the key's source and brands, never the browser's
    from .cloud_harness import inner_body
    assert json.loads(inner_body(hw.t, _posts_of(hw, a.org)[-1]))["source_id"] == str(b.org.source_id)
    with hw.t.superuser() as su:
        ev = su.execute("SELECT source_id, brand_ids FROM consentvault.event WHERE org_id = %s ORDER BY seq DESC LIMIT 1", (a.org.org_id,)).fetchone()
    assert str(ev["source_id"]) == str(a.org.source_id) and [str(x) for x in ev["brand_ids"]] == [str(a.org.brand_id)]
    assert len(_posts_of(hw, b.org)) == before_b


def test_an_unknown_revoked_or_unsigned_edge_capture_is_stored_with_the_reason_and_makes_no_event(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    revoked = _site_key(hw, a, revoke=True)
    unknown = "cv_site_" + secrets.token_urlsafe(18)
    home = hw.t.home
    before_events = len(_events_of(hw, a.org))
    before_a = len(_posts_of(hw, a.org))
    from .cloud_harness import raw_posts
    cases = [
        (_edge_post(hw, _envelope(unknown, _edge_body(a, unknown))), "site_key_state", "unknown", home),
        (_edge_post(hw, _envelope("not-a-key", _edge_body(a, "not-a-key"))), "site_key_state", "unknown", home),
        (_edge_post(hw, _envelope(revoked, _edge_body(a, revoked))), "site_key_state", "revoked", a.org.org_id),  # names its organisation
        (_edge_post(hw, _envelope(key, _edge_body(a, key)), secret=b"another-secret-another-secret-123456"), "edge_envelope_signature", "failed", home),
        (_edge_post(hw, _envelope(key, _edge_body(a, key)), sig="0" * 64), "edge_envelope_signature", "failed", home),
    ]
    platform, mine = raw_posts(hw.t, home), _posts_of(hw, a.org)[before_a:]
    assert len(platform) == 4 and len(mine) == 1
    seen = {str(home): iter(platform), str(a.org.org_id): iter(mine)}
    for (status, answer), name, value, org in cases:
        assert status == 201 and answer["stored"] is True and answer["receipt"]["org_id"] == str(org)
        assert _facts(hw, next(seen[str(org)]))[name] == value
    assert len(_events_of(hw, a.org)) == before_events
    # an envelope whose signature failed is stored exactly as received (the envelope itself), and trusted for nothing
    assert (platform[2]["intake"], platform[2]["headers_presented_by"]) == ("api", "vault-http")


def test_a_stale_edge_timestamp_is_a_fact_not_a_refusal(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    before = len(_events_of(hw, a.org))
    status, body = _edge_post(hw, _envelope(key, _edge_body(a, key)), ts=int(time.time()) - 3600)
    assert status == 201  # the signature covers the timestamp it was made with, so a stale one is still verified, and flagged
    facts = _facts(hw, _posts_of(hw, a.org)[-1])
    assert facts["edge_timestamp"] == "stale" and facts["event_not_derived"] == "stale_timestamp"
    assert len(_events_of(hw, a.org)) == before  # an old signed request makes no consent event


def test_a_replayed_edge_capture_is_stored_again_and_the_fold_makes_one_event(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    raw = _envelope(key, _edge_body(a, key))
    stamp = str(int(time.time()))
    sig = hmac.new(EDGE_SECRET, stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    before = len(_events_of(hw, a.org))
    assert _edge_post(hw, raw, ts=stamp, sig=sig)[0] == 201
    status, body = _edge_post(hw, raw, ts=stamp, sig=sig)
    assert status == 201 and body["stored"] is True
    first, second = _posts_of(hw, a.org)[-2:]
    assert "replay" not in _facts(hw, first) and "replay" not in _facts(hw, second)
    assert len(_events_of(hw, a.org)) == before + 1


def test_a_queued_request_delivered_again_under_its_request_id_is_recorded_once_though_signed_again(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    before = len(_events_of(hw, a.org))
    first = _envelope(key, _edge_body(a, key), facts={"request_id": "req-42"})
    again = _envelope(key, _edge_body(a, key), facts={"request_id": "req-42", "queued_at_edge": "x", "delivered_from_queue_at": "y"})
    assert _edge_post(hw, first, ts=int(time.time()) - 3)[0] == 201
    assert _edge_post(hw, again)[0] == 201  # a new signature, the same request
    assert len(_events_of(hw, a.org)) == before + 1
    assert _facts(hw, _posts_of(hw, a.org)[-1])["event_not_derived"] == "request_seen_before"
    other = _envelope(key, _edge_body(a, key), facts={"request_id": "req-43"})  # the same words, a different request
    assert _edge_post(hw, other)[0] == 201 and len(_events_of(hw, a.org)) == before + 2


def test_a_retired_source_stores_the_capture_and_makes_no_event(hw):
    a = hw.cloud.a
    key = _site_key(hw, a, retire=True)
    before = len(_events_of(hw, a.org))
    status, body = _edge_post(hw, _envelope(key, _edge_body(a, key)))
    assert status == 201 and body["stored"] is True and body["receipt"]["org_id"] == str(a.org.org_id)
    assert _facts(hw, _posts_of(hw, a.org)[-1])["site_key_state"] == "source_retired"
    assert len(_events_of(hw, a.org)) == before


def test_an_edge_capture_cannot_claim_a_verified_contact(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    status, body = _edge_post(hw, _envelope(key, _edge_body(a, key, contact_verification="otp", origin="staff", method="staff")))
    assert status == 201
    with hw.t.superuser() as su:
        ev = su.execute("SELECT contact_verification, origin, method FROM consentvault.event WHERE org_id = %s ORDER BY seq DESC LIMIT 1",
                        (a.org.org_id,)).fetchone()
    assert (ev["contact_verification"], ev["origin"], ev["method"]) == ("none", "consumer", "checkbox")


def test_the_edge_path_stores_the_post_as_received_until_a_signing_secret_is_configured(tenancy, tmp_path, pg_server):
    cloud = Cloud(tenancy, str(tmp_path / "evidence"))
    w = Wired(cloud, tmp_path, pg_server)  # no edge secret
    try:
        key = _site_key(w, cloud.a)
        status, body = _edge_post(w, _envelope(key, _edge_body(cloud.a, key)))
        assert status == 201 and body["stored"] is True
        from .cloud_harness import raw_posts
        post = raw_posts(tenancy, tenancy.home)[-1]
        assert _facts(w, post)["edge_envelope_signature"] == "no_edge_secret_configured"
    finally:
        w.close()
        cloud.close()


def test_the_lookup_answers_one_row_by_hash_and_the_hash_is_what_is_compared(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    with hw.t.app() as app:
        owner = resolve_site_key(app, key)
        assert owner is not None and (owner.org_id, owner.source_id, owner.state) == (a.org.org_id, a.org.source_id, "active")
        assert resolve_site_key(app, "cv_site_" + secrets.token_urlsafe(18)) is None
        assert resolve_site_key(app, "x' OR '1'='1") is None
        assert app.execute("SELECT count(*) AS n FROM consentvault.resolve_site_key(%s)", (key,)).fetchone()["n"] == 1
    with hw.t.superuser() as su:
        assert su.execute("SELECT site_key_hash FROM consentvault.credential WHERE site_key_id = %s",
                          (key,)).fetchone()["site_key_hash"] == hashlib.sha256(key.encode()).hexdigest()


# ---- (f) per-record checklist results ------------------------------------------------------------------------------
def _checklist(w, org, elements, *, approved=True) -> int:
    t = w.t
    with t.operator() as o, org_transaction(o, t.admin_token(org.org_id)):
        o.execute("INSERT INTO consentvault.doc_checklist (org_id, version, kind, label, elements, status, approved_at)"
                  " VALUES (%s, 1, 'custom', 'test list', %s::jsonb, %s, %s)",
                  (org.org_id, json.dumps(elements), "approved" if approved else "draft",
                   datetime.now(timezone.utc) if approved else None))
    return 1


def test_stored_documentation_results_are_read_in_the_proof_and_the_contact_check_stays_the_facts(hw):
    a = hw.cloud.a
    e1, e2, e3 = (str(uuid.uuid4()) for _ in range(3))
    _checklist(hw, a.org, [{"element_id": e1, "name": "Seller named", "description": "", "required": True},
                           {"element_id": e2, "name": "Agreement captured", "description": "", "required": True},
                           {"element_id": e3, "name": "Optional note", "description": "", "required": False}])
    rules = policy_rules()
    for p in rules["purposes"].values():
        p["checklist_version"] = 1
    approve_policy(hw.t, a.org, rules, version=2)
    status, granted = hw.cloud.grant(a, X)
    assert status == 201, granted
    event_id = granted["event_id"]

    status, answer = hw.cloud.gate(a, X)
    assert status == 200 and answer["status"] == "records_found", answer  # the facts, whatever a checklist says

    admin_token = hw.portal_token(a.org)
    s, raw, _ = hw.call("POST", "/v1/doc-checks", {"results": [
        {"event_id": event_id, "checklist_version": 1, "present": [e1]}]}, token=admin_token)
    assert s == 201, raw
    item = _j(raw)["items"][0]
    assert item["present"] == [e1] and item["missing"] == [e2]  # the optional element is not "missing"
    status, answer = hw.cloud.gate(a, X)
    assert status == 200 and answer["status"] == "records_found" and "evidence_status" not in answer, answer

    s, raw, _ = hw.call("POST", "/v1/doc-checks", {"results": [
        {"event_id": event_id, "checklist_version": 1, "present": [e1, e2]}]}, token=admin_token)
    assert s == 201 and _j(raw)["items"][0]["missing"] == []
    status, answer = hw.cloud.gate(a, X)
    assert status == 200 and answer["status"] == "records_found", answer

    status, proof = hw.cloud.proof(a, X)
    assert status == 200 and proof["doc_check_results"] == [
        {"event_id": event_id, "checklist_version": 1, "present": sorted([e1, e2]), "missing": []}], proof


def test_doc_check_refusals_and_isolation(hw):
    a, b = hw.cloud.a, hw.cloud.b
    e1 = str(uuid.uuid4())
    _checklist(hw, a.org, [{"element_id": e1, "name": "Seller named", "description": "", "required": True}])
    _checklist(hw, b.org, [{"element_id": e1, "name": "Seller named", "description": "", "required": True}], approved=False)
    status, granted = hw.cloud.grant(a, X)
    ev = granted["event_id"]
    ta, tb = hw.portal_token(a.org), hw.portal_token(b.org)
    post = lambda body, tok: hw.call("POST", "/v1/doc-checks", body, token=tok)  # noqa: E731
    s, raw, _ = post({"results": [{"event_id": ev, "checklist_version": 1, "present": [str(uuid.uuid4())]}]}, ta)
    assert s == 422 and _j(raw)["error"] == "validation_failed"  # an element that is not on the checklist
    s, raw, _ = post({"results": [{"event_id": str(uuid.uuid4()), "checklist_version": 1, "present": [e1]}]}, ta)
    assert (s, _j(raw)["error"]) == (404, "not_found")  # no such record
    s, raw, _ = post({"results": [{"event_id": ev, "checklist_version": 9, "present": []}]}, ta)
    assert (s, _j(raw)["error"]) == (404, "not_found")
    s, raw, _ = post({"results": [{"event_id": ev, "checklist_version": 1, "present": [e1]}]}, tb)  # org B: draft list
    assert s == 422
    with hw.t.superuser() as su:  # B's draft list is unreachable, and a record of A is not B's to check
        assert su.execute("SELECT count(*) AS n FROM consentvault.doc_check_result").fetchone()["n"] == 0
    approved_b = "UPDATE consentvault.doc_checklist SET status = 'approved', approved_at = now() WHERE org_id = %s"
    with hw.t.operator() as o, org_transaction(o, hw.t.admin_token(b.org.org_id)):
        o.execute(approved_b, (b.org.org_id,))
    s, raw, _ = post({"results": [{"event_id": ev, "checklist_version": 1, "present": [e1]}]}, tb)
    assert (s, _j(raw)["error"]) == (404, "not_found")  # A's record does not exist in B
    with hw.t.app() as app, org_transaction(app, hw.t.token(a.org)):  # the table is append-only
        with pytest.raises(Exception):
            app.execute("DELETE FROM consentvault.doc_check_result")


# ---- (g) contract follow-ups ----------------------------------------------------------------------------------------
def test_current_org_answers_the_chosen_org_and_says_no_org_selected_before_a_choice(hw):
    tok = hw.portal_token(hw.cloud.a.org)
    s, raw, _ = hw.call("GET", "/v1/session/current-org", token=tok)
    body = _j(raw)
    assert s == 200 and body["org_id"] == str(hw.cloud.a.org.org_id) and body["role"] == "admin", raw
    assert set(body) == {"org_id", "name", "role", "status", "expires_at"} and body["expires_at"].endswith("Z")
    assert hw.call("GET", "/v1/session/current-org")[0] == 401
    signed_in = hw.identity.issue(OPERATOR[1], "someone@example.com")
    s, raw, _ = hw.call("GET", "/v1/session/current-org", token=signed_in)
    assert (s, _j(raw)["error"]) == (409, "no_org_selected")
    s, raw, _ = hw.call("GET", "/v1/session/current-org", token=FakeIdentity().issue("x", "x@example.com"))
    assert s == 401


def test_a_compliance_viewer_reads_brand_and_source_names_only(hw):
    a = hw.cloud.a
    with hw.t.superuser() as su:
        su.execute("UPDATE consentvault.capture_source SET name = 'Signup form' WHERE org_id = %s", (a.org.org_id,))
    with hw.t.operator() as o, org_transaction(o, hw.t.admin_token(a.org.org_id)):
        mid = o.execute("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role)"
                        " VALUES (%s, 'https://idp.example.com', 'viewer-1', 'compliance_viewer') RETURNING member_id",
                        (a.org.org_id,)).fetchone()["member_id"]
    from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX
    from consentvault.tenancy.tokens import mint_org_token
    tok = mint_org_token(hw.t.key, a.org.org_id, ROLE_SCOPES["compliance_viewer"],
                         credential_id=MEMBER_CREDENTIAL_PREFIX + str(mid))
    s, raw, _ = hw.call("GET", "/v1/brand-names", token=tok)
    assert s == 200 and _j(raw)["items"] == [{"brand_id": str(a.org.brand_id), "display_name": "alpha Brand"}], raw
    s, raw, _ = hw.call("GET", "/v1/source-names", token=tok)
    assert s == 200 and _j(raw)["items"] == [{"source_id": str(a.org.source_id), "name": "Signup form"}], raw
    assert hw.call("GET", "/v1/brands", token=tok)[0] == 403  # the full reads stay closed to the viewer
    assert hw.call("GET", "/v1/sources", token=tok)[0] == 403
    assert hw.call("GET", "/v1/brand-names")[0] == 401
    # one organisation's names never show in another's list
    tb = hw.portal_token(hw.cloud.b.org)
    s, raw, _ = hw.call("GET", "/v1/brand-names", token=tb)
    assert [i["display_name"] for i in _j(raw)["items"]] == ["bravo Brand"]


def test_a_revoke_answer_carries_the_credential_created_at_and_retention_needs_a_reason(hw):
    a = hw.cloud.a
    tok = hw.portal_token(a.org)
    s, raw, _ = hw.call("POST", "/v1/credentials", {"name": "site", "kind": "edge_site_key", "scope": "capture",
                                                    "source_id": str(a.org.source_id)}, token=tok)
    assert s == 201, raw
    issued = _j(raw)
    assert issued["site_key_id"].startswith("cv_site_") and issued["created_at"]
    with hw.t.app() as app:  # the key issued through the admin route is found by its hash
        assert resolve_site_key(app, issued["site_key_id"]).credential_id == uuid.UUID(issued["credential_id"])
    s, raw, _ = hw.call("POST", f"/v1/credentials/{issued['credential_id']}:revoke", {"reason": "rotated"}, token=tok)
    assert s == 200 and _j(raw)["created_at"] == issued["created_at"] and _j(raw)["revoked_at"], raw
    with hw.t.app() as app:
        assert resolve_site_key(app, issued["site_key_id"]).state == "revoked"
    s, raw, _ = hw.call("PUT", "/v1/retention", {"evidence_years": 7}, token=tok)
    assert (s, _j(raw)["error"]) == (422, "validation_failed") and "reason" in _j(raw)["fields"]
    s, raw, _ = hw.call("PUT", "/v1/retention", {"evidence_years": 7, "reason": "contract"}, token=tok)
    assert s == 200, raw


def test_the_signed_in_read_carries_the_session_expiry(hw):
    idt = hw.identity.issue(OPERATOR[1], "someone@example.com")
    s, raw, _ = hw.call("GET", "/v1/session", token=idt)
    assert s == 200 and _j(raw)["expires_at"].endswith("Z"), raw
