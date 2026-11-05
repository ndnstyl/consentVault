"""The multi-tenant path through the one door: a crash after the answer leaves a stored post and no event, the resend of the
request then counts once, and a duplicate is a fold rule that spends no evidence."""
import json, os, threading, time, urllib.request, uuid

import psycopg
import pytest

from consentvault import door
from .cloud_harness import Cloud, facts_of, raw_posts

X = "+15555550177"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    c.evidence_dir = str(tmp_path / "evidence")
    yield c
    c.close()


def _stop(cloud, **extra):
    body = {"contact": X, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", **extra}
    return cloud.call("/v1/events", body, token=cloud.token(cloud.a, "capture"))


def _open_stops(cloud):
    s, r = cloud.gate(cloud.a, X)
    return [x for x in r["stops"] if not x["lifted_by_post_ids"]]


def _last_facts(cloud):
    return {k: v for k, v in facts_of(cloud.t, raw_posts(cloud.t, cloud.a.org.org_id)[-1]).items() if k.startswith("event_")}


def _events(cloud, typ):
    with cloud.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id=%s AND event_type=%s",
                          (cloud.a.org.org_id, typ)).fetchone()["n"]


def _grant_body(cloud, nonce):
    co = cloud.a
    return {"contact": X, "event_type": "grant", "checked": True, "channels": ["sms"], "purposes": ["marketing"],
            "disclosure_sha256": co.wording, "brand_ids": [str(co.org.brand_id)], "session_ref": "s-1",
            "page_url": "https://example.test/signup", "client_nonce": nonce}


def test_a_crash_after_the_answer_leaves_no_event_and_a_stop_is_not_lifted_by_a_resend_of_a_recorded_grant(cloud, monkeypatch):
    nonce = str(uuid.uuid4())
    tok = cloud.token(cloud.a, "capture")
    h = {"X-ConsentVault-Request-Id": "form-1"}
    real = door.TenantBackend.apply
    n = {"c": 0}

    def dies(self, *a, **k):
        n["c"] += 1
        if n["c"] == 1:
            raise psycopg.OperationalError("process died before the event")  # stands in for a crash between the answer and the event (a passing fault)
        return real(self, *a, **k)
    base = _events(cloud, "grant")
    monkeypatch.setattr(door.TenantBackend, "apply", dies)
    cloud.call("/v1/events", _grant_body(cloud, nonce), token=tok, headers=h)
    cloud.server.drain(30)
    assert _events(cloud, "grant") == base  # the post is stored, the crash left no event
    monkeypatch.setattr(door.TenantBackend, "apply", real)
    cloud.call("/v1/events", _grant_body(cloud, nonce), token=tok, headers=h)  # the resend records the grant, once
    cloud.server.drain(30)
    assert _events(cloud, "grant") == base + 1
    assert _stop(cloud)[0] == 201
    assert len(_open_stops(cloud)) == 1
    cloud.call("/v1/events", _grant_body(cloud, nonce), token=tok, headers=h)  # the documented safe resend after a stop
    cloud.server.drain(30)
    assert _last_facts(cloud).get("event_not_derived") == "request_seen_before"
    assert _events(cloud, "grant") == base + 1
    assert len(_open_stops(cloud)) == 1


def test_two_concurrent_copies_of_one_request_record_one_event(cloud, monkeypatch):
    from consentvault.tenancy import pipeline
    real = pipeline.CapturePipeline.capture

    def slow(self, *a, **k):
        time.sleep(1.0)
        return real(self, *a, **k)
    monkeypatch.setattr(pipeline.CapturePipeline, "capture", slow)
    tok = cloud.token(cloud.a, "capture")
    base = _events(cloud, "grant")
    body = json.dumps(_grant_body(cloud, str(uuid.uuid4()))).encode()

    def send():
        req = urllib.request.Request(cloud.base + "/v1/events", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok,
                                              "X-ConsentVault-Request-Id": "form-2"})
        urllib.request.urlopen(req, timeout=30).read()
    ts = [threading.Thread(target=send) for _ in range(2)]
    [t.start() for t in ts]; [t.join() for t in ts]
    cloud.server.drain(30)
    assert _events(cloud, "grant") == base + 1


def _evidence(cloud):
    with cloud.t.superuser() as su:
        rows = su.execute("SELECT count(*) AS n FROM consentvault.evidence_object WHERE org_id=%s",
                          (cloud.a.org.org_id,)).fetchone()["n"]
    files = sum(len(fs) for _, _, fs in os.walk(cloud.evidence_dir))
    return rows, files


def test_duplicate_resends_write_no_evidence_row_and_no_blob(cloud):
    tok = cloud.token(cloud.a, "capture")
    h = {"X-ConsentVault-Request-Id": "form-3"}
    body = _grant_body(cloud, str(uuid.uuid4()))
    assert cloud.call("/v1/events", body, token=tok, headers=h)[0] == 201
    cloud.server.drain(30)
    one = _evidence(cloud)
    for _ in range(3):
        cloud.call("/v1/events", body, token=tok, headers=h)
        cloud.server.drain(30)
    assert _evidence(cloud) == one


def test_a_cloud_stop_carrying_the_text_is_recorded(cloud):
    assert cloud.grant(cloud.a, X)[0] == 201
    base = _events(cloud, "revoke")
    for extra in ({"inbound_message": "STOP"}, {"contact_verification": "inbound_keyword", "inbound_message": "STOP"}):
        assert _stop(cloud, **extra)[0] == 201
        cloud.server.drain(30)
    assert _events(cloud, "revoke") == base + 2
    assert len(_open_stops(cloud)) >= 1  # a text lifts nothing


def test_a_start_text_through_tenant_capture_writes_no_grant_and_leaves_the_check_stopped(cloud):
    from consentvault.door import write_tenant_event as tenant_capture
    from consentvault.errors import InvalidEventError
    from consentvault.tenancy.tokens import org_transaction

    assert cloud.grant(cloud.a, X)[0] == 201
    assert _stop(cloud)[0] == 201
    base = _events(cloud, "grant")
    with cloud.t.app() as app, pytest.raises(InvalidEventError):
        with org_transaction(app, cloud.t.token(cloud.t.a, ("capture", "capture_verified"))):
            tenant_capture(app, cloud.t.crypto, contact=X, event_type="grant", channels=["sms"], purposes=["marketing"],
                           checked=True, disclosure_sha256=cloud.a.wording, contact_verification="inbound_keyword",
                           inbound_message="START", method="keyword")
    assert _events(cloud, "grant") == base
    assert len(_open_stops(cloud)) >= 1  # a text lifts nothing


def test_a_stop_through_parse_capture_and_tenant_capture_ignores_the_text():
    from consentvault.tenancy.pipeline import parse_capture

    body = {"contact": X, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
            "contact_verification": "inbound_keyword", "inbound_message": "STOP"}
    req = parse_capture(body, b"{}", ("capture",))
    assert req.fields.get("contact_verification", "none") == "none" and "inbound_message" not in req.fields
