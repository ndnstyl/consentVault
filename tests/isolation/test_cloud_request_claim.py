"""The multi-tenant path claims a request in the same transaction as the event it derives."""
import json, threading, time, urllib.request, uuid

import pytest

from consentvault.rawpost import RawPostWriter
from .cloud_harness import Cloud, facts_of, raw_posts

X = "+15555550177"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _stop(cloud, **extra):
    body = {"contact": X, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", **extra}
    return cloud.call("/v1/events", body, token=cloud.token(cloud.a, "capture"))


def _allowed(cloud):
    s, r = cloud.gate(cloud.a, X)
    return {"allowed": r.get("evidence_status") == "consent_record_found", "status": r.get("evidence_status"), "reasons": r.get("reasons")}


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


def test_crash_at_the_claim_leaves_no_event_and_a_stop_is_not_lifted_by_a_resend_of_a_recorded_grant(cloud, monkeypatch):
    nonce = str(uuid.uuid4())
    tok = cloud.token(cloud.a, "capture")
    h = {"X-ConsentVault-Request-Id": "form-1"}
    real = RawPostWriter.claim_request
    n = {"c": 0}

    def dies(self, *a, **k):
        n["c"] += 1
        if n["c"] == 1:
            raise RuntimeError("process died after the event committed")  # stands in for a crash
        return real(self, *a, **k)
    base = _events(cloud, "grant")
    monkeypatch.setattr(RawPostWriter, "claim_request", dies)
    try:
        cloud.call("/v1/events", _grant_body(cloud, nonce), token=tok, headers=h)
    except Exception:
        pass
    cloud.server.drain(30)
    assert _events(cloud, "grant") == base  # the claim and the event stand or fall together: the crash left neither
    monkeypatch.setattr(RawPostWriter, "claim_request", real)
    cloud.call("/v1/events", _grant_body(cloud, nonce), token=tok, headers=h)  # the resend records the grant, once
    cloud.server.drain(30)
    assert _events(cloud, "grant") == base + 1
    assert _stop(cloud)[0] == 201
    assert _allowed(cloud)["allowed"] is False
    cloud.call("/v1/events", _grant_body(cloud, nonce), token=tok, headers=h)  # the documented safe resend after a stop
    cloud.server.drain(30)
    assert _events(cloud, "grant") == base + 1
    assert _allowed(cloud)["allowed"] is False


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
