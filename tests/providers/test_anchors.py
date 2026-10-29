import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from consentvault.providers.anchors import (
    AnchorSink, FileAnchorSink, S3ObjectLockAnchorSink, TenantAnchorSink, WebhookAnchorSink)
from consentvault.providers.errors import AnchorSinkError, ProviderConfigError, ProviderTransportError
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore, S3ObjectLockEvidenceStore

from .test_evidence import FakeS3

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
H1, H2 = "a" * 64, "b" * 64
REC = {"seq": 7, "row_hash": H1, "anchored_at": "2026-01-01T00:00:00.000000Z"}


def s3_anchor(fake=None):
    fake = fake or FakeS3()
    store = S3ObjectLockEvidenceStore(endpoint="https://s3.example.com", bucket="anchors-bkt", region="us-east-1",
                                      access_key="AK", secret_key="SK", transport=fake, clock=lambda: NOW)
    return S3ObjectLockAnchorSink(store, clock=lambda: NOW), fake


def test_file_sink_appends_one_line_per_anchor(tmp_path):
    sink = FileAnchorSink(tmp_path / "sub" / "anchors.jsonl")
    r1 = sink.publish("org-a", REC)
    sink.publish("org-a", {**REC, "seq": 8, "row_hash": H2})
    lines = (tmp_path / "sub" / "anchors.jsonl").read_text().splitlines()
    assert [json.loads(x)["seq"] for x in lines] == [7, 8]
    assert json.loads(lines[0])["org_id"] == "org-a"
    assert r1.record_sha256 == hashlib.sha256(lines[0].encode()).hexdigest() and r1.tenant_owned is False


def test_file_sink_unwritable_path_is_named_error(tmp_path):
    (tmp_path / "f").write_text("x")
    with pytest.raises(AnchorSinkError, match="cannot append"):
        FileAnchorSink(tmp_path / "f" / "anchors.jsonl").publish("org-a", REC)


@pytest.mark.parametrize("bad", [{}, {"seq": 0, "row_hash": H1}, {"seq": True, "row_hash": H1},
                                 {"seq": 1, "row_hash": "XYZ"}, {"seq": 1, "row_hash": "../" + "a" * 20}])
def test_bad_records_refused_by_every_sink(tmp_path, bad):
    sinks = [FileAnchorSink(tmp_path / "a"), WebhookAnchorSink("https://h.example.com/a", transport=lambda *a: 200),
             s3_anchor()[0]]
    for s in sinks:
        with pytest.raises(AnchorSinkError):
            s.publish("org-a", bad)
    with pytest.raises(AnchorSinkError):
        sinks[0].publish("../evil", REC)


def test_webhook_posts_signed_body_and_hides_query_in_label():
    seen = {}

    def transport(url, headers, body):
        seen.update(url=url, headers=dict(headers), body=body)
        return 202

    sink = WebhookAnchorSink("https://hook.example.com/in?token=SECRET", secret="shh", transport=transport)
    r = sink.publish("org-a", REC)
    assert seen["url"].endswith("token=SECRET")
    assert json.loads(seen["body"])["org_id"] == "org-a"
    want = hmac.new(b"shh", seen["body"], hashlib.sha256).hexdigest()
    assert seen["headers"]["X-ConsentVault-Signature"] == f"sha256={want}"
    assert "SECRET" not in sink.label and "SECRET" not in r.location


@pytest.mark.parametrize("status", [301, 400, 500])
def test_webhook_non_2xx_is_error(status):
    with pytest.raises(AnchorSinkError, match=str(status)):
        WebhookAnchorSink("https://h.example.com/a", transport=lambda *a: status).publish("org-a", REC)


def test_webhook_transport_failure_propagates_loudly():
    def boom(*a):
        raise AnchorSinkError("unreachable")

    with pytest.raises(AnchorSinkError):
        WebhookAnchorSink("https://h.example.com/a", transport=boom).publish("org-a", REC)


def test_webhook_requires_https_or_loopback():
    with pytest.raises(ProviderConfigError):
        WebhookAnchorSink("http://h.example.com/a")
    with pytest.raises(ProviderConfigError):
        WebhookAnchorSink("ftp://h.example.com/a")
    WebhookAnchorSink("http://127.0.0.1:9/a")


def test_s3_anchor_writes_locked_object_per_org_and_is_idempotent():
    sink, fake = s3_anchor()
    r = sink.publish("org-a", REC)
    assert r.location == f"org-a/anchors/000000000007-{H1[:32]}.json"
    obj = fake.objects[f"anchors-bkt/{r.location}"]
    assert obj["mode"] == "COMPLIANCE"
    sink.publish("org-a", {**REC, "anchored_at": "later"})  # same head again: fine
    assert len([k for k in fake.objects]) == 1


def test_s3_anchor_conflicting_head_at_same_key_is_error():
    sink, fake = s3_anchor()
    sink.publish("org-a", REC)
    key = next(iter(fake.objects))
    fake.objects[key]["body"] = json.dumps({"seq": 7, "row_hash": "c" * 64}).encode()
    fake.objects[key]["sha"] = hashlib.sha256(fake.objects[key]["body"]).hexdigest()
    with pytest.raises(AnchorSinkError, match="different head"):
        sink.publish("org-a", REC)


def test_s3_anchor_server_failure_is_anchor_error():
    sink, fake = s3_anchor()
    fake.force = 503
    with pytest.raises(AnchorSinkError):
        sink.publish("org-a", REC)


def test_s3_anchor_refuses_a_store_that_cannot_enforce_retention(tmp_path):
    with pytest.raises(ProviderConfigError):
        S3ObjectLockAnchorSink(LocalAppendOnlyEvidenceStore(tmp_path))


def test_tenant_sink_marks_receipts_and_hides_credentials():
    fake = FakeS3()
    sink = TenantAnchorSink.from_config(
        {"kind": "s3", "endpoint": "https://s3.tenant.example", "bucket": "tenant-anchors", "region": "eu-west-1",
         "access_key": "TENANTAK", "secret_key": "TENANTSECRET"}, owner="org-a", transport=fake, clock=lambda: NOW)
    r = sink.publish("org-a", REC)
    assert sink.tenant_owned and r.tenant_owned
    assert r.sink == "tenant:org-a:s3://tenant-anchors"
    assert "TENANTSECRET" not in repr(r)
    assert "tenant-anchors/org-a/anchors/" in next(iter(fake.requests))[1]


def test_tenant_webhook_from_config():
    calls = []
    sink = TenantAnchorSink.from_config({"kind": "webhook", "url": "https://t.example.com/h", "secret": "s"},
                                        owner="org-a", transport=lambda u, h, b: calls.append(u) or 200)
    assert sink.publish("org-a", REC).tenant_owned and calls == ["https://t.example.com/h"]


def test_tenant_sink_config_errors(tmp_path):
    with pytest.raises(ProviderConfigError):
        TenantAnchorSink.from_config({"kind": "ftp"}, owner="o")
    with pytest.raises(ProviderConfigError, match="missing 'bucket'"):
        TenantAnchorSink.from_config({"kind": "s3", "endpoint": "https://x.example"}, owner="o")
    with pytest.raises(ProviderConfigError, match="not a tenant-owned"):
        TenantAnchorSink(FileAnchorSink(tmp_path / "a"), owner="o")
    with pytest.raises(ProviderConfigError):
        TenantAnchorSink(WebhookAnchorSink("https://x.example.com/a"), owner="")


def test_all_are_anchor_sinks(tmp_path):
    for s in (FileAnchorSink(tmp_path / "a"), WebhookAnchorSink("https://x.example.com/a"), s3_anchor()[0]):
        assert isinstance(s, AnchorSink) and s.tenant_owned is False
