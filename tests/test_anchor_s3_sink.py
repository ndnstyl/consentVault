"""The cloud anchor sink: ``CONSENTVAULT_ANCHOR_SINK=s3://<bucket>`` writes each chain head as one write-once object under
Object Lock (COMPLIANCE) in the log-archive account's anchor bucket, with the anchor job's own task role access.

The setting is refused while it is a placeholder, and in the cloud a file path is refused (a task's disk is lost when it
stops). Database-backed runs are in tests/isolation/test_anchor_s3.py."""

import json
from datetime import datetime, timezone

import pytest

from consentvault import anchor
from consentvault.config import load_config
from consentvault.errors import AnchorError, ConfigError
from consentvault.providers.anchors import S3ObjectLockAnchorSink
from consentvault.providers.rds_iam import AwsCredentials

from providers.test_evidence import FakeS3

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
BUCKET = "cv-logarchive-anchors-122372146390"
ENV = {"AWS_REGION": "us-east-1", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x"}
ORG = "6f1c3c5e-2b0a-4c1e-9a55-0f2d3c4b5a69"
REC = {"seq": 12, "row_hash": "c" * 64, "anchored_at": "2026-10-31T12:00:00.000000Z", "org_id": ORG}


class Creds:
    def get(self):
        return AwsCredentials("ASIAANCHOR", "anchor-secret", "anchor-session", None)


def _sink(fake, env=ENV):
    return anchor.s3_sink(f"s3://{BUCKET}", env=env, transport=fake, clock=lambda: NOW, credentials=Creds())


def test_an_s3_sink_writes_one_locked_object_per_head_with_the_task_roles_access():
    fake = FakeS3()
    sink = _sink(fake)
    assert isinstance(sink, S3ObjectLockAnchorSink) and sink.label == f"s3://{BUCKET}"
    receipt = sink.publish(ORG, REC)
    method, url, headers, body = fake.requests[-1]
    assert method == "PUT"
    # Under the bucket's one platform-anchor prefix, the only place the anchor job's role may write (the bucket also holds
    # the erasure ledger, which it may never touch).
    assert url == f"https://s3.us-east-1.amazonaws.com/{BUCKET}/anchors/{ORG}/anchors/000000000012-{'c' * 32}.json"
    assert headers["x-amz-object-lock-mode"] == "COMPLIANCE"
    assert headers["x-amz-object-lock-retain-until-date"].startswith(str(NOW.year + 7))
    assert headers["x-amz-security-token"] == "anchor-session" and headers["if-none-match"] == "*"
    assert json.loads(body) == {**REC, "org_id": ORG}
    assert receipt.location == f"{ORG}/anchors/000000000012-{'c' * 32}.json" and receipt.tenant_owned is False
    assert all(u.split(f"/{BUCKET}/", 1)[1].startswith("anchors/") for _, u, _, _ in fake.requests)


def test_republishing_the_same_head_is_idempotent_and_a_different_head_at_the_key_is_refused():
    fake = FakeS3()
    sink = _sink(fake)
    sink.publish(ORG, REC)
    sink.publish(ORG, REC)
    key = next(iter(fake.objects))
    fake.objects[key]["body"] = json.dumps({**REC, "seq": 99}).encode()
    import hashlib

    fake.objects[key]["sha"] = hashlib.sha256(fake.objects[key]["body"]).hexdigest()
    from consentvault.providers.errors import AnchorSinkError

    with pytest.raises(AnchorSinkError, match="different head"):
        sink.publish(ORG, REC)


@pytest.mark.parametrize("value", ["s3://", "s3:///", f"s3://{BUCKET}/prefix", f"s3://{BUCKET}?x=1", f"s3://{BUCKET}#f",
                                   "s3://Upper-Case", "s3://user@bucket-name", "s3://ab"])
def test_a_malformed_s3_sink_is_refused_by_name(value):
    with pytest.raises(ConfigError, match="CONSENTVAULT_ANCHOR_SINK"):
        anchor.s3_sink(value, env=ENV, transport=FakeS3())


def test_an_s3_sink_needs_the_region_and_the_task_role():
    with pytest.raises(ConfigError, match="AWS_REGION"):
        anchor.s3_sink(f"s3://{BUCKET}", env={k: v for k, v in ENV.items() if k != "AWS_REGION"})
    with pytest.raises(ConfigError, match="AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        anchor.s3_sink(f"s3://{BUCKET}", env={"AWS_REGION": "us-east-1"})


def test_an_s3_store_that_refuses_the_write_is_a_named_anchor_error():
    fake = FakeS3()
    fake.force = 403
    with pytest.raises(AnchorError) as exc:
        anchor.publish_s3(f"s3://{BUCKET}", ORG, REC, sink=_sink(fake))
    assert exc.value.code == "s3_write_refused"


def test_the_label_stored_in_chain_head_is_the_bucket_url():
    assert anchor.sink_label(f"s3://{BUCKET}") == f"s3://{BUCKET}"


@pytest.mark.parametrize("value", ["UNSET:anchor-sink", "UNSET"])
def test_a_placeholder_sink_is_refused_by_name(value):
    with pytest.raises(ConfigError, match="CONSENTVAULT_ANCHOR_SINK"):
        load_config(env={"CONSENTVAULT_ANCHOR_SINK": value}).require_anchor_sink()


@pytest.mark.parametrize("value,ok", [("/var/anchors.jsonl", False), ("anchors.jsonl", False),
                                      ("http://127.0.0.1:9/a", False), (f"s3://{BUCKET}", True),
                                      ("https://anchors.example.com/in", True)])
def test_the_cloud_refuses_a_sink_on_the_tasks_own_disk(value, ok, monkeypatch):
    monkeypatch.setattr(anchor, "_S3_SINKS", {})
    cfg = load_config(env={"CONSENTVAULT_ANCHOR_SINK": value, "CONSENTVAULT_DB_AUTH": "iam",
                           "CONSENTVAULT_DB_HOST": "h", "CONSENTVAULT_DB_NAME": "n", "CONSENTVAULT_DB_USER": "u",
                           "AWS_REGION": "us-east-1"})
    if ok:
        assert anchor.cloud_sink(cfg, env=ENV) == value
    else:
        with pytest.raises(ConfigError, match="CONSENTVAULT_ANCHOR_SINK"):
            anchor.cloud_sink(cfg, env=ENV)


def test_a_malformed_or_unreachable_s3_sink_stops_the_run_before_any_organisation(monkeypatch):
    monkeypatch.setattr(anchor, "_S3_SINKS", {})
    cfg = load_config(env={"CONSENTVAULT_ANCHOR_SINK": f"s3://{BUCKET}/x", "CONSENTVAULT_DSN": "postgresql://x@h/d"})
    with pytest.raises(ConfigError, match="CONSENTVAULT_ANCHOR_SINK"):
        anchor.cloud_sink(cfg, env=ENV)
    cfg = load_config(env={"CONSENTVAULT_ANCHOR_SINK": f"s3://{BUCKET}", "CONSENTVAULT_DSN": "postgresql://x@h/d"})
    with pytest.raises(ConfigError, match="AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        anchor.cloud_sink(cfg, env={"AWS_REGION": "us-east-1"})
    assert anchor._S3_SINKS == {}
    assert anchor.cloud_sink(cfg, env=ENV) == f"s3://{BUCKET}" and f"s3://{BUCKET}" in anchor._S3_SINKS


def test_the_self_host_keeps_its_file_sink():
    cfg = load_config(env={"CONSENTVAULT_ANCHOR_SINK": "/var/anchors.jsonl", "CONSENTVAULT_DSN": "postgresql://x@h/d"})
    assert anchor.cloud_sink(cfg) == "/var/anchors.jsonl"


# ---- opt-in live check against the anchor bucket (never run by default; writes one object locked for seven years) ------------
@pytest.mark.skipif(not __import__("os").environ.get("CONSENTVAULT_LIVE_ANCHOR_BUCKET"),
                    reason="live anchor check: set CONSENTVAULT_LIVE_ANCHOR_BUCKET, AWS_REGION and AWS credentials")
def test_live_anchor_object_is_written_under_compliance_lock():  # pragma: no cover - needs AWS
    import os
    import secrets

    class EnvCreds:
        def get(self):
            return AwsCredentials(os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"],
                                  os.environ.get("AWS_SESSION_TOKEN"), None)

    sink = anchor.s3_sink("s3://" + os.environ["CONSENTVAULT_LIVE_ANCHOR_BUCKET"], env=os.environ, credentials=EnvCreds())
    rec = {**REC, "row_hash": secrets.token_hex(32), "org_id": "live-check"}
    receipt = sink.publish("live-check", rec)
    assert receipt.location.startswith("live-check/anchors/")
