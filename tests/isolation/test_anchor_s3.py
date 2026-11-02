"""The hourly anchor job against the cloud sink (``s3://<bucket>``), on a real multi-tenant database: every organisation's head
becomes one Object Lock object under its own prefix, the chain_head row names the bucket, a refused write fails that
organisation by name without stopping the others, and verify-chain with the same setting reads no local file."""

from error_names import named_any  # noqa: F401
import json

import pytest

from consentvault import anchor, cli, db, integrity

from providers.test_evidence import FakeS3
from .test_integrity_jobs import PHONE, two_orgs  # noqa: F401, F811  (the fixture)

BUCKET = "cv-logarchive-anchors-122372146390"
SINK = f"s3://{BUCKET}"


class Creds:
    def get(self):
        from consentvault.providers.rds_iam import AwsCredentials

        return AwsCredentials("ASIAANCHOR", "anchor-secret", "anchor-session", None)


@pytest.fixture
def fake_bucket(monkeypatch):
    fake = FakeS3()
    sink = anchor.s3_sink(SINK, env={"AWS_REGION": "us-east-1"}, transport=fake, credentials=Creds())
    monkeypatch.setitem(anchor._S3_SINKS, SINK, sink)
    return fake


def test_every_organisation_is_anchored_as_its_own_locked_object(two_orgs, fake_bucket):
    with db.connect(two_orgs.integrity_dsn) as c:
        out = integrity.anchor_every_org(c, SINK)
    for org in (two_orgs.a, two_orgs.b):
        rec = out["anchored"][str(org.org_id)]
        assert rec["seq"] == 2 and rec["sink"] == SINK
        key = f"{BUCKET}/anchors/{org.org_id}/anchors/{2:012d}-{rec['row_hash'][:32]}.json"
        obj = fake_bucket.objects[key]
        assert obj["mode"] == "COMPLIANCE"
        assert json.loads(obj["body"])["org_id"] == str(org.org_id)
    with db.connect(two_orgs.super_dsn) as su:
        sinks = {r["sink"] for r in su.execute("SELECT sink FROM consentvault.chain_head WHERE org_id = ANY(%s)",
                                               ([two_orgs.a.org_id, two_orgs.b.org_id],))}
    assert sinks == {SINK}
    with db.connect(two_orgs.integrity_dsn) as c:  # an hour later, nothing new: the same objects, no error
        integrity.anchor_every_org(c, SINK)


def test_a_refused_write_fails_that_organisation_by_name_and_records_no_anchor(two_orgs, fake_bucket):
    fake_bucket.force = 403
    with db.connect(two_orgs.integrity_dsn) as c, pytest.raises(integrity.IntegrityRunError) as e:
        integrity.anchor_every_org(c, SINK)
    failed = {f[0] for f in e.value.failures}
    assert {str(two_orgs.a.org_id), str(two_orgs.b.org_id)} <= failed
    assert all("s3_write_refused" in f[1] for f in e.value.failures) and PHONE not in str(e.value)
    with db.connect(two_orgs.super_dsn) as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.chain_head WHERE sink = %s", (SINK,)).fetchone()["n"] == 0


def test_verify_chain_with_the_s3_setting_does_not_read_it_as_a_file(two_orgs, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", two_orgs.integrity_dsn)
    monkeypatch.setenv("CONSENTVAULT_ANCHOR_SINK", SINK)
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    assert cli.main(["verify-chain"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["ok"] is True
