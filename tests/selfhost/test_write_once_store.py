"""The write-once evidence store (RustFS, S3 Object Lock) refuses delete and overwrite in COMPLIANCE mode.

Drives the real S3ObjectLockEvidenceStore for the supported path and raw signed requests for every attack the
provider itself cannot make (version delete, governance bypass, shortening the retention, deleting the bucket).
Each object lives one day under COMPLIANCE retention and cannot be removed early; the stack teardown removes the volume.
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from consentvault.providers.errors import EvidenceExistsError, EvidenceNotFoundError, RetentionError
from consentvault.providers.evidence import S3ObjectLockEvidenceStore, sigv4_headers, urllib_s3_transport

REGION = "us-east-1"


@pytest.fixture(scope="module")
def ctx(settings):
    port = settings["S3_PORT"]
    host = f"127.0.0.1:{port}"
    bucket = settings["S3_EVIDENCE_BUCKET"]
    ak, sk = settings["S3_ACCESS_KEY"], settings["S3_SECRET_KEY"]
    store = S3ObjectLockEvidenceStore(endpoint=f"http://{host}", bucket=bucket, region=REGION, access_key=ak, secret_key=sk)
    send = urllib_s3_transport()

    def raw(method, path, headers=None, body=b"", query=""):
        s = sigv4_headers(method=method, host=host, path=path, query=query, headers=headers or {},
                          payload_sha256=hashlib.sha256(body).hexdigest(), access_key=ak, secret_key=sk, region=REGION,
                          amz_date=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
        s = {k: v for k, v in s.items() if k != "host"}
        status, hdrs, resp = send(method, f"http://{host}{path}" + (f"?{query}" if query else ""), s, body)
        return status, {k.lower(): v for k, v in hdrs.items()}, resp

    return {"store": store, "raw": raw, "bucket": bucket}


def _until(days=1):
    return datetime.now(timezone.utc) + timedelta(days=days)


def test_bucket_default_is_compliance(ctx):
    status, _, body = ctx["raw"]("GET", f"/{ctx['bucket']}", query="object-lock=")
    assert status == 200, body
    text = body.decode()
    assert "<ObjectLockEnabled>Enabled</ObjectLockEnabled>" in text
    assert "<Mode>COMPLIANCE</Mode>" in text


def test_put_get_verify_roundtrip(ctx):
    org, key = "org-" + uuid.uuid4().hex[:8], "evidence/roundtrip.json"
    rec = ctx["store"].put(org, key, b'{"consent": true}', retain_until=_until())
    assert rec.sha256 == hashlib.sha256(b'{"consent": true}').hexdigest()
    assert ctx["store"].get(org, key) == b'{"consent": true}'
    st = ctx["store"].verify_retention(org, key, min_retain_until=_until(0) + timedelta(hours=12))
    assert (st.mode, st.enforced) == ("COMPLIANCE", True)
    assert ctx["store"].enforces_retention is True


def test_second_write_to_a_taken_key_is_refused_and_original_survives(ctx):
    org, key = "org-" + uuid.uuid4().hex[:8], "evidence/once.json"
    ctx["store"].put(org, key, b"first", retain_until=_until())
    with pytest.raises(EvidenceExistsError):
        ctx["store"].put(org, key, b"second", retain_until=_until())
    assert ctx["store"].get(org, key) == b"first"


def test_raw_overwrite_with_if_none_match_is_412(ctx):
    org, key = "org-" + uuid.uuid4().hex[:8], "evidence/raw.json"
    ctx["store"].put(org, key, b"first", retain_until=_until())
    iso = _until().strftime("%Y-%m-%dT%H:%M:%SZ")
    status, _, _ = ctx["raw"]("PUT", f"/{ctx['bucket']}/{org}/{key}", {
        "if-none-match": "*", "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": iso,
        "x-amz-meta-sha256": hashlib.sha256(b"second").hexdigest()}, b"second")
    assert status == 412
    assert ctx["store"].get(org, key) == b"first"


def test_delete_of_the_locked_version_is_refused_even_with_the_governance_bypass(ctx):
    org, key = "org-" + uuid.uuid4().hex[:8], "evidence/locked.json"
    rec = ctx["store"].put(org, key, b"keep me", retain_until=_until())
    assert rec.version_id
    path = f"/{ctx['bucket']}/{org}/{key}"
    for extra in ({}, {"x-amz-bypass-governance-retention": "true"}):
        status, _, body = ctx["raw"]("DELETE", path, extra, query=f"versionId={rec.version_id}")
        assert status == 403, body
        assert b"COMPLIANCE" in body
    assert ctx["store"].get(org, key) == b"keep me"


def test_shortening_or_clearing_the_retention_is_refused(ctx):
    org, key = "org-" + uuid.uuid4().hex[:8], "evidence/retention.json"
    rec = ctx["store"].put(org, key, b"keep me", retain_until=_until(2))
    path = f"/{ctx['bucket']}/{org}/{key}"
    short = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for mode in ("COMPLIANCE", "GOVERNANCE"):
        body = (f'<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>{mode}</Mode>'
                f"<RetainUntilDate>{short}</RetainUntilDate></Retention>").encode()
        status, _, resp = ctx["raw"]("PUT", path, {"x-amz-bypass-governance-retention": "true"}, body,
                                     query=f"retention=&versionId={rec.version_id}")
        assert status == 403, (mode, resp)
    st = ctx["store"].verify_retention(org, key, min_retain_until=_until(1))
    assert st.mode == "COMPLIANCE"


def test_a_plain_delete_never_removes_the_locked_version(ctx):
    """A delete without a version id may add a delete marker; the locked version must stay readable by id."""
    org, key = "org-" + uuid.uuid4().hex[:8], "evidence/marker.json"
    rec = ctx["store"].put(org, key, b"still here", retain_until=_until())
    path = f"/{ctx['bucket']}/{org}/{key}"
    ctx["raw"]("DELETE", path)
    status, _, body = ctx["raw"]("GET", path, query=f"versionId={rec.version_id}")
    assert (status, body) == (200, b"still here")


def test_deleting_the_bucket_with_locked_objects_is_refused(ctx):
    status, _, body = ctx["raw"]("DELETE", f"/{ctx['bucket']}")
    assert status in (409, 403), (status, body)
    status, _, _ = ctx["raw"]("HEAD", f"/{ctx['bucket']}")
    assert status == 200


def test_missing_and_short_retention_cases(ctx):
    with pytest.raises(EvidenceNotFoundError):
        ctx["store"].get("org-none", "evidence/none.json")
    org, key = "org-" + uuid.uuid4().hex[:8], "evidence/future.json"
    ctx["store"].put(org, key, b"x", retain_until=_until(1))
    with pytest.raises(RetentionError):
        ctx["store"].verify_retention(org, key, min_retain_until=_until(30))
