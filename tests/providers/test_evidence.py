from datetime import datetime, timedelta, timezone

import pytest

from consentvault.providers.errors import (
    EvidenceExistsError, EvidenceIntegrityError, EvidenceNotFoundError, EvidenceStoreError, InvalidEvidenceKeyError,
    ProviderConfigError, ProviderTransportError, RetentionError)
from consentvault.providers.evidence import (
    EvidenceStore, LocalAppendOnlyEvidenceStore, S3ObjectLockEvidenceStore, sigv4_headers)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=365 * 5)


def test_sigv4_matches_the_published_aws_get_object_vector():
    h = sigv4_headers(
        method="GET", host="examplebucket.s3.amazonaws.com", path="/test.txt", headers={"Range": "bytes=0-9"},
        payload_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        access_key="AKIAIOSFODNN7EXAMPLE", secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1", amz_date="20130524T000000Z")
    assert h["authorization"].endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_sigv4_matches_the_published_aws_put_object_vector():
    h = sigv4_headers(
        method="PUT", host="examplebucket.s3.amazonaws.com", path="/test%24file.text",
        headers={"Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY"},
        payload_sha256="44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
        access_key="AKIAIOSFODNN7EXAMPLE", secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1", amz_date="20130524T000000Z")
    assert h["authorization"].endswith("Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")


class FakeS3:
    """In-memory S3 with Object Lock semantics; records every request."""

    def __init__(self):
        self.objects = {}
        self.requests = []
        self.force = None

    def __call__(self, method, url, headers, body):
        self.requests.append((method, url, dict(headers), body))
        if self.force:
            return self.force, {}, b"<Error>forced</Error>"
        assert "authorization" in headers and headers["authorization"].startswith("AWS4-HMAC-SHA256 ")
        assert "host" not in headers
        path = url.split("://", 1)[1].split("/", 1)[1]
        if method == "PUT":
            # S3 refuses (400 InvalidRequest) a write carrying an Object Lock retention without an integrity header.
            if headers.get("x-amz-object-lock-mode") and not (headers.get("content-md5") or headers.get("x-amz-checksum-sha256")):
                return 400, {}, b"<Error><Code>InvalidRequest</Code></Error>"
            if headers.get("if-none-match") == "*" and path in self.objects:
                return 412, {}, b"<Error>PreconditionFailed</Error>"
            self.objects[path] = {
                "body": body, "mode": headers.get("x-amz-object-lock-mode"),
                "until": headers.get("x-amz-object-lock-retain-until-date"), "sha": headers.get("x-amz-meta-sha256")}
            return 200, {"ETag": '"x"', "x-amz-version-id": "v1"}, b""
        o = self.objects.get(path)
        if o is None:
            return 404, {}, b"<Error>NoSuchKey</Error>"
        h = {"x-amz-meta-sha256": o["sha"], "x-amz-object-lock-mode": o["mode"],
             "x-amz-object-lock-retain-until-date": o["until"]}
        h = {k: v for k, v in h.items() if v is not None}
        return 200, h, (b"" if method == "HEAD" else o["body"])


def make_s3(fake=None, **kw):
    fake = fake or FakeS3()
    store = S3ObjectLockEvidenceStore(
        endpoint="https://s3.example.com", bucket="ev-bucket", region="us-east-1", access_key="AK", secret_key="SK",
        transport=fake, clock=lambda: NOW, **kw)
    return store, fake


def test_s3_put_writes_compliance_lock_once_and_reads_back():
    store, fake = make_s3()
    rec = store.put("org-a", "events/0001.bin", b"payload", retain_until=LATER)
    assert rec.size == 7 and rec.version_id == "v1" and rec.retain_until == LATER
    method, url, hdrs, _ = fake.requests[0]
    assert url == "https://s3.example.com/ev-bucket/org-a/events/0001.bin"
    assert hdrs["x-amz-object-lock-mode"] == "COMPLIANCE"
    assert hdrs["x-amz-object-lock-retain-until-date"] == "2030-12-31T00:00:00Z"
    assert hdrs["if-none-match"] == "*"
    assert "if-none-match" in hdrs["authorization"] and "x-amz-object-lock-mode" in hdrs["authorization"]
    assert store.get("org-a", "events/0001.bin") == b"payload"
    assert store.enforces_retention is True


def test_s3_put_carries_the_integrity_headers_object_lock_requires():
    import base64
    import hashlib

    fake = FakeS3()
    store = S3ObjectLockEvidenceStore(endpoint="https://s3.example.com", bucket="evidence-bkt", region="us-east-1",
                                      access_key="AK", secret_key="SK", transport=fake, clock=lambda: NOW)
    store.put("org-a", "e/1.json", b"payload", retain_until=LATER)
    _, _, headers, body = fake.requests[-1]
    assert headers["content-md5"] == base64.b64encode(hashlib.md5(body).digest()).decode()
    assert headers["x-amz-checksum-sha256"] == base64.b64encode(hashlib.sha256(body).digest()).decode()
    assert "content-md5" in headers["authorization"] and "x-amz-checksum-sha256" in headers["authorization"]


def test_s3_store_with_a_prefix_keeps_every_object_and_listing_under_it():
    fake = FakeS3()
    store = S3ObjectLockEvidenceStore(endpoint="https://s3.example.com", bucket="b-bkt", region="us-east-1",
                                      access_key="AK", secret_key="SK", transport=fake, clock=lambda: NOW, prefix="anchors")
    store.put("org-a", "x/1.json", b"d", retain_until=LATER)
    assert fake.requests[-1][1] == "https://s3.example.com/b-bkt/anchors/org-a/x/1.json"
    assert store.get("org-a", "x/1.json") == b"d"
    for bad in ("", "../x", "a/../b", "/abs"):
        with pytest.raises(ProviderConfigError):
            S3ObjectLockEvidenceStore(endpoint="https://s3.example.com", bucket="b-bkt", region="us-east-1",
                                      access_key="AK", secret_key="SK", transport=fake, prefix=bad)


def test_s3_overwrite_refused():
    store, _ = make_s3()
    store.put("org-a", "k", b"one", retain_until=LATER)
    with pytest.raises(EvidenceExistsError):
        store.put("org-a", "k", b"two", retain_until=LATER)
    assert store.get("org-a", "k") == b"one"


def test_s3_get_missing_and_tampered():
    store, fake = make_s3()
    with pytest.raises(EvidenceNotFoundError):
        store.get("org-a", "nope")
    store.put("org-a", "k", b"one", retain_until=LATER)
    fake.objects["ev-bucket/org-a/k"]["body"] = b"changed"
    with pytest.raises(EvidenceIntegrityError):
        store.get("org-a", "k")
    fake.objects["ev-bucket/org-a/k"]["sha"] = None
    with pytest.raises(EvidenceIntegrityError, match="no recorded sha256"):
        store.get("org-a", "k")


def test_s3_verify_retention_ok_short_and_wrong_mode():
    store, fake = make_s3()
    store.put("org-a", "k", b"x", retain_until=LATER)
    st = store.verify_retention("org-a", "k", min_retain_until=LATER)
    assert st.mode == "COMPLIANCE" and st.enforced and st.retain_until == LATER
    with pytest.raises(RetentionError, match="below the required"):
        store.verify_retention("org-a", "k", min_retain_until=LATER + timedelta(days=1))
    fake.objects["ev-bucket/org-a/k"]["mode"] = "GOVERNANCE"
    with pytest.raises(RetentionError, match="COMPLIANCE"):
        store.verify_retention("org-a", "k")
    fake.objects["ev-bucket/org-a/k"]["mode"] = None
    with pytest.raises(RetentionError):
        store.verify_retention("org-a", "k")
    with pytest.raises(EvidenceNotFoundError):
        store.verify_retention("org-a", "missing")


def test_s3_retention_in_the_past_or_naive_refused_before_any_request():
    store, fake = make_s3()
    with pytest.raises(RetentionError):
        store.put("org-a", "k", b"x", retain_until=NOW - timedelta(days=1))
    with pytest.raises(RetentionError):
        store.put("org-a", "k", b"x", retain_until=datetime(2040, 1, 1))
    assert fake.requests == []


def test_s3_server_error_is_transport_error_and_client_error_is_store_error():
    store, fake = make_s3()
    fake.force = 503
    with pytest.raises(ProviderTransportError):
        store.put("org-a", "k", b"x", retain_until=LATER)
    fake.force = 403
    with pytest.raises(EvidenceStoreError):
        store.get("org-a", "k")


@pytest.mark.parametrize("org,key", [("../b", "k"), ("org-a", "../org-b/k"), ("org-a", "a//b"), ("org-a", "/abs"),
                                      ("org-a", ""), ("org-a", "a/./b"), ("o/rg", "k")])
def test_unsafe_names_refused_everywhere(tmp_path, org, key):
    store, fake = make_s3()
    local = LocalAppendOnlyEvidenceStore(tmp_path, clock=lambda: NOW)
    for s in (store, local):
        with pytest.raises(InvalidEvidenceKeyError):
            s.put(org, key, b"x", retain_until=LATER)
        with pytest.raises(InvalidEvidenceKeyError):
            s.get(org, key)
    assert fake.requests == []


def test_s3_config_validation():
    base = dict(endpoint="https://s3.example.com", bucket="ev-bucket", region="r", access_key="a", secret_key="s")
    with pytest.raises(ProviderConfigError):
        S3ObjectLockEvidenceStore(**{**base, "endpoint": "http://s3.example.com"})
    with pytest.raises(ProviderConfigError):
        S3ObjectLockEvidenceStore(**{**base, "bucket": "Bad_Bucket"})
    with pytest.raises(ProviderConfigError):
        S3ObjectLockEvidenceStore(**{**base, "secret_key": ""})
    S3ObjectLockEvidenceStore(**{**base, "endpoint": "http://127.0.0.1:9000"}, transport=FakeS3())


def test_s3_session_token_is_signed():
    store, fake = make_s3(session_token="TOK")
    store.put("org-a", "k", b"x", retain_until=LATER)
    assert fake.requests[0][2]["x-amz-security-token"] == "TOK"


# local append-only
@pytest.fixture
def local(tmp_path):
    return LocalAppendOnlyEvidenceStore(tmp_path / "ev", clock=lambda: NOW)


def test_local_roundtrip_and_states_it_is_not_enforced(local):
    rec = local.put("org-a", "events/1.bin", b"data", retain_until=LATER)
    assert local.get("org-a", "events/1.bin") == b"data" and rec.size == 4
    st = local.verify_retention("org-a", "events/1.bin", min_retain_until=LATER)
    assert st.mode == "LOCAL_APPEND_ONLY" and st.enforced is False
    assert local.enforces_retention is False
    assert "not undeletable" in LocalAppendOnlyEvidenceStore.__doc__.lower()


def test_local_refuses_overwrite_and_leaves_original(local, tmp_path):
    local.put("org-a", "k", b"one", retain_until=LATER)
    with pytest.raises(EvidenceExistsError):
        local.put("org-a", "k", b"two", retain_until=LATER)
    assert local.get("org-a", "k") == b"one"
    assert not list((tmp_path / "ev" / "org-a" / "objects").glob("*.tmp*"))


def test_local_files_are_read_only(local, tmp_path):
    local.put("org-a", "k", b"one", retain_until=LATER)
    f = tmp_path / "ev" / "org-a" / "objects" / "k"
    assert (f.stat().st_mode & 0o222) == 0


def test_local_detects_tamper_and_missing_metadata(local, tmp_path):
    local.put("org-a", "k", b"one", retain_until=LATER)
    f = tmp_path / "ev" / "org-a" / "objects" / "k"
    f.chmod(0o644)
    f.write_bytes(b"two")
    with pytest.raises(EvidenceIntegrityError):
        local.get("org-a", "k")
    with pytest.raises(EvidenceIntegrityError):
        local.verify_retention("org-a", "k")
    (tmp_path / "ev" / "org-a" / "objects" / "k.meta.json").unlink()
    with pytest.raises(EvidenceIntegrityError, match="no metadata"):
        local.get("org-a", "k")


def test_local_missing_object_and_short_retention(local):
    with pytest.raises(EvidenceNotFoundError):
        local.get("org-a", "none")
    local.put("org-a", "k", b"x", retain_until=LATER)
    with pytest.raises(RetentionError):
        local.verify_retention("org-a", "k", min_retain_until=LATER + timedelta(seconds=1))
    with pytest.raises(RetentionError):
        local.put("org-a", "k2", b"x", retain_until=NOW)


def test_local_orgs_are_separate_prefixes(local):
    local.put("org-a", "k", b"a", retain_until=LATER)
    local.put("org-b", "k", b"b", retain_until=LATER)
    assert local.get("org-a", "k") == b"a" and local.get("org-b", "k") == b"b"


def test_local_bookkeeping_names_refused(local):
    for k in ("k.meta.json", "k.tmp9"):
        with pytest.raises(InvalidEvidenceKeyError):
            local.put("org-a", k, b"x", retain_until=LATER)


def test_both_implement_the_interface(local):
    assert isinstance(local, EvidenceStore) and isinstance(make_s3()[0], EvidenceStore)
