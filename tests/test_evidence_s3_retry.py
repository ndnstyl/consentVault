"""One transient S3 stall on a read is retried; a write is never retried; a real outage still raises."""

from datetime import datetime, timedelta, timezone

import pytest

from consentvault.providers.errors import ProviderTransportError
from consentvault.providers.evidence import S3ObjectLockEvidenceStore
from consentvault.tenancy.erasure import LedgerUnavailableError, LifecycleLedger

T0 = datetime(2026, 11, 16, 9, 45, tzinfo=timezone.utc)
SHA = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"  # sha256(b"foo")


def _store(send, sleeps):
    return S3ObjectLockEvidenceStore(endpoint="https://s3.us-east-1.amazonaws.com", bucket="cv-ledger", region="us-east-1",
                                     access_key="AK", secret_key="SK", transport=send, clock=lambda: T0,
                                     sleep=sleeps.append)


def _timeout(*_a):
    raise ProviderTransportError("S3 GET unreachable: TimeoutError")


def test_a_get_that_times_out_once_then_answers_succeeds():
    calls, sleeps = [], []

    def send(method, url, headers, body):
        calls.append(method)
        if len(calls) == 1:
            _timeout()
        return 200, {"x-amz-meta-sha256": SHA}, b"foo"

    assert _store(send, sleeps).get("org-a", "ledger/1") == b"foo"
    assert calls == ["GET", "GET"] and sleeps == [1]


def test_a_get_that_always_times_out_is_three_attempts_then_the_same_error():
    calls, sleeps = [], []

    def send(method, url, headers, body):
        calls.append(method)
        _timeout()

    with pytest.raises(ProviderTransportError):
        _store(send, sleeps).get("org-a", "ledger/1")
    assert len(calls) == 3 and sleeps == [1, 2]


def test_a_head_and_a_list_are_retried_too():
    calls, sleeps = [], []

    def send(method, url, headers, body):
        calls.append(method)
        if len(calls) % 2 == 1:
            _timeout()
        return 200, {"x-amz-object-lock-mode": "COMPLIANCE"}, b"<ListBucketResult/>"

    store = _store(send, sleeps)
    assert store.inventory("org-a", T0 - timedelta(days=1)) == []
    try:
        store.verify_retention("org-a", "ledger/1")
    except Exception:  # the answer's content is not the point; the second HEAD attempt is
        pass
    assert calls[:2] == ["GET", "GET"] and calls[2:4] == ["HEAD", "HEAD"]


def test_the_ledger_read_surfaces_as_unavailable_after_the_last_attempt():
    calls, sleeps = [], []

    def send(method, url, headers, body):
        calls.append(method)
        _timeout()

    ledger = LifecycleLedger(_store(send, sleeps), clock=lambda: T0)
    with pytest.raises(LedgerUnavailableError):
        ledger.append("org-a", {"kind": "x"}, hint=2)
    assert len(calls) == 3


def test_a_put_that_times_out_is_not_retried():
    calls, sleeps = [], []

    def send(method, url, headers, body):
        calls.append(method)
        _timeout()

    with pytest.raises(ProviderTransportError):
        _store(send, sleeps).put("org-a", "ledger/1", b"x", retain_until=T0 + timedelta(days=400))
    assert calls == ["PUT"] and sleeps == []
