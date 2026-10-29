import json
import urllib.error
from datetime import datetime, timezone

import pytest

from consentvault.adapters import (
    AdapterError,
    CrmAdapter,
    MessagingAdapter,
    NullCrmAdapter,
    NullMessagingAdapter,
    PermissionChange,
    WebhookCrmAdapter,
)
from consentvault.adapters.webhook import sign

CHANGE = PermissionChange(
    contact_norm="+15555550100",
    contact_kind="phone",
    channel="sms",
    purpose="marketing",
    allowed=False,
    reason="stop received",
    event_id="e-1",
    changed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
)


class Resp:
    def __init__(self, status):
        self.status = status


def test_null_adapters_satisfy_protocols():
    assert isinstance(NullCrmAdapter(), CrmAdapter)
    assert isinstance(NullMessagingAdapter(), MessagingAdapter)


def test_null_crm_records_and_null_messaging_is_empty():
    crm = NullCrmAdapter()
    crm.push_permission_change(CHANGE)
    assert crm.pushed == [CHANGE]
    assert list(NullMessagingAdapter().pull_stop_messages()) == []


def test_webhook_signs_timestamp_dot_body():
    seen = {}

    def opener(req, timeout):
        seen["req"], seen["timeout"] = req, timeout
        return Resp(204)

    WebhookCrmAdapter("https://hooks.example.com/x", "s3cret", opener=opener, clock=lambda: 1700000000).push_permission_change(CHANGE)
    req = seen["req"]
    body = req.data
    assert req.get_header("X-consentvault-timestamp") == "1700000000"
    assert req.get_header("X-consentvault-signature") == sign("s3cret", "1700000000", body)
    payload = json.loads(body)
    assert payload["allowed"] is False and payload["contact_norm"] == "+15555550100"
    assert seen["timeout"] == 10.0


def test_webhook_refuses_missing_url_or_secret():
    with pytest.raises(AdapterError):
        WebhookCrmAdapter("", "s")
    with pytest.raises(AdapterError):
        WebhookCrmAdapter("https://hooks.example.com/x", "")


def test_webhook_failures_raise_never_pass_silently():
    def http_500(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    def down(req, timeout):
        raise urllib.error.URLError("refused")

    for opener in (http_500, down, lambda r, timeout: Resp(302)):
        with pytest.raises(AdapterError, match="not delivered"):
            WebhookCrmAdapter("https://hooks.example.com/x", "s", opener=opener).push_permission_change(CHANGE)
