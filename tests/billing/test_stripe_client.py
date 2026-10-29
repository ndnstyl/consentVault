"""The HTTP Stripe client against a fake transport: request shape, idempotency, error classes. No network."""

import json
import urllib.parse

import pytest

from consentvault.billing.errors import StripeRejectedError, StripeUnavailableError
from consentvault.billing.stripe_client import HttpStripeClient, encode_form


class Wire:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.sent = []

    def __call__(self, method, url, body, headers):
        self.sent.append((method, url, body, headers))
        status, payload = self.answers.pop(0)
        return status, json.dumps(payload).encode()


def test_nested_form_encoding():
    pairs = encode_form({"mode": "subscription", "line_items": [{"price": "p1", "quantity": 1}, {"price": "p2"}],
                         "metadata": {"org_id": "o"}, "skip": None, "flag": True})
    assert pairs == [("mode", "subscription"), ("line_items[0][price]", "p1"), ("line_items[0][quantity]", "1"),
                     ("line_items[1][price]", "p2"), ("metadata[org_id]", "o"), ("flag", "true")]


def test_post_carries_the_bearer_key_and_the_idempotency_key():
    wire = Wire((200, {"id": "cus_1"}))
    c = HttpStripeClient("sk_test_x", transport=wire)
    assert c.create_customer(org_id="org-1", idempotency_key="customer:org-1")["id"] == "cus_1"
    method, url, body, headers = wire.sent[0]
    assert (method, url) == ("POST", "https://api.stripe.com/v1/customers")
    assert headers["Authorization"] == "Bearer sk_test_x" and headers["Idempotency-Key"] == "customer:org-1"
    assert urllib.parse.parse_qs(body.decode()) == {"metadata[org_id]": ["org-1"]}
    assert "sk_test_x" not in repr(c)


def test_meter_event_uses_the_identifier_as_idempotency_key():
    wire = Wire((200, {"identifier": "k"}))
    HttpStripeClient("sk_test_x", transport=wire).create_meter_event(
        event_name="consentvault_consent_events", customer="cus_1", value=7, identifier="org:2026-10-28:events",
        timestamp=1761600000)
    _, url, body, headers = wire.sent[0]
    assert url.endswith("/v1/billing/meter_events") and headers["Idempotency-Key"] == "org:2026-10-28:events"
    assert urllib.parse.parse_qs(body.decode())["payload[value]"] == ["7"]


@pytest.mark.parametrize("status", [429, 500, 503])
def test_429_and_5xx_are_unavailable(status):
    c = HttpStripeClient("sk_test_x", transport=Wire((status, {"error": {"message": "slow down"}})))
    with pytest.raises(StripeUnavailableError, match="slow down"):
        c.retrieve_subscription("sub_1")


def test_4xx_is_rejected_with_stripes_message_and_never_the_key():
    c = HttpStripeClient("sk_test_secretvalue", transport=Wire((400, {"error": {"message": "No such price"}})))
    with pytest.raises(StripeRejectedError, match="No such price") as exc:
        c.create_portal_session(customer="cus_1", return_url="https://x")
    assert "secretvalue" not in str(exc.value)


def test_a_non_json_answer_and_a_transport_fault_are_unavailable():
    class Garbled:
        def __call__(self, *a):
            return 200, b"<html>"
    with pytest.raises(StripeUnavailableError):
        HttpStripeClient("sk_test_x", transport=Garbled()).retrieve_invoice("in_1")
    with pytest.raises(StripeRejectedError):
        HttpStripeClient("")


def test_price_list_walks_pages_and_stops():
    wire = Wire((200, {"data": [{"id": "price_1"}], "has_more": True}), (200, {"data": [{"id": "price_2"}],
                                                                              "has_more": False}))
    assert [p["id"] for p in HttpStripeClient("sk_test_x", transport=wire).list_prices()] == ["price_1", "price_2"]
    assert "starting_after=price_1" in wire.sent[1][1]
