"""The webhook connector: signatures, classification, the egress door's answers. No network."""

import io
import json
import urllib.error
import uuid

import pytest

from consentvault.sync.connectors import webhook as wh
from consentvault.sync.errors import CredentialError, TransportError


def test_hmac_signature_round_trip_and_tamper():
    secret = b"s" * 32
    body = b'{"a":1}'
    header = wh.sign_body("hmac", secret, body)
    assert header.startswith("hmac-sha256=") and wh.verify_signature("hmac", secret, body, header)
    assert not wh.verify_signature("hmac", secret, b'{"a":2}', header)
    assert not wh.verify_signature("hmac", b"t" * 32, body, header)


def test_ed25519_signature_round_trip_and_tamper():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = b"e" * 32
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    body = b'{"state":"denied"}'
    header = wh.sign_body("ed25519", seed, body)
    assert header.startswith("ed25519=") and wh.verify_signature("ed25519", pub, body, header)
    assert not wh.verify_signature("ed25519", pub, body + b"x", header)
    assert not wh.verify_signature("ed25519", pub, body, "hmac-sha256=00")


@pytest.mark.parametrize("kind,secret", [("hmac", b"short"), ("ed25519", b"short"), ("rsa", b"s" * 32)])
def test_a_bad_credential_is_a_named_error(kind, secret):
    with pytest.raises(CredentialError):
        wh.sign_body(kind, secret, b"{}")


def test_the_idempotency_key_is_stable_and_separates_every_part():
    org = uuid.uuid4()
    base = wh.idempotency_key(org, "a" * 64, "sms", "marketing", 3)
    assert base == wh.idempotency_key(org, "a" * 64, "sms", "marketing", 3) and len(base) == 64
    for other in (wh.idempotency_key(uuid.uuid4(), "a" * 64, "sms", "marketing", 3),
                  wh.idempotency_key(org, "b" * 64, "sms", "marketing", 3),
                  wh.idempotency_key(org, "a" * 64, "email", "marketing", 3),
                  wh.idempotency_key(org, "a" * 64, "sms", "servicing", 3),
                  wh.idempotency_key(org, "a" * 64, "sms", "marketing", 4)):
        assert other != base


@pytest.mark.parametrize("result,expect", [
    (wh.TransportResult("response", 200), ("acknowledged", None)),
    (wh.TransportResult("response", 204), ("acknowledged", None)),
    (wh.TransportResult("response", 500), ("retry", "http_5xx")),
    (wh.TransportResult("response", 503), ("retry", "http_5xx")),
    (wh.TransportResult("response", 408), ("retry", "http_4xx")),
    (wh.TransportResult("response", 429), ("retry", "http_4xx")),
    (wh.TransportResult("response", 400), ("dead", "http_4xx")),
    (wh.TransportResult("response", 404), ("dead", "http_4xx")),
    (wh.TransportResult("response", 422), ("dead", "http_4xx")),
    (wh.TransportResult("response", 302), ("dead", "http_4xx")),
    (wh.TransportResult("response", 401), ("dead", "signature_rejected")),
    (wh.TransportResult("response", 403), ("dead", "signature_rejected")),
    (wh.TransportResult("timeout"), ("retry", "timeout")),
    (wh.TransportResult("unreachable"), ("retry", "unreachable")),
    (wh.TransportResult("refused"), ("dead", "unreachable")),
])
def test_classification(result, expect):
    out = wh.classify(result)
    assert (out.kind, out.error_class) == expect


def test_an_unknown_transport_result_is_a_named_error():
    with pytest.raises(TransportError):
        wh.classify(wh.TransportResult("shrug"))


@pytest.mark.parametrize("status,body,expect", [
    (200, {"delivered": True, "receiver_status": 200}, ("response", 200)),
    (502, {"delivered": False, "receiver_status": 503}, ("response", 503)),
    (502, {"delivered": False, "error": "receiver_redirect", "receiver_status": 301}, ("response", 301)),
    (504, {"delivered": False, "error": "receiver_timeout", "message": "10000 ms"}, ("timeout", None)),
    (502, {"delivered": False, "error": "receiver_unreachable"}, ("unreachable", None)),
    (502, {"delivered": False, "error": "dns_failed"}, ("unreachable", None)),
    (403, {"delivered": False, "error": "target_address_refused"}, ("refused", None)),
    (400, {"delivered": False, "error": "target_not_https"}, ("refused", None)),
])
def test_the_egress_doors_answers_become_transport_results(status, body, expect):
    r = wh.interpret_egress(status, json.dumps(body).encode())
    assert (r.kind, r.http_status) == expect


@pytest.mark.parametrize("status,body", [
    (401, {"delivered": False, "error": "unauthorized"}),
    (500, {"delivered": False, "error": "misconfigured"}),
    (404, {"delivered": False, "error": "not_found"}),
    (400, {"delivered": False, "error": "header_refused"}),
    (413, {"delivered": False, "error": "too_large"}),
    (500, {"delivered": False, "error": "internal"}),
])
def test_the_door_failing_is_a_transport_error_not_the_receivers_fault(status, body):
    with pytest.raises(TransportError):
        wh.interpret_egress(status, json.dumps(body).encode())


def test_an_egress_answer_that_is_not_json_is_a_transport_error():
    with pytest.raises(TransportError, match="not JSON"):
        wh.interpret_egress(502, b"<html>bad gateway</html>")


class _Res(io.BytesIO):
    def __init__(self, status, payload):
        super().__init__(json.dumps(payload).encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def test_the_egress_transport_posts_the_exact_signed_body_and_the_door_secret():
    seen = {}

    def opener(request, timeout):
        seen.update(url=request.full_url, auth=request.get_header("Authorization"), body=json.loads(request.data),
                    timeout=timeout)
        return _Res(200, {"delivered": True, "receiver_status": 204})

    t = wh.EgressTransport("https://egress.example.test", "door-secret", opener=opener)
    req = wh.build_request(endpoint="https://crm.example.test/hook", signature="hmac", secret=b"k" * 32,
                           body=b'{"x":"\xc3\xa9"}', outbox_id=uuid.uuid4(), org_id=uuid.uuid4(), contact_fp="a" * 64,
                           channel="sms", purpose="marketing", version=1)
    out = t.send(req)
    assert (out.kind, out.http_status) == ("response", 204)
    assert seen["url"] == "https://egress.example.test/push" and seen["auth"] == "Bearer door-secret"
    assert seen["body"]["target_url"] == "https://crm.example.test/hook" and seen["body"]["payload"] == '{"x":"é"}'
    assert set(seen["body"]["headers"]) <= {"X-ConsentVault-Signature", "X-ConsentVault-Delivery", "Idempotency-Key", "Content-Type"}
    assert 0 < seen["timeout"] <= 15
    assert "door-secret" not in repr(t)


def test_the_egress_transport_reads_a_502_body_and_names_an_unreachable_door():
    def refuses(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 502, "Bad Gateway", {}, _Res(502, {"delivered": False, "receiver_status": 500}))

    t = wh.EgressTransport("https://egress.example.test", "s", opener=refuses)
    req = wh.PushRequest("https://crm.example.test/hook", b"{}", {})
    assert t.send(req).http_status == 500

    def down(request, timeout):
        raise urllib.error.URLError("connection refused")

    with pytest.raises(TransportError, match="could not be reached"):
        wh.EgressTransport("https://egress.example.test", "s", opener=down).send(req)


@pytest.mark.parametrize("url,secret", [("http://egress.example.test", "s"), ("https://egress.example.test", "")])
def test_the_egress_transport_needs_https_and_a_secret(url, secret):
    with pytest.raises(TransportError):
        wh.EgressTransport(url, secret)


def test_a_push_request_never_prints_its_body():
    assert "secret-contact" not in repr(wh.PushRequest("https://x.example.test", b"secret-contact", {}))


@pytest.mark.parametrize("result,verdict,status", [
    (wh.TransportResult("response", 200), "accepted", 200), (wh.TransportResult("response", 404), "rejected", 404),
    (wh.TransportResult("response", 500), "server_error", 500), (wh.TransportResult("timeout"), "timeout", None),
    (wh.TransportResult("unreachable"), "unreachable", None)])
def test_a_test_push_reports_the_answer_not_an_error(result, verdict, status):
    class T:
        def send(self, request):
            body = json.loads(request.body)
            assert body["test"] is True and "contact" not in body
            return result

    out = wh.send_test_push(T(), endpoint="https://crm.example.test/hook", signature="hmac", secret=b"k" * 32,
                            org_id=uuid.uuid4())
    assert (out["result"], out["http_status"]) == (verdict, status) and isinstance(out["latency_ms"], int)
