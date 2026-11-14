"""Review fixes for the confirmation service in the cloud (marketing/specs/confirmations-go-live, review of 2026-11-14), the parts
that need no database: the fallback door's signature address, the link-host page probe, and DNS through the egress Worker."""

import json

import pytest

from consentvault.confirm import egress as ce
from consentvault.confirm import inbound, wiring
from consentvault.confirm.core import Reply
from consentvault.confirm.service import ConfirmationService
from consentvault.sync.connectors.twenty_api import CallResult
from consentvault.tenancy.tokens import TokenKey

BASE = "https://api.consentvault.ai"
KEY = "Abc_def-0123456789abcdefghijklmnopqrstuvwxyz"
STORED = f"{BASE}/v1/confirmations/inbound/{KEY}"


# ---- the fallback door ---------------------------------------------------------------------------------------------------
def test_the_fallback_address_is_derived_from_the_stored_one_never_from_the_request():
    assert inbound.signed_address(STORED, fallback=False) == STORED
    assert inbound.signed_address(STORED, fallback=True) == f"{BASE}/v1/confirmations/inbound-fallback/{KEY}"


def test_a_stored_address_that_is_not_an_inbound_address_has_no_fallback_form():
    with pytest.raises(ValueError):
        inbound.signed_address("https://api.consentvault.ai/v1/other/x", fallback=True)


def test_the_twilio_signature_ignores_the_retry_fragment_because_twilio_leaves_it_out():
    """Twilio's connection-override page: 'Twilio doesn't include the fragment in the signature computation'. The number is
    pointed at STORED + '#rp=all&rc=3'; the vault checks over STORED, so the fragment changes nothing."""
    pairs = [("Body", "STOP"), ("From", "+15555550100")]
    assert inbound.twilio_signature("tok", STORED, pairs) == inbound.twilio_signature("tok", STORED.split("#")[0], pairs)
    assert wiring.TWILIO_RETRY_FRAGMENT == "#rp=all&rc=3"


class _Svc:
    def __init__(self):
        self.calls = []

    def handle_inbound(self, inbound_key, headers, body, url, fallback=False):
        self.calls.append((inbound_key, url, fallback))
        return Reply(200, {})


def test_the_door_answers_the_fallback_path_with_the_fallback_flag():
    svc = _Svc()
    door = wiring.ConfirmationDoor(svc, BASE)
    assert door.handles("POST", f"/v1/confirmations/inbound-fallback/{KEY}")
    assert not door.handles("GET", f"/v1/confirmations/inbound-fallback/{KEY}")
    door.handle("POST", f"/v1/confirmations/inbound-fallback/{KEY}", body=b"a=b", headers={})
    door.handle("POST", f"/v1/confirmations/inbound/{KEY}", body=b"a=b", headers={})
    assert svc.calls == [(KEY, f"{BASE}/v1/confirmations/inbound-fallback/{KEY}", True), (KEY, STORED, False)]


# ---- the page probe ------------------------------------------------------------------------------------------------------
def test_the_door_answers_the_probe_with_the_link_host_it_was_reached_on():
    door = wiring.ConfirmationDoor(_Svc(), BASE)
    assert door.handles("GET", "/c/ping") and not door.handles("POST", "/c/ping")
    res = door.handle("GET", "/c/ping", body=b"", headers={"X-ConsentVault-Link-Host": "Consent.Acme.example"})
    assert res.status == 200 and res.payload == {"service": wiring.PROBE_SERVICE, "host": "consent.acme.example"}
    assert door.handle("GET", "/c/ping", body=b"", headers={}).status == 404


class FakeTransport:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def call(self, method, url, headers, payload):
        self.calls.append((method, url, dict(headers)))
        for prefix, result in self.answers.items():
            if url.startswith(prefix):
                return result
        return CallResult("unreachable", detail="no answer")


def test_dns_goes_through_the_egress_door_to_the_public_resolver():
    t = FakeTransport({"https://cloudflare-dns.com/dns-query?name=consent.acme.example&type=CNAME":
                       CallResult("response", 200, {}, {"Answer": [{"type": 5, "data": "edge.consentvault.ai."}]}),
                       "https://cloudflare-dns.com/dns-query?name=consent.acme.example&type=TXT":
                       CallResult("response", 200, {}, {"Answer": [{"type": 16, "data": '"cv-verify=abc"'}]})})
    dns = ce.EgressDns(t)
    assert dns.lookup("consent.acme.example", "CNAME") == "edge.consentvault.ai"
    assert dns.lookup("consent.acme.example", "TXT") == "cv-verify=abc"
    assert all(m == "GET" and h.get("accept") == "application/dns-json" for m, _, h in t.calls)


@pytest.mark.parametrize("result", [CallResult("timeout"), CallResult("unreachable"), CallResult("response", 503, {}, None)])
def test_a_resolver_that_does_not_answer_is_a_timeout_never_a_missing_record(result):
    with pytest.raises(TimeoutError):
        ce.EgressDns(FakeTransport({"https://cloudflare-dns.com/": result})).lookup("consent.acme.example", "CNAME")


@pytest.mark.parametrize("result,ok", [
    (CallResult("response", 200, {}, {"service": "consentvault-link-host", "host": "consent.acme.example"}), True),
    (CallResult("response", 200, {}, {"service": "consentvault-link-host", "host": "other.example"}), False),
    (CallResult("response", 200, {}, {"hello": "world"}), False),
    (CallResult("response", 530, {}, None), False),
    (CallResult("refused", detail="x"), False),
])
def test_the_probe_passes_only_when_the_vault_answers_on_that_host(result, ok):
    t = FakeTransport({"https://consent.acme.example/c/ping": result})
    assert ce.EgressDns(t).page_answers("consent.acme.example") is ok


def test_a_probe_that_times_out_is_a_timeout():
    with pytest.raises(TimeoutError):
        ce.EgressDns(FakeTransport({"https://consent.acme.example/c/ping": CallResult("timeout")})).page_answers("consent.acme.example")


def _service(dns):
    return ConfirmationService(connect=lambda: None, token_key=TokenKey("k1", b"x" * 32), custody=object(), providers={}, dns=dns,
                               clock=lambda: 0.0, jitter=lambda: 0.0)


class _Dns:
    def __init__(self, cname, txt, page):
        self.cname, self.txt, self.page = cname, txt, page

    def lookup(self, host, kind):
        return self.cname if kind == "CNAME" else self.txt

    def page_answers(self, host):
        return self.page


def test_verify_and_the_hourly_recheck_need_the_vault_to_answer_on_the_host_not_only_dns():
    row = {"host": "consent.acme.example", "txt_value": "cv-verify=abc"}
    assert _service(_Dns("edge.consentvault.ai", "cv-verify=abc", True))._dns_matches(row) is True
    assert _service(_Dns("edge.consentvault.ai", "cv-verify=abc", False))._dns_matches(row) is False
    assert _service(_Dns("other.example", "cv-verify=abc", True))._dns_matches(row) is False


def test_the_cloud_service_resolves_through_the_egress_door():
    svc = wiring.build_service(wiring_env(), connect=lambda: None, token_key=TokenKey("k1", b"x" * 32), custody=object(),
                               clock=lambda: 0.0, egress=FakeTransport({}))
    assert isinstance(svc._dns, ce.EgressDns)
    with pytest.raises(Exception, match="egress"):
        wiring.build_service(wiring_env(), connect=lambda: None, token_key=TokenKey("k1", b"x" * 32), custody=object(),
                             clock=lambda: 0.0, egress=None)


def wiring_env():
    return {wiring.ENV_API_BASE: BASE, wiring.ENV_EDGE_CNAME: "edge.consentvault.ai"}
