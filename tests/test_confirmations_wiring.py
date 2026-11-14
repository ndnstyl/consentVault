"""The confirmation service in the cloud server (marketing/specs/confirmations-go-live): two settings, both or neither; the
service handed to the admin app and the door route mounted only when both are set; the provider door and the two public
pages answered through the service, with the link host taken only from the edge's own header. No database here."""

import inspect
import json

import pytest

from consentvault import cmd_cloud
from consentvault.cloud_startup import build_routes
from consentvault.config import load_config
from consentvault.confirm import wiring
from consentvault.confirm.core import Reply
from consentvault.errors import ConfigError
from consentvault.tenancy.admin_routes import AdminApp
from consentvault.tenancy.tokens import TokenKey

from providers.test_edge_assertion import PEM

BASE = "https://api.consentvault.ai"
CNAME = "edge.consentvault.ai"
KEY = "Abc_def-0123456789abcdefghijklmnopqrstuvwxyz"
BOTH = {wiring.ENV_API_BASE: BASE, wiring.ENV_EDGE_CNAME: CNAME}


# ---- the two settings ---------------------------------------------------------------------------------------------------
def test_neither_setting_means_the_service_is_off():
    assert wiring.confirmation_settings({}) is None
    assert wiring.confirmation_settings({wiring.ENV_API_BASE: "  ", wiring.ENV_EDGE_CNAME: ""}) is None


def test_both_settings_are_read():
    assert wiring.confirmation_settings(BOTH) == (BASE, CNAME)
    assert wiring.confirmation_settings({wiring.ENV_API_BASE: BASE + "/", wiring.ENV_EDGE_CNAME: "Edge.ConsentVault.AI"}) == (BASE, CNAME)


@pytest.mark.parametrize("present,missing", [(wiring.ENV_API_BASE, wiring.ENV_EDGE_CNAME),
                                             (wiring.ENV_EDGE_CNAME, wiring.ENV_API_BASE)])
def test_one_setting_without_the_other_refuses_the_start_by_name(present, missing):
    with pytest.raises(ConfigError, match=missing):
        wiring.confirmation_settings({present: BOTH[present]})


@pytest.mark.parametrize("base", ["http://api.consentvault.ai", "https://api.consentvault.ai/v1", "https://api.consentvault.ai?x=1",
                                  "api.consentvault.ai", "https://", "https://user@api.consentvault.ai"])
def test_a_malformed_api_base_is_refused_by_name(base):
    with pytest.raises(ConfigError, match=wiring.ENV_API_BASE):
        wiring.confirmation_settings({wiring.ENV_API_BASE: base, wiring.ENV_EDGE_CNAME: CNAME})


@pytest.mark.parametrize("cname", ["https://edge.consentvault.ai", "edge.consentvault.ai/", "edge", "edge..consentvault.ai", "edge consentvault.ai"])
def test_a_malformed_edge_name_is_refused_by_name(cname):
    with pytest.raises(ConfigError, match=wiring.ENV_EDGE_CNAME):
        wiring.confirmation_settings({wiring.ENV_API_BASE: BASE, wiring.ENV_EDGE_CNAME: cname})


def test_half_configured_refuses_the_server_start_before_any_other_setting_is_read():
    env = {"CONSENTVAULT_DSN": "postgresql://x@127.0.0.1:1/x", "CONSENTVAULT_EDGE_ASSERTION_KEYS": json.dumps({"e": PEM.decode()}),
           wiring.ENV_API_BASE: BASE}
    with pytest.raises(ConfigError, match=wiring.ENV_EDGE_CNAME):
        cmd_cloud.build_cloud(load_config(env=env), env)


# ---- the service ---------------------------------------------------------------------------------------------------------
def test_the_service_is_built_with_the_settings_and_the_one_clock():
    clock = lambda: 1.0  # noqa: E731
    svc = wiring.build_service(BOTH, connect=lambda: None, token_key=TokenKey("k1", b"x" * 32), custody=object(), clock=clock)
    assert svc._api_base == BASE and svc._edge_cname == CNAME and svc._clock is clock
    assert wiring.build_service({}, connect=lambda: None, token_key=None, custody=None, clock=clock) is None


def test_the_server_hands_one_service_and_one_clock_to_the_admin_app_and_the_routes():
    src = inspect.getsource(cmd_cloud.build_cloud)
    assert "wiring.confirmation_settings(env)" in src.split("load_key_provider(")[0], "the settings are checked before anything else is built"
    assert "wiring.build_service(" in src
    assert src.count("confirmations=confirmations") == 2, "the admin app and the routes get the same service"
    assert "clock=clock" in src and "dbclock.epoch_clock(connect)" in src


class _Any:
    def __getattr__(self, name):
        return _Any()

    def __call__(self, *a, **k):
        return _Any()


def _routes(confirmations):
    stuff = _Any()
    admin = AdminApp(connect=lambda: None, owner_connect=lambda: None, token_key=TokenKey("k1", b"x" * 32), sessions=None,
                     custody=stuff, mailer=stuff, confirmations=confirmations)
    return build_routes(admin_app=admin, auth=stuff, connect=lambda: None, owner_connect=lambda: None, token_key=stuff,
                        crypto=stuff, custody=stuff, evidence_store=stuff, archive_store=stuff, ledger=stuff, signer=stuff,
                        notifier=stuff, stripe=stuff, webhook_secret="whsec", link_secret=b"x" * 32, mint_token=lambda o, s: "t",
                        region="US", confirmations=confirmations, confirmations_api_base=BASE)


DOOR_CALLS = [("POST", f"/v1/confirmations/inbound/{KEY}"), ("GET", "/c/r/abcdefgh12"), ("GET", "/c/stop/abcdefgh12"),
              ("POST", "/c/stop/abcdefgh12")]


def test_without_the_service_no_door_is_mounted():
    routes = _routes(None)
    assert not any(isinstance(r, wiring.ConfirmationDoor) for r in routes)
    for call in DOOR_CALLS:
        assert not any(r.handles(*call) for r in routes), call


def test_with_the_service_the_door_is_mounted_last_and_answers_only_its_paths():
    routes = _routes(_FakeService())
    assert isinstance(routes[-1], wiring.ConfirmationDoor)
    door = routes[-1]
    for call in DOOR_CALLS:
        assert door.handles(*call), call
    for call in [("GET", f"/v1/confirmations/inbound/{KEY}"), ("POST", f"/v1/confirmations/inbound/{KEY}/x"),
                 ("POST", "/v1/confirmations/inbound/"), ("POST", "/v1/confirmations/inbound/a b"), ("PUT", "/c/stop/abcdefgh12"),
                 ("POST", "/c/r/abcdefgh12x/"), ("GET", "/c/x/abcdefgh12"), ("GET", "/v1/confirmations/settings")]:
        assert not door.handles(*call), call


# ---- the door ------------------------------------------------------------------------------------------------------------
class _FakeService:
    def __init__(self):
        self.calls = []

    def handle_inbound(self, inbound_key, headers, body, url):
        self.calls.append(("inbound", inbound_key, dict(headers), body, url))
        return Reply(200, None)

    def handle_public(self, method, path, host, headers, body=b""):
        self.calls.append(("public", method, path, host, body))
        return Reply(200, raw=b"<p>page</p>", headers={"Content-Type": "text/html; charset=utf-8"})


def test_the_provider_door_passes_the_raw_body_and_headers_and_the_stored_address_form():
    svc = _FakeService()
    door = wiring.ConfirmationDoor(svc, BASE)
    body = b"Body=STOP&From=%2B15555550100"
    headers = {"X-Twilio-Signature": "sig=", "Content-Type": "application/x-www-form-urlencoded", "X-Request-Id": "r1"}
    res = door.handle("POST", f"/v1/confirmations/inbound/{KEY}", body=body, headers=headers, caller=None)
    assert res.status == 200 and res.payload == {}  # an empty JSON object, never null
    kind, key, seen, got, url = svc.calls[0]
    assert (kind, key, got, url) == ("inbound", KEY, body, f"{BASE}/v1/confirmations/inbound/{KEY}")
    assert seen["X-Twilio-Signature"] == "sig=" and seen["Content-Type"] == headers["Content-Type"]


@pytest.mark.parametrize("header", ["X-ConsentVault-Link-Host", "x-consentvault-link-host"])
def test_a_public_page_reads_the_link_host_from_the_edge_header_only(header):
    svc = _FakeService()
    door = wiring.ConfirmationDoor(svc, BASE)
    res = door.handle("GET", "/c/r/abcdefgh12", body=b"", headers={"Host": "localhost", header: "Consent.Acme.example"}, caller=None)
    assert res.status == 200 and res.raw == b"<p>page</p>"
    assert svc.calls == [("public", "GET", "/c/r/abcdefgh12", "consent.acme.example", b"")]


def test_a_public_page_without_the_edge_header_is_not_found_and_never_falls_back_to_host():
    svc = _FakeService()
    door = wiring.ConfirmationDoor(svc, BASE)
    res = door.handle("GET", "/c/r/abcdefgh12", body=b"", headers={"Host": "consent.acme.example"}, caller=None)
    assert res.status == 404 and svc.calls == []
    assert b"Not found" in res.raw


def test_a_stop_page_post_carries_its_body():
    svc = _FakeService()
    door = wiring.ConfirmationDoor(svc, BASE)
    door.handle("POST", "/c/stop/abcdefgh12", body=b"scope=email", headers={"X-ConsentVault-Link-Host": "consent.acme.example"})
    assert svc.calls == [("public", "POST", "/c/stop/abcdefgh12", "consent.acme.example", b"scope=email")]


# ---- inert until an organisation is armed --------------------------------------------------------------------------------
def test_a_sender_pass_with_no_organisation_waiting_calls_no_provider(monkeypatch):
    from consentvault.confirm.service import ConfirmationService

    class _Provider:
        def __getattr__(self, name):
            raise AssertionError(f"a provider was called ({name}) with nothing to send")

    svc = ConfirmationService(connect=lambda: None, token_key=TokenKey("k1", b"x" * 32), custody=object(),
                              providers={"twilio": _Provider(), "ses": _Provider(), "postmark": _Provider()}, dns=object(),
                              clock=lambda: 0.0, jitter=lambda: 0.0)
    monkeypatch.setattr(svc, "_org_list", lambda name: [])
    assert svc.run_sender() == 0
