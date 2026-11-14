"""Every route the dashboard's API client calls is mounted by serve-cloud (none missing), checked against the client file."""

import re
from pathlib import Path

from consentvault.tenancy.admin_routes import AdminApp
from consentvault.tenancy.tokens import TokenKey
from consentvault.cloud_startup import BUILT_IN_ROUTES, build_routes

CLIENT = Path(__file__).resolve().parents[1] / "portal/app/src/lib/api/client.ts"
VERBS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "del": "DELETE"}
LINE = re.compile(r"\b(get|post|put|patch|del)\b[^'`\n]*?[`'](/v1/[^`']*)[`']")
SAMPLE = "0a1b2c3d-0000-4000-8000-00000000000a"


def client_calls():
    calls = set()
    for line in CLIENT.read_text(encoding="utf-8").splitlines():
        for verb, path in LINE.findall(line):
            path = re.sub(r"\$\{[^}]*\}", SAMPLE, path)
            calls.add((VERBS[verb], path))
    return calls


class _Any:
    def __getattr__(self, name):
        return _Any()

    def __call__(self, *a, **k):
        return _Any()


def mounted():
    stuff = _Any()
    admin = AdminApp(connect=lambda: None, owner_connect=lambda: None, token_key=TokenKey("k1", b"x" * 32), sessions=None,
                     custody=stuff, mailer=stuff)
    return build_routes(admin_app=admin, auth=stuff, connect=lambda: None, owner_connect=lambda: None, token_key=stuff,
                        crypto=stuff, custody=stuff, evidence_store=stuff, archive_store=stuff, ledger=stuff, signer=stuff,
                        notifier=stuff, stripe=stuff, webhook_secret="whsec", link_secret=b"x" * 32, mint_token=lambda o, s: "t",
                        region="US")


def test_the_client_file_is_read_and_calls_something():
    calls = client_calls()
    assert len(calls) > 40 and ("POST", "/v1/session/org") in calls and ("POST", f"/v1/exports/{SAMPLE}:link") in calls


def test_serve_cloud_mounts_every_route_the_dashboard_calls():
    routes = mounted()
    missing = [c for c in sorted(client_calls())
               if c not in BUILT_IN_ROUTES and not any(r.handles(*c) for r in routes)]
    assert missing == [], f"the dashboard calls routes serve-cloud does not mount: {missing}"


def test_export_billing_and_lifecycle_families_are_all_mounted():
    routes = mounted()
    for call in [("POST", "/v1/exports"), ("GET", "/v1/billing"), ("POST", "/v1/billing/checkout"),
                 ("POST", "/v1/contacts:erase"), ("POST", "/v1/offboarding-requests"), ("POST", "/v1/systems"),
                 ("GET", "/v1/members"), ("PUT", "/v1/org/sso")]:
        assert any(r.handles(*call) for r in routes), call
