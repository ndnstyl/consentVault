"""Second-wave review: every lane's routes run through the real multi-tenant server, with callers produced from
authenticated sessions only. One route per lane end to end, DELETE routed, and a forged operator header refused.
All traffic is loopback to a server this test starts and stops."""

import dataclasses
import json
import os
import threading
import urllib.error
import urllib.request
import uuid

import pytest

from consentvault import api, db
from consentvault.billing.routes import BillingRoutes
from consentvault.evidence import ExportService, LocalEcdsaSigner
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.providers.keys import LocalFileKeyProvider
from consentvault.route_wiring import AdminRoutes, Authenticator, ExportRouteAdapter, SyncRouteAdapter
from consentvault.sync.routes import SyncRoutes
from consentvault.sync.systems import bind_signal_credential
from consentvault.tenancy.admin_base import ROLE_SCOPES
from consentvault.tenancy.admin_routes import AdminApp
from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX, SessionMinter
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from admin.support import FakeIdentity, RecordingMailer
from billing.fakes import FakeStripe
from sync.support import SyncEnv

from .cloud_harness import Cloud

X = "+15555550177"
OPERATOR = ("https://idp.example.com", "op-subject-1")
TEST_PASSPHRASE = "test-only-local-passphrase"
TEST_WEBHOOK_KEY = "test-only-webhook-key"


class Wired:
    def __init__(self, cloud: Cloud, tmp_path, pg_server, **settings_extra):
        t = cloud.t
        self.cloud, self.t = cloud, t
        self.identity = FakeIdentity()
        connect = lambda: db.connect(t.app_dsn)  # noqa: E731
        auth = Authenticator(connect=connect, access_tokens=cloud.access, identity=self.identity,
                             operators={OPERATOR: "op-1"})
        self.custody = LocalFileKeyProvider(tmp_path / "keys", TEST_PASSPHRASE)
        self.mailer = RecordingMailer()
        admin_app = AdminApp(connect=connect, owner_connect=lambda: db.connect(t.operator_dsn), token_key=t.key,
                             sessions=SessionMinter(self.identity, t.key), custody=self.custody, mailer=self.mailer)
        sync = SyncRoutes(connect, t.crypto)
        self.exports = ExportService(connect=connect,
                                     mint_token=lambda o, s: mint_org_token(t.key, o, s, credential_id=None),
                                     crypto=t.crypto, signer=LocalEcdsaSigner.generate("evidence-test", 1),
                                     store=LocalAppendOnlyEvidenceStore(tmp_path / "exports"), link_secret=os.urandom(32))
        billing = BillingRoutes(connect=connect, mint_token=lambda o, s: mint_org_token(t.key, o, s, credential_id=None),
                                client=FakeStripe(), webhook_secret=TEST_WEBHOOK_KEY)
        self.routes = routes = (AdminRoutes(admin_app, auth), SyncRouteAdapter(sync, auth, t.key),
                  ExportRouteAdapter(self.exports, auth), billing)
        settings = dataclasses.replace(cloud.settings, routes=routes, portal_caller=auth.billing_caller, **settings_extra)
        self.server = api.make_cloud_server(settings, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.env = SyncEnv(t, pg_server["port"])

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)

    def call(self, method, path, body=None, token=None, headers=None):
        h = {"Content-Type": "application/json", **(headers or {})}
        if token:
            h["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else (b"" if method in ("POST", "PUT", "PATCH") else None)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:  # loud-failure-exempt: a non-2xx answer is returned to the test to assert on
            return e.code, e.read(), dict(e.headers)

    def portal_token(self, org, role="admin"):
        with self.t.superuser() as su:
            mid = su.execute("SELECT member_id FROM consentvault.member WHERE org_id = %s AND role = %s LIMIT 1",
                             (org.org_id, role)).fetchone()["member_id"]
        return mint_org_token(self.t.key, org.org_id, ROLE_SCOPES[role],
                              credential_id=MEMBER_CREDENTIAL_PREFIX + str(mid))


@pytest.fixture
def wired(tenancy, tmp_path, pg_server):
    cloud = Cloud(tenancy, str(tmp_path / "evidence"))
    w = Wired(cloud, tmp_path, pg_server)
    yield w
    w.close()
    cloud.close()


def _j(raw):
    return json.loads(raw) if raw else None


def test_admin_route_and_delete_run_through_the_server_with_a_portal_session(wired):
    tok = wired.portal_token(wired.t.a)
    s, raw, _ = wired.call("GET", "/v1/brands", token=tok)
    assert s == 200 and [b["display_name"] for b in _j(raw)["items"]] == ["alpha Brand"], raw
    s, raw, _ = wired.call("POST", "/v1/members", {"email": "new@alpha.example.com", "role": "developer"}, token=tok)
    assert s == 201, raw
    s, raw, _ = wired.call("GET", "/v1/members?include=invites", token=tok)  # the query string reaches the route
    invite = [i for i in _j(raw)["items"] if i["kind"] == "invite"][0]["id"]
    s, raw, _ = wired.call("DELETE", f"/v1/invites/{invite}", token=tok)
    assert (s, raw) == (204, b"")
    s, raw, _ = wired.call("GET", "/v1/brands")
    assert s == 401 and _j(raw)["error"] == "unauthenticated"
    s, raw, _ = wired.call("GET", "/v1/brands", token=wired.cloud.token(wired.cloud.a, "capture"))  # machine != portal
    assert s == 401


def test_sync_signal_runs_through_the_server_on_a_bound_machine_credential(wired):
    a = wired.t.a
    crm = wired.env.add_system(a, "crm")
    cred = wired.cloud.a.clients["capture"].credential_id
    with wired.t.operator() as o, org_transaction(o, wired.t.admin_token(a.org_id)):
        bind_signal_credential(o, crm.system_id, cred)
    body = {"contact": X, "channel": "sms", "purpose": "marketing", "claimed_state": "denied",
            "external_ref": str(uuid.uuid4())}
    s, raw, _ = wired.call("POST", "/v1/signals", body, token=wired.cloud.token(wired.cloud.a, "capture"))
    assert s == 202 and _j(raw)["resolution"] == "applied_as_event", raw
    s, raw, _ = wired.call("POST", "/v1/signals", body)
    assert s == 401


def test_an_export_runs_through_the_server_and_its_creator_downloads_it(wired):
    co = wired.cloud.a
    assert wired.cloud.grant(co, X)[0] == 201
    tok = wired.cloud.token(co, "proof_read")
    s, raw, _ = wired.call("POST", "/v1/exports", {"contact": X}, token=tok)
    assert s == 202, raw
    eid = _j(raw)["export_id"]
    s, raw, _ = wired.call("GET", f"/v1/exports/{eid}", token=tok)
    assert s == 200 and _j(raw)["status"] == "ready", raw
    s, raw, _ = wired.call("POST", f"/v1/exports/{eid}:link", token=tok)
    assert s == 200, raw
    url = _j(raw)["download_url"]
    s, raw, headers = wired.call("GET", url[url.index("/v1/"):])
    assert s == 200 and raw[:2] == b"PK" and headers["Content-Type"] == "application/zip"


def test_a_billing_route_takes_its_caller_from_the_portal_session(wired):
    s, raw, _ = wired.call("GET", "/v1/billing", token=wired.portal_token(wired.t.a))
    assert s == 200, raw
    s, raw, _ = wired.call("GET", "/v1/billing")
    assert s == 401


def test_a_forged_operator_header_is_refused_and_only_a_verified_operator_session_passes(wired):
    body = {"name": "Forged Co", "admin_email": "boss@forged.example.com"}
    for h in ({"X-ConsentVault-Operator": "op-1"}, {"X-Operator-Id": "op-1"}, {"Operator-Id": "op-1"}):
        s, raw, _ = wired.call("POST", "/v1/orgs", body, headers=h)
        assert (s, _j(raw)["error"]) == (401, "unauthenticated"), (h, raw)
    stranger = wired.identity.issue("someone-else", "x@example.com")
    no_mfa = wired.identity.issue(OPERATOR[1], "op@example.com", mfa=False)
    for tok in (stranger, no_mfa, wired.portal_token(wired.t.a)):
        s, raw, _ = wired.call("POST", "/v1/orgs", body, token=tok, headers={"X-ConsentVault-Operator": "op-1"})
        assert s == 401, raw
    with wired.t.superuser() as su:
        before = su.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"]
    s, raw, _ = wired.call("POST", "/v1/orgs", body, token=wired.identity.issue(OPERATOR[1], "op@example.com"))
    assert s == 201, raw
    with wired.t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"] == before + 1


def _member_token(w, org, role):
    with w.t.superuser() as su:
        mid = su.execute("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role) VALUES (%s, %s, %s, %s)"
                         " RETURNING member_id", (org.org_id, "https://idp.example.com", f"u-{role}-{uuid.uuid4().hex[:6]}",
                                                  role)).fetchone()["member_id"]
    return mint_org_token(w.t.key, org.org_id, ROLE_SCOPES[role], credential_id=MEMBER_CREDENTIAL_PREFIX + str(mid))


def test_the_portal_reads_proof_as_admin_or_viewer_for_its_own_organisation_only(wired):
    # contracts/proof-export.md: POST /v1/proof is for A and V in the portal as well as M(proof_read); a developer never reads it
    assert wired.cloud.grant(wired.cloud.a, X)[0] == 201
    for role in ("admin", "compliance_viewer"):
        tok = wired.portal_token(wired.t.a) if role == "admin" else _member_token(wired, wired.t.a, role)
        s, raw, _ = wired.call("POST", "/v1/proof", {"contact": X}, token=tok)
        assert s == 200 and _j(raw)["found"] is True and _j(raw)["timeline"]["items"], (role, raw)
    with wired.t.superuser() as su:  # the read is tied to the person: the audit row names the member, never the contact
        member = str(su.execute("SELECT member_id FROM consentvault.member WHERE org_id = %s AND role = 'admin' LIMIT 1",
                                (wired.t.a.org_id,)).fetchone()["member_id"])
        rows = su.execute("SELECT actor_kind, actor_id, target_kind, target_id, reason FROM consentvault.audit_event"
                          " WHERE org_id = %s AND action = 'proof.read'", (wired.t.a.org_id,)).fetchall()
    assert len(rows) == 2 and {r["actor_kind"] for r in rows} == {"member"}, rows
    assert member in {r["actor_id"] for r in rows}, "the admin's own read names the admin"
    assert X not in str(rows) and all(r["target_kind"] == "contact" and len(r["target_id"]) == 8 for r in rows)
    s, raw, _ = wired.call("POST", "/v1/proof", {"contact": X}, token=_member_token(wired, wired.t.a, "developer"))
    assert s == 403 and _j(raw)["error"] == "role_not_allowed", raw
    s, raw, _ = wired.call("POST", "/v1/proof", {"contact": X}, token=wired.portal_token(wired.t.b))
    assert s == 200 and _j(raw)["found"] is False, "another organisation's admin finds nothing of A's contact"
    s, raw, _ = wired.call("POST", "/v1/proof", {"contact": X})
    assert s == 401
    s, raw, _ = wired.call("POST", "/v1/proof", {"contact": X}, token=wired.cloud.token(wired.cloud.a, "proof_read"))
    assert s == 200 and _j(raw)["found"] is True, "the machine credential path is unchanged"
