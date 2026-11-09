"""The local end-to-end stack for the dashboard: a throwaway Postgres, the real API, a stub sign-in issuer, the portal edge
Worker under ``wrangler dev`` serving the dashboard's static export, and synthetic organisations with sealed evidence.

    PG_BIN=/path/to/postgres/bin .venv/bin/python scripts/e2e/stack.py --wrangler /path/to/wrangler

It prints one JSON line starting ``{"ready":`` once everything answers, then runs until it is sent SIGTERM or SIGINT, or
its standard input closes (so a parent that dies takes the stack with it). Everything it starts is stopped on the way
out: the edge (its whole process group), the stub, the API thread and the database; its temporary directory is removed.

Local synthetic stack only. It reuses the test suite's helpers (a no-login migrator role, an in-memory key provider, a
throwaway timestamp authority, a Stripe stand-in) and seeds members with SQL as the database superuser. It holds no real
key, calls no production service and keeps no data.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))

import tsa as tsa_mod  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from conftest import (MIGRATOR_ROLE, _dsn, _free_port, _pg_bin, create_vault_database, ensure_roles,  # noqa: E402
                      pin_as_superuser)
from consentvault import api, db  # noqa: E402
from consentvault.billing.routes import BillingRoutes  # noqa: E402
from consentvault.evidence import ExportService, LocalEcdsaSigner  # noqa: E402
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore  # noqa: E402
from consentvault.config import Config
from consentvault.providers.identity import HttpJwksFetcher, OIDCIdentityProvider  # noqa: E402
from consentvault.providers.keys import LocalFileKeyProvider  # noqa: E402
from consentvault.route_wiring import AdminRoutes, Authenticator, ExportRouteAdapter, SyncRouteAdapter  # noqa: E402
from consentvault.sync.routes import SyncRoutes  # noqa: E402
from consentvault.tenancy.oauth import AccessTokenSigner  # noqa: E402
from consentvault.tenancy.pipeline import ReceiptSigner  # noqa: E402
from consentvault.cloud_startup import build_admin_app  # noqa: E402
from consentvault.tenancy.tokens import mint_org_token  # noqa: E402

from billing.fakes import FakeStripe  # noqa: E402
from export.support import PHONE, build_empty_tenancy, head_anchor, populate  # noqa: E402

CLIENT_ID = "client_e2e_stub"
CLIENT_SECRET = "e2e-stub-client-credential"
PASSPHRASE = "e2e-local-only-passphrase"
SSO_WORKOS_ORG = "org_01E4ZCR3C56J083X43JQXF3JK5"
SSO_CONNECTION = "conn_01E4ZCR3C56J083X43JQXF3JK5"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def wait_http(url: str, what: str, deadline_s: float, ok=(200, 301, 302)) -> None:
    """Poll until the URL answers with one of ``ok``; at the deadline raise, naming the last thing seen."""
    end = time.monotonic() + deadline_s
    last = "no answer yet"
    opener = urllib.request.build_opener(_NoRedirect)
    while time.monotonic() < end:
        try:
            with opener.open(url, timeout=3) as r:
                if r.status in ok:
                    return
                last = f"HTTP {r.status}"
        except urllib.error.HTTPError as exc:  # loud-failure-exempt: polling loop; the last answer is carried into the error raised at the deadline
            if exc.code in ok:
                return
            last = f"HTTP {exc.code}"
        except OSError as exc:  # loud-failure-exempt: polling loop; the last error is carried into the error raised at the deadline
            last = str(exc)
        time.sleep(0.4)
    raise RuntimeError(f"{what} did not answer at {url} within {deadline_s:.0f}s (last: {last})")


class Stack:
    def __init__(self, args) -> None:
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="cv-e2e-"))
        self.pg_data = self.root / "pg"
        self.started_pg = False
        self.bindir: Path | None = None
        self.stub: subprocess.Popen | None = None
        self.edge: subprocess.Popen | None = None
        self.server = None
        self.thread: threading.Thread | None = None

    # ---- database -------------------------------------------------------------------------------------------------
    def start_pg(self) -> int:
        self.bindir = _pg_bin()
        port = _free_port()
        subprocess.run([str(self.bindir / "initdb"), "-D", str(self.pg_data), "-U", "postgres", "-A", "trust", "-E",
                        "UTF8", "--locale=C"], check=True, capture_output=True)
        subprocess.run([str(self.bindir / "pg_ctl"), "start", "-w", "-t", "60", "-D", str(self.pg_data), "-l",
                        str(self.root / "pg.log"), "-o", f"-p {port} -k {self.root} -c listen_addresses=127.0.0.1 -c fsync=off"],
                       check=True, capture_output=True)
        self.started_pg = True
        return port

    def stop_pg(self) -> None:
        if self.started_pg and self.bindir is not None:
            subprocess.run([str(self.bindir / "pg_ctl"), "stop", "-m", "immediate", "-w", "-D", str(self.pg_data)],
                           check=True, capture_output=True)
            self.started_pg = False

    # ---- the stack ------------------------------------------------------------------------------------------------
    def run(self) -> dict:
        a = self.args
        port = self.start_pg()
        ensure_roles(port)
        name = "e2e_" + uuid.uuid4().hex[:8]
        create_vault_database(port, name)
        dsn = _dsn(port, name, MIGRATOR_ROLE)
        with db.connect(dsn) as c:
            db.migrate(c)
        pin_as_superuser(dsn)

        stub_port, edge_port, api_port = _free_port(), _free_port(), _free_port()
        public_url = f"http://localhost:{edge_port}"
        stub_url = f"http://127.0.0.1:{stub_port}"
        self.stub = subprocess.Popen(
            [a.node, str(REPO / "edge/test/support/stub-oidc.ts"), "--port", str(stub_port), "--client-id", CLIENT_ID,
             "--client-secret", CLIENT_SECRET, "--redirect", f"{public_url}/auth/callback", "--return-to", public_url],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = self.stub.stdout.readline()
        if "stub_ready" not in line:
            raise RuntimeError(f"the stub sign-in issuer did not start: {line!r}")

        (self.root / "tsa").mkdir()
        tsa = tsa_mod.build(self.root / "tsa")
        if tsa is None:
            raise RuntimeError("this openssl cannot run 'ts -reply' / 'ts -verify': the evidence seals cannot be made")
        t = build_empty_tenancy(dsn, port)
        populate(t, t.a, tsa)
        populate(t, t.b, tsa)
        people = self.seed_members(t, stub_url)
        self.seed_alarms(t)
        mailer = _Mailer()

        # the API, wired as tests/isolation/test_route_wiring.py wires it, with sign-in checked against the stub issuer
        # sign-in is checked the way the real provider's tokens need: the client id claim stands in for aud, and the portal
        # edge's signed assertion supplies the authentication methods (the token carries no amr)
        identity = OIDCIdentityProvider(issuer=stub_url, audience=CLIENT_ID, jwks_fetcher=HttpJwksFetcher(stub_url + "/jwks"),
                                        audience_claim="client_id")
        edge_key = ec.generate_private_key(ec.SECP256R1())
        edge_pem = edge_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.edge_jwk = json.dumps({**json.loads(_jwk_private(edge_key)), "kid": "edge-e2e"})
        real = api._migration_logins
        api._migration_logins = lambda conn: [r for r in real(conn) if r != MIGRATOR_ROLE]  # the suite's one kept login
        connect = lambda: db.connect(t.app_dsn)  # noqa: E731
        access = AccessTokenSigner.generate(key_id="at-e2e", issuer="https://api.consentvault.test")
        auth = Authenticator(connect=connect, access_tokens=access, identity=None, operators={})
        custody = LocalFileKeyProvider(self.root / "keys", PASSPHRASE)
        mint = lambda o, s: mint_org_token(t.key, o, s, credential_id=None)  # noqa: E731
        evidence_signer = LocalEcdsaSigner.generate("evidence-e2e", 1)
        exports = ExportService(connect=connect, mint_token=mint, crypto=t.crypto, signer=evidence_signer,
                                store=LocalAppendOnlyEvidenceStore(self.root / "exports"), link_secret=os.urandom(32))
        admin_app = build_admin_app(Config(edge_assertion_keys={"edge-e2e": edge_pem.decode()}), identity=identity, token_key=t.key,
                                    connect=connect, owner_connect=lambda: db.connect(t.operator_dsn), custody=custody,
                                    mailer=mailer)
        routes = (AdminRoutes(admin_app, auth), SyncRouteAdapter(SyncRoutes(connect, t.crypto), auth, t.key),
                  ExportRouteAdapter(exports, auth),
                  BillingRoutes(connect=connect, mint_token=mint, client=FakeStripe(), webhook_secret="e2e-webhook-key"))
        settings = api.CloudApiSettings(
            dsn=t.app_dsn, projection_dsn=t.projection_dsn, token_key=t.key, access_tokens=access, receipts=ReceiptSigner.generate(key_id="rcpt-e2e"),
            crypto=t.crypto, evidence_store=LocalAppendOnlyEvidenceStore(self.root / "evidence"),
            token_endpoint_url="https://api.consentvault.test/v1/oauth/token", cursor_key=os.urandom(32),
            allowed_hosts=("127.0.0.1", "localhost"), default_retain_years=7, region="US", routes=routes,
            portal_caller=auth.billing_caller)
        self.server = api.make_cloud_server(settings, "127.0.0.1", api_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        cafile = self.root / "tsa-ca.pem"
        shutil.copyfile(tsa.ca, cafile)
        evkey = self.root / "evidence-public.pem"
        evkey.write_bytes(evidence_signer.public_key_pem())

        # the operator binds a company connection to alpha (the admin never types one); unproved until an admin signs in through it
        from consentvault.tenancy import admin as admin_mod
        with db.connect(t.operator_dsn) as oc:
            admin_mod.bind_sso(oc, token_key=t.key, operator_id="op-e2e", request_id="e2e-bind", org_id=t.a.org_id,
                               body={"workos_organization_id": SSO_WORKOS_ORG, "connection_ids": [SSO_CONNECTION]})
        self.start_edge(edge_port, api_port, stub_port, public_url)
        return {
            "sso": {"workos_org": SSO_WORKOS_ORG, "connection": SSO_CONNECTION},
            "edge": public_url, "stub": stub_url, "api": f"http://127.0.0.1:{api_port}", "client_id": CLIENT_ID,
            "cafile": str(cafile), "evidence_key": str(evkey), "contact": PHONE, "people": people,
            "invite": self.seed_invite(t, admin_app, mailer),
            "orgs": {"alpha": {"org_id": str(t.a.org_id), "anchor": head_anchor(t, t.a)},
                     "bravo": {"org_id": str(t.b.org_id), "anchor": head_anchor(t, t.b)}},
            "python": sys.executable,
        }

    def seed_members(self, t, stub_url: str) -> dict:
        """The harness makes one admin per organisation under a made-up issuer; point them at the stub issuer and add a
        person who belongs to both (so the organisation chooser appears). Synthetic rows, written as the superuser."""
        people = {"alice": ("sub-alice", "alice@alpha.test", "Alice Alpha"), "bob": ("sub-bob", "bob@bravo.test", "Bob Bravo"),
                  "carol": ("sub-carol", "carol@both.test", "Carol Both"), "dave": ("sub-dave", "dave@nowhere.test", "Dave Nobody"),
                  "erin": ("sub-erin", "erin@alpha.test", "Erin Invited")}
        with t.superuser() as su:
            su.execute("ALTER TABLE consentvault.member DISABLE TRIGGER member_last_admin_guard")
            for org, who in ((t.a, "alice"), (t.b, "bob")):
                sub, email, name = people[who]
                su.execute("UPDATE consentvault.member SET idp_issuer = %s, idp_subject = %s, email_norm = %s, display_name = %s"
                           " WHERE org_id = %s", (stub_url, sub, email, name, org.org_id))
            sub, email, name = people["carol"]
            for org, role in ((t.a, "admin"), (t.b, "compliance_viewer")):
                su.execute("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role, email_norm, display_name)"
                           " VALUES (%s, %s, %s, %s, %s, %s)", (org.org_id, stub_url, sub, role, email, name))
            su.execute("ALTER TABLE consentvault.member ENABLE TRIGGER member_last_admin_guard")
        return {k: {"sub": v[0], "email": v[1], "name": v[2]} for k, v in people.items()}

    def seed_alarms(self, t) -> None:
        """Open alarms for the overview. Alpha: reveal volume, a failing sending account (and one cleared), five unconfirmed stops
        put back by a restore (two stand, one confirmed, one lifted), a second live subscription, and a usage alarm that no
        customer may ever see. Bravo: one unconfirmed stop and a second live subscription."""
        import uuid as _uuid
        from consentvault.ledger import record_tenant_event
        from consentvault.tenancy.tokens import org_transaction

        with t.superuser() as su:
            for org, kind, detail, cleared in ((t.a, "reveal_volume", {"member_id": None, "count": 5200, "window": "24h"}, False),
                                               (t.a, "sending_account_failing", {"account_id": "a1", "channel": "sms"}, False),
                                               (t.a, "link_host_failing", {}, True)):
                su.execute("INSERT INTO consentvault.org_alarm (org_id, kind, detail, cleared_at) VALUES (%s, %s, %s, %s)",
                           (org.org_id, kind, json.dumps(detail), "2026-01-01T00:00:00Z" if cleared else None))
            for org, name in ((t.a, "billing.second_live_subscription"), (t.b, "billing.second_live_subscription"),
                              (t.a, "usage_day_abandoned")):
                su.execute("INSERT INTO consentvault.operator_alarm (org_id, name, error_class) VALUES (%s, %s, 'Seeded')", (org.org_id, name))
        eid = str(_uuid.uuid4())
        for org, marker, phone in ((t.a, f"erasure-unconfirmed:{eid}:1", "+15555550111"), (t.a, f"erasure-unconfirmed:{eid}:2", "+15555550112"),
                                   (t.a, f"erasure-unconfirmed:{eid}:3", "+15555550113"), (t.a, f"erasure:{eid}:3", "+15555550113"),
                                   (t.b, f"erasure-unconfirmed:{eid}:1", "+15555550111")):
            with t.app() as app, org_transaction(app, t.token(org)):
                record_tenant_event(app, t.crypto, contact=phone, event_type="suppress", channels=["sms"], purposes=["*"],
                                    method="written", origin="consumer", source="erasure", recorded_by=marker)

    def seed_invite(self, t, admin_app, mailer) -> dict:
        """An invitation to erin@alpha.test into alpha, sent by alpha's admin through the real route (the mailer records the
        link token the way the mail would have carried it)."""
        from consentvault.tenancy.admin_base import ROLE_SCOPES
        from consentvault.tenancy.admin_routes import Request
        from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX

        with t.superuser() as su:
            mid = su.execute("SELECT member_id FROM consentvault.member WHERE org_id = %s AND role = 'admin' LIMIT 1",
                             (t.a.org_id,)).fetchone()["member_id"]
        tok = mint_org_token(t.key, t.a.org_id, ROLE_SCOPES["admin"], credential_id=MEMBER_CREDENTIAL_PREFIX + str(mid))
        r = admin_app.handle(Request("POST", "/v1/members", {}, {"email": "erin@alpha.test", "role": "compliance_viewer"},
                                     tenant_token=tok, request_id="e2e-invite"))
        if r.status != 201:
            raise RuntimeError(f"the seeded invitation was not made: {r.status} {r.body}")
        return {"token": mailer.token_for("erin@alpha.test"), "email": "erin@alpha.test", "org_id": str(t.a.org_id)}

    def start_edge(self, edge_port: int, api_port: int, stub_port: int, public_url: str) -> None:
        a = self.args
        out = REPO / "portal/app/out"
        if not (out / "index.html").exists():
            raise RuntimeError(f"{out} is missing: run `npx next build` in portal/app first")
        cfg = self.root / "edge"
        cfg.mkdir()
        (cfg / "wrangler.toml").write_text(f"""name = "cv-portal-e2e"
main = "{REPO}/edge/src/portal.ts"
compatibility_date = "2026-01-01"

[assets]
directory = "{out}"
binding = "ASSETS"
run_worker_first = ["/auth/*", "/v1/*"]

[[kv_namespaces]]
binding = "SESSIONS"
id = "e2e-sessions"

[[durable_objects.bindings]]
name = "SESSION_GATE"
class_name = "SessionGate"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["SessionGate"]

[vars]
ORIGIN_URL = "http://127.0.0.1:{api_port}"
ACCESS_CLIENT_ID = "local-access-id"
AUTH_BASE_URL = "http://127.0.0.1:{stub_port}/user_management"
AUTH_CLIENT_ID = "{CLIENT_ID}"
PUBLIC_URL = "{public_url}"
""", encoding="utf-8")
        (cfg / ".dev.vars").write_text(f"ACCESS_CLIENT_SECRET=local-access-value\nAUTH_CLIENT_SECRET={CLIENT_SECRET}\nASSERTION_KEY_JWK={self.edge_jwk}\n", encoding="utf-8")
        os.chmod(cfg / ".dev.vars", 0o600)
        env = {**os.environ, "WRANGLER_SEND_METRICS": "false", "CI": "1", "NO_COLOR": "1"}
        self.edge = subprocess.Popen(
            [a.wrangler, "dev", "--config", str(cfg / "wrangler.toml"), "--local", "--ip", "127.0.0.1", "--port", str(edge_port),
             "--persist-to", str(cfg / "state"), "--log-level", "warn"],
            cwd=str(cfg), env=env, stdout=open(self.root / "edge.log", "wb"), stderr=subprocess.STDOUT, start_new_session=True)
        try:
            wait_http(f"{public_url}/sign-in", "the portal edge (wrangler dev)", 120)
        except RuntimeError:
            log((self.root / "edge.log").read_text(errors="replace")[-3000:])
            raise

    # ---- teardown -------------------------------------------------------------------------------------------------
    def stop(self) -> None:
        problems: list[str] = []
        if self.edge is not None and self.edge.poll() is None:
            os.killpg(self.edge.pid, signal.SIGTERM)
            try:
                self.edge.wait(timeout=15)
            except subprocess.TimeoutExpired:  # loud-failure-exempt: escalates to SIGKILL on the next line, whose wait raises if it fails
                os.killpg(self.edge.pid, signal.SIGKILL)
                self.edge.wait(timeout=10)
        if self.stub is not None and self.stub.poll() is None:
            self.stub.terminate()
            try:
                self.stub.wait(timeout=10)
            except subprocess.TimeoutExpired:  # loud-failure-exempt: escalates to kill on the next line, whose wait raises if it fails
                self.stub.kill()
                self.stub.wait(timeout=10)
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            if self.thread:
                self.thread.join(timeout=10)
        try:
            self.stop_pg()
        except subprocess.CalledProcessError as exc:  # loud-failure-exempt: recorded in problems and raised at the end of stop()
            problems.append(f"postgres: {exc.stderr!r}")
        shutil.rmtree(self.root, ignore_errors=True)
        if problems:
            raise RuntimeError("; ".join(problems))


def _jwk_private(key) -> str:
    """A P-256 private key as a JWK (d, x, y), the form the edge Worker imports."""
    import base64

    n = key.private_numbers()
    b = lambda v: base64.urlsafe_b64encode(v.to_bytes(32, "big")).rstrip(b"=").decode()  # noqa: E731
    return json.dumps({"kty": "EC", "crv": "P-256", "x": b(n.public_numbers.x), "y": b(n.public_numbers.y), "d": b(n.private_value)})


class _Mailer:
    """Sends nothing: keeps the invitation link tokens the mail would have carried."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send_invite(self, **kw) -> None:
        self.sent.append(kw)

    def token_for(self, email: str) -> str:
        return [m for m in self.sent if m["to"] == email][-1]["token"]


def watch_parent(stop: threading.Event) -> None:
    """Stop the stack when its standard input closes (the parent exited or let go). Reads the raw descriptor, blocking,
    because a pipe a parent shares can arrive non-blocking."""
    try:
        os.set_blocking(0, True)
        while os.read(0, 4096):
            pass
    finally:
        stop.set()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--wrangler", default=os.environ.get("WRANGLER", "wrangler"), help="the wrangler executable (default: $WRANGLER or PATH)")
    ap.add_argument("--node", default=shutil.which("node") or "node")
    args = ap.parse_args()
    stack = Stack(args)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    code = 0
    try:
        ready = stack.run()
        print(json.dumps({"ready": ready}), flush=True)
        threading.Thread(target=watch_parent, args=(stop,), daemon=True).start()
        stop.wait()
    except Exception as exc:  # loud-failure-exempt: named on stderr with a non-zero exit, after teardown below
        log(f"stack failed: {type(exc).__name__}: {exc}")
        code = 1
    finally:
        try:
            stack.stop()
        except Exception as exc:  # loud-failure-exempt: teardown trouble is named on stderr and fails the exit code
            log(f"teardown problem: {exc}")
            code = code or 2
    return code


if __name__ == "__main__":
    sys.exit(main())
