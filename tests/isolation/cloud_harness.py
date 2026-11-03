"""The multi-tenant API over the two synthetic organisations of ``harness.py``, as a client would reach it.

Each organisation gets the channels and purposes an operator provisions, four machine credentials with real keys
(capture ES256, capture_verified EdDSA, gate_read ES256, proof_read EdDSA), and wording naming every channel and
purpose. Organisation A has an approved policy; B has none until a test approves one.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from consentvault import api, disclosure as disc
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.oauth import AccessTokenSigner, make_client_assertion
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from .harness import Org, Tenancy

TOKEN_URL = "https://api.consentvault.test/v1/oauth/token"
CHANNELS = ("sms", "voice", "artificial_voice", "email")
PURPOSES = ("marketing", "billing")


def policy_rules(narrowing=None, proceed_found=True) -> dict:
    cells = []
    for ch in CHANNELS:
        for st in ("consent_record_found", "stop_on_record", "no_record", "record_incomplete", "unavailable"):
            action = "proceed" if (st == "consent_record_found" and proceed_found) else "hold"
            cells.append({"evidence_status": st, "channel": ch, "action": action})
    rules = {"schema_version": 1, "purposes": {p: {"cells": cells, "checklist_version": None} for p in PURPOSES}}
    if narrowing is not None:
        rules["narrowing"] = narrowing
    return rules


@dataclass
class Client:
    credential_id: str
    alg: str
    key: object
    scopes: tuple[str, ...]


@dataclass
class CloudOrg:
    org: Org
    clients: dict[str, Client] = field(default_factory=dict)
    wording: str = ""
    policy_version: int | None = None


def _pem(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def add_credential(t: Tenancy, org: Org, scope: str, alg: str) -> Client:
    key = ec.generate_private_key(ec.SECP256R1()) if alg == "ES256" else ed25519.Ed25519PrivateKey.generate()
    with t.operator() as o, org_transaction(o, t.admin_token(org.org_id)):
        cid = o.execute(
            "INSERT INTO consentvault.credential (org_id, source_id, kind, alg, public_key, scope)"
            " VALUES (%s, %s, 'jwt_public_key', %s, %s, %s) RETURNING credential_id",
            (org.org_id, org.source_id, alg, _pem(key.public_key()), [scope])).fetchone()["credential_id"]
    return Client(str(cid), alg, key, (scope,))


def approve_policy(t: Tenancy, org: Org, rules: dict, version: int = 1) -> int:
    member = uuid.uuid4()
    with t.operator() as o, org_transaction(o, t.admin_token(org.org_id)):
        o.execute("UPDATE consentvault.policy SET status = 'retired', retired_at = now(), retired_by_version = %s"
                  " WHERE org_id = %s AND status = 'approved'", (version, org.org_id))
        o.execute("INSERT INTO consentvault.policy (org_id, version, rules, status, approved_by, approved_at)"
                  " VALUES (%s, %s, %s, 'approved', %s, now())", (org.org_id, version, json.dumps(rules), member))
        o.execute("INSERT INTO consentvault.policy_approval (org_id, version, approved_by, attestation_version,"
                  " attestation_sha256) SELECT %s, %s, %s, version, sha256 FROM consentvault.attestation_text"
                  " ORDER BY version DESC LIMIT 1", (org.org_id, version, member))
    return version


def provision(t: Tenancy, org: Org) -> CloudOrg:
    co = CloudOrg(org)
    with t.operator() as o, org_transaction(o, t.admin_token(org.org_id)):
        for ch in CHANNELS:
            o.execute("INSERT INTO consentvault.channel (org_id, channel, label) VALUES (%s, %s, %s)",
                      (org.org_id, ch, ch))
        for p in PURPOSES:
            o.execute("INSERT INTO consentvault.purpose (org_id, purpose, label) VALUES (%s, %s, %s)",
                      (org.org_id, p, p))
    with t.app() as app, org_transaction(app, t.token(org)):
        co.wording = disc.register(app, f"{org.name} may text and call you about offers. Reply STOP to end.",
                                   f"{org.name}-offers", "en", list(CHANNELS), list(PURPOSES))
    co.clients["capture"] = add_credential(t, org, "capture", "ES256")
    co.clients["capture_verified"] = add_credential(t, org, "capture_verified", "EdDSA")
    co.clients["gate_read"] = add_credential(t, org, "gate_read", "ES256")
    co.clients["proof_read"] = add_credential(t, org, "proof_read", "EdDSA")
    return co


class Cloud:
    def __init__(self, t: Tenancy, evidence_dir: str, **settings_extra):
        self.t = t
        self.access = AccessTokenSigner.generate(key_id="at-test", issuer="https://api.consentvault.test")
        self.receipts = ReceiptSigner.generate(key_id="rcpt-test")
        self.store = LocalAppendOnlyEvidenceStore(evidence_dir)
        self.settings = api.CloudApiSettings(
            dsn=t.app_dsn, token_key=t.key, access_tokens=self.access, receipts=self.receipts, crypto=t.crypto,
            evidence_store=self.store, token_endpoint_url=TOKEN_URL, cursor_key=os.urandom(32),
            allowed_hosts=("127.0.0.1",), default_retain_years=7, region="US", **settings_extra)
        self.a = provision(t, t.a)
        self.b = provision(t, t.b)
        self.a.policy_version = approve_policy(t, t.a, policy_rules())
        self.server = api.make_cloud_server(self.settings, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)

    def call(self, path: str, body=None, *, token: str | None = None, form: dict | None = None,
             headers: dict | None = None) -> tuple[int, dict]:
        h = dict(headers or {})
        if form is not None:
            data = urllib.parse.urlencode(form).encode("ascii")
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode("utf-8") if body is not None else b""
            h["Content-Type"] = "application/json"
        if token:
            h["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.base + path, data=data, method="POST", headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                out = r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:  # loud-failure-exempt: a non-2xx answer is returned to the test to assert on
            out = e.code, json.loads(e.read())
        self.server.drain(30)  # the work that follows an answer (reading the post, alarms, the transitional event) is done
        if path == "/v1/events" and out[0] == 201 and out[1].get("stored"):
            with self.t.superuser() as su:  # the event this post was derived into, when it was (the link table is the record)
                ev = su.execute("SELECT event_id FROM consentvault.event_source_post WHERE post_id = %s", (out[1]["post_id"],)).fetchone()
            if ev is not None:
                out[1]["event_id"] = str(ev["event_id"])
        return out

    def assertion(self, client: Client, **kw) -> str:
        return make_client_assertion(client.key, alg=client.alg, client_id=client.credential_id, audience=TOKEN_URL,
                                     **kw)

    def token_form(self, client: Client, scope: str | None = None, **kw) -> dict:
        form = {"grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": self.assertion(client, **kw)}
        if scope is not None:
            form["scope"] = scope
        return form

    def token(self, co: CloudOrg, which: str) -> str:
        status, body = self.call("/v1/oauth/token", form=self.token_form(co.clients[which]))
        assert status == 200, body
        return body["access_token"]

    def grant(self, co: CloudOrg, contact: str, *, token: str | None = None, **extra) -> tuple[int, dict]:
        body = {"contact": contact, "event_type": "grant", "checked": True, "channels": ["sms"],
                "purposes": ["marketing"], "disclosure_sha256": co.wording, "brand_ids": [str(co.org.brand_id)],
                "session_ref": "s-1", "page_url": "https://example.test/signup", **extra}
        return self.call("/v1/events", body, token=token or self.token(co, "capture"))

    def gate(self, co: CloudOrg, contact: str, channel="sms", purpose="marketing", token=None) -> tuple[int, dict]:
        return self.call("/v1/permission", {"contact": contact, "channel": channel, "purpose": purpose},
                         token=token or self.token(co, "gate_read"))

    def proof(self, co: CloudOrg, contact: str, page=None, token=None) -> tuple[int, dict]:
        body = {"contact": contact} if page is None else {"contact": contact, "page": page}
        return self.call("/v1/proof", body, token=token or self.token(co, "proof_read"))


def without(answer: dict, *keys: str) -> dict:
    return {k: v for k, v in answer.items() if k not in keys}


def raw_posts(t: Tenancy, org_id) -> list:
    """The raw posts of one organisation, oldest first (an out-of-band read)."""
    with t.superuser() as su:
        return su.execute("SELECT * FROM consentvault.raw_post WHERE org_id = %s ORDER BY seq", (org_id,)).fetchall()


def _post_key(t: Tenancy, org_id, post_id):
    from consentvault.tenancy.keys_protocol import WrappedKey

    with t.superuser() as su:
        k = su.execute("SELECT post_key_wrapped, key_version FROM consentvault.raw_post_key WHERE org_id = %s AND post_id = %s",
                       (org_id, post_id)).fetchone()
    return None if k is None else t.crypto.open_contact_key(org_id, WrappedKey(bytes(k["post_key_wrapped"]), k["key_version"]))


def post_body(t: Tenancy, row) -> bytes:
    """The decrypted body of an inline raw post row."""
    from consentvault.tenancy import crypto as tc

    key = _post_key(t, row["org_id"], row["post_id"])
    blob = bytes(row["body_ct"])
    return blob if key is None else tc.decrypt_field(key, row["org_id"], str(row["post_id"]), "raw_post.body", blob)


def facts_of(t: Tenancy, row) -> dict:
    """Every fact stored beside a raw post, name to value (a name stored twice keeps the last)."""
    from consentvault.tenancy import crypto as tc

    key = _post_key(t, row["org_id"], row["post_id"])
    with t.superuser() as su:
        found = su.execute("SELECT name, value_ct FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s"
                           " ORDER BY recorded_at", (row["org_id"], row["post_id"])).fetchall()
    return {f["name"]: json.loads(bytes(f["value_ct"]) if key is None else
                                  tc.decrypt_field(key, row["org_id"], str(row["post_id"]), "raw_post_fact.value", bytes(f["value_ct"])))
            for f in found}
