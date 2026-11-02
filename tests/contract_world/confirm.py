"""Seams and fakes for the confirmation-message contract.

Seams are those of confirmations.md section 13; request bodies are those of section 12.
  consentvault.confirm.ConfirmationService(connect, token_key, custody, providers, dns, clock, jitter)
      .handle_inbound / .handle_public / .run_sender(now) / .recheck_link_hosts(now) / .run_alarm_checks(now) / .purge(now)
  consentvault.confirm.ProviderError(kind, code); consentvault.confirm.texts.FIXED_TEXT_VERSION
Still assumed (the contract names no mounting point): AdminApp(..., confirmations=<service>, evidence_store=<store>)
(Telnyx is out of scope, so there is no Telnyx fake).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from consentvault import db
from consentvault.tenancy.admin_routes import AdminApp

from .world import PHONE, need

OUR_NUMBER = "+15555550100"
INBOUND_BASE = "https://api.consentvault.ai/v1/confirmations/inbound/"


class Clock:
    def __init__(self, start: datetime | None = None):
        self.now = start or datetime(2026, 11, 3, 15, 0, tzinfo=timezone.utc)  # a Tuesday, 10:00 in New York

    def __call__(self):
        return self.now.timestamp()  # epoch seconds (a float): the one clock handed to the service and the admin app

    def advance(self, **kw):
        self.now += timedelta(**kw)

    def set(self, dt):
        self.now = dt


@dataclass
class FakeTwilio:
    """A fake Twilio: records sends, signs inbound requests, can be told to refuse or time out."""
    auth_token: str = "twilio-auth-token-secret"
    api_key_secret: str = "twilio-api-key-secret"
    numbers: tuple = (OUR_NUMBER,)
    inbound_pointed_at: str | None = None
    sent: list = field(default_factory=list)
    script: list = field(default_factory=list)  # outcomes for the next sends: "ok", ("retry", code), ("refuse", code)
    unreachable: bool = False
    used_auth_token_to_call: int = 0
    name: str = "twilio"
    unknown_messages: set = field(default_factory=set)  # inbound message ids the provider does not know
    asked_about: list = field(default_factory=list)

    def message_exists(self, creds, *, message_id, from_number):
        """The provider's own record of an inbound message (confirmations.md section 7: a START is confirmed before it lifts a stop)."""
        self.asked_about.append((message_id, from_number))
        return message_id not in self.unknown_messages

    def read_sender(self, creds):
        if self.unreachable:
            raise TimeoutError("twilio unreachable")
        return {"numbers": list(self.numbers), "inbound_webhook": self.inbound_pointed_at}

    def send(self, creds, *, to, body, sender, status_callback):
        if creds.get("auth_token_used"):
            self.used_auth_token_to_call += 1
        outcome = self.script.pop(0) if self.script else "ok"
        self.sent.append({"to": to, "body": body, "from": sender, "status_callback": status_callback, "outcome": outcome,
                          "creds": creds})
        if outcome == "ok":
            return {"provider_message_id": "SM" + uuid.uuid4().hex[:30], "status": "queued"}
        raise _provider_error(*outcome)

    def sign(self, url: str, params: dict) -> str:
        data = url + "".join(k + params[k] for k in sorted(params))
        return base64.b64encode(hmac.new(self.auth_token.encode(), data.encode(), hashlib.sha1).digest()).decode()


def _provider_error(kind, code):
    return need("consentvault.confirm", "ProviderError")(kind, code)


@dataclass
class FakeEmail:
    verified_domains: tuple = ("example.com", "acme.example", "bravo.example")
    sent: list = field(default_factory=list)
    script: list = field(default_factory=list)

    def domain_verified(self, creds, domain):
        return domain in self.verified_domains

    def send(self, creds, *, to, subject, body, headers, sender):
        outcome = self.script.pop(0) if self.script else "ok"
        self.sent.append({"to": to, "subject": subject, "body": body, "headers": headers, "from": sender, "outcome": outcome})
        if outcome == "ok":
            return {"provider_message_id": "pm-" + uuid.uuid4().hex[:12]}
        raise _provider_error(*outcome)


@dataclass
class FakeDns:
    records: dict = field(default_factory=dict)

    def lookup(self, host, kind):
        return self.records.get((host, kind))


@dataclass
class Stack:
    world: object
    app: AdminApp
    service: object
    twilio: FakeTwilio
    email: FakeEmail
    dns: FakeDns
    clock: Clock

    # ---- raw doors ----------------------------------------------------------------------------------------------------
    def inbound(self, inbound_key: str, params: dict, *, url: str | None = None, headers: dict | None = None, sign_url: str | None = None):
        url = url or INBOUND_BASE + inbound_key
        h = {"X-Twilio-Signature": self.twilio.sign(sign_url or url, params), **(headers or {})}
        body = urllib.parse.urlencode(params).encode()
        return self.service.handle_inbound(inbound_key, headers=h, body=body, url=url)

    def advance(self, **kw):
        """Move the one shared clock (service and admin app)."""
        self.clock.advance(**kw)  # the app reads this same clock (build_stack)

    def alarms(self, admin):
        return {a["kind"]: a for a in admin.ok("GET", "/v1/confirmations/settings").get("alarms", [])}

    def public(self, method, path, host, body=b"", headers=None):
        return self.service.handle_public(method, path, host=host, headers=headers or {}, body=body)

    def run(self, **advance):
        if advance:
            self.clock.advance(**advance)
        return self.service.run_sender(now=self.clock())


def build_stack(world, **kw) -> Stack:
    world = getattr(world, '_get', lambda: world)()
    if getattr(world, "stack_built", False):
        import pytest
        pytest.fail("a second stack was built for this world: use the stack fixture, or build one stack in the test", pytrace=False)
    svc_cls = need("consentvault.confirm", "ConfirmationService")
    vault = world.vault
    twilio, email, dns, clock = FakeTwilio(), FakeEmail(), FakeDns(), Clock()
    service = svc_cls(connect=lambda: db.connect(vault.app_dsn), token_key=vault.key, custody=vault.custody,
                      providers={"twilio": twilio, "ses": email, "postmark": email}, dns=dns, clock=clock,
                      jitter=kw.get("jitter", lambda: 0.0))
    app = AdminApp(connect=lambda: db.connect(vault.app_dsn), owner_connect=lambda: db.connect(vault.operator_dsn),
                   token_key=vault.key, sessions=vault.sessions, custody=vault.custody, mailer=vault.mailer,
                   confirmations=service, evidence_store=world.store,
                   clock=clock)  # ONE clock: the same callable, epoch seconds, goes to the service and the app
    vault.app = app
    world.stack_built = True
    return Stack(world, app, service, twilio, email, dns, clock)


# ---- configuration helpers (the request field names are the tests' assumption) --------------------------------------------
def set_sender(admin, **kw):
    body = {"organization_name": "Acme Flooring", "postal_address": "1 Main St, Tampa FL 33601",
            "help_contact": {"email": "help@acme.example", "phone": "+18135550100"}, **kw}
    return admin.ok("PUT", "/v1/confirmations/settings", body=body)


def connect_twilio(stack, admin, *, provider_replies_itself=False):
    acct = admin.ok("POST", "/v1/confirmations/sending-accounts", body={
        "channel": "sms", "provider": "twilio",
        "credentials": {"account_sid": "AC" + "0" * 32, "api_key_sid": "SK" + "0" * 32, "api_key_secret": stack.twilio.api_key_secret, "auth_token": stack.twilio.auth_token},
        "sender": {"number": OUR_NUMBER}, "provider_replies_itself": provider_replies_itself})
    return acct


def verify_inbound(stack, acct, *, from_number="+15555550177"):
    key = acct["inbound_url"].rsplit("/", 1)[1]
    r = stack.inbound(key, {"From": from_number, "To": OUR_NUMBER, "Body": "test", "MessageSid": "SMtest" + uuid.uuid4().hex[:8]})
    assert r.status == 200, (r.status, r.payload)
    return key


def connect_email(stack, admin, address="hello@example.com"):
    return admin.ok("POST", "/v1/confirmations/sending-accounts", body={
        "channel": "email", "provider": "ses", "credentials": {"access_key": "k", "secret": "s"},
        "from": {"email_address": address, "display_name": "Acme"}})


def set_link_host(stack, admin, host="consent.example.com"):
    admin.ok("POST", "/v1/confirmations/link-host", body={"host": host})
    stack.dns.records[(host, "CNAME")] = "edge.consentvault.ai"
    got = admin.ok("GET", "/v1/confirmations/settings")["link_host"]
    stack.dns.records[(host, "TXT")] = got["txt_record"]
    return admin.ok("POST", "/v1/confirmations/link-host:verify", body={})


def mark_registered(admin):
    return admin.ok("POST", "/v1/confirmations/texting-registration",
                    body={"kind": "10dlc", "reference": "CMP123", "accepted": True, "samples_included": True})


def enable_rule(admin, source_id, channel, brand_id, **kw):
    body = {"enabled": True, "sending_brand_id": brand_id, **kw}
    return admin.ok("PUT", f"/v1/confirmations/rules/{source_id}/{channel}", body=body)


@dataclass
class Armed:
    stack: Stack
    org: object
    twilio_key: str


def arm(stack, org, *, email=True, text=True, provider_replies_itself=False, host="consent.example.com", **rule_kw) -> Armed:
    """Everything a confirmation needs: sender details, link host, text account verified and registered, rules on."""
    a = org.boss
    set_sender(a)
    set_link_host(stack, a, host)
    key = ""
    if text:
        acct = connect_twilio(stack, a, provider_replies_itself=provider_replies_itself)
        key = verify_inbound(stack, acct)
        mark_registered(a)
        enable_rule(a, org.web_id, "sms", org.brand_id, **rule_kw)
    if email:
        connect_email(stack, a)
        enable_rule(a, org.web_id, "email", org.brand_id, **rule_kw)
    return Armed(stack, org, key)


def sends(admin, **q):
    return admin.ok("GET", "/v1/confirmations/sends", {k: str(v) for k, v in q.items()})["items"]


def replies(admin, **q):
    return admin.ok("GET", "/v1/confirmations/replies", {k: str(v) for k, v in q.items()})["items"]


def text_in(armed, body, *, sender=PHONE, sid=None):
    return armed.stack.inbound(armed.twilio_key, {"From": sender, "To": OUR_NUMBER, "Body": body,
                                                  "MessageSid": sid or "SM" + uuid.uuid4().hex[:30]})
