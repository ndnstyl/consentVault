"""The configuration side of confirmations (confirmations.md sections 1 to 4, 6 and 12): sending accounts, settings, the wording
link host, texting registration, rules, templates, preview and the test message.

Every function takes the request's ``Ctx`` (a connection already inside the caller's tenant, the caller, the request id). The
route table checks the role first; the bodies are checked in the pinned order: role, then body shape (naming every bad field),
then ownership of the objects the body names, then state (the prerequisites). A route's refusals therefore never depend on which
of several things is wrong first.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

import psycopg
from psycopg.types.json import Jsonb

from .. import testing
from ..errors import NormalizationError
from ..tenancy.admin_base import (ROLE_ADMIN, ApiError, Ctx, body_dict, invalid, iso, need_text, require_can_add)
from ..tenancy.errors import KeyProviderError as TenantKeyError
from ..tenancy.records_admin import region_of
from . import texts, zones
from .core import ALL_CHANNELS, KEY_ERRORS, STOP_CHANNELS, ProviderError, SECRET_FIELD, log

SENDER_KEYS = {"organization_name", "postal_address", "help_contact", "send_cap_per_hour"}
RULE_KEYS = {"enabled", "sending_brand_id", "template_id", "send_for_test_events", "dedupe_hours", "max_delay_minutes"}
TWILIO_CREDENTIALS = ("account_sid", "api_key_sid", "api_key_secret", "auth_token")
CREDENTIAL_KEYS = {"twilio": set(TWILIO_CREDENTIALS), "ses": {"access_key", "secret", "region"}, "postmark": {"server_token", "account_token"}}
SES_REGIONS = ("us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
               "eu-north-1", "eu-south-1", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1",
               "ap-southeast-2", "sa-east-1", "af-south-1", "me-south-1")
EMAIL_CREDENTIALS = {"ses": ("access_key", "secret"), "postmark": ("server_token",)}  # required; account_token is optional and sealed
PROVIDERS = {"sms": ("twilio",), "email": ("ses", "postmark")}
E164 = re.compile(r"^\+[0-9]{7,15}$")
HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SERVICE_ID = re.compile(r"^[A-Za-z0-9]{10,64}$")
ALARM_KINDS = ("inbound_signature_failures", "replies_unread_24h", "delivery_reports_stale", "link_host_failing", "optout_reply_dead",
               "provider_refusal_stop", "sending_account_failing", "send_cap_reached", "send_outcome_unknown")
SEND_CAP_DEFAULT = 500
TEST_SENDS_PER_HOUR = 5
NO_SENDER = {"organization_name": None, "postal_address": None, "help_contact": {"email": None, "phone": None}}


def strict(body: Any, allowed: set[str]) -> dict:
    b = body_dict(body)
    extra = sorted(set(b) - allowed)
    if extra:
        raise ApiError("validation_failed", "the body has fields this call does not take", {k: "not accepted" for k in extra})
    return b


def is_int(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def uuid_text(v: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(v) if isinstance(v, str) else None
    except ValueError:
        return None


class ConfigMixin:
    # ---- provider answers become API answers ----------------------------------------------------------------------------------
    def _provider(self, fn):
        try:
            return fn()
        except ProviderError as exc:
            if exc.kind == "retry":
                raise ApiError("provider_unreachable", "the sending provider did not answer; nothing was sent or changed") from None
            raise ApiError("provider_refused", "the sending provider refused", {"provider_code": str(exc.code)}) from None
        except (TimeoutError, OSError):
            raise ApiError("provider_unreachable", "the sending provider did not answer; nothing was sent or changed") from None

    @staticmethod
    def _check_credential_keys(provider: str, creds: dict) -> None:
        """Only the keys a provider's credentials have are accepted (every unknown key is refused by name), every value is text, and
        an SES region must be one of the allowlist, so a body cannot steer a call to another host or carry a stray secret."""
        extra = sorted(set(creds) - CREDENTIAL_KEYS[provider])
        if extra:
            raise ApiError("validation_failed", "the credentials have fields this provider does not take",
                           {"credentials": ", ".join(extra) + " not accepted"})
        if any(not isinstance(v, str) or len(v) > 300 for v in creds.values()):
            raise ApiError("validation_failed", "every credential is text of at most 300 characters", {"credentials": "text only"})
        if "region" in creds and creds["region"] not in SES_REGIONS:
            raise ApiError("validation_failed", "that region is not one SES is used in here", {"credentials": "region not allowed"})

    def _adapter(self, provider: str):
        adapter = self._providers.get(provider)
        if adapter is None:
            raise ApiError("provider_not_supported", "that provider is not supported for this channel")
        return adapter

    # ---- settings ------------------------------------------------------------------------------------------------------------
    def get_settings(self, ctx: Ctx) -> dict:
        conn, org = ctx.conn, ctx.org_id()
        s, reg, host = self._settings_row(conn), self._registration_row(conn), self._link_host_row(conn)
        have = self._org_channels(conn)
        accounts = conn.execute(
            "SELECT * FROM (SELECT org_id, account_id, channel, provider, status, from_email, from_display_name, sender_id, number_hint,"
            " inbound_url, provider_replies, inbound_verified_at, last_check, created_at FROM consentvault.sending_account) a"
            " WHERE a.org_id = %s ORDER BY (a.status = 'disconnected'), a.created_at DESC, a.account_id", (org,)).fetchall()
        alarms = conn.execute("SELECT kind, opened_at, detail FROM consentvault.org_alarm WHERE org_id = %s AND cleared_at IS NULL"
                              " AND kind = ANY(%s) ORDER BY opened_at, kind", (org, list(ALARM_KINDS))).fetchall()
        return {
            "version": s["version"] if s else 0,
            "sender": ({"organization_name": s["organization_name"], "postal_address": s["postal_address"],
                        "help_contact": {"email": s["help_email"], "phone": s["help_phone"]}} if s else NO_SENDER),
            "send_cap_per_hour": s["send_cap_per_hour"] if s else SEND_CAP_DEFAULT,
            "link_host": self._link_host_obj(host),
            "stop_scopes": {"text_reply": [c for c in STOP_CHANNELS if c in have], "email_link": ["email"],
                            "email_link_everything": [c for c in ALL_CHANNELS if c in have]},
            "texting_registration": self._registration_obj(reg),
            "fixed_text_version": texts.FIXED_TEXT_VERSION,
            "fixed_texts": self._fixed_texts(s),
            "sending_accounts": [self._account_obj(a) for a in accounts],
            "counts": self._counts(ctx, org),
            "alarms": [{"kind": a["kind"], "opened_at": iso(a["opened_at"]), "detail": a["detail"]} for a in alarms],
        }

    def _link_host_obj(self, host: Optional[dict]) -> dict:
        if host is None:
            return {"host": None, "status": "unset", "txt_record": None, "cname_target": None, "verified_at": None}
        return {"host": host["host"], "status": host["status"], "txt_record": host["txt_value"], "cname_target": self._edge_cname,
                "verified_at": iso(host["verified_at"]) if host["verified_at"] else None}

    @staticmethod
    def _fixed_texts(s: Optional[dict]) -> dict:
        """The four fixed texts as the sender builds them (the same functions), with the places a message fills in left as
        <placeholders>; the HELP text carries the organization's own help contact once it has one."""
        brand = "<Sending brand>"
        email = s["help_email"] if s else "<help email>"
        phone = s["help_phone"] if s else None
        return {"version": texts.FIXED_TEXT_VERSION, "items": [
            {"kind": "confirmation", "text": texts.sms_confirmation(brand, "<date and time>", texts.channel_words(("sms", "voice")),
                                                                      "<purposes>", "<link>")},
            {"kind": "optout_reply", "text": texts.optout_reply(brand)},
            {"kind": "help_reply", "text": texts.help_reply(brand, email, phone)},
            {"kind": "start_reply", "text": texts.start_reply(brand)}]}

    def _registration_obj(self, reg: Optional[dict]) -> dict:
        if reg is None or reg["status"] != "marked":
            return {"status": "not_marked", "kind": None, "reference": None, "samples_statement_version": None,
                    "marked_by": None, "marked_at": None}
        stale = reg["samples_statement_version"] != texts.FIXED_TEXT_VERSION
        return {"status": "not_marked" if stale else "marked", "kind": reg["kind"], "reference": reg["reference"],
                "samples_statement_version": reg["samples_statement_version"], "marked_by": str(reg["marked_by"]),
                "marked_at": iso(reg["marked_at"]), **({"stale": True} if stale else {})}

    def _account_obj(self, a: dict) -> dict:
        sms = a["channel"] == "sms"
        return {"account_id": str(a["account_id"]), "channel": a["channel"], "provider": a["provider"], "status": a["status"],
                "from": ({"sender_id": a["sender_id"], "number_hint": a["number_hint"]} if sms
                         else {"email_address": a["from_email"], "display_name": a["from_display_name"]}),
                "inbound_url": a["inbound_url"], "provider_replies": a["provider_replies"],
                "inbound_verified_at": iso(a["inbound_verified_at"]), "last_check": a["last_check"],
                "created_at": iso(a["created_at"])}

    def _counts(self, ctx: Ctx, org) -> Optional[dict]:
        """The counts on screen 25, or None when any of them cannot be read: a count that failed is never 0."""
        if "confirmations.counts" in testing.fail_reads:
            return None
        at = self._when(ctx.conn)
        day, hour = at - timedelta(hours=24), at - timedelta(hours=1)
        try:
            with ctx.conn.transaction():
                c = ctx.conn.execute(
                    "SELECT count(*) FILTER (WHERE status IN ('sent', 'delivered') AND at > %s) AS sent_24h,"
                    " count(*) FILTER (WHERE status = 'failed' AND at > %s) AS failed_24h,"
                    " count(*) FILTER (WHERE status = 'dead' AND at > %s) AS dead_24h,"
                    " count(*) FILTER (WHERE provider_refusal_stop AND at > %s) AS refusal_stops"
                    " FROM consentvault.confirmation_send_intent WHERE org_id = %s", (day, day, day, day, org)).fetchone()
                r = ctx.conn.execute("SELECT count(*) AS n, min(received_at) AS oldest FROM consentvault.confirmation_reply"
                                     " WHERE org_id = %s AND state = 'to_read'", (org,)).fetchone()
                f = ctx.conn.execute("SELECT count(*) AS n FROM consentvault.confirmation_inbound_failure WHERE org_id = %s AND at > %s",
                                     (org, hour)).fetchone()
                last_at, stale = self._delivery_state(ctx.conn, org, at)
        except psycopg.Error:  # loud-failure-exempt: the whole block of counts is null in the answer (confirmations.md section 2)
            log.error("the confirmation counts could not be read")
            return None
        return {"sent_24h": c["sent_24h"], "failed_24h": c["failed_24h"], "dead_24h": c["dead_24h"], "to_read": r["n"],
                "to_read_oldest_at": iso(r["oldest"]), "provider_refusal_stops_24h": c["refusal_stops"],
                "inbound_signature_failures_1h": f["n"], "delivery_reports": {"last_at": iso(last_at), "stale": stale}}

    def _delivery_state(self, conn, org, at: datetime) -> tuple[Optional[datetime], bool]:
        """(when the newest text delivery report arrived, whether the reports have stopped): stale when a text was accepted more
        than 3 hours ago and no report has arrived since. Only texts report; email has no report door."""
        last = conn.execute("SELECT max(s.received_at) AS t FROM consentvault.confirmation_send_status s JOIN"
                            " consentvault.confirmation_send_intent i ON i.org_id = s.org_id AND i.send_id = s.send_id"
                            " WHERE s.org_id = %s AND i.channel = 'sms'", (org,)).fetchone()["t"]
        stale = conn.execute("SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND channel = 'sms'"
                             " AND provider_message_id IS NOT NULL AND last_attempt_at <= %s"
                             " AND (%s::timestamptz IS NULL OR %s::timestamptz < last_attempt_at) LIMIT 1",
                             (org, at - timedelta(hours=3), last, last)).fetchone() is not None
        return last, stale

    def put_settings(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, SENDER_KEYS)
        bad: dict = {}
        name, addr = b.get("organization_name"), b.get("postal_address")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 200:
            bad["organization_name"] = "required text, 1 to 200 characters"
        if not isinstance(addr, str) or not 1 <= len(addr.strip()) <= 300:
            bad["postal_address"] = "required text, 1 to 300 characters"
        help_ = b.get("help_contact")
        email = phone = None
        if not isinstance(help_, dict) or set(help_) - {"email", "phone"}:
            bad["help_contact"] = "an object with an email and, optionally, a phone in international form"
        else:
            email, phone = help_.get("email"), help_.get("phone")
            if not isinstance(email, str) or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()) or len(email) > 320:
                bad["help_contact"] = "a real email address is required"
            if phone is not None and (not isinstance(phone, str) or not E164.match(phone)):
                bad["help_contact"] = "the phone must be in international form like +18135550100"
        cap = b.get("send_cap_per_hour")
        if "send_cap_per_hour" in b and not is_int(cap, 1, 10000):
            bad["send_cap_per_hour"] = "a whole number from 1 to 10000"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        conn, org = ctx.conn, ctx.org_id()
        cur = self._settings_row(conn)
        if "send_cap_per_hour" not in b:
            cap = cur["send_cap_per_hour"] if cur else SEND_CAP_DEFAULT
        version = (cur["version"] if cur else 0) + 1
        conn.execute("INSERT INTO consentvault.confirmation_settings (org_id, version, organization_name, postal_address, help_email,"
                     " help_phone, send_cap_per_hour, created_by, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                     (org, version, name.strip(), addr.strip(), email.strip(), phone, cap, ctx.actor.member_uuid, self._dt(ctx.now())))
        ctx.audit("confirmations.settings_changed", "confirmations", "settings",
                  detail={"version": version, "send_cap_per_hour": cap})
        return self.get_settings(ctx)

    # ---- sending accounts ----------------------------------------------------------------------------------------------------
    def connect_account(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, {"channel", "provider", "credentials", "sender", "from", "provider_replies_itself"})
        channel, provider, creds = b.get("channel"), b.get("provider"), b.get("credentials")
        bad = {}
        if channel not in PROVIDERS:
            bad["channel"] = "sms or email"
        if not isinstance(provider, str) or not provider:
            bad["provider"] = "required"
        if not isinstance(creds, dict):
            bad["credentials"] = "an object"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        require_can_add(ctx)
        if provider not in PROVIDERS[channel]:
            raise ApiError("provider_not_supported", f"{provider} is not a supported {channel} provider")
        conn, org, now = ctx.conn, ctx.org_id(), self._dt(ctx.now())
        if self._live_account(conn, channel) is not None:
            raise ApiError("validation_failed", "a sending account is already connected for this channel; disconnect it first",
                           {"channel": "already connected"})
        account_id = uuid.uuid4()
        adapter = self._adapter(provider)
        if channel == "sms":
            row = self._connect_text(ctx, b, adapter, org, account_id, creds, now)
        else:
            row = self._connect_email(ctx, b, adapter, org, account_id, creds, now)
        ctx.audit("confirmations.account_connected", "sending_account", str(account_id),
                  detail={"channel": channel, "provider": provider})
        return self._account_obj(row)

    def _connect_text(self, ctx: Ctx, b: dict, adapter, org, account_id, creds: dict, now: datetime) -> dict:
        sender, replies_itself = b.get("sender"), b.get("provider_replies_itself", False)
        bad = {}
        if not isinstance(sender, dict) or set(sender) not in ({"number"}, {"messaging_service_sid"}):
            bad["sender"] = "exactly one of number or messaging_service_sid"
        elif "number" in sender and not (isinstance(sender["number"], str) and E164.match(sender["number"])):
            bad["sender"] = "the number must be in international form like +15555550100"
        elif "messaging_service_sid" in sender and not (isinstance(sender["messaging_service_sid"], str)
                                                         and SERVICE_ID.match(sender["messaging_service_sid"])):
            bad["sender"] = "not a messaging service id"
        if not isinstance(replies_itself, bool):
            bad["provider_replies_itself"] = "true or false"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        sid = creds.get("account_sid")
        if sid is not None and not (isinstance(sid, str) and re.fullmatch(r"AC[0-9a-f]{32}", sid)):
            raise ApiError("validation_failed", "the account id is AC followed by 32 hex characters", {"credentials": "account_sid"})
        probe = {k: v for k, v in creds.items() if k != "auth_token"}
        info = self._provider(lambda: adapter.read_sender({**probe, "sender": sender}))
        numbers = [n for n in info.get("numbers", []) if isinstance(n, str)]
        if not numbers or ("number" in sender and sender["number"] not in numbers):
            raise ApiError("validation_failed", "that sender has no number on this account", {"sender": "not on the account"})
        self._check_credential_keys("twilio", creds)
        missing = [k for k in TWILIO_CREDENTIALS if not isinstance(creds.get(k), str) or not creds[k]]
        if missing:
            raise ApiError("validation_failed", "the credentials are incomplete", {"credentials": ", ".join(missing) + " required"})
        creds = {k: v for k, v in creds.items() if k != "account_sid"}  # kept in its own clear column, not in the sealed ids
        sealed = self._seal_credentials(org, "twilio", creds, str(account_id))
        spec = {"numbers": numbers, **sender}
        key = secrets.token_urlsafe(32)
        hint = "***" + (sender.get("number") or numbers[0])[-4:]
        return ctx.conn.execute(
            "INSERT INTO consentvault.sending_account (org_id, account_id, channel, provider, status, sender_id, number_hint,"
            " sender_ct, inbound_key, inbound_url, provider_replies, replies_answered_by, replies_answered_at, credentials_ct,"
            " credential_ids_ct, auth_token_ct, created_by, created_at, account_sid) VALUES (%s, %s, 'sms', 'twilio', 'awaiting_test_reply',"
            " %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " RETURNING org_id, account_id, channel, provider, status, from_email, from_display_name, sender_id, number_hint,"
            " inbound_url, provider_replies, inbound_verified_at, last_check, created_at",
            (org, account_id, sender.get("messaging_service_sid") or "number:" + hint, hint,
             self._seal(org, str(account_id), "sender_ct", json.dumps(spec, sort_keys=True)), key,
             f"{self._api_base}/v1/confirmations/inbound/{key}",
             Jsonb({"stop": replies_itself, "help": replies_itself, "start": replies_itself}),
             ctx.actor.member_uuid, now, sealed[0], sealed[1], sealed[2], ctx.actor.member_uuid, now, sid)).fetchone()

    def _connect_email(self, ctx: Ctx, b: dict, adapter, org, account_id, creds: dict, now: datetime) -> dict:
        provider = b["provider"]
        sender = b.get("from")
        if not isinstance(sender, dict) or set(sender) != {"email_address", "display_name"} \
                or not isinstance(sender["email_address"], str) or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender["email_address"]) \
                or not isinstance(sender["display_name"], str) or not 1 <= len(sender["display_name"]) <= 200:
            raise ApiError("validation_failed", "a field is missing or malformed",
                           {"from": "an object with an email_address and a display_name"})
        if "sender" in b or "provider_replies_itself" in b:
            raise ApiError("validation_failed", "those fields belong to a text account",
                           {k: "not accepted" for k in ("sender", "provider_replies_itself") if k in b})
        if "region" in creds and creds["region"] not in SES_REGIONS:
            raise ApiError("validation_failed", "that region is not one SES is used in here", {"credentials": "region not allowed"})
        domain = sender["email_address"].rsplit("@", 1)[1].lower()
        if not self._provider(lambda: adapter.domain_verified(creds, domain)):
            raise ApiError("sender_not_verified", "the sending domain is not verified at the provider", {"domain": domain})
        self._check_credential_keys(provider, creds)
        missing = [k for k in EMAIL_CREDENTIALS[provider] if not isinstance(creds.get(k), str) or not creds[k]]
        if missing:
            raise ApiError("validation_failed", "the credentials are incomplete", {"credentials": ", ".join(missing)})
        sealed = self._seal_credentials(org, provider, creds, str(account_id))
        return ctx.conn.execute(
            "INSERT INTO consentvault.sending_account (org_id, account_id, channel, provider, status, from_email, from_display_name,"
            " credentials_ct, credential_ids_ct, created_by, created_at) VALUES (%s, %s, 'email', %s, 'connected', %s, %s, %s, %s, %s, %s)"
            " RETURNING org_id, account_id, channel, provider, status, from_email, from_display_name, sender_id, number_hint,"
            " inbound_url, provider_replies, inbound_verified_at, last_check, created_at",
            (org, account_id, provider, sender["email_address"].lower(), sender["display_name"], sealed[0], sealed[1],
             ctx.actor.member_uuid, now)).fetchone()

    def _account(self, ctx: Ctx, account_id: str) -> dict:
        try:
            aid = uuid.UUID(account_id)
        except ValueError:
            raise ApiError("not_found", "no such sending account") from None
        row = ctx.conn.execute(
            "SELECT * FROM (SELECT org_id, account_id, channel, provider, status, from_email, from_display_name, sender_id, number_hint,"
            " sender_ct, inbound_key, inbound_url, provider_replies, inbound_verified_at, last_check, refusal_count, created_at,"
            " disconnected_at FROM consentvault.sending_account) a WHERE a.org_id = %s AND a.account_id = %s",
            (ctx.org_id(), aid)).fetchone()
        if row is None:
            raise ApiError("not_found", "no such sending account")
        return row

    def patch_account(self, ctx: Ctx, account_id: str, body: Any) -> dict:
        b = strict(body, {"provider_replies_itself"})
        flag = b.get("provider_replies_itself")
        if not isinstance(flag, bool):
            raise ApiError("validation_failed", "a field is missing or malformed", {"provider_replies_itself": "true or false"})
        acct = self._account(ctx, account_id)
        if acct["channel"] != "sms" or acct["status"] == "disconnected":
            raise ApiError("validation_failed", "only a connected text account has this answer", {"account": "not a connected text account"})
        row = ctx.conn.execute(
            "UPDATE consentvault.sending_account SET provider_replies = %s, replies_answered_by = %s, replies_answered_at = %s"
            " WHERE org_id = %s AND account_id = %s RETURNING org_id, account_id, channel, provider, status, from_email,"
            " from_display_name, sender_id, number_hint, inbound_url, provider_replies, inbound_verified_at, last_check, created_at",
            (Jsonb({"stop": flag, "help": flag, "start": flag}), ctx.actor.member_uuid, self._dt(ctx.now()),
             ctx.org_id(), acct["account_id"])).fetchone()
        ctx.audit("confirmations.settings_changed", "sending_account", str(acct["account_id"]),
                  detail={"provider_replies_itself": flag})
        return self._account_obj(row)

    def check_account(self, ctx: Ctx, account_id: str, body: Any) -> dict:
        strict(body, set())
        acct = self._account(ctx, account_id)
        if acct["status"] == "disconnected":
            raise ApiError("not_found", "no such sending account")
        org, now = ctx.org_id(), self._dt(ctx.now())
        adapter = self._adapter(acct["provider"])
        try:
            creds = self._open_credentials(ctx.conn, org, acct)
        except KEY_ERRORS as exc:
            raise ApiError("key_unavailable", "the organization key could not be used; nothing was changed") from exc
        if acct["channel"] == "sms":
            creds["sender"] = self._sender_spec(org, acct)
            self._provider(lambda: adapter.read_sender(creds))
            detail = "the provider answered and the number is on the account"
        else:
            domain = acct["from_email"].rsplit("@", 1)[1]
            if not self._provider(lambda: adapter.domain_verified(creds, domain)):
                raise ApiError("sender_not_verified", "the sending domain is no longer verified at the provider", {"domain": domain})
            detail = "the provider answered and the sending domain is verified"
        status = acct["status"]
        if status == "failing":
            status = "connected" if acct["channel"] == "email" or acct["inbound_verified_at"] else "awaiting_test_reply"
        row = ctx.conn.execute(
            "UPDATE consentvault.sending_account SET status = %s, refusal_count = 0, last_refusal_code = NULL, last_check = %s"
            " WHERE org_id = %s AND account_id = %s RETURNING org_id, account_id, channel, provider, status, from_email,"
            " from_display_name, sender_id, number_hint, inbound_url, provider_replies, inbound_verified_at, last_check, created_at",
            (status, Jsonb({"at": iso(now), "result": "ok", "detail": detail}), org, acct["account_id"])).fetchone()
        if acct["status"] == "failing":
            self._alarm_clear(ctx.conn, "sending_account_failing", now)
        return self._account_obj(row)

    def delete_account(self, ctx: Ctx, account_id: str, body: Any) -> dict:
        b = strict(body, {"reason"})
        reason = need_text(b, "reason", max_len=200)
        acct = self._account(ctx, account_id)
        if acct["status"] == "disconnected":
            raise ApiError("not_found", "no such sending account")
        org, now = ctx.org_id(), self._dt(ctx.now())
        if acct["channel"] == "sms":
            adapter = self._adapter(acct["provider"])
            try:
                creds = self._open_credentials(ctx.conn, org, acct)
            except KEY_ERRORS as exc:
                raise ApiError("key_unavailable", "the organization key could not be used; nothing was changed") from exc
            creds["sender"] = self._sender_spec(org, acct)
            info = self._provider(lambda: adapter.read_sender(creds))
            if info.get("inbound_webhook") and info["inbound_webhook"] == acct["inbound_url"]:
                raise ApiError("inbound_still_pointed_here", "the number's replies still come to ConsentVault; point them elsewhere first")
        row = ctx.conn.execute(
            "UPDATE consentvault.sending_account SET status = 'disconnected', disconnected_at = clock_timestamp(), credentials_ct = NULL,"
            " credential_ids_ct = NULL WHERE org_id = %s AND account_id = %s RETURNING org_id, account_id, channel, provider, status,"
            " from_email, from_display_name, sender_id, number_hint, inbound_url, provider_replies, inbound_verified_at, last_check,"
            " created_at", (org, acct["account_id"])).fetchone()
        ctx.conn.execute("UPDATE consentvault.confirmation_rule SET enabled = false, updated_by = %s, updated_at = %s"
                         " WHERE org_id = %s AND channel = %s AND enabled", (ctx.actor.member_uuid, now, org, acct["channel"]))
        ctx.audit("confirmations.account_removed", "sending_account", str(acct["account_id"]), reason=reason,
                  detail={"channel": acct["channel"]})
        return self._account_obj(row)

    # ---- the wording link host -----------------------------------------------------------------------------------------------
    def set_link_host(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, {"host"})
        host = b.get("host")
        if not isinstance(host, str) or not HOST.match(host.strip().lower()):
            raise ApiError("validation_failed", "a field is missing or malformed", {"host": "a host name like consent.example.com"})
        host, org, now = host.strip().lower(), ctx.org_id(), self._dt(ctx.now())
        if ctx.conn.execute("SELECT consentvault.confirmation_host_lookup(%s) AS o", (host,)).fetchone()["o"] not in (None, org):
            raise ApiError("validation_failed", "that host cannot be used", {"host": "not available"})
        txt = "consentvault-verify=" + secrets.token_hex(16)
        ctx.conn.execute(
            "INSERT INTO consentvault.confirmation_link_host (org_id, host, status, txt_value, fail_count, updated_by, updated_at)"
            " VALUES (%s, %s, 'pending_dns', %s, 0, %s, %s) ON CONFLICT (org_id) DO UPDATE SET host = EXCLUDED.host,"
            " status = 'pending_dns', txt_value = EXCLUDED.txt_value, fail_count = 0, last_checked_at = NULL, verified_at = NULL,"
            " updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at", (org, host, txt, ctx.actor.member_uuid, now))
        self._alarm_clear(ctx.conn, "link_host_failing", now)
        ctx.audit("confirmations.link_host_set", "link_host", host)
        return self._link_host_obj(self._link_host_row(ctx.conn))

    def verify_link_host(self, ctx: Ctx, body: Any) -> dict:
        strict(body, set())
        row = self._link_host_row(ctx.conn)
        if row is None:
            raise ApiError("validation_failed", "set a host first", {"host": "not set"})
        expected = f"CNAME {row['host']} -> {self._edge_cname}; TXT {row['host']} = {row['txt_value']}"
        if not self._provider(lambda: self._dns_matches(row)):
            raise ApiError("link_host_dns_missing", "the CNAME or TXT record is not there yet", {"expected": expected})
        org, now = ctx.org_id(), self._dt(ctx.now())
        if ctx.conn.execute("SELECT consentvault.confirmation_host_lookup(%s) AS o", (row["host"],)).fetchone()["o"] not in (None, org):
            raise ApiError("validation_failed", "that host cannot be used", {"host": "not available"})
        ctx.conn.execute("UPDATE consentvault.confirmation_link_host SET status = 'verified', fail_count = 0, verified_at = %s,"
                         " last_checked_at = %s WHERE org_id = %s", (now, now, org))
        self._alarm_clear(ctx.conn, "link_host_failing", now)
        ctx.audit("confirmations.link_host_verified", "link_host", row["host"])
        return self._link_host_obj(self._link_host_row(ctx.conn))

    def _dns_matches(self, row: dict) -> bool:
        return (self._dns.lookup(row["host"], "CNAME") == self._edge_cname
                and self._dns.lookup(row["host"], "TXT") == row["txt_value"])

    # ---- texting registration ------------------------------------------------------------------------------------------------
    def mark_registration(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, {"kind", "reference", "accepted", "samples_included"})
        bad = {}
        if b.get("kind") not in ("10dlc", "toll_free", "short_code"):
            bad["kind"] = "10dlc, toll_free or short_code"
        ref = b.get("reference")
        if ref is not None and (not isinstance(ref, str) or not 1 <= len(ref) <= 100):
            bad["reference"] = "1 to 100 characters"
        for k in ("accepted", "samples_included"):
            if not isinstance(b.get(k), bool):
                bad[k] = "true or false"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        acct = self._live_account(ctx.conn, "sms")
        if acct is None:
            raise ApiError("no_sending_account", "connect a text sending account first")
        if acct["inbound_verified_at"] is None:
            raise ApiError("inbound_not_verified", "no test reply has arrived at the inbound address yet")
        if b["accepted"] is not True or b["samples_included"] is not True:
            raise ApiError("acknowledgement_required", "both statements must be accepted")
        org, now = ctx.org_id(), self._dt(ctx.now())
        was = self._registration_row(ctx.conn)
        if was is not None and was["status"] == "marked" and was["samples_statement_version"] != texts.FIXED_TEXT_VERSION:
            ctx.conn.execute("UPDATE consentvault.confirmation_rule SET enabled = false, updated_by = %s, updated_at = %s"
                             " WHERE org_id = %s AND channel = 'sms' AND enabled", (ctx.actor.member_uuid, now, org))
        ctx.conn.execute(
            "INSERT INTO consentvault.confirmation_registration (org_id, status, kind, reference, samples_statement_version, marked_by,"
            " marked_at, withdrawn_at) VALUES (%s, 'marked', %s, %s, %s, %s, %s, NULL) ON CONFLICT (org_id) DO UPDATE SET"
            " status = 'marked', kind = EXCLUDED.kind, reference = EXCLUDED.reference,"
            " samples_statement_version = EXCLUDED.samples_statement_version, marked_by = EXCLUDED.marked_by,"
            " marked_at = EXCLUDED.marked_at, withdrawn_at = NULL",
            (org, b["kind"], ref, texts.FIXED_TEXT_VERSION, ctx.actor.member_uuid, now))
        ctx.audit("confirmations.registration_marked", "texting_registration", None,
                  detail={"kind": b["kind"], "fixed_text_version": texts.FIXED_TEXT_VERSION})
        return self._registration_obj(self._registration_row(ctx.conn))

    def withdraw_registration(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, {"reason"})
        reason = need_text(b, "reason", max_len=200)
        org, now = ctx.org_id(), self._dt(ctx.now())
        ctx.conn.execute(
            "INSERT INTO consentvault.confirmation_registration (org_id, status, withdrawn_at) VALUES (%s, 'not_marked', %s)"
            " ON CONFLICT (org_id) DO UPDATE SET status = 'not_marked', kind = NULL, reference = NULL,"
            " samples_statement_version = NULL, marked_by = NULL, marked_at = NULL, withdrawn_at = EXCLUDED.withdrawn_at", (org, now))
        ctx.conn.execute("UPDATE consentvault.confirmation_rule SET enabled = false, updated_by = %s, updated_at = %s"
                         " WHERE org_id = %s AND channel = 'sms' AND enabled", (ctx.actor.member_uuid, now, org))
        ctx.audit("confirmations.registration_withdrawn", "texting_registration", None, reason=reason)
        return self._registration_obj(self._registration_row(ctx.conn))

    # ---- rules ----------------------------------------------------------------------------------------------------------------
    @staticmethod
    def _name_maps(conn, org) -> tuple[dict, dict]:
        """(source id -> name, brand id -> display name) of this organization, for the rows that carry names beside ids."""
        return ({r["source_id"]: r["name"] for r in conn.execute(
                    "SELECT source_id, name FROM consentvault.capture_source WHERE org_id = %s", (org,))},
                {r["brand_id"]: r["display_name"] for r in conn.execute(
                    "SELECT brand_id, display_name FROM consentvault.brand WHERE org_id = %s", (org,))})

    def _rule_obj(self, source_id, channel: str, r: Optional[dict], reg_ok: bool, names: tuple[dict, dict]) -> dict:
        source_name = names[0].get(source_id)
        if r is None:
            return {"source_id": str(source_id), "source_name": source_name, "channel": channel, "enabled": False,
                    "sending_brand_id": None, "brand_name": None, "template_id": None,
                    "send_for_test_events": True, "dedupe_hours": 24, "max_delay_minutes": 10, "updated_by": None, "updated_at": None}
        return {"source_id": str(r["source_id"]), "source_name": source_name, "channel": channel,
                "enabled": bool(r["enabled"] and (channel == "email" or reg_ok)),
                "sending_brand_id": str(r["sending_brand_id"]) if r["sending_brand_id"] else None,
                "brand_name": names[1].get(r["sending_brand_id"]),
                "template_id": str(r["template_id"]) if r["template_id"] else None, "send_for_test_events": r["send_for_test_events"],
                "dedupe_hours": r["dedupe_hours"], "max_delay_minutes": r["max_delay_minutes"],
                "updated_by": str(r["updated_by"]) if r["updated_by"] else None, "updated_at": iso(r["updated_at"])}

    def list_rules(self, ctx: Ctx) -> dict:
        org = ctx.org_id()
        sources = ctx.conn.execute("SELECT source_id, name FROM consentvault.capture_source WHERE org_id = %s AND kind <> 'system'"
                                   " AND status = 'active' ORDER BY name, source_id", (org,)).fetchall()
        rules = {(r["source_id"], r["channel"]): r for r in ctx.conn.execute(
            "SELECT * FROM consentvault.confirmation_rule WHERE org_id = %s", (org,))}
        reg_ok = self._registration_current(self._registration_row(ctx.conn))
        names = self._name_maps(ctx.conn, org)
        return {"items": [self._rule_obj(s["source_id"], ch, rules.get((s["source_id"], ch)), reg_ok, names)
                          for s in sources for ch in ("email", "sms")], "next_cursor": None}

    def put_rule(self, ctx: Ctx, source_id: str, channel: str, body: Any) -> dict:
        b = strict(body, RULE_KEYS)
        bad = {}
        if channel not in ("email", "sms"):
            bad["channel"] = "email or sms"
        if not isinstance(b.get("enabled"), bool):
            bad["enabled"] = "true or false"
        brand = uuid_text(b.get("sending_brand_id"))
        if brand is None:
            bad["sending_brand_id"] = "the id of a brand"
        template = None
        if b.get("template_id") is not None:
            template = uuid_text(b["template_id"])
            if template is None:
                bad["template_id"] = "the id of an email template"
            elif channel == "sms":
                bad["template_id"] = "an email rule only"
        if "send_for_test_events" in b and not isinstance(b["send_for_test_events"], bool):
            bad["send_for_test_events"] = "true or false"
        if "dedupe_hours" in b and not is_int(b["dedupe_hours"], 1, 168):
            bad["dedupe_hours"] = "a whole number from 1 to 168"
        if "max_delay_minutes" in b and not is_int(b["max_delay_minutes"], 1, 60):
            bad["max_delay_minutes"] = "a whole number from 1 to 60"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        conn, org, now = ctx.conn, ctx.org_id(), self._dt(ctx.now())
        src = uuid_text(source_id)
        if src is None or conn.execute("SELECT 1 FROM consentvault.capture_source WHERE org_id = %s AND source_id = %s AND kind <> 'system'",
                                       (org, src)).fetchone() is None:
            raise ApiError("not_found", "no such source")
        if conn.execute("SELECT 1 FROM consentvault.brand WHERE org_id = %s AND brand_id = %s", (org, brand)).fetchone() is None:
            raise ApiError("not_found", "no such brand")
        if template is not None and conn.execute("SELECT 1 FROM consentvault.confirmation_template WHERE org_id = %s AND template_id = %s",
                                                 (org, template)).fetchone() is None:
            raise ApiError("not_found", "no such template")
        if b["enabled"]:
            self._require_ready(conn, channel)
        cur = conn.execute("SELECT * FROM consentvault.confirmation_rule WHERE org_id = %s AND source_id = %s AND channel = %s",
                           (org, src, channel)).fetchone()

        def pick(name: str, default):
            return b[name] if name in b else (cur[name] if cur else default)

        conn.execute(
            "INSERT INTO consentvault.confirmation_rule (org_id, source_id, channel, enabled, sending_brand_id, template_id,"
            " send_for_test_events, dedupe_hours, max_delay_minutes, updated_by, updated_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (org_id, source_id, channel) DO UPDATE SET"
            " enabled = EXCLUDED.enabled, sending_brand_id = EXCLUDED.sending_brand_id, template_id = EXCLUDED.template_id,"
            " send_for_test_events = EXCLUDED.send_for_test_events, dedupe_hours = EXCLUDED.dedupe_hours,"
            " max_delay_minutes = EXCLUDED.max_delay_minutes, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at",
            (org, src, channel, b["enabled"], brand, template if "template_id" in b else (cur["template_id"] if cur else None),
             pick("send_for_test_events", True), pick("dedupe_hours", 24), pick("max_delay_minutes", 10), ctx.actor.member_uuid, now))
        ctx.audit("confirmations.rule_changed", "confirmation_rule", f"{src}/{channel}",
                  detail={"source_id": str(src), "channel": channel, "enabled": b["enabled"]})
        row = conn.execute("SELECT * FROM consentvault.confirmation_rule WHERE org_id = %s AND source_id = %s AND channel = %s",
                           (org, src, channel)).fetchone()
        return self._rule_obj(src, channel, row, self._registration_current(self._registration_row(conn)), self._name_maps(conn, org))

    def _require_ready(self, conn, channel: str) -> None:
        """The prerequisites for a rule that is on, in the pinned order (the first one that fails is the answer)."""
        acct = self._live_account(conn, channel)
        if acct is None:
            raise ApiError("no_sending_account", "connect a sending account for this channel first")
        if channel == "sms":
            if acct["inbound_verified_at"] is None:
                raise ApiError("inbound_not_verified", "no test reply has arrived at the inbound address yet")
            if not self._registration_current(self._registration_row(conn)):
                raise ApiError("texting_not_registered", "mark the texting registration complete first")
        if self._settings_row(conn) is None:
            raise ApiError("sender_details_missing", "the organization name, postal address and help contact are required first")
        host = self._link_host_row(conn)
        if host is None or host["status"] != "verified":
            raise ApiError("link_host_not_verified", "verify the wording link host first")

    # ---- templates --------------------------------------------------------------------------------------------------------------
    @staticmethod
    def _template_obj(r: dict, newest: int) -> dict:
        """The list fields (a template is an email template, named by its subject, never edited, so it was last updated when it
        was made; only the newest version is current) plus the editable parts."""
        return {"template_id": str(r["template_id"]), "channel": "email", "name": r["subject"], "body_version": r["version"],
                "status": "current" if r["version"] == newest else "superseded", "updated_at": iso(r["created_at"]),
                "version": r["version"], "subject": r["subject"], "opening_line": r["opening_line"],
                "created_by": str(r["created_by"]) if r["created_by"] else None, "created_at": iso(r["created_at"])}

    @staticmethod
    def _template_fields(item: dict) -> dict:
        return {k: item[k] for k in ("template_id", "channel", "name", "body_version", "status", "updated_at")}

    @staticmethod
    def _newest_template(conn, org) -> int:
        return conn.execute("SELECT coalesce(max(version), 0) AS v FROM consentvault.confirmation_template WHERE org_id = %s",
                            (org,)).fetchone()["v"]

    def create_template(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, {"subject", "opening_line"})
        bad = {}
        if not isinstance(b.get("subject"), str) or not 1 <= len(b["subject"]) <= 80:
            bad["subject"] = "1 to 80 characters"
        line = b.get("opening_line")
        if line is not None and (not isinstance(line, str) or len(line) > 300):
            bad["opening_line"] = "at most 300 characters"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        org = ctx.org_id()
        n = ctx.conn.execute("SELECT coalesce(max(version), 0) AS v FROM consentvault.confirmation_template WHERE org_id = %s",
                             (org,)).fetchone()["v"]
        tid = uuid.uuid4()
        ctx.conn.execute("INSERT INTO consentvault.confirmation_template (org_id, template_id, version, subject, opening_line, created_by,"
                         " created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                         (org, tid, n + 1, b["subject"], line or None, ctx.actor.member_uuid, self._dt(ctx.now())))
        ctx.audit("confirmations.template_created", "confirmation_template", str(tid), detail={"version": n + 1})
        return {"template_id": str(tid), "version": n + 1}

    def list_templates(self, ctx: Ctx) -> dict:
        rows = ctx.conn.execute("SELECT * FROM consentvault.confirmation_template WHERE org_id = %s ORDER BY version DESC",
                                (ctx.org_id(),)).fetchall()
        newest = rows[0]["version"] if rows else 0
        return {"items": [self._template_fields(self._template_obj(r, newest)) for r in rows], "next_cursor": None}

    def get_template(self, ctx: Ctx, template_id: str) -> dict:
        tid = uuid_text(template_id)
        row = ctx.conn.execute("SELECT * FROM consentvault.confirmation_template WHERE org_id = %s AND template_id = %s",
                               (ctx.org_id(), tid)).fetchone() if tid else None
        if row is None:
            raise ApiError("not_found", "no such template")
        return self._template_obj(row, self._newest_template(ctx.conn, ctx.org_id()))

    # ---- preview and the test message --------------------------------------------------------------------------------------------
    def _sample(self, ctx: Ctx, b: dict, *, link_token: str) -> tuple[str, Optional[str], str]:
        """(channel, subject, body) rendered with sample values from the organization's own sender details."""
        conn, org = ctx.conn, ctx.org_id()
        channel = b.get("channel")
        bad = {}
        if channel not in ("email", "sms"):
            bad["channel"] = "email or sms"
        src = uuid_text(b.get("source_id")) if b.get("source_id") is not None else None
        if "source_id" in b and b["source_id"] is not None and src is None:
            bad["source_id"] = "the id of a source"
        tmpl_in = b.get("template")
        template_id = uuid_text(b["template_id"]) if b.get("template_id") is not None else None
        if b.get("template_id") is not None and template_id is None:
            bad["template_id"] = "the id of an email template"
        if tmpl_in is not None:
            if not isinstance(tmpl_in, dict):
                bad["template"] = "an object with a subject and an opening_line"
            else:
                for k in tmpl_in:
                    if k not in ("subject", "opening_line"):
                        bad[k] = "not editable: only the subject and the opening line can change"
                if not isinstance(tmpl_in.get("subject"), str) or not 1 <= len(tmpl_in["subject"]) <= 80:
                    bad.setdefault("subject", "1 to 80 characters")
                if tmpl_in.get("opening_line") is not None and (not isinstance(tmpl_in["opening_line"], str)
                                                               or len(tmpl_in["opening_line"]) > 300):
                    bad["opening_line"] = "at most 300 characters"
            if template_id is not None:
                bad["template"] = "give a template_id or a template, not both"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        if src is not None and conn.execute("SELECT 1 FROM consentvault.capture_source WHERE org_id = %s AND source_id = %s AND kind <> 'system'",
                                            (org, src)).fetchone() is None:
            raise ApiError("not_found", "no such source")
        tmpl = None
        if template_id is not None:
            tmpl = conn.execute("SELECT subject, opening_line FROM consentvault.confirmation_template WHERE org_id = %s AND template_id = %s",
                                (org, template_id)).fetchone()
            if tmpl is None:
                raise ApiError("not_found", "no such template")
        elif tmpl_in is not None:
            tmpl = tmpl_in
        s, host = self._settings_row(conn), self._link_host_row(conn)
        brand = s["organization_name"] if s else "Your organization"
        link_host = host["host"] if host else "consent.example.com"
        now = self._dt(ctx.now())
        if channel == "sms":
            body = texts.sms_confirmation(brand, zones.format_when(now, zones.ET), "texts and calls", texts.SAMPLE_PURPOSES,
                                          f"https://{link_host}/c/r/{link_token}")
            return channel, None, body
        source = "your sign-up"
        if src is not None:
            source = conn.execute("SELECT name FROM consentvault.capture_source WHERE org_id = %s AND source_id = %s", (org, src)).fetchone()["name"]
        body = texts.email_body(
            opening_line=(tmpl or {}).get("opening_line"), brand=brand, when=zones.format_when(now, None), source_name=source,
            wording="[The exact wording the person agreed to appears here, word for word.]", channels="email",
            purposes=texts.SAMPLE_PURPOSES, stop_link=f"https://{link_host}/c/stop/{link_token}",
            org_name=brand, postal_address=s["postal_address"] if s else "Your postal address",
            help_email=s["help_email"] if s else "help@example.com", help_phone=s["help_phone"] if s else None)
        return channel, texts.email_subject((tmpl or {}).get("subject"), brand), body

    def preview(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, {"source_id", "channel", "template_id", "template"})
        channel, subject, text = self._sample(ctx, b, link_token="SAMPLE")
        return {"subject": subject, "body": text, "segments": texts.segments(text) if channel == "sms" else None,
                "characters": len(text)}

    def test_message(self, ctx: Ctx, body: Any) -> dict:
        b = strict(body, {"source_id", "channel", "contact", "template_id"})
        contact = b.get("contact")
        if not isinstance(contact, str) or not contact.strip():
            raise ApiError("validation_failed", "a field is missing or malformed", {"contact": "the contact point to send the test to"})
        if b.get("channel") not in ("email", "sms"):
            raise ApiError("validation_failed", "a field is missing or malformed", {"channel": "email or sms"})
        from ..normalize import normalize_contact
        try:
            kind, norm = normalize_contact(contact, None, region_of(ctx))
        except NormalizationError:
            raise ApiError("invalid_contact", "the contact point is not a valid phone number or email address") from None
        if kind != ("phone" if b["channel"] == "sms" else "email"):
            raise ApiError("validation_failed", "that contact point does not fit the channel", {"contact": "wrong kind"})
        channel, org, now = b["channel"], ctx.org_id(), self._when(ctx.conn)
        token = secrets.token_urlsafe(18)
        channel, subject, text = self._sample(ctx, b, link_token=token)
        self._require_ready(ctx.conn, channel)
        ctx.conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"cvconfirm-test:{org}",))  # count and send in turn
        recent = ctx.conn.execute("SELECT count(*) AS n FROM consentvault.confirmation_page_token WHERE org_id = %s AND is_test"
                                  " AND created_at > %s", (org, now - timedelta(hours=1))).fetchone()["n"]
        if recent >= TEST_SENDS_PER_HOUR:
            err = ApiError("rate_limited", f"at most {TEST_SENDS_PER_HOUR} test messages an hour")
            err.retry_after = 3600
            raise err
        try:
            fp = self.crypto.contact_fingerprint(org, kind, norm)
        except KEY_ERRORS as exc:
            raise ApiError("key_unavailable", "the organization key could not be used; nothing was sent") from exc
        if self._stop_on_record(ctx.conn, org, fp, channel):
            raise ApiError("validation_failed", "a stop is on record for that contact; nothing was sent", {"contact": "stop on record"})
        if channel == "sms":
            zone = zones.zone_for_phone(norm)
            if zone is None:  # fail safe: a number whose zone cannot be worked out gets no text, a test text included
                raise ApiError("validation_failed", "the time zone of that number cannot be determined; nothing was sent",
                               {"contact": "time_zone_unknown"})
            if not zones.text_window_open(zones.local(now, zone)):
                raise ApiError("validation_failed", "that number is outside texting hours right now; nothing was sent",
                               {"contact": "outside texting hours"})
        acct = self._live_account(ctx.conn, channel)
        adapter = self._adapter(acct["provider"])
        try:
            creds = self._open_credentials(ctx.conn, org, acct)
            spec = self._sender_spec(org, acct) if channel == "sms" else None
        except KEY_ERRORS as exc:
            raise ApiError("key_unavailable", "the organization key could not be used; nothing was sent") from exc
        ctx.conn.execute("INSERT INTO consentvault.confirmation_page_token (org_id, token_hash, kind, send_id, is_test, created_at)"
                         " VALUES (%s, %s, %s, NULL, true, %s)",
                         (org, hashlib.sha256(token.encode()).hexdigest(), "wording" if channel == "sms" else "stop", now))
        if channel == "sms":
            creds["sender"] = spec
            self._provider(lambda: adapter.send(creds, to=norm, body=text, sender=spec.get("messaging_service_sid") or spec["number"],
                                                 status_callback=f"{self._api_base}/v1/confirmations/inbound/{acct['inbound_key']}"))
        else:
            host = self._link_host_row(ctx.conn)["host"]
            stop = f"https://{host}/c/stop/{token}"
            sender = {"email_address": acct["from_email"], "display_name": acct["from_display_name"]}
            self._provider(lambda: adapter.send(creds, to=norm, subject=subject, body=text, sender=sender,
                                                 headers={"List-Unsubscribe": f"<{stop}>",
                                                          "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}))
        ctx.audit("confirmations.test_sent", "confirmations", None, detail={"channel": channel})
        return {"status": "sent", "channel": channel}

