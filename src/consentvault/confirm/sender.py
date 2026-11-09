"""The sender (confirmations.md sections 5 to 7): one pass over the intents that are due, in three short steps per intent.

1. **Claim and decide**, in one transaction: ``FOR UPDATE SKIP LOCKED`` claims one due intent, a transaction-scoped lock on the
   (organization, contact, channel) keeps two intents for one person in order, every check runs, and the intent either ends
   there (a named skip, or dead) or moves to ``sending`` with the message built. That transaction commits before anything is sent.
2. **Send**, with no lock and no transaction held: the clock is read and quiet hours judged on that reading as the last step,
   then one call to the provider; a text whose check is more than 2 seconds old when the call is made is not sent (retried).
3. **Record the outcome**, in a second transaction: accepted (the sealed text, its SHA-256, the contact-log row, the record
   list), a retry on the schedule, a refusal, or an account-level refusal.

A message the provider accepted is therefore never sent twice: an intent left ``sending`` by a crash between steps 2 and 3 is
never retried by the sender; ``run_alarm_checks`` ends it as dead with cause ``send_outcome_unknown`` and raises an alarm.
Retries run at fixed offsets from the first attempt (1, 2, 4, 8, 16, 32 and 57 minutes, each stretched by the injected jitter);
none runs later than 120 minutes after the first (5 minutes for a reply to a person's own message).
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg

from .. import door
from ..tenancy import crypto as tc
from . import basis, texts, zones
from .core import (KEY_ERRORS, RECORDED_BY, SYSTEM_REPLIES, ProviderError, log)

RETRY_OFFSETS_MINUTES = (1, 2, 4, 8, 16, 32, 57)
RETRY_WINDOW = timedelta(minutes=120)
REPLY_WINDOW = timedelta(minutes=5)
ACCOUNT_REFUSALS_TO_FAIL = 5
HELP_ANSWER_INTERVAL = timedelta(hours=1)
MAX_PER_ORG_PASS = 5000
SEND_CHECK_MAX_SECONDS = 2.0
_monotonic = time.monotonic  # real elapsed time between the hours check and the provider call
OUTCOME = {"confirmation": "confirmation", "optout_reply": "optout_reply", "help_reply": "help_reply",
           "start_reply": "start_reply"}
REPLY_KEY = {"optout_reply": "stop", "help_reply": "help", "start_reply": "start"}
def db_now(conn) -> datetime:
    """The database's clock: every confirmation decision reads it, so a worker whose own clock is off cannot send in quiet
    hours, early, twice inside a day or past the hourly cap."""
    return conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]


CLAIM_SQL = ("SELECT * FROM consentvault.confirmation_send_intent WHERE org_id = %s AND status = 'intent'"
             " AND (next_attempt_at IS NULL OR next_attempt_at <= %s) AND send_id <> ALL(%s) {only}"
             " ORDER BY created_at, send_id LIMIT 1 FOR UPDATE SKIP LOCKED")


class _Skip(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.skip_code = reason


@dataclass
class Plan:
    send_id: uuid.UUID
    kind: str
    channel: str
    provider: str
    account_id: uuid.UUID
    creds: dict
    to: str
    body: str
    subject: Optional[str]
    headers: dict
    sender: object
    status_callback: Optional[str]
    fp: str
    contact_kind: str
    data_key: Optional[bytes]
    template_id: Optional[uuid.UUID]
    attempts: int
    first_attempt_at: datetime
    tokens: list = field(default_factory=list)
    zone: Optional[str] = None


class SenderMixin:
    # ---- the pass -------------------------------------------------------------------------------------------------------
    def run_sender(self, now: Optional[float] = None) -> int:
        """One pass over the intents that are due, for every organization with one waiting. Returns the number of intents
        it finished: sent, refused, skipped or dead (a retry scheduled for later is not finished)."""
        pinned = datetime.fromtimestamp(now, tz=timezone.utc) if now is not None else None  # a pinned time is for tests and replays; otherwise each message reads the clock
        finished = 0
        for org in self._org_list("confirmation_work_orgs"):
            finished += self._run_org(org, pinned)
        return finished

    def _run_org(self, org, when: Optional[datetime], only: Optional[uuid.UUID] = None) -> int:
        finished, seen = 0, set()
        for _ in range(MAX_PER_ORG_PASS):
            step = self._process_next(org, when, only, list(seen))  # an intent is tried once per pass, whatever its next due time
            if step is None:
                break
            send_id, done = step
            seen.add(send_id)
            finished += done
            if only is not None:
                break
        return finished

    def _process_next(self, org, pinned: Optional[datetime], only: Optional[uuid.UUID], exclude: list):
        """Claim and decide one intent, send it, record the outcome. None when nothing is due; else (send_id, 0 or 1)."""
        # this reading claims the intent and runs the checks that do not depend on the hour; quiet hours are judged again on a
        # fresh reading as the last step before the provider call (_send_gate), so a wait on the lock below cannot carry a
        # 7:59 PM reading past 8 PM
        with self.tx(org) as conn:
            # the database's clock, read in the claim's own transaction: what is due, the retry window, the 24-hour duplicate
            # check and the hourly cap are all decided on this one reading, never on this process's clock
            when = pinned if pinned is not None else db_now(conn)
            sql = CLAIM_SQL.format(only="AND send_id = %s" if only else "")
            it = conn.execute(sql, (org, when, exclude) + ((only,) if only else ())).fetchone()
            if it is None:
                return None
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"cvconfirm:{org}:{it['contact_fp']}:{it['channel']}",))
            plan = self._phase_one(conn, org, it, when)
        if plan is None:
            return it["send_id"], 1
        done = self._phase_two_and_three(org, plan, when, pinned)
        return it["send_id"], done

    # ---- step 1: decide ---------------------------------------------------------------------------------------------------
    def _phase_one(self, conn, org, it: dict, when: datetime) -> Optional[Plan]:
        kind, attempts, first = it["kind"], it["attempts"], it["first_attempt_at"]
        window = RETRY_WINDOW if kind == "confirmation" else REPLY_WINDOW
        if attempts > 0 and first is not None and when > first + window:
            self._dead(conn, org, it, when, it["last_error"] or "retry_window_over")
            return None
        try:
            if kind == "confirmation":
                plan = self._plan_confirmation(conn, org, it, when)
            else:
                plan = self._plan_reply(conn, org, it, when)
        except _Skip as skip:
            self._skip(conn, org, it, skip.skip_code, when)
            return None
        except ProviderError as exc:  # the stored credentials are gone: the account was disconnected under this intent
            log.warning("confirmation skipped: the account credentials are gone", send_id=it["send_id"], provider_code=exc.code)
            self._skip(conn, org, it, "no_sending_account", when)
            return None
        except KEY_ERRORS:
            self._after_failure(conn, org, it, when, "key_unavailable", attempts + 1, first or when, count=True)
            return None
        conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'sending', attempts = attempts + 1,"
                     " first_attempt_at = coalesce(first_attempt_at, %s), last_attempt_at = %s, at = %s, next_attempt_at = NULL"
                     " WHERE org_id = %s AND send_id = %s", (when, when, when, org, it["send_id"]))
        for kind_, token in plan.tokens:
            conn.execute("INSERT INTO consentvault.confirmation_page_token (org_id, token_hash, kind, send_id, created_at)"
                         " VALUES (%s, %s, %s, %s, %s)", (org, hashlib.sha256(token.encode()).hexdigest(), kind_, plan.send_id, when))
        plan.attempts, plan.first_attempt_at = attempts + 1, first or when
        return plan

    def _contact_exists(self, conn, fp: str) -> bool:
        return conn.execute("SELECT 1 FROM consentvault.contact_key_of(%s)", (fp,)).fetchone() is not None

    def _stop_on_record(self, conn, org, fp: str, channel: str) -> bool:
        if conn.execute("SELECT 1 FROM consentvault.history_stop_on_record(%s, %s, %s)", (org, fp, channel)).fetchone() is not None:
            return True
        return conn.execute("SELECT 1 FROM consentvault.current_permission WHERE org_id = %s AND contact_fp = %s AND channel = %s"
                            " AND NOT allowed AND reason LIKE 'stopped:%%' LIMIT 1", (org, fp, channel)).fetchone() is not None

    def _plan_confirmation(self, conn, org, it: dict, when: datetime) -> Plan:
        fp, ch, send_id = it["contact_fp"], it["channel"], it["send_id"]
        ev = basis.event_like(conn, org, it["basis_event_id"] or it["basis_history_event_id"])
        rule = conn.execute("SELECT * FROM consentvault.confirmation_rule WHERE org_id = %s AND source_id = %s AND channel = %s",
                            (org, ev["source_id"], ch)).fetchone()
        if rule is None:
            raise _Skip("rule_off")
        if not self._contact_exists(conn, fp):
            raise _Skip("contact_erased")
        if ch not in ev["channels"]:
            raise _Skip("channel_not_in_grant")
        if ev["contact_kind"] != ("phone" if ch == "sms" else "email"):
            raise _Skip("contact_kind")
        if rule["sending_brand_id"] not in (ev["brand_ids"] or []):
            raise _Skip("brand_not_in_grant")
        if ev["received_at"] - ev["captured_at"] > timedelta(minutes=rule["max_delay_minutes"]):
            raise _Skip("late")
        held: dict = {}

        def data_key() -> bytes:
            if "k" not in held:
                held["k"] = self._contact_key(conn, org, fp)
            return held["k"]

        acct, host = self._live_account(conn, ch), self._link_host_row(conn)
        reg = self._registration_row(conn)
        if ch == "sms":
            if not self._registration_current(reg):
                raise _Skip("texting_not_registered")
            if acct is None:
                raise _Skip("no_sending_account")
            if acct["status"] == "awaiting_test_reply":
                raise _Skip("inbound_not_verified")
        elif acct is None:
            raise _Skip("no_sending_account")
        if host is None or host["status"] not in ("verified", "failing"):
            raise _Skip("link_host_not_verified")
        if host["status"] == "failing":
            raise _Skip("link_host_failing")
        if acct["status"] == "failing":
            raise _Skip("sending_account_failing")
        if self._org_status(conn) in ("suspended", "offboarding", "closed"):
            raise _Skip("org_not_active")
        norm = tc.decrypt_text(data_key(), org, str(ev["event_id"]), "contact_norm", bytes(ev["contact_ct"]))
        zone = None
        if ch == "sms":
            zone = zones.zone_for_phone(norm)
            if zone is None:
                raise _Skip("time_zone_unknown")
            if not zones.text_window_open(zones.local(when, zone)):
                raise _Skip("quiet_hours")
        if self._stop_on_record(conn, org, fp, ch):
            raise _Skip("stop_on_record")
        if conn.execute("SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND contact_fp = %s AND channel = %s"
                        " AND kind = 'confirmation' AND send_id <> %s AND status IN ('sending', 'sent', 'delivered')"
                        " AND at > %s LIMIT 1", (org, fp, ch, send_id, when - timedelta(hours=rule["dedupe_hours"]))).fetchone():
            raise _Skip("recent_confirmation")
        if not rule["enabled"]:
            raise _Skip("rule_off")
        if not rule["send_for_test_events"] and self._org_status(conn) == "trial":
            raise _Skip("test_event")
        settings = self._settings_row(conn)
        if settings is None:
            raise _Skip("sender_details_missing")
        cap = settings["send_cap_per_hour"]
        used = conn.execute("SELECT count(*) AS n FROM consentvault.confirmation_send_intent WHERE org_id = %s AND channel = %s"
                            " AND kind = 'confirmation' AND send_id <> %s AND status IN ('sending', 'sent', 'delivered')"
                            " AND at > %s", (org, ch, send_id, when - timedelta(hours=1))).fetchone()["n"]
        if used >= cap:
            self._alarm_raise(conn, "send_cap_reached", {"channel": ch, "cap": cap}, when)
            raise _Skip("org_hourly_cap")

        creds = self._open_credentials(conn, org, acct)
        labels = self._purpose_labels(conn, org, ev["purposes"])
        brand = settings["organization_name"]
        token = secrets.token_urlsafe(18)
        if ch == "sms":
            spec = self._sender_spec(org, acct)
            creds["sender"] = spec
            body = texts.sms_confirmation(brand, zones.format_when(ev["received_at"], zone), texts.channel_words(ev["channels"]),
                                          labels, f"https://{host['host']}/c/r/{token}")
            return Plan(send_id, "confirmation", ch, acct["provider"], acct["account_id"], creds, norm, body, None, {},
                        spec.get("messaging_service_sid") or spec["number"],
                        f"{self._api_base}/v1/confirmations/inbound/{acct['inbound_key']}", fp, "phone", data_key(), None,
                        it["attempts"], it["first_attempt_at"] or when, [("wording", token)], zone)
        tmpl = None
        if rule["template_id"]:
            tmpl = conn.execute("SELECT subject, opening_line FROM consentvault.confirmation_template WHERE org_id = %s"
                                " AND template_id = %s", (org, rule["template_id"])).fetchone()
        wording = conn.execute("SELECT body FROM consentvault.disclosure WHERE org_id = %s AND sha256 = %s",
                               (org, ev["disclosure_sha256"])).fetchone()["body"]
        source = conn.execute("SELECT name FROM consentvault.capture_source WHERE org_id = %s AND source_id = %s",
                              (org, ev["source_id"])).fetchone()["name"]
        zone = self._linked_phone_zone(conn, org, ev)
        stop_link = f"https://{host['host']}/c/stop/{token}"
        body = texts.email_body(
            opening_line=tmpl["opening_line"] if tmpl else None, brand=brand, when=zones.format_when(ev["received_at"], zone),
            source_name=source or "your sign-up", wording=wording, channels=texts.email_channel_words(ev["channels"]),
            purposes=labels, stop_link=stop_link, org_name=settings["organization_name"], postal_address=settings["postal_address"],
            help_email=settings["help_email"], help_phone=settings["help_phone"])
        headers = {"List-Unsubscribe": f"<{stop_link}>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}
        sender = {"email_address": acct["from_email"], "display_name": acct["from_display_name"]}
        return Plan(send_id, "confirmation", ch, acct["provider"], acct["account_id"], creds, norm,
                    body, texts.email_subject(tmpl["subject"] if tmpl else None, brand), headers, sender, None, fp, "email",
                    data_key(), rule["template_id"], it["attempts"], it["first_attempt_at"] or when, [("stop", token)])

    def _purpose_labels(self, conn, org, purposes) -> str:
        names = {r["purpose"]: r["label"] for r in conn.execute("SELECT purpose, label FROM consentvault.purpose WHERE org_id = %s", (org,))}
        return texts.words([names.get(p, p).lower() for p in purposes])

    def _linked_phone_zone(self, conn, org, ev: dict) -> Optional[str]:
        """The zone of the phone whose current record belongs to the same person as this email's current record (the records
        layer's link, records.md section 1; never an event scan), the most recently active one first; None names UTC."""
        row = conn.execute("SELECT p.contact_fp, e.event_id, e.contact_ct FROM consentvault.confirmation_person_contacts(%s) p"
                           " JOIN consentvault.event e ON e.org_id = %s AND e.event_id = p.event_id WHERE p.contact_kind = 'phone'"
                           " ORDER BY e.seq DESC LIMIT 1", (ev["contact_fp"], org)).fetchone()
        if row is None:
            return None
        key = self._contact_key(conn, org, row["contact_fp"])
        if key is None:
            return None
        return zones.zone_for_phone(tc.decrypt_text(key, org, str(row["event_id"]), "contact_norm", bytes(row["contact_ct"])))

    def _plan_reply(self, conn, org, it: dict, when: datetime) -> Plan:
        kind, send_id, fp = it["kind"], it["send_id"], it["contact_fp"]
        rep = conn.execute("SELECT account_id FROM consentvault.confirmation_reply WHERE org_id = %s AND reply_id = %s",
                           (org, it["reply_id"])).fetchone()
        acct = conn.execute(
            "SELECT * FROM (SELECT org_id, account_id, channel, provider, status, sender_ct, inbound_key, provider_replies"
            " FROM consentvault.sending_account) a WHERE a.org_id = %s AND a.account_id = %s", (org, rep["account_id"])).fetchone()
        replies = acct["provider_replies"] or {}
        if replies.get(REPLY_KEY[kind]):
            raise _Skip("provider_replied")
        if acct["status"] == "disconnected":
            raise _Skip("no_sending_account")
        status = self._org_status(conn)
        if status == "closed" or (kind != "optout_reply" and status == "offboarding") \
                or (kind == "start_reply" and status == "suspended"):
            raise _Skip("org_not_active")
        if kind != "optout_reply" and not self._registration_current(self._registration_row(conn)):
            raise _Skip("texting_not_registered")
        if kind == "help_reply" and conn.execute(
                "SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND contact_fp = %s AND kind = 'help_reply'"
                " AND send_id <> %s AND status IN ('sending', 'sent', 'delivered') AND at > %s LIMIT 1",
                (org, fp, send_id, when - HELP_ANSWER_INTERVAL)).fetchone():
            raise _Skip("help_recent")
        creds = self._open_credentials(conn, org, acct)
        spec = self._sender_spec(org, acct)
        creds["sender"] = spec
        return Plan(send_id, kind, "sms", acct["provider"], acct["account_id"], creds,
                    self._unseal(org, str(send_id), "dest_ct", it["dest_ct"]), self._unseal(org, str(send_id), "body_ct", it["body_ct"]),
                    None, {}, spec.get("messaging_service_sid") or spec["number"],
                    f"{self._api_base}/v1/confirmations/inbound/{acct['inbound_key']}", fp, "phone",
                    self._contact_key(conn, org, fp), None, it["attempts"], it["first_attempt_at"] or when)

    # ---- step 2 and 3: send, record -------------------------------------------------------------------------------------------
    def _send_gate(self, plan: Plan, pinned: Optional[datetime]) -> tuple:
        """The last step before a confirmation text leaves: read the clock, judge quiet hours on that reading, and answer
        (refusal or None, the reading, the monotonic time it was taken at). Replies to a person's own message have no hours."""
        checked = _monotonic()
        if pinned is not None:
            now = pinned
        else:
            with self._connect() as conn:   # a fresh reading of the database's clock, the last step before the provider call
                now = db_now(conn)
        if plan.kind == "confirmation" and plan.channel == "sms" and not zones.text_window_open(zones.local(now, plan.zone)):
            return ("quiet_hours", None), now, checked
        return None, now, checked

    def _phase_two_and_three(self, org, plan: Plan, when: datetime, pinned: Optional[datetime] = None) -> int:
        adapter = self._providers.get(plan.provider)
        outcome: tuple
        try:
            if adapter is None:
                raise ProviderError("account", "provider_not_supported")
            refused, when, checked = self._send_gate(plan, pinned)
            if refused is not None:
                outcome = refused
            elif _monotonic() - checked > SEND_CHECK_MAX_SECONDS:
                outcome = ("check_stale", None)  # the hours were judged too long before this call: nothing is sent on them
            elif plan.channel == "sms":
                outcome = ("accepted", adapter.send(plan.creds, to=plan.to, body=plan.body, sender=plan.sender,
                                                    status_callback=plan.status_callback))
            else:
                outcome = ("accepted", adapter.send(plan.creds, to=plan.to, subject=plan.subject, body=plan.body,
                                                    headers=plan.headers, sender=plan.sender))
        except ProviderError as exc:
            outcome = (exc.kind, exc.code)
        except (TimeoutError, OSError):
            outcome = ("unreachable", None)
        except Exception as exc:  # loud-failure-exempt: recorded as dead with its class below; the queue goes on
            log.error("confirmation: the provider adapter failed", send_id=plan.send_id, error=type(exc).__name__)
            outcome = ("defect", type(exc).__name__)
        with self.tx(org) as conn:
            it = conn.execute("SELECT * FROM consentvault.confirmation_send_intent WHERE org_id = %s AND send_id = %s FOR UPDATE",
                              (org, plan.send_id)).fetchone()
            if it["status"] != "sending":
                raise RuntimeError(f"confirmation intent {plan.send_id} left 'sending' while its message was out")
            return self._apply_outcome(conn, org, it, plan, outcome, when)

    def _apply_outcome(self, conn, org, it: dict, plan: Plan, outcome: tuple, when: datetime) -> int:
        what, value = outcome
        if what == "accepted":
            self._accepted(conn, org, it, plan, value, when)
            return 1
        conn.execute("DELETE FROM consentvault.confirmation_page_token WHERE org_id = %s AND send_id = %s", (org, plan.send_id))
        if what == "quiet_hours":
            self._skip(conn, org, it, "quiet_hours", when)
            return 1
        if what == "check_stale":
            self._after_failure(conn, org, it, when, "send_check_stale", plan.attempts, plan.first_attempt_at)
            return 0
        if what in ("retry", "unreachable"):
            error = f"retry:{value}" if what == "retry" else "provider_unreachable"
            self._after_failure(conn, org, it, when, error, plan.attempts, plan.first_attempt_at)
            return 0
        if what == "defect":
            self._dead(conn, org, it, when, "send_error")
            return 1
        if what == "account":
            row = conn.execute("UPDATE consentvault.sending_account SET refusal_count = refusal_count + 1, last_refusal_code = %s"
                               " WHERE org_id = %s AND account_id = %s RETURNING refusal_count, status, channel",
                               (str(value)[:60], org, plan.account_id)).fetchone()
            if row["refusal_count"] >= ACCOUNT_REFUSALS_TO_FAIL and row["status"] != "failing":
                conn.execute("UPDATE consentvault.sending_account SET status = 'failing' WHERE org_id = %s AND account_id = %s",
                             (org, plan.account_id))
                self._alarm_raise(conn, "sending_account_failing", {"account_id": str(plan.account_id), "channel": row["channel"],
                                                                    "last_code": str(value)}, when)
        self._failed(conn, org, it, plan, str(value), when)
        return 1

    def _accepted(self, conn, org, it: dict, plan: Plan, res: dict, when: datetime) -> None:
        pmid = str(res["provider_message_id"])[:200]
        conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'sent', provider_message_id = %s, provider_status = %s,"
                     " at = %s, last_error = NULL, next_attempt_at = NULL WHERE org_id = %s AND send_id = %s",
                     (pmid, (res.get("status") or None), when, org, plan.send_id))
        conn.execute("UPDATE consentvault.sending_account SET refusal_count = 0 WHERE org_id = %s AND account_id = %s"
                     " AND refusal_count > 0", (org, plan.account_id))
        if plan.data_key is not None:
            payload = plan.body if plan.channel == "sms" else json.dumps({"subject": plan.subject, "body": plan.body})
            conn.execute("INSERT INTO consentvault.confirmation_send (org_id, send_id, provider_message_id, body_ct, body_sha256,"
                         " fixed_text_version, template_id, sent_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                         (org, plan.send_id, pmid, tc.encrypt_field(plan.data_key, org, str(plan.send_id), "body_ct", payload),
                          hashlib.sha256(plan.body.encode("utf-8")).hexdigest(), texts.FIXED_TEXT_VERSION, plan.template_id, when))
            from ..gate import record_tenant_contact
            record_tenant_contact(conn, org=org, data_key=plan.data_key, contact_fp=plan.fp, contact_kind=plan.contact_kind,
                                  contact_norm=plan.to, channel=plan.channel, outcome=OUTCOME[plan.kind], ref=str(plan.send_id),
                                  contacted_at=when, recorded_by=RECORDED_BY)
            self._clear_sealed(conn, org, it)
        self._note_status(conn, org, it, "sent", when)

    def _clear_sealed(self, conn, org, it: dict) -> None:
        """A reply's destination and text were sealed under the organization's display key for the queue. Once the contact has a
        key of its own, the text lives sealed under that, and the display-key copies go (an erased contact leaves no number)."""
        if it["dest_ct"] is not None or it["body_ct"] is not None:
            conn.execute("UPDATE consentvault.confirmation_send_intent SET dest_ct = NULL, body_ct = NULL"
                         " WHERE org_id = %s AND send_id = %s", (org, it["send_id"]))

    def _failed(self, conn, org, it: dict, plan: Plan, code: str, when: datetime) -> None:
        stop_recorded = False
        if plan.channel == "sms" and code == "21610":
            channels = self._stop_channels(conn)
            door.record_observed(conn, self.crypto, intake="provider_refusal", fields=dict(
                contact=plan.to, event_type="revoke", channels=channels, purposes=["*"], method="keyword", origin="consumer",
                source_id=self._system_source(conn, SYSTEM_REPLIES), recorded_by="provider_refusal"))
            stop_recorded = True
        conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'failed', failed_code = %s, at = %s, last_error = NULL,"
                     " next_attempt_at = NULL, provider_refusal_stop = %s WHERE org_id = %s AND send_id = %s",
                     (code[:60], when, stop_recorded, org, plan.send_id))
        if stop_recorded:
            self._alarm_raise(conn, "provider_refusal_stop", {"channel": plan.channel}, when)
        if plan.data_key is not None:
            self._clear_sealed(conn, org, it)
        self._note_status(conn, org, it, "failed", when)

    def _after_failure(self, conn, org, it: dict, when: datetime, error: str, attempts: int, first: datetime, count: bool = False) -> None:
        """A retryable failure: schedule the next attempt, or end the send as dead when the schedule or the window is spent."""
        if count:
            conn.execute("UPDATE consentvault.confirmation_send_intent SET attempts = %s, first_attempt_at = %s, last_attempt_at = %s"
                         " WHERE org_id = %s AND send_id = %s", (attempts, first, when, org, it["send_id"]))
        retries_done = attempts - 1
        window = RETRY_WINDOW if it["kind"] == "confirmation" else REPLY_WINDOW
        if retries_done >= len(RETRY_OFFSETS_MINUTES):
            return self._dead(conn, org, it, when, error)
        due = first + timedelta(minutes=RETRY_OFFSETS_MINUTES[retries_done] * (1 + min(max(self._jitter(), 0.0), 0.2)))
        if due > first + window:
            return self._dead(conn, org, it, when, error)
        conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'intent', next_attempt_at = %s, last_error = %s, at = %s"
                     " WHERE org_id = %s AND send_id = %s", (due, error[:60], when, org, it["send_id"]))

    def _dead(self, conn, org, it: dict, when: datetime, cause: str) -> None:
        conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'dead', dead_cause = %s, at = %s, next_attempt_at = NULL"
                     " WHERE org_id = %s AND send_id = %s", (cause[:60], when, org, it["send_id"]))
        if it["kind"] == "optout_reply":
            self._alarm_raise(conn, "optout_reply_dead", {"send_id": str(it["send_id"])}, when)
        self._tidy_dead_or_skipped(conn, org, it)
        self._note_status(conn, org, it, "dead", when)

    def _skip(self, conn, org, it: dict, reason: str, when: datetime) -> None:
        conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'skipped', skip_reason = %s, at = %s, next_attempt_at = NULL"
                     " WHERE org_id = %s AND send_id = %s", (reason, when, org, it["send_id"]))
        self._tidy_dead_or_skipped(conn, org, it)
        self._note_status(conn, org, it, "skipped", when)

    def _tidy_dead_or_skipped(self, conn, org, it: dict) -> None:
        if it["kind"] != "confirmation" and self._contact_exists(conn, it["contact_fp"]):
            self._clear_sealed(conn, org, it)

    def _note_status(self, conn, org, it: dict, status: str, when: datetime) -> None:
        """Tell the record list the latest status of this contact's confirmation (confirmation messages only)."""
        if it["kind"] != "confirmation":
            return
        rid = self._record_of(conn, it["contact_fp"])
        if rid is not None:
            conn.execute("SELECT consentvault.record_index_set_confirmation(%s, %s, %s, %s)", (rid, it["channel"], status, when))
