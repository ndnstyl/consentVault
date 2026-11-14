"""The inbound door (confirmations.md sections 7 and 9): replies and delivery reports posted by the text provider.

``handle_inbound(inbound_key, headers, body, url)`` runs the checks in the pinned order, and the first that fails ends the
request and records nothing as a reply:

0. a body over 16 KB answers 413 before the signature is computed;
1. the signature is checked over the ``inbound_url`` STORED on the sending account, never over a URL rebuilt from the request;
2. the number must be the account's own: ``To`` on a reply, ``From`` on a delivery report;
3. a provider message id is accepted once per organization (a repeat answers 200 and changes nothing).

Everything a reply causes (the seen-message row, the stop or START event, the reply row, our answer queued) is written in ONE
transaction, so a failure answers 503, the provider retries, and the retry is not taken for a replay. Our answers are sent
after that transaction commits, so a provider fault never undoes a stop.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import urllib.parse
import uuid
from datetime import datetime, timedelta
from typing import Optional

import psycopg

from .. import stopwords
from ..capture import tenant_capture
from ..errors import (ConsentVaultError, EmptyConsentError, InvalidEventError, LedgerError, NormalizationError,
                      UncheckedConsentError, UnknownDisclosureError)
from ..ledger import record_tenant_event
from ..normalize import normalize_phone
from ..release import release_after_tenant_grant
from ..tenancy import crypto as tc
from ..tenancy.errors import TenancyError
from . import texts
from .core import KEY_ERRORS, RECORDED_BY, SYSTEM_REPLIES, ProviderError, Reply, log

MAX_BODY_BYTES = 16384
DISCONNECTED_KEEPS_ACCEPTING = timedelta(days=30)
FAILURE_WINDOW = timedelta(minutes=10)
FAILURES_TO_ALARM = 5
START_WORDS = ("start", "unstop", "yes")
RECORD_ERRORS = (psycopg.Error, LedgerError, ConsentVaultError, TenancyError, *KEY_ERRORS)


def twilio_signature(auth_token: str, url: str, pairs: list[tuple[str, str]]) -> str:
    """Twilio's request signature: base64 HMAC-SHA1, keyed with the account auth token, over the full URL followed by the POST
    parameters sorted by name and concatenated as name then value."""
    data = url + "".join(k + v for k, v in sorted(pairs))
    mac = hmac.new(auth_token.encode("utf-8"), data.encode("utf-8"), hashlib.sha1)  # nosec B324  (the provider's own scheme)
    return base64.b64encode(mac.digest()).decode("ascii")


whole_start_word = stopwords.is_whole_start_word


def read_text(text: str) -> tuple[str, str, str, list[str]]:
    """(verdict, reason, action, matched words). The action is stop, start, help or read (a person reads it)."""
    c = stopwords.classify(text)
    matched = [c.matched] if c.matched else []
    if c.verdict == stopwords.STOP or (c.verdict == stopwords.NEEDS_REVIEW and c.reason == "stop_word_in_longer_message"):
        return c.verdict, c.reason, "stop", matched
    if c.verdict == stopwords.START:
        if whole_start_word(text):
            return c.verdict, c.reason, "start", matched
        return stopwords.NEEDS_REVIEW, "start_word_in_longer_message", "read", matched
    if c.verdict == stopwords.NOT_STOP and stopwords.fold(text) in ("help", "info"):
        return "help", "help_keyword", "help", matched
    return c.verdict, c.reason, "read", matched


class _NotLifted(Exception):
    def __init__(self, causes):
        super().__init__("not lifted")
        self.causes = causes


class InboundMixin:
    def handle_inbound(self, inbound_key: str, headers: dict, body: bytes, url: str) -> Reply:
        """``url`` is the URL as the request arrived; it is NOT used for the signature (section 9, check 1)."""
        conn = self._connect()
        try:
            hit = conn.execute("SELECT org_id, account_id FROM consentvault.confirmation_inbound_lookup(%s)",
                               (inbound_key if isinstance(inbound_key, str) else "",)).fetchone()
        except psycopg.OperationalError:
            return Reply(503, {"error": "service_unavailable"})
        finally:
            conn.close()
        if hit is None:
            return Reply(404, {"error": "not_found"})
        org, account_id = hit["org_id"], hit["account_id"]
        pending: list[uuid.UUID] = []
        try:
            with self.tx(org) as conn:
                answer = self._inbound(conn, org, account_id, headers, body or b"", self._when(conn), pending)
        except RECORD_ERRORS as exc:
            log.error("an inbound text could not be recorded; answering 503 so the provider retries", error=type(exc).__name__)
            return Reply(503, {"error": "service_unavailable"})
        for send_id in pending:
            try:
                self._run_org(org, None, only=send_id)   # our answer is decided on the database's clock, as every send is
            except Exception as exc:  # loud-failure-exempt: the stop is recorded and the answer stays queued for the next pass
                log.error("our answer to an inbound text could not be sent now; it stays queued", error=type(exc).__name__)
        return answer

    # ---- checks ------------------------------------------------------------------------------------------------------------
    def _failure(self, conn, org, account_id, cause: str, now: datetime) -> None:
        conn.execute("INSERT INTO consentvault.confirmation_inbound_failure (org_id, account_id, cause, at) VALUES (%s, %s, %s, %s)",
                     (org, account_id, cause, now))
        n = conn.execute("SELECT count(*) AS n FROM consentvault.confirmation_inbound_failure WHERE org_id = %s AND account_id = %s"
                         " AND at > %s", (org, account_id, now - FAILURE_WINDOW)).fetchone()["n"]
        if n >= FAILURES_TO_ALARM:
            self._alarm_raise(conn, "inbound_signature_failures", {"account_id": str(account_id), "count": n}, now)

    def _inbound(self, conn, org, account_id, headers: dict, body: bytes, now: datetime, pending: list) -> Reply:
        acct = conn.execute("SELECT org_id, account_id, status, provider, sender_ct, inbound_url, provider_replies, inbound_verified_at,"
                            " disconnected_at FROM consentvault.sending_account WHERE org_id = %s AND account_id = %s",
                            (org, account_id)).fetchone()
        if acct is None or (acct["disconnected_at"] is not None
                            and now >= acct["disconnected_at"] + DISCONNECTED_KEEPS_ACCEPTING):
            return Reply(404, {"error": "not_found"})
        if len(body) > MAX_BODY_BYTES:
            self._failure(conn, org, account_id, "too_large", now)
            return Reply(413, {"error": "inbound_too_large"})
        token = self._open_auth_token(conn, org, account_id)
        if token is None:
            return Reply(404, {"error": "not_found"})
        got = {k.lower(): v for k, v in (headers or {}).items()}.get("x-twilio-signature", "")
        try:
            pairs = urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True)
            expected = twilio_signature(token, acct["inbound_url"], pairs)
            valid = hmac.compare_digest(got.encode("ascii"), expected.encode("ascii"))
        except (UnicodeError, AttributeError):
            valid = False
        if not valid:
            self._failure(conn, org, account_id, "signature", now)
            return Reply(401, {"error": "unauthenticated"})
        params = dict(pairs)
        is_report = "MessageStatus" in params
        ours = params.get("From" if is_report else "To", "")
        try:
            number = normalize_phone(ours, "US")
        except NormalizationError:
            number = None
        if number is None or number not in (self._sender_spec(org, acct).get("numbers") or []):
            self._failure(conn, org, account_id, "number_mismatch", now)
            return Reply(403, {"error": "inbound_number_mismatch"})
        if is_report:
            return self._delivery_report(conn, org, params, now)
        return self._inbound_text(conn, org, acct, params, now, pending)

    # ---- a delivery report -------------------------------------------------------------------------------------------------
    def _delivery_report(self, conn, org, params: dict, now: datetime) -> Reply:
        sid, status = params.get("MessageSid", ""), params.get("MessageStatus", "")
        if not sid or not status:
            return Reply(400, {"error": "invalid_request"})
        it = conn.execute("SELECT * FROM consentvault.confirmation_send_intent WHERE org_id = %s AND provider_message_id = %s FOR UPDATE",
                          (org, sid)).fetchone()
        if it is None:
            return Reply(200, {"status": "unknown_message"})
        code = params.get("ErrorCode") or None
        conn.execute("INSERT INTO consentvault.confirmation_send_status (org_id, send_id, provider_status, error_code, received_at)"
                     " VALUES (%s, %s, %s, %s, clock_timestamp())", (org, it["send_id"], status[:40], code[:60] if code else None))
        conn.execute("UPDATE consentvault.confirmation_send_intent SET provider_status = %s WHERE org_id = %s AND send_id = %s",
                     (status[:40], org, it["send_id"]))
        if status == "delivered" and it["status"] == "sent":
            conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'delivered', at = clock_timestamp()"
                         " WHERE org_id = %s AND send_id = %s", (org, it["send_id"]))
            self._note_status(conn, org, it, "delivered", now)
        elif status in ("failed", "undelivered") and it["status"] == "sent":
            conn.execute("UPDATE consentvault.confirmation_send_intent SET status = 'failed', failed_code = %s, at = clock_timestamp()"
                         " WHERE org_id = %s AND send_id = %s", ((code or status)[:60], org, it["send_id"]))
            self._note_status(conn, org, it, "failed", now)
        return Reply(200, {"status": "recorded"})

    # ---- a reply -----------------------------------------------------------------------------------------------------------
    def _inbound_text(self, conn, org, acct: dict, params: dict, now: datetime, pending: list) -> Reply:
        sid, frm, text = params.get("MessageSid", ""), params.get("From", ""), params.get("Body", "")
        if not sid or not frm:
            return Reply(400, {"error": "invalid_request"})
        seen = conn.execute("INSERT INTO consentvault.confirmation_inbound_seen (org_id, provider, provider_message_id, seen_at)"
                            " VALUES (%s, 'twilio', %s, %s) ON CONFLICT DO NOTHING RETURNING 1 AS ok", (org, sid, now)).fetchone()
        if seen is None:
            self._audit(conn, "confirmations.inbound_replayed", "inbound", sid, detail={"provider": "twilio"})
            return Reply(200, {"status": "replayed"})
        try:
            norm = normalize_phone(frm, "US")
        except NormalizationError:
            log.warning("an inbound text came from a sender that is not a phone number; it was not recorded as a reply")
            return Reply(200, {"status": "ignored"})
        fp = self.crypto.contact_fingerprint(org, "phone", norm)
        verdict, reason, action, matched_words = read_text(text)
        if acct["inbound_verified_at"] is None:
            conn.execute("INSERT INTO consentvault.confirmation_connect_test (org_id, account_id, provider_message_id, received_at,"
                         " from_fp, body_ct) VALUES (%s, %s, %s, clock_timestamp(), %s, %s)",
                         (org, acct["account_id"], sid, fp, self._seal(org, sid, "body_ct", text)))
            conn.execute("UPDATE consentvault.sending_account SET inbound_verified_at = clock_timestamp(),"
                         " status = CASE WHEN status = 'awaiting_test_reply' THEN 'connected' ELSE status END"
                         " WHERE org_id = %s AND account_id = %s", (org, acct["account_id"]))
            self._audit(conn, "confirmations.inbound_verified", "sending_account", str(acct["account_id"]))
            if action == "read":  # a plain test message: no reply row, no record, no event
                return Reply(200, {"status": "verified"})
        reply_id = uuid.uuid4()
        record_id = self._record_of(conn, fp)
        record = {"record_id": record_id} if record_id else None
        data_key = self._contact_key(conn, org, fp) if record else None
        if data_key is not None:
            body_ct, from_ct, key_kind = tc.encrypt_field(data_key, org, str(reply_id), "body_ct", text), None, "contact"
        else:
            record = None
            body_ct, key_kind = self._seal(org, str(reply_id), "body_ct", text), "org"
            from_ct = self._seal(org, str(reply_id), "from_ct", norm)
        state, event_id, queued = "to_read", None, []
        settings = self._settings_row(conn)
        if action == "stop":
            ev = record_tenant_event(conn, self.crypto, contact=norm, event_type="revoke", channels=self._stop_channels(conn),
                                     purposes=["*"], method="keyword", origin="consumer",
                                     source_id=self._system_source(conn, SYSTEM_REPLIES), session_ref=f"twilio:{sid}",
                                     recorded_by=RECORDED_BY)
            state, event_id = "stop", uuid.UUID(ev.event_id)
            if settings:
                queued.append(("optout_reply", texts.optout_reply(settings["organization_name"])))
        elif action == "help":
            state = "help"
            if settings:
                queued.append(("help_reply", texts.help_reply(settings["organization_name"], settings["help_email"], settings["help_phone"])))
        elif action == "start":
            state = "start"
            if any(self._stop_on_record(conn, org, fp, ch) for ch in ("sms", "voice", "artificial_voice")):
                granted, why = self._lift_stop(conn, org, acct, norm, fp, text, sid)
                if granted is not None:
                    event_id = uuid.UUID(granted)
                    if settings:
                        queued.append(("start_reply", texts.start_reply(settings["organization_name"])))
                else:
                    state, reason = "to_read", f"{reason}; texts not turned back on: {why}"[:300]
                    if settings:
                        queued.append(("start_reply", texts.start_refused_reply(settings["organization_name"], settings["help_email"],
                                                                                  settings["help_phone"])))
        conn.execute(
            "INSERT INTO consentvault.confirmation_reply (org_id, reply_id, account_id, from_fp, matched_record_id, body_ct, from_ct,"
            " key_kind, received_at, provider_message_id, verdict, reason, matched_words, state, event_id)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s,"   # the receipt time is the database's, strictly after the last reply's so the list keeps their order
            " greatest(clock_timestamp(), coalesce((SELECT max(r.received_at) FROM consentvault.confirmation_reply r WHERE r.org_id = %s)"
            " + interval '1 microsecond', '-infinity'::timestamptz)), %s, %s, %s, %s, %s, %s)",
            (org, reply_id, acct["account_id"], fp, record["record_id"] if record else None, body_ct, from_ct, key_kind,
             org, sid, verdict, reason[:300], matched_words, state, event_id))
        for kind, message in queued:
            pending.append(self._queue_reply(conn, org, kind=kind, reply_id=reply_id, fp=fp, dest=norm, body=message, now=now))
        return Reply(200, {"status": state})

    def _lift_stop(self, conn, org, acct: dict, norm: str, fp: str, text: str, sid: str) -> tuple[Optional[str], str]:
        """START after a stop: the person's own message is a keyword grant naming texts, and the core's release rule decides.
        Returns (the grant's event id, "") when it lifted the stop, else (None, why). Nothing is written when it did not."""
        if not self._provider_holds(conn, org, acct, sid, norm):
            return None, "provider_unconfirmed"
        last = conn.execute("SELECT disclosure_sha256, brand_ids, purposes FROM consentvault.event WHERE org_id = %s AND contact_fp = %s"
                            " AND event_type = 'grant' ORDER BY seq DESC LIMIT 1", (org, fp)).fetchone()
        if last is None:
            return None, "no_held_disclosure"
        try:
            with conn.transaction():  # a savepoint: a START that lifts nothing leaves no grant behind
                ev = tenant_capture(conn, self.crypto, contact=norm, event_type="grant", channels=["sms"],
                                    purposes=list(last["purposes"]), method="keyword", origin="consumer", checked=True,
                                    contact_verification="inbound_keyword", inbound_message=text,
                                    disclosure_sha256=last["disclosure_sha256"], brand_ids=list(last["brand_ids"] or []),
                                    session_ref=f"twilio:{sid}", recorded_by=RECORDED_BY,
                                    source_id=self._system_source(conn, SYSTEM_REPLIES))
                result = release_after_tenant_grant(conn, self.crypto, ev.event_id)
                if "sms" not in result.released_channels:
                    raise _NotLifted(sorted(result.refusals) or ["not_released"])
        except _NotLifted as refused:
            return None, ",".join(refused.causes)
        except (InvalidEventError, EmptyConsentError, UncheckedConsentError, UnknownDisclosureError) as exc:
            return None, type(exc).__name__
        return ev.event_id, ""

    def _provider_holds(self, conn, org, acct: dict, sid: str, number: str) -> bool:
        """A stop is lifted only on a message the provider itself confirms it received from this number. Anything else (no way to
        ask, an answer of no, an unreachable provider, a credential that will not open) leaves the stop in place."""
        check = getattr(self._providers.get(acct["provider"]), "message_exists", None)
        if check is None:
            return False
        try:
            return bool(check(self._open_credentials(conn, org, acct), message_id=sid, from_number=number))
        except (ProviderError, TimeoutError, OSError, *KEY_ERRORS) as exc:
            log.warning("a START could not be confirmed with the provider; the stop stays", error=type(exc).__name__)
            return False

    def _queue_reply(self, conn, org, *, kind: str, reply_id, fp: str, dest: str, body: str, now: datetime) -> uuid.UUID:
        """Queue our answer to a person's message. It is tried at once after the transaction commits, and by the sender after that."""
        send_id = uuid.uuid4()
        conn.execute("INSERT INTO consentvault.confirmation_send_intent (org_id, send_id, kind, reply_id, contact_fp, channel, status,"
                     " created_at, at, dest_ct, body_ct) VALUES (%s, %s, %s, %s, %s, 'sms', 'intent', %s, %s, %s, %s)",
                     (org, send_id, kind, reply_id, fp, now, now, self._seal(org, str(send_id), "dest_ct", dest),
                      self._seal(org, str(send_id), "body_ct", body)))
        return send_id
