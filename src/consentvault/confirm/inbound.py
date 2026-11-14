"""The inbound door (confirmations.md sections 7 and 9): replies and delivery reports posted by the text provider.

``handle_inbound(inbound_key, headers, body, url)`` runs the checks in the pinned order, and the first that fails ends the
request and records nothing as a reply:

0. a body over 16 KB answers 413 before the signature is computed;
1. the signature is checked over the ``inbound_url`` STORED on the sending account (on the fallback door, over its fallback form,
   ``signed_address``), never over a URL rebuilt from the request. Size and signature are checked before anything is stored:
   an unsigned body is never written;
2. the number must be the account's own: ``To`` on a reply, ``From`` on a delivery report. A number not in the list kept at
   connect is read from the provider once, live (a number added to a Messaging Service later is taken); a STOP to a number
   that is still not the account's raises the signature-failure alarm at once;
3. a provider message id is accepted once per organization (a repeat answers 200 and changes nothing).

Everything a reply causes (the seen-message row, the stop or START event, the reply row, our answer queued) is written in ONE
transaction, so a failure answers 503 and the retry is not taken for a replay. Twilio does NOT retry a messaging webhook by
default (one retry, on a connect timeout only), so the number is pointed at the primary address with the connection overrides
``#rp=all&rc=3`` (retry on any failure; Twilio leaves the fragment out of the signature) and at the fallback address, which the
edge spools durably before the vault sees it (edge gateway.ts, the inbound spool). Our answers are sent after that transaction
commits, so a provider fault never undoes a stop.
"""

from __future__ import annotations

import base64
import json
import hashlib
import hmac
import urllib.parse
import uuid
from datetime import datetime, timedelta
from typing import Optional

import psycopg

from .. import stopwords
from ..errors import (ConsentVaultError, EmptyConsentError, InvalidEventError, LedgerError, NormalizationError,
                      UncheckedConsentError, UnknownDisclosureError)
from ..normalize import normalize_phone
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


PRIMARY_SEGMENT = "/v1/confirmations/inbound/"
FALLBACK_SEGMENT = "/v1/confirmations/inbound-fallback/"


def signed_address(stored: str, fallback: bool) -> str:
    """The address the provider signed: the stored inbound address, or its fallback form (the same key under the fallback
    path), derived from the stored address only."""
    if not fallback:
        return stored
    if stored.count(PRIMARY_SEGMENT) != 1:
        raise ValueError("the stored inbound address is not an inbound address")
    return stored.replace(PRIMARY_SEGMENT, FALLBACK_SEGMENT, 1)


def twilio_signature(auth_token: str, url: str, pairs: list[tuple[str, str]]) -> str:
    """Twilio's request signature: base64 HMAC-SHA1, keyed with the account auth token, over the full URL followed by the POST
    parameters sorted by name and concatenated as name then value."""
    data = url + "".join(k + v for k, v in sorted(pairs))
    mac = hmac.new(auth_token.encode("utf-8"), data.encode("utf-8"), hashlib.sha1)  # nosec B324 -- Twilio's own request-signature scheme is HMAC-SHA1; not ours to change
    return base64.b64encode(mac.digest()).decode("ascii")


read_text = stopwords.read_text


class _NotLifted(Exception):
    def __init__(self, causes):
        super().__init__("not lifted")
        self.causes = causes


class InboundMixin:
    def handle_inbound(self, inbound_key: str, headers: dict, body: bytes, url: str, fallback: bool = False) -> Reply:
        """``url`` is the URL as the request arrived; it is NOT used for the signature (section 9, check 1). ``fallback``: the
        post came to the fallback door, so its signature is over the fallback form of the stored address."""
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
            with self.tx(org) as check_conn:  # size and signature first, the failure counted and committed: nothing unsigned is stored
                checked = self._checked(check_conn, org, account_id, headers, body or b"", self._when(check_conn), fallback)
            if isinstance(checked, Reply):
                return checked
            with self.tx(org) as raw_conn:  # the signed text, as received, is committed on its own: a later failure never takes it back
                stored = self._store_raw(raw_conn, org, account_id, headers, body or b"")
            with self.tx(org) as conn:
                answer = self._inbound(conn, org, account_id, headers, body or b"", self._when(conn), pending, stored, fallback)
        except RECORD_ERRORS as exc:
            log.error("an inbound text could not be recorded; answering 503 so the provider retries", error=type(exc).__name__)
            return Reply(503, {"error": "service_unavailable"})
        for send_id in pending:
            try:
                self._run_org(org, None, only=send_id)   # our answer is decided on the database's clock, as every send is
            except Exception as exc:  # loud-failure-exempt: the stop is recorded and the answer stays queued for the next pass
                log.error("our answer to an inbound text could not be sent now; it stays queued", error=type(exc).__name__)
        return answer

    def rebuild_replies(self, org) -> int:
        """The rebuild for texts: project every stored reply of ``org`` that has no outcome, in arrival order. Safe to run twice."""
        from .. import door
        from ..rawpost import RawPostWriter

        with self.tx(org) as conn:
            backend = door.TenantLedgerBackend(self.crypto, region="US", defaults={
                "channels": self._stop_channels(conn), "source_id": self._system_source(conn, SYSTEM_REPLIES),
                "recorded_by": RECORDED_BY})
            return len(door.project_pending(RawPostWriter(crypto=self.crypto), conn, lambda c: c.transaction(), backend,
                                             intakes=("sms_reply",)))

    # ---- checks ------------------------------------------------------------------------------------------------------------
    def _failure(self, conn, org, account_id, cause: str, now: datetime) -> None:
        conn.execute("INSERT INTO consentvault.confirmation_inbound_failure (org_id, account_id, cause, at) VALUES (%s, %s, %s, %s)",
                     (org, account_id, cause, now))
        n = conn.execute("SELECT count(*) AS n FROM consentvault.confirmation_inbound_failure WHERE org_id = %s AND account_id = %s"
                         " AND at > %s", (org, account_id, now - FAILURE_WINDOW)).fetchone()["n"]
        if n >= FAILURES_TO_ALARM:
            self._alarm_raise(conn, "inbound_signature_failures", {"account_id": str(account_id), "count": n}, now)

    def _store_raw(self, conn, org, account_id, headers: dict, body: bytes):
        """The request, exactly as received, is the first thing written (before any check). Raises StoreUnavailable."""
        from ..rawpost import Fact, RawPostWriter, RawRequest

        req = RawRequest(intake="sms_reply", method="POST", path=f"/v1/connectors/sms/{account_id}", query="",
                         headers=tuple((str(k), str(v)) for k, v in (headers or {}).items()), body=bytes(body),
                         facts=(Fact("vault", "account_id", str(account_id)),))
        return RawPostWriter(crypto=self.crypto).write(conn, lambda c: c.transaction(), req)

    def _checked(self, conn, org, account_id, headers: dict, body: bytes, now: datetime, fallback: bool = False):
        """Checks 0 and 1 (and the account's own state): the account row and the parsed pairs, or the Reply that ends the
        request. A failure is counted in this transaction."""
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
            expected = twilio_signature(token, signed_address(acct["inbound_url"], fallback), pairs)
            valid = hmac.compare_digest(got.encode("ascii"), expected.encode("ascii"))
        except (UnicodeError, AttributeError, ValueError):
            valid = False
        if not valid:
            self._failure(conn, org, account_id, "signature", now)
            return Reply(401, {"error": "unauthenticated"})
        return acct, pairs

    def _inbound(self, conn, org, account_id, headers: dict, body: bytes, now: datetime, pending: list, stored=None,
                 fallback: bool = False) -> Reply:
        checked = self._checked(conn, org, account_id, headers, body, now, fallback)
        if isinstance(checked, Reply):
            return checked
        acct, pairs = checked
        params = dict(pairs)
        is_report = "MessageStatus" in params
        if not is_report and stored is not None and params.get("MessageSid"):
            self._record_provider_authentication(org, stored, params)
        ours = params.get("From" if is_report else "To", "")
        try:
            number = normalize_phone(ours, "US")
        except NormalizationError:
            number = None
        numbers = self._sender_spec(org, acct).get("numbers") or []
        if number is not None and number not in numbers:
            numbers = self._live_numbers(conn, org, acct) or numbers
        if number is None or number not in numbers:
            self._failure(conn, org, account_id, "number_mismatch", now)
            if not is_report and read_text(params.get("Body", ""))[2] == "stop":
                # A person's STOP that cannot be taken: the first one is an alarm, not the fifth
                self._alarm_raise(conn, "inbound_signature_failures", {"account_id": str(account_id), "cause": "stop_number_mismatch"}, now)
            return Reply(403, {"error": "inbound_number_mismatch"})
        if is_report:
            return self._delivery_report(conn, org, params, now)
        return self._inbound_text(conn, org, acct, params, now, pending, stored, body)

    def _live_numbers(self, conn, org, acct) -> Optional[list]:
        """The sender's numbers read from the provider now, kept on the account when they changed; None when it cannot say."""
        try:
            spec = self._sender_spec(org, acct)
            creds = {**self._open_credentials(conn, org, acct), "sender": spec}
            info = self._providers[acct["provider"]].read_sender(creds)
        except (ProviderError, TimeoutError, KeyError, *KEY_ERRORS) as exc:  # loud-failure-exempt: the post is still refused 403 and counted; the class is logged
            log.warning("the sender's numbers could not be read live; the stored list stands", error=type(exc).__name__)
            return None
        fresh = []
        for n in info.get("numbers") or []:
            try:
                fresh.append(normalize_phone(n, "US"))
            except NormalizationError:  # loud-failure-exempt: a number the provider lists that is not a phone number is not ours to take
                continue
        if fresh and sorted(fresh) != sorted(spec.get("numbers") or []):
            conn.execute("UPDATE consentvault.sending_account SET sender_ct = %s WHERE org_id = %s AND account_id = %s",
                         (self._seal(org, str(acct["account_id"]), "sender_ct", json.dumps({**spec, "numbers": fresh}, sort_keys=True)),
                          org, acct["account_id"]))
        return fresh

    def _record_provider_authentication(self, org, stored, params: dict) -> None:
        """The provider's signature checked out: record that beside the stored reply, committed on its own, for every validly
        signed reply, before the seen-message check and before anything reads the text. A reply that is not a stop, and a second
        copy of any reply, are then settled by the projection like every other post; none waits for authentication forever. A
        reply that is a stop carries the settings it is projected with (the channels and the system source), made here, in this
        committed transaction."""
        from .. import door
        from ..rawpost import RawPostWriter

        defaults = None
        with self.tx(org) as auth_conn:
            if read_text(params.get("Body", ""))[2] == "stop":
                defaults = {"channels": self._stop_channels(auth_conn), "source_id": self._system_source(auth_conn, SYSTEM_REPLIES),
                            "recorded_by": RECORDED_BY}
            door.authenticate_text(RawPostWriter(crypto=self.crypto), auth_conn, lambda c: c.transaction(), stored,
                                   f"twilio:{params['MessageSid']}", defaults=defaults, region="US")

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
    def _inbound_text(self, conn, org, acct: dict, params: dict, now: datetime, pending: list, stored=None, body: bytes = b"") -> Reply:
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
            from .. import door
            from ..rawpost import RawPostWriter

            writer = RawPostWriter(crypto=self.crypto)
            with self.tx(org) as auth_conn:  # committed on its own first: a later failure never takes the check back
                # the settings the stop is projected with are stored beside the post, so the source they name is made here, in
                # this committed transaction, and not in the one a failure may roll back
                defaults = {"channels": self._stop_channels(auth_conn), "source_id": self._system_source(auth_conn, SYSTEM_REPLIES),
                            "recorded_by": RECORDED_BY}
                door.authenticate_text(writer, auth_conn, lambda c: c.transaction(), stored, f"twilio:{sid}",
                                       defaults=defaults, region="US")
            outcome = door.project_text_reply(
                writer, conn, lambda c: c.transaction(), self.crypto, stored, bytes(body),
                request_key=f"twilio:{sid}", region="US", defaults=defaults)
            state, event_id = "stop", uuid.UUID(outcome.event_id)
            if settings:
                queued.append(("optout_reply", texts.optout_reply(settings["organization_name"])))
        elif action == "help":
            state = "help"
            if settings:
                queued.append(("help_reply", texts.help_reply(settings["organization_name"], settings["help_email"], settings["help_phone"])))
        elif action == "start":
            # A START text restores nothing (ruling: the way back is a form the person fills in). It is stored as received (the
            # raw post and this reply row), writes no event and lifts no stop; the customer's own automation answers it with a
            # link to its re-engagement form, and a grant from that form is the only way consent returns.
            state = "start"
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
