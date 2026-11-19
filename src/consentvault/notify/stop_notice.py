"""Stop notices: tell an organisation's admins that a stop was recorded. ConsentVault only notifies.

Two halves.

**Recording** (``record_stop_notice``, called by ``ledger.record_tenant_event`` in the event's own transaction): one notice row
carrying the contact masked to its last four digits (or first letter plus domain) and sealed under the organisation's display key
(the way ``record_index.mask_ct`` is; ``erase_contact`` blanks it), the channels and purposes that moved to denied, and the push
versions, plus one queued email per admin and per added recipient. The notice is written inside a savepoint: a failure there never
refuses or rolls back the stop; it raises an operator alarm and the stop commits. A stop that queued no email at all (no admin
address, no added recipient) raises an alarm too.

**Sending** (``StopNoticeSender.run_once``, the worker role, which holds no key: the queued row carries the masked text, blanked when
the email is sent and by an erasure): rows are claimed with a lease (``FOR UPDATE SKIP LOCKED``), so
overlapping runs never take the same row, and a recipient's rows are held until their oldest is ``BATCH_WINDOW`` old, so a burst of
stops leaves as ONE email. A claimed row whose lease runs out with no answer is never sent again (it may have been sent); an alarm
names it. A failed send is the notifier's loud failure (a send-log row and an alarm) and is retried up to ``MAX_ATTEMPTS``; the
attempt that runs out writes a send-log row and an alarm. One stop that cannot be rendered never blocks the others: the group is
split and each stop is sent on its own. One organisation's error never stops the rest.

Nothing in an email, a log line or an error carries a full phone number or email address.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

import psycopg
from psycopg.types.json import Jsonb

from .. import safelog
from ..alarms import AlarmWriteError, raise_operator_alarm
from ..safelog import describe
from ..tenancy import crypto as tc
from ..tenancy.errors import FieldCryptoError, KeyProviderError, TenantTokenError
from .errors import NotifyError, NotifyRefused, SendFailed
from .service import Notifier

log = safelog.get("consentvault.notify.stop_notice")

STOP_EVENT_TYPES = ("revoke", "suppress")
BATCH_WINDOW = timedelta(seconds=60)
LEASE_SECONDS = 300
MAX_ATTEMPTS = 5
FETCH_LIMIT = 500
PAGE_LIMIT = 500
MASK_COLUMN = "stop_mask"
UNSHOWN = "contact not shown"
ALARM_NOT_RECORDED = "stop_notice.not_recorded"
ALARM_NO_RECIPIENTS = "stop_notice.no_recipients"
ALARM_STOP_NOTICE_REFUSED = "notify.stop_notice_refused"
ALARM_STOP_NOTICE_GAVE_UP = "notify.stop_notice_gave_up"
ALARM_STOP_NOTICE_UNKNOWN = "notify.stop_notice_unknown"
ALARM_STOP_NOTICE_ORPHANED = "notify.stop_notice_orphaned"
ALARM_STOP_NOTICE_LEASE_LOST = "notify.stop_notice_lease_lost"
ALARM_MASK_NOT_SEALED = "stop_notice.mask_not_sealed"
RUN_SECONDS = 240


class StopNoticeError(NotifyError):
    """A stop notice could not be recorded."""


class StopNoticeSendError(NotifyError):
    """One or more stop-notice emails were not sent. The queue rows stay; the send log and the alarm carry the detail."""


def notice_mask(kind: str, norm: str) -> str:
    """The contact as a notice shows it: ``***-0177`` (the last four digits only, no area code) for a number, ``d***@example.com``
    (first letter plus domain) for an email address."""
    if kind == "email":
        local, _, domain = norm.partition("@")
        if not local or not domain:
            raise StopNoticeError("an email address to mask has no local part or domain")
        return f"{local[0]}***@{domain}"
    if kind == "phone":
        digits = "".join(ch for ch in norm if ch.isdigit())
        if len(digits) < 4:
            raise StopNoticeError("a phone number to mask has fewer than four digits")
        return f"***-{digits[-4:]}"
    raise StopNoticeError(f"cannot mask a contact point of kind {kind!r}")


def read_mask(crypto, org_id, notice_id, blob) -> str:
    """The unsealed mask of a notice, or ``UNSHOWN`` when it was never sealed, was blanked by an erasure, or cannot be opened."""
    if blob is None:
        return UNSHOWN
    try:
        return tc.decrypt_text(crypto.display_key(org_id), org_id, str(notice_id), MASK_COLUMN, bytes(blob))
    except (KeyProviderError, FieldCryptoError) as exc:
        log.error("a stop notice's mask could not be opened", error=type(exc).__name__)
        return UNSHOWN


def _raise_alarm(conn: psycopg.Connection, name: str, error_class: str, event_id) -> None:
    try:
        raise_operator_alarm(conn, name=name, error_class=error_class, ref_kind="event", ref_id=event_id)
    except AlarmWriteError as exc:
        # the stop is recorded and stands; the missing alarm is itself loud, never silent
        log.critical("a stop notice alarm was NOT written; the operator must be told by another route", alarm=name,
                     event_id=str(event_id), error=type(exc).__name__)


def record_stop_notice(conn: psycopg.Connection, crypto, *, org, event_id, contact_fp: str, contact_kind: str, contact_norm: str,
                       event_type: str, changes, stopped_at: datetime) -> uuid.UUID | None:
    """Queue the notice for a just-inserted event, inside the event's transaction. Nothing is queued unless the event is a stop that
    moved at least one (channel, purpose) to denied. A failure to write the notice never refuses the stop: it is rolled back to a
    savepoint, an operator alarm is raised, and the stop commits."""
    if event_type not in STOP_EVENT_TYPES:
        return None
    denied = [c for c in changes if c.state == "denied"]
    if not denied:
        return None
    notice_id = uuid.uuid4()
    mask_ct = mask_text = None
    try:
        mask_text = notice_mask(contact_kind, contact_norm)
        mask_ct = tc.encrypt_field(crypto.display_key(org), org, str(notice_id), MASK_COLUMN, mask_text)
    except (KeyProviderError, StopNoticeError) as exc:
        log.error("a stop notice is recorded without its mask", error=type(exc).__name__, event_id=str(event_id))
        _raise_alarm(conn, ALARM_MASK_NOT_SEALED, type(exc).__name__, event_id)
    payload = [{"channel": c.channel, "purpose": c.purpose, "version": c.version} for c in denied]
    try:
        with conn.transaction():  # a savepoint: a failure here undoes the notice only
            queued = conn.execute(
                "SELECT consentvault.stop_notice_record(%s, %s, %s, %s, %s, %s, %s, %s, %s) AS n",
                (notice_id, uuid.UUID(str(event_id)), contact_fp, mask_ct, mask_text, sorted({c.channel for c in denied}),
                 sorted({c.purpose for c in denied}), Jsonb(payload), stopped_at)).fetchone()["n"]
    except psycopg.Error as exc:
        log.error("a stop notice could not be written; the stop stands and an alarm is raised", alarm=ALARM_NOT_RECORDED,
                  event_id=str(event_id), error=type(exc).__name__)
        _raise_alarm(conn, ALARM_NOT_RECORDED, type(exc).__name__, event_id)
        return None
    if queued == 0:
        _raise_alarm(conn, ALARM_NO_RECIPIENTS, "NoRecipient", event_id)
    return notice_id


@dataclass(frozen=True)
class DueMail:
    mail_id: uuid.UUID
    notice_id: uuid.UUID
    address: str
    queued_at: datetime
    attempts: int
    org_name: str
    contact: str
    channels: list
    purposes: list
    stopped_at: datetime
    record_id: uuid.UUID | None


def group_by_recipient(rows: Iterable[DueMail]) -> list[list[DueMail]]:
    """One group per recipient: every row the claim took for an address leaves as one email. The database decides what is due (a
    recipient's rows are held until the oldest is ``BATCH_WINDOW`` old), so a burst is merged there, not re-split here."""
    groups: dict[str, list[DueMail]] = {}
    for row in sorted(rows, key=lambda r: (r.queued_at, str(r.mail_id))):
        groups.setdefault(row.address, []).append(row)
    return list(groups.values())


def _when(at: datetime) -> str:
    return at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass
class StopNoticeReport:
    emails_sent: int = 0
    stops_listed: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


class StopNoticeSender:
    """Sends the queued stop notices of every dispatched organisation. Runs as the worker role beside the sync worker."""

    def __init__(self, notifier: Notifier, *, portal_url: str, batch_window: timedelta = BATCH_WINDOW,
                 max_attempts: int = MAX_ATTEMPTS, lease_seconds: int = LEASE_SECONDS) -> None:
        self._notifier = notifier
        self._portal = portal_url.rstrip("/")
        self._window = batch_window
        self._max_attempts = max_attempts
        self._lease = lease_seconds

    def run_once(self, conn: psycopg.Connection, *, raise_on_error: bool = True) -> StopNoticeReport:
        from ..tenancy.tokens import org_transaction
        report = StopNoticeReport()
        try:
            org_ids = [r["org_id"] for r in conn.execute("SELECT * FROM consentvault.dispatch_org_ids('sync') AS org_id")]
        except psycopg.Error as exc:
            raise StopNoticeSendError(f"the stop-notice sender could not list the organisations: {describe(exc)}") from exc
        for org_id in org_ids:
            try:
                token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]
                self._run_org(conn, org_id, token, report, org_transaction)
            except (psycopg.Error, TenantTokenError, NotifyError, KeyProviderError) as exc:
                report.failed += 1
                report.errors.append(f"organisation {org_id}: {type(exc).__name__}")
                log.error("the stop-notice run for an organisation failed", org_id=str(org_id), error=type(exc).__name__)
        if raise_on_error and report.errors:
            raise StopNoticeSendError(f"{report.failed} stop-notice failure(s): " + "; ".join(report.errors))
        return report

    def _run_org(self, conn, org_id, token: str, report: StopNoticeReport, org_transaction: Callable) -> None:
        with org_transaction(conn, token):
            swept = conn.execute("SELECT * FROM consentvault.stop_notice_sweep(%s)", (self._max_attempts,)).fetchone()
        if swept["lost"]:
            self._notifier.alarm.raise_alarm(ALARM_STOP_NOTICE_UNKNOWN, f"{swept['lost']} stop notice email(s) were claimed and never answered")
            report.failed += 1
            report.errors.append(f"organisation {org_id}: {swept['lost']} email(s) with an unknown outcome")
        if swept["orphaned"]:
            self._notifier.alarm.raise_alarm(ALARM_STOP_NOTICE_ORPHANED, f"{swept['orphaned']} stop notice email(s) have no address to go to")
            report.failed += 1
            report.errors.append(f"organisation {org_id}: {swept['orphaned']} email(s) with no address")
        handled: list[uuid.UUID] = []
        deadline = time.monotonic() + RUN_SECONDS
        while time.monotonic() < deadline:  # one recipient per claim: one send, always inside its lease
            with org_transaction(conn, token):
                raw = conn.execute("SELECT * FROM consentvault.stop_notice_claim(%s, %s, %s, %s, %s)",
                                   (FETCH_LIMIT, self._max_attempts, int(self._window.total_seconds()), self._lease, handled)).fetchall()
                if not raw:
                    return
                rows = [DueMail(contact=r["mask_text"] or UNSHOWN, **{k: v for k, v in r.items() if k != "mask_text"}) for r in raw]
                delivery: dict[uuid.UUID, list[tuple[str, str]]] = {}
                for d in conn.execute("SELECT * FROM consentvault.stop_notice_delivery(%s)",
                                      (sorted({r.notice_id for r in rows}, key=str),)).fetchall():
                    delivery.setdefault(d["notice_id"], []).append((d["system_name"], d["status"]))
            handled += [r.mail_id for r in rows]
            self._deliver(conn, token, rows, delivery, report, org_transaction)
        log.warning("the stop-notice pass reached its time limit; the rest waits for the next pass", org_id=str(org_id))

    def _deliver(self, conn, token: str, rows: list[DueMail], delivery: dict, report: StopNoticeReport, org_transaction: Callable) -> None:
        groups = group_by_recipient(rows)
        in_flight: list[DueMail] | None = None
        finished = 0
        try:
            for group in groups:
                in_flight = group
                ok, bad = self._send_group(group, delivery, report)
                with org_transaction(conn, token):
                    moved = 0
                    if ok:
                        moved += conn.execute("SELECT consentvault.stop_notice_mail_done(%s, true, %s) AS n",
                                              ([r.mail_id for r in ok], self._max_attempts)).fetchone()["n"]
                    if bad:
                        moved += conn.execute("SELECT consentvault.stop_notice_mail_done(%s, false, %s) AS n",
                                              ([r.mail_id for r in bad], self._max_attempts)).fetchone()["n"]
                in_flight = None
                finished += 1
                if moved != len(group):  # a lease ran out under this send: its outcome was not recorded
                    self._notifier.alarm.raise_alarm(ALARM_STOP_NOTICE_LEASE_LOST, f"{len(group) - moved} stop notice row(s) lost their claim")
                    report.failed += 1
                    report.errors.append(f"{len(group) - moved} row(s) lost their claim")
                for r in bad:
                    if r.attempts >= self._max_attempts:
                        self._notifier.record_failure("stop_notice", r.address, "attempts_exhausted", ALARM_STOP_NOTICE_GAVE_UP)
        finally:
            # rows never attempted go back to the queue; only the row actually in flight may turn unknown
            never = [r.mail_id for g in groups[finished:] if g is not in_flight for r in g]
            if never:
                with org_transaction(conn, token):
                    conn.execute("SELECT consentvault.stop_notice_mail_release(%s)", (never,))

    def _send_group(self, group: list[DueMail], delivery: dict, report: StopNoticeReport) -> tuple[list[DueMail], list[DueMail]]:
        first = group[0]
        stops = [{"contact": r.contact, "channels": r.channels, "purposes": r.purposes, "when": _when(r.stopped_at),
                  "delivery": delivery.get(r.notice_id, [])} for r in group]
        try:
            self._notifier.send("stop_notice", first.address,
                                {"company": first.org_name, "stops": stops, "review_url": f"{self._portal}/records?has_stop=true"})
        except SendFailed as exc:  # the notifier has already written the send log row and raised its alarm
            report.failed += 1
            report.errors.append(f"send failed: {exc.kind}")
            log.error("a stop-notice email was not sent", error_class=exc.kind)
            return [], group
        except NotifyRefused as exc:
            log.error("a stop-notice email was refused before sending", error_code=exc.code)
            if len(group) == 1:
                self._notifier.record_failure("stop_notice", first.address, f"refused {exc.code}", ALARM_STOP_NOTICE_REFUSED)
                report.failed += 1
                report.errors.append(f"refused before sending: {exc.code}")
                return [], group
            ok: list[DueMail] = []
            bad: list[DueMail] = []
            for row in group:  # one bad stop never blocks the others: each is sent on its own
                o, b = self._send_group([row], delivery, report)
                ok += o
                bad += b
            return ok, bad
        report.emails_sent += 1
        report.stops_listed += len(group)
        return group, []
