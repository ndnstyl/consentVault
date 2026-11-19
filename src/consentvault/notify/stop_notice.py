"""Stop notices: tell an organisation's admins, at once, that a stop was recorded. ConsentVault only notifies.

Two halves.

**Recording** (``record_stop_notice``, called by ``ledger.record_tenant_event`` in the event's own transaction): one notice row
carrying the masked contact point, the channels and purposes that moved to denied, and the push versions (so the delivery status
can be read later), plus one queued email per admin and per added recipient (``consentvault.stop_notice_record``). The event and
its notice commit together or not at all.

**Sending** (``StopNoticeSender.run_once``, the worker role): the queued emails of one recipient that lie within 60 seconds of each
other leave as ONE email listing every stop; each email shows the delivery status of every connected system as it stands at send
time (delivered, waiting, refused, none connected). A failed send is the notifier's loud failure (a send log row and an alarm);
the queue row stays for the next run, up to ``MAX_ATTEMPTS``, and the run raises ``StopNoticeSendError`` naming how many failed.

Nothing in an email, a log line or an error carries a full phone number or email address: the notice stores the masked form only
(``records.mask_contact``), and the template refuses anything shaped like a full contact point.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

import psycopg
from psycopg.types.json import Jsonb

from .. import safelog
from ..records import mask_contact
from ..safelog import describe
from .errors import NotifyError, NotifyRefused, SendFailed
from .service import Notifier

log = safelog.get("consentvault.notify.stop_notice")

STOP_EVENT_TYPES = ("revoke", "suppress")
BATCH_WINDOW = timedelta(seconds=60)
MAX_ATTEMPTS = 5
FETCH_LIMIT = 500
ALARM_STOP_NOTICE_REFUSED = "notify.stop_notice_refused"


class StopNoticeError(NotifyError):
    """A stop notice could not be recorded."""


class StopNoticeSendError(NotifyError):
    """One or more stop-notice emails were not sent. The queue rows stay; the send log and the alarm carry the detail."""


def record_stop_notice(conn: psycopg.Connection, *, event_id, contact_fp: str, contact_kind: str, contact_norm: str,
                       event_type: str, changes, stopped_at: datetime) -> uuid.UUID | None:
    """Queue the notice for a just-inserted event, inside the event's transaction. Nothing is queued unless the event is a stop
    that moved at least one (channel, purpose) to denied: repeating a stop that already stands is not a new stop. Any database
    refusal propagates, so the event rolls back with its notice."""
    if event_type not in STOP_EVENT_TYPES:
        return None
    denied = [c for c in changes if c.state == "denied"]
    if not denied:
        return None
    notice_id = uuid.uuid4()
    payload = [{"channel": c.channel, "purpose": c.purpose, "version": c.version} for c in denied]
    try:
        row = conn.execute(
            "SELECT consentvault.stop_notice_record(%s, %s, %s, %s, %s, %s, %s, %s) AS id",
            (notice_id, uuid.UUID(str(event_id)), contact_fp, mask_contact(contact_kind, contact_norm),
             sorted({c.channel for c in denied}), sorted({c.purpose for c in denied}), Jsonb(payload), stopped_at)).fetchone()
    except psycopg.Error as exc:
        raise StopNoticeError(f"the stop notice for event {event_id} could not be queued: {describe(exc)}") from exc
    return row["id"]


@dataclass(frozen=True)
class DueMail:
    mail_id: uuid.UUID
    notice_id: uuid.UUID
    address: str
    queued_at: datetime
    org_name: str
    masked_contact: str
    channels: list
    purposes: list
    stopped_at: datetime
    record_id: uuid.UUID | None


def group_by_window(rows: Iterable[DueMail], window: timedelta = BATCH_WINDOW) -> list[list[DueMail]]:
    """One group per recipient and burst: a row joins its recipient's open group while it was queued within ``window`` of the
    group's first row, else it starts a new group."""
    groups: list[list[DueMail]] = []
    open_group: dict[str, list[DueMail]] = {}
    for row in sorted(rows, key=lambda r: (r.queued_at, str(r.mail_id))):
        g = open_group.get(row.address)
        if g is None or row.queued_at - g[0].queued_at > window:
            g = open_group[row.address] = []
            groups.append(g)
        g.append(row)
    return groups


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
                 max_attempts: int = MAX_ATTEMPTS) -> None:
        self._notifier = notifier
        self._portal = portal_url.rstrip("/")
        self._window = batch_window
        self._max_attempts = max_attempts

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
                self._run_org(conn, token, report, org_transaction)
            except psycopg.Error as exc:
                report.failed += 1
                report.errors.append(f"organisation {org_id}: {describe(exc)}")
                log.error("the stop-notice run for an organisation failed", error=describe(exc))
        if raise_on_error and report.errors:
            raise StopNoticeSendError(f"{report.failed} stop-notice email(s) were not sent: " + "; ".join(report.errors))
        return report

    def _run_org(self, conn, token: str, report: StopNoticeReport, org_transaction: Callable) -> None:
        with org_transaction(conn, token):
            rows = [DueMail(**r) for r in conn.execute("SELECT * FROM consentvault.stop_notice_due(%s, %s)",
                                                       (FETCH_LIMIT, self._max_attempts)).fetchall()]
            groups = group_by_window(rows, self._window)
            ids = sorted({r.notice_id for r in rows}, key=str)
            delivery: dict[uuid.UUID, list[tuple[str, str]]] = {}
            if ids:
                for d in conn.execute("SELECT * FROM consentvault.stop_notice_delivery(%s)", (ids,)).fetchall():
                    delivery.setdefault(d["notice_id"], []).append((d["system_name"], d["status"]))
        for group in groups:
            ok = self._send(group, delivery, report)
            with org_transaction(conn, token):
                conn.execute("SELECT consentvault.stop_notice_mail_done(%s, %s)", ([r.mail_id for r in group], ok))

    def _send(self, group: list[DueMail], delivery: dict, report: StopNoticeReport) -> bool:
        first = group[0]
        stops = [{"contact": r.masked_contact, "channels": r.channels, "purposes": r.purposes, "when": _when(r.stopped_at),
                  "delivery": delivery.get(r.notice_id, [])} for r in group]
        try:
            self._notifier.send("stop_notice", first.address,
                                {"company": first.org_name, "stops": stops, "review_url": f"{self._portal}/records?has_stop=true"})
        except SendFailed as exc:  # the notifier has already written the send log row and raised its alarm
            report.failed += 1
            report.errors.append(f"send failed: {exc.kind}")
            log.error("a stop-notice email was not sent", error_class=exc.kind)
            return False
        except NotifyRefused as exc:  # nothing was sent and the notifier logged nothing: say so loudly here
            self._notifier.alarm.raise_alarm(ALARM_STOP_NOTICE_REFUSED, f"stop_notice refused: {exc.code}")
            report.failed += 1
            report.errors.append(f"refused before sending: {exc.code}")
            log.error("a stop-notice email was refused before sending", error_code=exc.code)
            return False
        report.emails_sent += 1
        report.stops_listed += len(group)
        return True
