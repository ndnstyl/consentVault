"""The periodic reconcile and the nightly full scan of a Twenty system (contracts: twenty.md sections 3.5, 6.3).

A webhook is not guaranteed (Twenty does not retry one), so every ``reconcile_interval_minutes`` (default 15) the reconcile reads
every Person whose ``updatedAt`` is past the system's watermark, oldest first, and for each one:
1. applies the inbound rules (``twenty_receiver.apply_person_event``: a flag transition records a stop, an erased point is
   skipped, a changed set of contact points queues refreshes), under a ``capture`` token, exactly as the webhook would, with
   the same external references so the two dedupe;
2. applies the scan rule under the Person's lease (rule R21): the fields are recomputed from the Person's remaining
   contributing contacts and written when they differ, blank only when none is left. A correction that finds Twenty showing a
   channel less restrictive than the ledger, with no write of that Person queued or in flight, raises ``connector.stop_hidden``
   EVERY time (rule R28), never folded into the drift count.
The watermark advances only after a page is fully processed. The full scan reads every Person, nightly and after a version
change. Three runs in a row that fail to complete raise an alarm: a missing stop path must never look quiet.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from ...safelog import describe
from ...tenancy.tokens import org_transaction
from ..errors import SyncError
from . import twenty_api as api
from .twenty import (ALARM_HIDDEN, LEASE_SECONDS, SEND_DEADLINE_SECONDS, derive_fields, differs, hides_a_stop, load_keys,
                     person_id_hash)
from .twenty_receiver import apply_person_event, record_counts

PAGE_DEADLINE_SECONDS = 30
FULL_SCAN_DEADLINE_SECONDS = 6 * 3600
FAILURES_ALARM = 3
ALARM_RECONCILE = "connector.reconcile_failing"


@dataclass
class ReconcileReport:
    read: int = 0
    drifted: int = 0
    corrected: int = 0
    stops_found: int = 0
    stops_hidden: int = 0
    lease_busy: int = 0
    refused_late_send: int = 0
    pages: int = 0
    complete: bool = False
    error: str | None = None


class TwentyReconcile:
    """One system's reconcile. ``app`` holds a ``capture`` token (inbound rules); ``worker`` a ``worker:sync`` one (writes)."""

    def __init__(self, crypto, custody, transport: api.CallTransport, *, clock: Callable[[], datetime],
                 monotonic: Callable[[], float] = time.monotonic, region: str | None = None) -> None:
        self.crypto, self.custody, self.transport = crypto, custody, transport
        self.clock, self.monotonic, self.region = clock, monotonic, region

    def run(self, app, capture_token: str, worker, worker_token: str, org_id, system_id, *, full: bool = False) -> ReconcileReport:
        rep = ReconcileReport()
        started = self.monotonic()
        with org_transaction(worker, worker_token):
            sysrow = next((s for s in worker.execute("SELECT * FROM consentvault.connector_systems()").fetchall()
                           if s["system_id"] == system_id), None)
            if sysrow is None:
                raise SyncError(f"system {system_id} is not a live Twenty system of this organisation")
            keys = load_keys(worker, self.custody, org_id, system_id)
        base = (sysrow["config"] or {}).get("base_url") or sysrow["endpoint"]
        holder = uuid.uuid4()
        page_started = [self.monotonic()]

        def before() -> None:
            if self.monotonic() - page_started[0] > PAGE_DEADLINE_SECONDS:
                raise api.TwentyError("a reconcile page passed its 30 s deadline", error_class="timeout", outcome="retry")
            if full and self.monotonic() - started > FULL_SCAN_DEADLINE_SECONDS:
                raise api.TwentyError("the full scan passed its 6 hour deadline", error_class="timeout", outcome="retry")
            with org_transaction(worker, worker_token):
                if not worker.execute("SELECT consentvault.sync_rate_take(%s, 1) AS ok", (system_id,)).fetchone()["ok"]:
                    raise api.TwentyError("the pacing bucket is empty", error_class="http_4xx", outcome="retry")

        client = api.TwentyClient(base, keys["api_key"].decode("utf-8"), self.transport, before_call=before)
        watermark = None if full else sysrow["watermark"]
        flt = None if watermark is None else f'updatedAt[gt]:"{watermark.isoformat().replace("+00:00", "Z")}"'
        after, newest = None, watermark
        try:
            while True:
                page_started[0] = self.monotonic()
                people, info = client.people(filter=flt, starting_after=after, order_by="updatedAt[AscNullsFirst]")
                rep.pages += 1
                for person in people:
                    self._one(app, capture_token, worker, worker_token, org_id, system_id, client, keys, person, holder, rep)
                    stamp = _instant(person.get("updatedAt"))
                    if stamp is not None and (newest is None or stamp > newest):
                        newest = stamp
                with org_transaction(worker, worker_token):   # the watermark moves only after a fully processed page
                    worker.execute("SELECT consentvault.connector_reconcile_done(%s, true, %s, false)", (system_id, newest))
                if not info.get("hasNextPage") or not info.get("endCursor"):
                    break
                after = info["endCursor"]
            rep.complete = True
        except (api.TwentyError, SyncError) as exc:  # loud-failure-exempt: recorded as the run's failure, counted toward the 3-in-a-row alarm and raised below
            rep.error = f"{describe(exc)}"
        with org_transaction(worker, worker_token):
            fails = worker.execute("SELECT consentvault.connector_reconcile_done(%s, %s, %s, %s) AS f",
                                   (system_id, rep.complete, newest, full and rep.complete)).fetchone()["f"]
            for name, n in (("reconcile_read", rep.read), ("reconcile_drifted", rep.drifted),
                            ("reconcile_corrected", rep.corrected), ("stops_found", rep.stops_found)):
                if n:
                    worker.execute("SELECT consentvault.connector_count(%s, %s, %s)", (system_id, name, n))
            if fails >= FAILURES_ALARM:
                from ...alarms import raise_operator_alarm

                raise_operator_alarm(worker, name=ALARM_RECONCILE, error_class="reconcile_incomplete", ref_kind="system",
                                     ref_id=system_id)
        if rep.error:
            raise SyncError(f"the reconcile of system {system_id} did not complete ({fails} run(s) in a row): {rep.error}")
        return rep

    def _one(self, app, capture_token, worker, worker_token, org_id, system_id, client, keys, person, holder, rep) -> None:
        rep.read += 1
        with org_transaction(app, capture_token):
            res = apply_person_event(app, self.crypto, org_id, system_id, event="person.updated", record=person,
                                     hash_key=keys["hash_key"], region=self.region)
            record_counts(app, system_id, res)
        rep.stops_found += res.stops_recorded
        if res.after_destroyed:
            return
        h = person_id_hash(keys["hash_key"], person["id"])
        with org_transaction(worker, worker_token):
            got = worker.execute("SELECT consentvault.sync_lease_person(%s, %s, %s, 1) AS ok",
                                 (system_id, h, holder)).fetchone()["ok"]
        if not got:
            rep.lease_busy += 1   # a delivery is writing this Person now; the next run reads it again
            return
        try:
            self._scan_write(worker, worker_token, org_id, system_id, client, person, rep)
        finally:
            with org_transaction(worker, worker_token):
                worker.execute("SELECT consentvault.sync_release_person(%s, %s, %s)", (system_id, h, holder))

    def _scan_write(self, worker, worker_token, org_id, system_id, client, person, rep) -> None:
        """Rule R21 under the lease: recompute from the remaining contributing contacts; write only on a difference."""
        t_lease = self.monotonic()
        fps = [self.crypto.contact_fingerprint(org_id, k, n) for k, n in api.contact_points(person, self.region)]
        with org_transaction(worker, worker_token):
            srows = worker.execute("SELECT * FROM consentvault.sync_person_state(%s, %s)", (system_id, fps)).fetchall()
            pending = worker.execute("SELECT consentvault.connector_write_pending(%s, %s) AS p", (system_id, fps)).fetchone()["p"]
        want = derive_fields(srows)
        if not differs(person, want):
            return
        rep.drifted += 1
        if hides_a_stop(person, want) and not pending:
            rep.stops_hidden += 1      # an uncovered stop alarms every time (R28), counts and the system only
            with org_transaction(worker, worker_token):
                from ...alarms import raise_operator_alarm

                raise_operator_alarm(worker, name=ALARM_HIDDEN, error_class="stop_hidden_corrected", ref_kind="system",
                                     ref_id=system_id)
                worker.execute("SELECT consentvault.connector_count(%s, 'stop_hidden_corrected', 1)", (system_id,))
        if self.monotonic() - t_lease > min(SEND_DEADLINE_SECONDS, LEASE_SECONDS - SEND_DEADLINE_SECONDS):
            rep.refused_late_send += 1   # the lease may not outlive this write: send nothing; the next run corrects it
            return
        client.patch(person["id"], want)
        if differs(client.person(person["id"]), want):
            raise api.TwentyError("the scan's read-back differs from what it wrote", error_class="readback_mismatch",
                                  outcome="retry")
        rep.corrected += 1


def _instant(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None  # loud-failure-exempt: a Person with no readable updatedAt does not move the watermark; it is read again


def due(sysrow) -> tuple[bool, bool]:
    """(run the reconcile now, run the full scan now) for one system row of ``connector_systems``, as the database decided
    them on its own clock (the system's interval, 5 to 1440 minutes, 15 by default; the full scan every 24 hours)."""
    return bool(sysrow["reconcile_due"]), bool(sysrow["full_scan_due"])
