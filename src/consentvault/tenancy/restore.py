"""Restore reconciliation: after a database restore the gate answers 503 until this job has finished.

1. ``begin_restore`` is the first command run against a restored database. From then the gate refuses to record a
   decision (``gate_decision_restore_guard``), so every gate answer is 503 until step 3 ends, and the sync worker
   pauses (``consentvault.restore_pending()``): nothing is pushed from a database that may be missing stops.
2. ``reconcile`` then, for every organisation:
   a. replays the lifecycle ledger from the write-once archive store in order: holds set and released after the
      restore point come back, and every erasure whose intent has a commit entry deletes its contact key again, at
      the intent's place in the order (an erasure survives a restore). An intent with no commit (its transaction never
      committed) is never executed: it is reported in ``uncommitted_intents`` and its request, if still open, is held
      with ``wait_reason = uncommitted_ledger_intent`` for the operator to re-confirm. A committed erasure that a hold
      covers at its place in the order is never executed either: it is reported in ``erasures_held`` and its request
      is queued behind the hold. Neither stops the reconciliation;
   b. re-checks every write-once evidence object written after the restore point (digest and retention), and for an
      object whose ledger row is missing re-ingests it as a new event when it is a stop, with an audit entry naming
      the gap. A missing grant is not re-ingested: it is reported and audited (the gate holds without it). An object
      with no fingerprint on record is tried against every contact key of the organisation, in batches;
   c. names every object it could not read (its contact's key was created after the restore point and is gone);
   d. re-verifies the event chain (and its anchors), the audit chain and every stored seal; any break is a failed
      check.
3. Only a run with no failed check and no unreadable object (or an operator's recorded acceptance of the unreadable
   objects) completes; the gate and the sync worker resume from that moment. Anything else raises
   ``RestoreIncompleteError`` with the report, and the gate stays at 503.

``inventory(org_id, since)`` lists the object keys an evidence store holds for an organisation written after a time;
``local_inventory`` is the one for ``LocalAppendOnlyEvidenceStore``. The managed service passes an S3 listing.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

import psycopg

from ..safelog import describe
from .admin_base import ApiError
from .erasure import (WAIT_INTENT, LifecycleError, LifecycleLedger, audit_org, audit_platform, covering_hold, held_note, record_erasure_stop, erasure_stop_present, ERASURE_SOURCE,
                      hold_in, operator_org)
from .tokens import TokenKey

STOP_TYPES = ("revoke", "suppress")
KEY_BATCH = 5000  # contact keys read per page when an object names no fingerprint; every page is tried
RESTORE_SCOPES = ("admin", "worker:restore")
# "erasure" is the one-phase entry written before the two-phase ledger: like an intent, it runs only with a commit
ALARM_STOPS_UNCONFIRMED = "restore.stops_unconfirmed"
INTENT_KINDS = ("erasure_intent", "erasure")


class RestoreIncompleteError(LifecycleError):
    """Reconciliation found a failed check or an unreadable object; the gate stays at 503. ``report`` says what."""

    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report


def begin_restore(conn: psycopg.Connection, *, operator_id: str, request_id: str, restore_point: datetime) -> str:
    """Mark the database as restored and unreconciled (owner connection). The gate answers 503 from here."""
    if not isinstance(restore_point, datetime) or restore_point.tzinfo is None:
        raise ApiError("validation_failed", "the restore point is a time with a zone", {"restore_point": "required"})
    try:
        row = conn.execute("INSERT INTO consentvault.restore_run (restore_point, started_by) VALUES (%s, %s)"
                           " RETURNING run_id", (restore_point, operator_id)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise LifecycleError("a restore reconciliation is already pending") from None
    audit_platform(conn, operator_id=operator_id, action="restore.begun", target_kind="restore",
                   target_id=row["run_id"], reason=f"restore point {restore_point.isoformat()}", request_id=request_id)
    return str(row["run_id"])


def pending(conn) -> Optional[dict]:
    return conn.execute("SELECT * FROM consentvault.restore_run WHERE state = 'pending'").fetchone()


def local_inventory(root: str | Path) -> Callable[[str, datetime], list[str]]:
    """Object keys of a ``LocalAppendOnlyEvidenceStore`` written after ``since``, from its metadata records."""
    base = Path(root)

    def listing(org_id: str, since: datetime) -> list[str]:
        objs = base / org_id / "objects"
        out = []
        for meta in sorted(objs.rglob("*.meta.json")) if objs.is_dir() else []:
            try:
                written = datetime.fromisoformat(json.loads(meta.read_text(encoding="utf-8"))["written_at"])
            except (OSError, ValueError, KeyError) as exc:
                raise LifecycleError(f"the metadata record {meta.name} could not be read: {type(exc).__name__}") from exc
            if written > since:
                out.append(str(meta.relative_to(objs))[: -len(".meta.json")])
        return out

    return listing


# ---- step a: the lifecycle ledger --------------------------------------------------------------------------------------------
def _commits(entries: list[dict], failed: list[dict]) -> dict[int, dict]:
    """intent seq -> its commit entry. A commit naming no matching intent is a failed check, never a replay."""
    intents = {e["seq"]: e for e in entries if e.get("kind") in INTENT_KINDS}
    out: dict[int, dict] = {}
    for e in entries:
        if e.get("kind") != "erasure_commit":
            continue
        i = intents.get(e.get("intent_seq"))
        if i is None or i.get("erasure_id") != e.get("erasure_id") or i.get("contact_fp") != e.get("contact_fp"):
            failed.append({"key": f"ledger:{e['seq']}", "cause": "commit_without_matching_intent"})
            continue
        out[e["intent_seq"]] = e
    return out


def _replay_stop(conn, crypto, e: dict, n: dict, settled: set, *, unconfirmed: bool = False,
                 request_id: str = "") -> None:
    """Write again the stop a ledger entry records, only when the database holds none for that exact entry (erasure and
    sequence number). A stop the copy already records is counted as present and never written twice, so a backup taken
    after the erasure (and after the person returned) is left alone. An unconfirmed entry is superseded (not replayed)
    only when another committed stop entry, or a stop event the copy holds, covers the same erasure; the erasure's own
    commit never settles its stop. A stop that cannot be written under a missing key is a failed
    check, not a skip."""
    fp, eid = e["contact_fp"], e["erasure_id"]
    if erasure_stop_present(conn, fp, eid, e["seq"]) is not None:
        n["stops_present"] += 1
        return
    if unconfirmed and (eid in settled or conn.execute(
            "SELECT 1 FROM consentvault.event WHERE org_id = (SELECT consentvault.current_org()) AND contact_fp = %s"
            " AND source = %s AND (recorded_by LIKE %s OR recorded_by LIKE %s) LIMIT 1",
            (fp, ERASURE_SOURCE, f"erasure:{eid}:%", f"erasure-unconfirmed:{eid}:%")).fetchone() is not None):
        n["stops_superseded"].append({"erasure_id": eid, "seq": e["seq"]})
        return
    try:
        with conn.transaction():
            record_erasure_stop(conn, crypto, fp=fp, erasure_id=eid, channels=e["channels"], unconfirmed=unconfirmed,
                                stop_seq=e["seq"])
    except LifecycleError as exc:
        n["failed_checks"].append({"key": f"ledger:{e['seq']}", "cause": f"erasure_stop_not_replayable: {describe(exc)}"})
        return
    n["stops_replayed"] += 1
    if unconfirmed:
        from ..alarms import raise_operator_alarm

        n["stops_unconfirmed"].append({"erasure_id": eid, "seq": e["seq"]})
        audit_org(conn, actor_kind="system", actor_id="restore", action="restore.stop_unconfirmed",
                  target_kind="erasure", target_id=eid,
                  reason=f"ledger entry {e['seq']} has no commit: replayed as an unconfirmed stop; lift it only "
                         "through the normal release rules", request_id=request_id)
        raise_operator_alarm(conn, name=ALARM_STOPS_UNCONFIRMED, error_class="UnconfirmedErasureStop",
                             ref_kind="erasure", ref_id=eid, request_id=request_id)


RESTORE_REQUESTER = "00000000-0000-0000-0000-000000000000"  # a request the restore records from the ledger


def _replay_erasure(conn, crypto, e: dict, commit: dict, n: dict, *, request_id: str) -> None:
    if conn.execute("SELECT 1 FROM consentvault.erasure_request WHERE org_id = (SELECT consentvault.current_org())"
                    " AND erasure_id = %s AND status = 'completed'", (e["erasure_id"],)).fetchone() is not None:
        # the copy records this erasure already: a key it holds now is a returning person's, never deleted again
        conn.execute("INSERT INTO consentvault.erasure_ledger_commit (org_id, erasure_id, intent_seq, commit_seq)"
                     " VALUES ((SELECT consentvault.current_org()), %s, %s, %s) ON CONFLICT DO NOTHING",
                     (e["erasure_id"], e["seq"], commit["seq"]))
        n["erasures_present"] += 1
        return
    hold = covering_hold(conn, e["contact_fp"])
    if hold is None:
        try:
            with conn.transaction():
                deleted = conn.execute("SELECT consentvault.erase_contact(%s) AS d", (e["contact_fp"],)).fetchone()["d"]
        except psycopg.Error as exc:
            hold = hold_in(exc)
            if hold is None:
                raise LifecycleError(f"ledger entry {e['seq']} (a committed erasure) could not be replayed: "
                                     f"{type(exc).__name__}") from exc
    if hold is not None:  # never under a hold: the request is queued behind it, visibly
        conn.execute("UPDATE consentvault.erasure_request SET held_by = %s, held_since = coalesce(held_since,"
                     " clock_timestamp()) WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s"
                     " AND status = 'pending_operator_confirmation'", (hold, e["erasure_id"]))
        note = held_note(conn, hold)  # the tenant's chain names only the client's own hold
        audit_org(conn, actor_kind="system", actor_id="restore", action="erasure.held", target_kind="erasure",
                  target_id=e["erasure_id"], reason=f"restore: ledger entry {e['seq']} not replayed while held"
                  + (f"; {note}" if note else ""), request_id=request_id)
        n["erasures_held"].append({"erasure_id": e["erasure_id"], "seq": e["seq"], "hold_id": str(hold)})
        return
    # the copy may predate the request: record it, so the completion below stamps the sequence the erasure covers
    conn.execute("INSERT INTO consentvault.erasure_request (org_id, erasure_id, contact_fp, reason, requested_by)"
                 " VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s) ON CONFLICT (org_id, erasure_id) DO NOTHING",
                 (e["erasure_id"], e["contact_fp"], f"restore: replayed from lifecycle ledger entry {e['seq']}",
                  RESTORE_REQUESTER))
    done = conn.execute("UPDATE consentvault.erasure_request SET status = 'completed', completed_at = %s,"
                 " confirmed_by = coalesce(confirmed_by, 'restore-replay'), held_by = NULL, held_since = NULL,"
                 " wait_reason = NULL, wait_since = NULL, ledger_seq = %s"
                 " WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s"
                 " AND status = 'pending_operator_confirmation' RETURNING erasure_id",
                 (e["erased_at"], e["seq"], e["erasure_id"])).fetchone()
    if done is None:
        raise LifecycleError(f"ledger entry {e['seq']} (a committed erasure) could not be recorded as completed: its"
                             " request is neither open nor completed in the restored copy")
    conn.execute("INSERT INTO consentvault.erasure_ledger_commit (org_id, erasure_id, intent_seq, commit_seq)"
                 " VALUES ((SELECT consentvault.current_org()), %s, %s, %s) ON CONFLICT DO NOTHING",
                 (e["erasure_id"], e["seq"], commit["seq"]))
    n["erasures_replayed"] += 1
    n["keys_deleted"] += bool(deleted)
    # the contact is gone: an open Twenty clear of this request has nothing left to send (twenty.md 5.1); the fields in
    # Twenty are the nightly scan's (it recomputes every Person from its remaining contacts)
    conn.execute("SELECT consentvault.connector_clear_supersede(%s, 'erased', ARRAY['pending', 'failed', 'sent', 'dead'])",
                 (e["erasure_id"],))
    if deleted:
        audit_org(conn, actor_kind="system", actor_id="restore", action="restore.erasure_replayed",
                  target_kind="erasure", target_id=e["erasure_id"], reason=f"ledger entries {e['seq']} and "
                  f"{commit['seq']}", request_id=request_id)


def _hold_uncommitted(conn, e: dict, *, request_id: str) -> bool:
    """An intent with no commit: never executed. Its request, if still open, waits for the operator. True if marked."""
    row = conn.execute("UPDATE consentvault.erasure_request SET wait_reason = %s, wait_since = coalesce(wait_since,"
                       " clock_timestamp()) WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s"
                       " AND status = 'pending_operator_confirmation' AND wait_reason IS DISTINCT FROM %s"
                       " RETURNING erasure_id", (WAIT_INTENT, e["erasure_id"], WAIT_INTENT)).fetchone()
    if row is not None:
        # its Twenty clear waits too, revived only by the operator's re-confirm of this request (twenty.md 5.1)
        conn.execute("SELECT consentvault.connector_clear_supersede(%s, 'held',"
                     " ARRAY['pending', 'failed', 'sent', 'dead', 'acknowledged'])", (e["erasure_id"],))
        audit_org(conn, actor_kind="system", actor_id="restore", action="erasure.held", target_kind="erasure",
                  target_id=e["erasure_id"], reason=f"{WAIT_INTENT}: ledger entry {e['seq']} has no commit; the key "
                  "was not deleted and the request waits for an operator to confirm it again", request_id=request_id)
    return row is not None


def _replay(conn, crypto, entries: list[dict], *, request_id: str) -> dict:
    n = {"holds_restored": 0, "releases_restored": 0, "erasures_replayed": 0, "stops_replayed": 0, "stops_present": 0, "stops_superseded": [], "stops_unconfirmed": [],
         "erasures_present": 0, "keys_deleted": 0,
         "erasures_held": [], "uncommitted_intents": [], "failed_checks": []}
    commits = _commits(entries, n["failed_checks"])
    stop_commits = {e.get("stop_seq") for e in entries if e.get("kind") == "erasure_stop_commit"}
    # a stop is settled only by a committed stop entry of the same erasure (or a stop event of it the copy holds); the
    # erasure's own commit never settles its stop, so an unsettled stop of a committed erasure is replayed
    settled = {e.get("erasure_id") for e in entries if e.get("kind") == "erasure_stop" and e["seq"] in stop_commits}
    committed_ids = {c["erasure_id"] for c in commits.values()}
    orphans = []
    for e in entries:
        kind = e.get("kind")
        if kind == "hold_set":
            row = conn.execute("INSERT INTO consentvault.legal_hold (org_id, hold_id, scope, contact_fps, set_by_kind,"
                               " set_by, set_at, reason, legal_process_id, set_ledger_seq) VALUES"
                               " ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                               " ON CONFLICT DO NOTHING RETURNING hold_id",
                               (e["hold_id"], e["scope"], e["contact_fps"], e["set_by_kind"], e["set_by"], e["set_at"],
                                e["reason"], e.get("legal_process_id"), e["seq"])).fetchone()
            n["holds_restored"] += row is not None
        elif kind == "hold_released":
            row = conn.execute("UPDATE consentvault.legal_hold SET released_by_kind = %s, released_by = %s,"
                               " released_at = %s, release_reason = %s, release_ledger_seq = %s"
                               " WHERE org_id = (SELECT consentvault.current_org()) AND hold_id = %s"
                               " AND released_at IS NULL RETURNING hold_id",
                               (e["released_by_kind"], e["released_by"], e["released_at"], e["release_reason"], e["seq"],
                                e["hold_id"])).fetchone()
            n["releases_restored"] += row is not None
        elif kind in INTENT_KINDS:
            commit = commits.get(e["seq"])
            if commit is not None:
                _replay_erasure(conn, crypto, e, commit, n, request_id=request_id)
            elif e.get("erasure_id") not in committed_ids:
                orphans.append(e)
        elif kind == "erasure_stop":
            # committed: replayed as it was. No commit: its transaction may have rolled back, or the ledger was down when
            # the commit was due. An over-stop is safe and an under-stop is not, so it is replayed marked unconfirmed
            # and alarmed, one alarm and one audit row for that stop; the operator lifts it only through the release rules
            _replay_stop(conn, crypto, e, n, settled, unconfirmed=e["seq"] not in stop_commits, request_id=request_id)
        elif kind in ("erasure_commit", "erasure_stop_commit"):
            continue  # acted on at its intent's place in the order
        else:
            raise LifecycleError(f"ledger entry {e.get('seq')} has an unknown kind {kind!r}")
    for e in orphans:
        marked = _hold_uncommitted(conn, e, request_id=request_id)
        n["uncommitted_intents"].append({"erasure_id": e.get("erasure_id"), "seq": e["seq"], "request_held": marked})
    return n


# ---- step b: write-once objects ----------------------------------------------------------------------------------------------
def _open_object(conn, crypto, org, object_id: str, blob: bytes, fp_hint: Optional[str], cache: dict):
    """(fp, evidence dict) or None when no key of this organisation opens the object."""
    from . import crypto as tc
    from .errors import FieldCryptoError, KeyProviderError
    from .keys_protocol import WrappedKey

    fps = [fp_hint] if fp_hint is not None else _every_key(conn)
    for fp in fps:
        if fp not in cache:
            held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
            try:
                cache[fp] = None if held is None else crypto.open_contact_key(
                    org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
            except KeyProviderError as exc:
                raise LifecycleError(f"the organization key could not open contact keys ({type(exc).__name__})") from exc
        if cache[fp] is None:
            continue
        try:
            raw = tc.decrypt_field(cache[fp], org, object_id, "evidence_object", blob)
        except FieldCryptoError:  # loud-failure-exempt: not this contact's key; the next is tried and a miss is reported
            continue
        return fp, json.loads(raw)
    return None


def _every_key(conn):
    """Every contact fingerprint of the entered organisation, newest first, read ``KEY_BATCH`` at a time."""
    last = None
    while True:
        batch = KEY_BATCH
        if last is None:
            rows = conn.execute("SELECT contact_fp, created_at FROM consentvault.contact_key"
                                " WHERE org_id = (SELECT consentvault.current_org())"
                                " ORDER BY created_at DESC, contact_fp DESC LIMIT %s", (batch,)).fetchall()
        else:
            rows = conn.execute("SELECT contact_fp, created_at FROM consentvault.contact_key"
                                " WHERE org_id = (SELECT consentvault.current_org()) AND (created_at, contact_fp) < (%s, %s)"
                                " ORDER BY created_at DESC, contact_fp DESC LIMIT %s", (*last, batch)).fetchall()
        yield from (r["contact_fp"] for r in rows)
        if len(rows) < batch:
            return
        last = (rows[-1]["created_at"], rows[-1]["contact_fp"])


def _verify(conn, crypto, anchor_sink: Optional[str]) -> list[dict]:
    """Inside the entered organisation: the event chain (with its anchors), the audit chain and every stored seal."""
    from .. import ledger as event_ledger, seal
    from ..errors import ConsentVaultError
    from . import audit

    failed = []
    try:
        for b in event_ledger.verify_chain(conn, sink_file=anchor_sink, crypto=crypto):
            failed.append({"key": f"chain:event:{b.seq}", "cause": b.reason})
    except (ConsentVaultError, psycopg.Error, OSError) as exc:  # loud-failure-exempt: a check that cannot run fails
        failed.append({"key": "chain:event", "cause": f"verification could not run: {type(exc).__name__}"})
    try:
        for b in audit.chain_breaks(conn):
            failed.append({"key": f"chain:audit:{b['seq']}", "cause": b["reason"]})
    except psycopg.Error as exc:  # loud-failure-exempt: recorded as a failed check; reconcile raises on any
        failed.append({"key": "chain:audit", "cause": f"verification could not run: {type(exc).__name__}"})
    try:
        _checked, bad = seal.verify_all(conn)
        failed.extend({"key": f"seal:{r.event_id}", "cause": r.reason} for r in bad)
    except (ConsentVaultError, psycopg.Error, OSError) as exc:  # loud-failure-exempt: recorded as a failed check
        failed.append({"key": "seal", "cause": f"verification could not run: {type(exc).__name__}"})
    return failed


def _fields(evidence: dict) -> dict:
    out = {}
    for k, v in evidence["fields"].items():
        if isinstance(v, str) and k.endswith("_at"):
            try:
                v = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:  # loud-failure-exempt: a text field named *_at that is not a time stays text
                pass
        out[k] = v
    return out


def _reingest(conn, crypto, *, key: str, object_id: str, fp: str, evidence: dict, sha256: str, retain_until, region,
              restore_point, request_id: str, row: Optional[dict]) -> str:
    from .. import door

    if row is None:
        conn.execute("INSERT INTO consentvault.evidence_object (org_id, object_id, object_key, contact_fp, retain_until)"
                     " VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s)",
                     (object_id, key, fp, retain_until))
    # the restored input goes in as a stored post of its own (the evidence's fields and the original bytes, whole) and through
    # the door like every other post, so the event cites its post and a rebuild can reproduce it
    outcome = door.record_observed(conn, crypto, intake="restore", region=region, allowed_purposes=None,
                                   fields={**_fields(evidence), "payload_b64": evidence["body_b64"]})
    event_id = outcome.event_id
    conn.execute("UPDATE consentvault.evidence_object SET status = 'committed', event_id = %s, sha256 = %s,"
                 " settled_at = clock_timestamp() WHERE org_id = (SELECT consentvault.current_org()) AND object_id = %s",
                 (event_id, sha256, object_id))
    audit_org(conn, actor_kind="system", actor_id="restore", action="restore.stop_reingested", target_kind="event",
              target_id=event_id, reason=f"gap: object {object_id} was written after the restore point "
              f"{restore_point.isoformat()} and had no ledger row; re-ingested as a new event", request_id=request_id)
    return str(event_id)


def _objects(conn, *, crypto, store, inventory, org, restore_point, region, request_id: str) -> dict:
    from ..providers.errors import ProviderError

    n = {"checked": 0, "stops_reingested": [], "not_reingested": [], "unreadable": [], "failed_checks": []}
    cache: dict = {}
    for key in inventory(str(org), restore_point):
        if not key.startswith("events/"):
            continue  # ledger entries are checked by their chain, export packages by their job digest
        n["checked"] += 1
        object_id = key[len("events/"):]
        try:
            blob = store.get(str(org), key)
            retained = store.verify_retention(str(org), key)
        except ProviderError as exc:  # loud-failure-exempt: recorded as a failed check; reconcile raises on any
            n["failed_checks"].append({"key": key, "cause": type(exc).__name__})
            continue
        row = conn.execute("SELECT * FROM consentvault.evidence_object WHERE org_id = (SELECT consentvault.current_org())"
                           " AND object_key = %s", (key,)).fetchone()
        if row is not None and row["status"] == "committed":
            if row["sha256"] != hashlib.sha256(blob).hexdigest():
                n["failed_checks"].append({"key": key, "cause": "digest_mismatch"})
            continue
        opened = _open_object(conn, crypto, org, object_id, blob, row["contact_fp"] if row else None, cache)
        if opened is None:
            n["unreadable"].append(key)
            audit_org(conn, actor_kind="system", actor_id="restore", action="restore.gap", target_kind="object",
                      target_id=object_id, reason="written after the restore point; no key on record opens it",
                      request_id=request_id)
            continue
        fp, evidence = opened
        if evidence["fields"].get("event_type") not in STOP_TYPES:
            n["not_reingested"].append(key)
            audit_org(conn, actor_kind="system", actor_id="restore", action="restore.gap", target_kind="object",
                      target_id=object_id, reason=f"a {evidence['fields'].get('event_type')} written after the restore "
                      "point is not re-ingested", request_id=request_id)
            continue
        with conn.transaction():
            n["stops_reingested"].append(_reingest(
                conn, crypto, key=key, object_id=object_id, fp=fp, evidence=evidence,
                sha256=hashlib.sha256(blob).hexdigest(), retain_until=retained.retain_until, region=region,
                restore_point=restore_point, request_id=request_id, row=row))
    return n


def reconcile(conn: psycopg.Connection, *, token_key: TokenKey, crypto, store, ledger: LifecycleLedger,
              inventory: Callable[[str, datetime], Iterable[str]], operator_id: str, request_id: str,
              region: Optional[str] = None, accept_unreadable: Optional[str] = None,
              anchor_sink: Optional[str] = None) -> dict:
    """Run steps 2 and 3. ``accept_unreadable`` is the operator's recorded reason for completing despite objects no key
    opens; without it any unreadable object keeps the gate at 503. ``anchor_sink`` is the chain-head anchor file held
    outside the database (log-archive account), checked against the restored chain when given."""
    run = pending(conn)
    if run is None:
        raise LifecycleError("no restore reconciliation is pending; run begin_restore first")
    report: dict = {"run_id": str(run["run_id"]), "restore_point": run["restore_point"].isoformat(), "orgs": {}}
    for org in [r["o"] for r in conn.execute("SELECT o FROM consentvault.restore_org_ids() AS o")]:
        entries = ledger.entries(org)
        with operator_org(conn, token_key, org, scopes=RESTORE_SCOPES):
            replayed = _replay(conn, crypto, entries, request_id=request_id)
            objs = _objects(conn, crypto=crypto, store=store, inventory=inventory, org=org,
                            restore_point=run["restore_point"], region=region, request_id=request_id)
        with operator_org(conn, token_key, org, scopes=RESTORE_SCOPES):  # after every write the reconcile made
            verified = _verify(conn, crypto, anchor_sink)
        objs["failed_checks"] = replayed.pop("failed_checks") + objs["failed_checks"] + verified
        report["orgs"][str(org)] = {"ledger_entries": len(entries), **replayed, **objs}
    failed = [k for o in report["orgs"].values() for k in o["failed_checks"]]
    unreadable = [k for o in report["orgs"].values() for k in o["unreadable"]]
    if failed:
        raise RestoreIncompleteError(f"{len(failed)} write-once objects failed their re-check; the gate stays at 503",
                                     report)
    if unreadable and not accept_unreadable:
        raise RestoreIncompleteError(f"{len(unreadable)} objects written after the restore point cannot be read; the "
                                     "gate stays at 503 until an operator records why to proceed", report)
    report["accepted_unreadable"] = accept_unreadable
    conn.execute("UPDATE consentvault.restore_run SET state = 'complete', finished_at = clock_timestamp(), report = %s"
                 " WHERE run_id = %s", (json.dumps(report, default=str), run["run_id"]))
    audit_platform(conn, operator_id=operator_id, action="restore.reconciled", target_kind="restore",
                   target_id=run["run_id"], reason=accept_unreadable, request_id=request_id)
    return report
