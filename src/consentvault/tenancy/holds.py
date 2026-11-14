"""Legal holds: while active, an erasure, a contact key delete and an organisation key destruction inside the hold's
scope are refused. Refused work is queued, never dropped, and resumes when the hold is released.

- An org-scope hold covers every contact of the organisation and its key. A contact-scope hold covers its
  fingerprints, and also blocks the organisation key's destruction (destroying that key destroys their data too).
- Placing and releasing a hold each append to the lifecycle ledger in the archive store first, so a restored database
  replays them (``restore.py``); the hold row and the ledger entry carry the same id.
- The database enforces the hold for every path (``contact_key_hold_guard``, ``org_key_hold_guard``,
  ``erasure_request_guard``); these functions add the queue, the audit and the provider side.
- A hold an operator set (legal process) is released only by an operator.
- A release goes through ``release_hold_as_member`` (the actor is the member the tenant token names) or
  ``release_hold_as_operator`` (the operator console's role only; the operator is the one the signed operator session
  names, ``operator_org(..., operator_id=...)``); the tenant runtime role cannot write the release columns.
- Placing a hold while a key destruction is scheduled cancels it with the key provider at once (``enforce_on_keys``):
  a managed key service deletes on its own when the window ends, so waiting for a job is not enough.
"""

from __future__ import annotations

import base64
import struct
import uuid
from typing import Any, Iterable, Optional

import psycopg

from .. import dbclock
from ..safelog import describe
from .admin_base import ROLE_ADMIN, ApiError, Ctx, body_dict, iso, need_text, to_uuid, want_enum
from .erasure import (VIEW_HIDDEN, VIEW_NEUTRAL, LifecycleError, LifecycleLedger, audit_org, audit_platform, commit_after,
                      covering_hold, erase_in_org, held_note, hold_view, ledger_hint, operator_org,
                      purge_export_cache)
from .offboard import DestructionError, _open_request, _record, _step, any_hold, schedule_key_destruction
from .tokens import TokenKey

MAX_CONTACTS = 1000


class HoldEnforcementError(LifecycleError):
    """The hold is recorded, but a scheduled key destruction it covers could not be cancelled with the provider."""


SEALED_PREFIX = "ocv1:"
AUDIT_NOTE = "reason recorded (encrypted under the organization key)"
# the columns of a hold the tenant runtime role may read (never the reason, the release reason or the process link)
HOLD_COLUMNS = ("hold_id, scope, contact_fps, set_by_kind, set_by, set_at, released_by_kind, released_by, released_at,"
                " set_ledger_seq, release_ledger_seq")


def tenant_note(view: str) -> Optional[str]:
    """The reason a hold's own tenant audit row carries: the client's hold says a reason was recorded; an operator's hold
    reaches the tenant as a neutral hold with no reason text."""
    return None if view == VIEW_NEUTRAL else AUDIT_NOTE


def seal_reason(crypto, org, hold_id, column: str, text: str) -> str:
    """A hold's reason as it is stored, in the ledger and in the row: sealed under a fresh data key that the organisation
    key wraps, bound to the organisation, the hold and the column. It dies with the organisation key. Never plaintext."""
    from . import crypto as tc
    from .errors import KeyProviderError

    if crypto is None:
        raise LifecycleError("a hold's reason is sealed under the organization key; no key service is configured")
    try:
        ck = crypto.new_contact_key(org)
    except KeyProviderError as exc:
        raise ApiError("key_unavailable", "the organization key could not seal the reason; nothing was written") from exc
    blob = tc.encrypt_field(ck.data_key, org, str(hold_id), column, text)
    packed = struct.pack(">HI", len(ck.wrapped.ciphertext), ck.wrapped.key_version) + ck.wrapped.ciphertext + blob
    return SEALED_PREFIX + base64.urlsafe_b64encode(packed).decode("ascii")


def sealed_key_version(sealed: str) -> int:
    """The organisation key version that wraps the data key of a sealed reason."""
    if not isinstance(sealed, str) or not sealed.startswith(SEALED_PREFIX):
        raise LifecycleError("this value is not sealed under the organization key")
    try:
        packed = base64.urlsafe_b64decode(sealed[len(SEALED_PREFIX):])
        return struct.unpack(">HI", packed[:6])[1]
    except (ValueError, struct.error) as exc:
        raise LifecycleError(f"a sealed reason is malformed: {describe(exc)}") from exc


def open_reason(crypto, org, hold_id, column: str, sealed: str) -> str:
    """The operator's read of a sealed reason. Raises when the organisation key can no longer open it."""
    from . import crypto as tc
    from .keys_protocol import WrappedKey

    if not isinstance(sealed, str) or not sealed.startswith(SEALED_PREFIX):
        raise LifecycleError("this reason is not sealed under the organization key")
    packed = base64.urlsafe_b64decode(sealed[len(SEALED_PREFIX):])
    n, version = struct.unpack(">HI", packed[:6])
    wrapped = WrappedKey(packed[6:6 + n], version)
    data_key = crypto.open_contact_key(org, wrapped)
    return tc.decrypt_text(data_key, org, str(hold_id), column, packed[6 + n:])


def _hold_obj(r: dict) -> dict:
    return {"hold_id": str(r["hold_id"]), "scope": r["scope"], "contact_count": len(r["contact_fps"]),
            "set_at": iso(r["set_at"]), "released_at": iso(r["released_at"])}


def _fingerprints(crypto, org, contacts: Iterable[Any], region: Optional[str]) -> list[str]:
    from .errors import KeyProviderError
    from .pipeline import normalize

    out = []
    for c in contacts:
        if not isinstance(c, str):
            raise ApiError("invalid_contact", "the contact point is not a valid phone number or email address")
        kind, norm = normalize(c, region)
        try:
            out.append(crypto.contact_fingerprint(org, kind, norm))
        except KeyProviderError as exc:
            raise ApiError("key_unavailable", "the organization key could not be used; nothing was written") from exc
    return sorted(set(out))


def place_in_org(conn, *, ledger: LifecycleLedger, actor_kind: str, actor_id: str, request_id: str, scope: str,
                 contact_fps: list[str], reason: str, crypto, legal_process_id=None) -> dict:
    """Inside the entered organisation: ledger entry first, then the row, then the audit, under the lifecycle lock."""
    want_enum(scope, "scope", ("org", "contacts"))
    if scope == "contacts" and not 1 <= len(contact_fps) <= MAX_CONTACTS:
        raise ApiError("validation_failed", f"a contact hold names 1 to {MAX_CONTACTS} contacts", {"contacts": "1 to 1000"})
    fps = [] if scope == "org" else sorted(set(contact_fps))
    org = conn.execute("SELECT consentvault.lifecycle_lock() AS o").fetchone()["o"]
    hold_id, set_at = uuid.uuid4(), dbclock.now(conn)
    reason = seal_reason(crypto, org, hold_id, "legal_hold.reason", reason)
    seq, _ = ledger.append(org, {"kind": "hold_set", "hold_id": str(hold_id), "scope": scope, "contact_fps": fps,
                                 "set_by_kind": actor_kind, "set_by": actor_id, "set_at": set_at.isoformat(),
                                 "reason": reason, "legal_process_id": str(legal_process_id) if legal_process_id
                                 else None}, hint=ledger_hint(conn))
    row = conn.execute(
        "INSERT INTO consentvault.legal_hold (org_id, hold_id, scope, contact_fps, set_by_kind, set_by, set_at, reason,"
        " legal_process_id, set_ledger_seq) VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s, %s, %s, %s,"
        " %s) RETURNING " + HOLD_COLUMNS,
        (hold_id, scope, fps, actor_kind, actor_id, set_at, reason, legal_process_id, seq)).fetchone()
    from ..sync.connectors import twenty as twenty_connector  # a hold blocks the Twenty clear, never a stop (twenty.md 5.1)

    twenty_connector.on_hold_placed(conn, crypto, org, fps or None)
    if legal_process_id is None:  # a legal-process hold reaches the tenant's chain only once the customer is notified
        audit_org(conn, actor_kind=actor_kind, actor_id=actor_id, action="legal_hold.set", target_kind="legal_hold",
                  target_id=hold_id, reason=None if actor_kind == "operator" else AUDIT_NOTE, request_id=request_id)
    return _hold_obj(row)


def place_hold_member(ctx: Ctx, body: Any, *, ledger: LifecycleLedger, crypto, region: Optional[str] = None) -> dict:
    """POST /v1/legal-holds (client admin): {scope: org|contacts, contacts?: [...], reason}."""
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    if "org_id" in b:
        raise ApiError("validation_failed", "the organization comes from the session", {"org_id": "not accepted"})
    reason = need_text(b, "reason", max_len=500)
    scope = want_enum(b.get("scope"), "scope", ("org", "contacts"))
    fps = _fingerprints(crypto, ctx.org_id(), b.get("contacts") or [], region) if scope == "contacts" else []
    return place_in_org(ctx.conn, ledger=ledger, actor_kind=ctx.actor.kind, actor_id=ctx.actor.id,
                        request_id=ctx.request_id, scope=scope, contact_fps=fps, reason=reason, crypto=crypto)


def place_hold_operator(conn: psycopg.Connection, *, token_key: TokenKey, ledger: LifecycleLedger, custody,
                        operator_id: str, request_id: str, org_id, scope: str, reason: str, contacts=(),
                        contact_fps=(), crypto=None, region: Optional[str] = None, legal_process_id=None) -> dict:
    """An operator's hold (legal process). Cancels any scheduled key destruction it covers before returning."""
    reason = need_text({"reason": reason}, "reason", max_len=500)
    with operator_org(conn, token_key, org_id) as org:
        fps = list(contact_fps) + (_fingerprints(crypto, org, contacts, region) if contacts else [])
        out = place_in_org(conn, ledger=ledger, actor_kind="operator", actor_id=operator_id, request_id=request_id,
                           scope=scope, contact_fps=fps, reason=reason, crypto=crypto, legal_process_id=legal_process_id)
        audit_platform(conn, operator_id=operator_id, action="legal_hold.set", target_kind="legal_hold",
                       target_id=out["hold_id"], reason=AUDIT_NOTE, request_id=request_id)
    out["destruction_cancelled"] = enforce_on_keys(conn, token_key=token_key, custody=custody, org_id=org,
                                                   actor_id=operator_id, request_id=request_id)
    return out


def enforce_on_keys(conn: psycopg.Connection, *, token_key: TokenKey, custody, org_id, actor_id: str,
                    request_id: str) -> bool:
    """If any hold is active and the organisation key is scheduled for destruction, cancel it with the provider and
    record the destruction as held. Returns True when a scheduled destruction was cancelled."""
    from ..providers.errors import KeyProviderError

    with operator_org(conn, token_key, org_id) as org:
        conn.execute("SELECT consentvault.lifecycle_lock()")
        hold = any_hold(conn)
        sched = conn.execute("SELECT 1 FROM consentvault.org_key WHERE org_id = (SELECT consentvault.current_org())"
                             " AND status = 'scheduled_destroy' LIMIT 1").fetchone()
        if hold is None or sched is None:
            return False
        if custody is None:
            raise HoldEnforcementError(f"hold {hold} is recorded but no key provider is configured to cancel the "
                                       f"scheduled destruction of {org}: cancel it by hand now")
        try:
            custody.cancel_destruction(str(org))
        except KeyProviderError as exc:
            raise HoldEnforcementError(f"hold {hold} is recorded but the scheduled key destruction of {org} could not "
                                       f"be cancelled ({type(exc).__name__}): cancel it by hand now") from exc
        from .offboard import restore_scheduled_versions

        restore_scheduled_versions(conn)
        req = _open_request(conn)
        if req is not None:  # the step is tenant-readable: a neutral held state; the record keeps the hold id
            _step(conn, req["request_id"], "key_destruction", {"status": "held", "at": iso(dbclock.now(conn))})
            _record(conn, req["request_id"], "held", hold_id=uuid.UUID(hold))
        audit_org(conn, actor_kind="system", actor_id=actor_id, action="offboarding.destruction_held",
                  target_kind="org", target_id=org, reason=held_note(conn, hold), request_id=request_id)
        return True


def release_in_org(conn, *, ledger: LifecycleLedger, actor_kind: str, actor_id: str, request_id: str, hold_id,
                   reason: str, crypto) -> dict:
    org = conn.execute("SELECT consentvault.lifecycle_lock() AS o").fetchone()["o"]
    hid = to_uuid(hold_id, "hold")
    h = conn.execute("SELECT " + HOLD_COLUMNS + " FROM consentvault.legal_hold WHERE org_id ="
                     " (SELECT consentvault.current_org()) AND hold_id = %s", (hid,)).fetchone()  # the release function locks
    if h is None:
        raise ApiError("not_found", "no such legal hold in this organization")
    if h["released_at"] is not None:
        raise ApiError("validation_failed", "the hold is already released", {"hold_id": "released"})
    if h["set_by_kind"] == "operator" and actor_kind != "operator":
        raise ApiError("role_not_allowed", "a hold set for legal process is released only by the operator",
                       {"role": "admin"})
    view = hold_view(conn, hid)
    at = dbclock.now(conn)
    reason = seal_reason(crypto, org, hid, "legal_hold.release_reason", reason)
    seq, _ = ledger.append(org, {"kind": "hold_released", "hold_id": str(hid), "released_by_kind": actor_kind,
                                 "released_by": actor_id, "released_at": at.isoformat(), "release_reason": reason},
                           hint=ledger_hint(conn))
    if actor_kind == "operator":
        conn.execute("SELECT consentvault.release_hold_as_operator(%s, %s, %s, %s, %s)", (hid, reason, at, seq, actor_id))
    else:
        conn.execute("SELECT consentvault.release_hold_as_member(%s, %s, %s, %s, %s)", (hid, reason, at, seq, actor_id))
    row = conn.execute("SELECT " + HOLD_COLUMNS + " FROM consentvault.legal_hold WHERE org_id ="
                       " (SELECT consentvault.current_org()) AND hold_id = %s", (hid,)).fetchone()
    if row is None or row["released_at"] is None or row["released_by"] != actor_id:
        raise LifecycleError(f"hold {hid} was not recorded as released by {actor_kind} {actor_id}")
    from ..sync.connectors import twenty as twenty_connector  # a release writes current state back to Twenty (rule R7)

    twenty_connector.on_hold_released(conn, crypto, org, list(h["contact_fps"]) or None)
    if view != VIEW_HIDDEN:  # a hold the customer was never told of is never released in front of them
        audit_org(conn, actor_kind=actor_kind, actor_id=actor_id, action="legal_hold.released",
                  target_kind="legal_hold", target_id=hid, reason=tenant_note(view), request_id=request_id)
    return _hold_obj(row)


def release_hold_member(ctx: Ctx, hold_id, body: Any, *, ledger: LifecycleLedger, crypto) -> dict:
    """POST /v1/legal-holds/{id}:release (client admin). The caller resumes the queue afterwards (``resume``)."""
    ctx.actor.require(ROLE_ADMIN)
    reason = need_text(body_dict(body), "reason", max_len=500)
    return release_in_org(ctx.conn, ledger=ledger, actor_kind=ctx.actor.kind, actor_id=ctx.actor.id,
                          request_id=ctx.request_id, hold_id=hold_id, reason=reason, crypto=crypto)


def release_hold_operator(conn: psycopg.Connection, *, token_key: TokenKey, ledger: LifecycleLedger, custody,
                          operator_id: str, request_id: str, org_id, hold_id, reason: str, crypto, export_cache=None) -> dict:
    reason = need_text({"reason": reason}, "reason", max_len=500)
    with operator_org(conn, token_key, org_id, operator_id=operator_id) as org:
        out = release_in_org(conn, ledger=ledger, actor_kind="operator", actor_id=operator_id, request_id=request_id,
                             hold_id=hold_id, reason=reason, crypto=crypto)
        audit_platform(conn, operator_id=operator_id, action="legal_hold.released", target_kind="legal_hold",
                       target_id=out["hold_id"], reason=AUDIT_NOTE, request_id=request_id)
    out["resumed"] = resume(conn, token_key=token_key, ledger=ledger, custody=custody, crypto=crypto,
                            org_id=org, request_id=request_id, export_cache=export_cache)
    return out


def resume(conn: psycopg.Connection, *, token_key: TokenKey, ledger: LifecycleLedger, custody, crypto, org_id,
           request_id: str, export_cache=None, window_days: int = 30) -> dict:
    """Resume queued work that no active hold covers any more: confirmed erasures run, unconfirmed ones return to the
    operator's queue, and a held key destruction is scheduled again (a fresh window of at least 30 days)."""
    done = {"erasures_completed": 0, "erasures_still_held": 0, "erasures_returned_to_queue": 0, "erasures_waiting": [],
            "destruction": None, "export_cache": [], "ledger_commit": None}
    with operator_org(conn, token_key, org_id) as org:
        queued = conn.execute("SELECT erasure_id, contact_fp, confirmed_by FROM consentvault.erasure_request"
                              " WHERE org_id = (SELECT consentvault.current_org()) AND held_by IS NOT NULL"
                              " AND status = 'pending_operator_confirmation' ORDER BY requested_at").fetchall()
    for q in queued:
        with operator_org(conn, token_key, org):
            conn.execute("SELECT consentvault.lifecycle_lock()")
            still = covering_hold(conn, q["contact_fp"])
            if still is not None:
                conn.execute("UPDATE consentvault.erasure_request SET held_by = %s WHERE org_id ="
                             " (SELECT consentvault.current_org()) AND erasure_id = %s", (still, q["erasure_id"]))
                done["erasures_still_held"] += 1
                continue
            if q["confirmed_by"] is None:
                conn.execute("UPDATE consentvault.erasure_request SET held_by = NULL, held_since = NULL"
                             " WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s", (q["erasure_id"],))
                done["erasures_returned_to_queue"] += 1
                continue
            conn.execute("UPDATE consentvault.erasure_request SET held_by = NULL, held_since = NULL"
                         " WHERE org_id = (SELECT consentvault.current_org()) AND erasure_id = %s", (q["erasure_id"],))
            out = erase_in_org(conn, ledger=ledger, crypto=crypto, erasure_id=q["erasure_id"], actor_kind="system",
                               actor_id="hold-release", request_id=request_id)
        if out["status"] != "completed":  # waiting on delivery (a visible held state): resume_waiting runs it later
            done["erasures_waiting"].append(str(q["erasure_id"]))
            continue
        done["export_cache"].append(purge_export_cache(org, out.pop("export_objects"), export_cache))
        done["erasures_completed"] += 1
    # the commit entry of every erasure that completed, through the two-phase ledger, in its own transaction
    done["ledger_commit"] = commit_after(conn, token_key=token_key, ledger=ledger, org_id=org, request_id=request_id)
    with operator_org(conn, token_key, org):
        req = _open_request(conn)
        if req is not None and (req["steps"].get("key_destruction") or {}).get("status") == "held" \
                and any_hold(conn) is None:
            if custody is None:
                raise DestructionError("the hold is released but no key provider is configured to schedule the queued "
                                       "destruction")
            done["destruction"] = schedule_key_destruction(conn, custody=custody, request=req, window_days=window_days,
                                                           actor_kind="system", actor_id="hold-release",
                                                           request_id=request_id)
            _record(conn, req["request_id"], "resumed", detail={"after": "legal hold released"})
    return done
