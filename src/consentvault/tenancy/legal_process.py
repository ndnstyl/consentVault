"""The custodian's records: the legal-process log (subpoenas, orders, regulator requests) and operator access.

Legal process (runbook ``legal-process.md``): log the request the day it arrives, preserve the asked scope with a legal
hold, notify the customer unless the request itself prohibits notice (the basis is then recorded instead), and close
the entry with what was produced. An entry cannot close without either a notice time or a recorded basis.

Every legal-process audit row goes to the platform chain only; nothing of a legal process reaches a surface the tenant
reads. The preservation hold a process places is audited on the platform chain when it is placed, and reaches the
tenant's own audit chain only once the customer has been notified (``record_customer_notice``). Under a prohibition of
notice it never does.

Operator access: any operator read of a tenant's personal data needs an open, unexpired record here (4 hours by
default). It is opened against a customer approval that one of the tenant's admins gave in their own signed-in session
(``approve_operator_access``: the approver is read from the verified session, never typed by the operator; one use, by
the operator it names, within 24 hours), or opened as an emergency, which notifies the tenant's admins before the record
opens (a notice that cannot be sent refuses the access). ``require_open_access`` is the check an operator read path
calls.

Nothing here states a legal conclusion; a records-custodian declaration describes how records are kept and exported.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg

from .. import dbclock
from ..safelog import describe
from .admin_base import ROLE_ADMIN, ApiError, Ctx, body_dict, iso, need_text, to_uuid, want_enum
from .erasure import LifecycleError, LifecycleLedger, audit_org, audit_platform, ledger_hint, operator_org
from .holds import AUDIT_NOTE, MAX_CONTACTS, _hold_obj, enforce_on_keys, seal_reason
from .offboard import OffboardNoticeError, notify_admins
from .tokens import TokenKey

ACCESS_DEFAULT_MINUTES = 240
ACCESS_MIN_MINUTES = 15

PROCESS_TYPES = ("subpoena", "court_order", "search_warrant", "regulator_request", "law_enforcement_request",
                 "civil_discovery", "other")


class AccessNoticeError(LifecycleError):
    """An emergency access could not notify the tenant's admins, so it was not opened."""


def _process_obj(r: dict) -> dict:
    return {"process_id": str(r["process_id"]), "type": r["type"], "received_at": iso(r["received_at"]),
            "response_deadline": iso(r["response_deadline"]), "hold_id": str(r["hold_id"]) if r["hold_id"] else None,
            "client_notified_at": iso(r["client_notified_at"]),
            "notice_prohibited": r["notice_prohibited_basis"] is not None, "closed_at": iso(r["closed_at"])}


def _time(value, name: str) -> datetime:
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value
    raise ApiError("validation_failed", f"{name} must be a time with a zone", {name: "timezone-aware datetime"})


def _place_process_hold(conn, *, ledger: LifecycleLedger, operator_id: str, request_id: str, scope: str,
                        contact_fps: list[str], reason: str, crypto, legal_process_id) -> dict:
    """Inside the entered organisation: the preservation hold of a legal process. Ledger entry first, then the row, under
    the lifecycle lock, like any hold; audited on the platform chain only until the customer is notified."""
    want_enum(scope, "scope", ("org", "contacts"))
    if scope == "contacts" and not 1 <= len(contact_fps) <= MAX_CONTACTS:
        raise ApiError("validation_failed", f"a contact hold names 1 to {MAX_CONTACTS} contacts", {"contacts": "1 to 1000"})
    fps = [] if scope == "org" else sorted(set(contact_fps))
    org = conn.execute("SELECT consentvault.lifecycle_lock() AS o").fetchone()["o"]
    hold_id, set_at = uuid.uuid4(), dbclock.now(conn)
    sealed = seal_reason(crypto, org, hold_id, "legal_hold.reason", reason)
    seq, _ = ledger.append(org, {"kind": "hold_set", "hold_id": str(hold_id), "scope": scope, "contact_fps": fps,
                                 "set_by_kind": "operator", "set_by": operator_id, "set_at": set_at.isoformat(),
                                 "reason": sealed, "legal_process_id": str(legal_process_id)}, hint=ledger_hint(conn))
    row = conn.execute(
        "INSERT INTO consentvault.legal_hold (org_id, hold_id, scope, contact_fps, set_by_kind, set_by, set_at, reason,"
        " legal_process_id, set_ledger_seq) VALUES ((SELECT consentvault.current_org()), %s, %s, %s, 'operator', %s, %s,"
        " %s, %s, %s) RETURNING *", (hold_id, scope, fps, operator_id, set_at, sealed, legal_process_id, seq)).fetchone()
    audit_platform(conn, operator_id=operator_id, action="legal_hold.set", target_kind="legal_hold", target_id=hold_id,
                   reason=AUDIT_NOTE, request_id=request_id)
    return _hold_obj(row)


def log_legal_process(conn: psycopg.Connection, *, token_key: TokenKey, ledger: LifecycleLedger, custody, crypto,
                      operator_id: str, request_id: str, org_id, type: str, received_at: datetime, received_via: str,
                      requester: str, scope_summary: str, response_deadline: Optional[datetime] = None,
                      hold_scope: Optional[str] = "org", contact_fps=()) -> dict:
    """Log a request and, unless ``hold_scope`` is None, preserve its scope with an operator hold in the same step.
    Audited on the platform chain only."""
    want_enum(type, "type", PROCESS_TYPES)
    received_at = _time(received_at, "received_at")
    if response_deadline is not None:
        response_deadline = _time(response_deadline, "response_deadline")
    via = need_text({"v": received_via}, "v", max_len=200)
    who = need_text({"v": requester}, "v", max_len=300)
    scope = need_text({"v": scope_summary}, "v", max_len=2000)
    pid = uuid.uuid4()
    with operator_org(conn, token_key, org_id) as org:
        conn.execute("INSERT INTO consentvault.legal_process (org_id, process_id, type, received_at, received_via,"
                     " requester, scope_summary, response_deadline, handled_by) VALUES"
                     " ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s, %s, %s, %s)",
                     (pid, type, received_at, via, who, scope, response_deadline, operator_id))
        if hold_scope is not None:
            hold = _place_process_hold(conn, ledger=ledger, operator_id=operator_id, request_id=request_id,
                                       scope=hold_scope, contact_fps=list(contact_fps),
                                       reason=f"preservation for legal process {pid}", crypto=crypto,
                                       legal_process_id=pid)
            conn.execute("UPDATE consentvault.legal_process SET hold_id = %s WHERE org_id ="
                         " (SELECT consentvault.current_org()) AND process_id = %s", (hold["hold_id"], pid))
        audit_platform(conn, operator_id=operator_id, action="legal_process.logged", target_kind="legal_process",
                       target_id=pid, reason=type, request_id=request_id)
        row = conn.execute("SELECT * FROM consentvault.legal_process WHERE org_id = (SELECT consentvault.current_org())"
                           " AND process_id = %s", (pid,)).fetchone()
    if hold_scope is not None:
        enforce_on_keys(conn, token_key=token_key, custody=custody, org_id=org, actor_id=operator_id,
                        request_id=request_id)
    return _process_obj(row)


def _load(conn, process_id) -> dict:
    row = conn.execute("SELECT * FROM consentvault.legal_process WHERE org_id = (SELECT consentvault.current_org())"
                       " AND process_id = %s FOR UPDATE", (to_uuid(process_id, "legal process"),)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such legal process entry in this organization")
    return row


def record_customer_notice(conn: psycopg.Connection, *, token_key: TokenKey, notifier, operator_id: str,
                           request_id: str, org_id, process_id, prohibited_basis: Optional[str] = None,
                           review_url: str = "https://app.consentvault.ai/settings") -> dict:
    """Notify the customer's admins, or record the basis on which notice is prohibited. Exactly one is recorded, on the
    platform chain. Once notified, the process's preservation hold is entered in the tenant's own audit chain."""
    with operator_org(conn, token_key, org_id):
        p = _load(conn, process_id)
        if p["client_notified_at"] is not None or p["notice_prohibited_basis"] is not None:
            raise ApiError("validation_failed", "the notice decision is already recorded", {"notice": "recorded"})
        if prohibited_basis is not None:
            basis = need_text({"v": prohibited_basis}, "v", max_len=1000)
            conn.execute("UPDATE consentvault.legal_process SET notice_prohibited_basis = %s WHERE org_id ="
                         " (SELECT consentvault.current_org()) AND process_id = %s", (basis, p["process_id"]))
            action, reason = "legal_process.notice_prohibited", basis
        else:
            try:
                notify_admins(conn, notifier, event=f"A {p['type'].replace('_', ' ')} naming your organization's "
                              "records was received; we will contact you about it", review_url=review_url)
            except OffboardNoticeError as exc:
                raise LifecycleError(f"the customer notice could not be sent ({describe(exc)}); nothing is recorded as notified"
                                     ) from exc
            conn.execute("UPDATE consentvault.legal_process SET client_notified_at = clock_timestamp() WHERE org_id ="
                         " (SELECT consentvault.current_org()) AND process_id = %s", (p["process_id"],))
            action, reason = "legal_process.customer_notified", None
            if p["hold_id"] is not None:  # the customer knows now: the hold enters their own audit chain
                h = conn.execute("SELECT set_at FROM consentvault.legal_hold WHERE org_id ="
                                 " (SELECT consentvault.current_org()) AND hold_id = %s", (p["hold_id"],)).fetchone()
                audit_org(conn, actor_kind="operator", actor_id=operator_id, action="legal_hold.set",
                          target_kind="legal_hold", target_id=p["hold_id"],
                          reason=f"placed {iso(h['set_at'])}; {AUDIT_NOTE}", request_id=request_id)
        audit_platform(conn, operator_id=operator_id, action=action, target_kind="legal_process",
                       target_id=p["process_id"], reason=reason, request_id=request_id)
        return _process_obj(_load(conn, process_id))


def close_legal_process(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id,
                        process_id, response_ref: str, produced_sha256=()) -> dict:
    """Close an entry with what was produced. Refused until the notice decision is recorded."""
    ref = need_text({"v": response_ref}, "v", max_len=500)
    with operator_org(conn, token_key, org_id):
        p = _load(conn, process_id)
        if p["client_notified_at"] is None and p["notice_prohibited_basis"] is None:
            raise ApiError("validation_failed", "record the customer notice or its prohibited basis before closing",
                           {"notice": "missing"})
        conn.execute("UPDATE consentvault.legal_process SET response_ref = %s, produced_sha256 = %s, closed_at ="
                     " clock_timestamp() WHERE org_id = (SELECT consentvault.current_org()) AND process_id = %s",
                     (ref, list(produced_sha256), p["process_id"]))
        audit_platform(conn, operator_id=operator_id, action="legal_process.closed", target_kind="legal_process",
                       target_id=p["process_id"], reason=ref, request_id=request_id)
        return _process_obj(_load(conn, process_id))


def custodian_declaration(org_name: str, *, generated_at: Optional[datetime] = None) -> str:
    """The records-custodian declaration text: how records are kept and exported, no statement about consent."""
    when = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    return (f"Records custodian declaration for {org_name}, {when}.\n"
            "ConsentVault keeps each record as received in an append-only ledger with a hash chain, seals each record "
            "with an outside timestamp, anchors chain heads outside the database, and stores write-once evidence "
            "copies. Exports are produced by the evidence export process and carry their own integrity data.\n"
            "This declaration describes how records are kept and exported. It makes no statement about whether any "
            "consent was valid or sufficient.\n")


# ---- operator access ------------------------------------------------------------------------------------------------------
def _access_obj(r: dict) -> dict:
    return {"access_id": str(r["access_id"]), "operator_id": r["operator_id"], "emergency": r["emergency"],
            "approved_by_client": str(r["approved_by_client"]) if r["approved_by_client"] else None,
            "approval_id": str(r["approval_id"]) if r.get("approval_id") else None,
            "client_notified_at": iso(r["client_notified_at"]), "opened_at": iso(r["opened_at"]),
            "expires_at": iso(r.get("expires_at")), "closed_at": iso(r["closed_at"])}


def _minutes(value) -> int:
    if value is None:
        return ACCESS_DEFAULT_MINUTES
    if isinstance(value, bool) or not isinstance(value, int) or not ACCESS_MIN_MINUTES <= value <= ACCESS_DEFAULT_MINUTES:
        raise ApiError("validation_failed", f"an access lasts {ACCESS_MIN_MINUTES} to {ACCESS_DEFAULT_MINUTES} minutes",
                       {"access_minutes": f"{ACCESS_MIN_MINUTES} to {ACCESS_DEFAULT_MINUTES}"})
    return value


def approve_operator_access(ctx: Ctx, body) -> dict:
    """POST /v1/operator-access-approvals (client admin): the admin's own approval of one access by one named operator.
    The approver is the member of the signed-in session (read by the database from the verified token)."""
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    operator = need_text(b, "operator_id", max_len=200)
    reason = need_text(b, "reason", max_len=500)
    minutes = _minutes(b.get("access_minutes"))
    try:
        with ctx.conn.transaction():
            row = ctx.conn.execute("SELECT * FROM consentvault.approve_operator_access(%s, %s, %s)",
                                   (operator, reason, minutes)).fetchone()
            audit_org(ctx.conn, actor_kind=ctx.actor.kind, actor_id=ctx.actor.id, action="operator_access.approved",
                      target_kind="operator_access_approval", target_id=row["approval_id"],
                      reason=f"operator {operator}, {minutes} minutes: {reason}", request_id=ctx.request_id)
    except psycopg.errors.InsufficientPrivilege:
        raise ApiError("role_not_allowed", "only an admin signed in to this organization approves operator access",
                       {"role": ctx.actor.role or ctx.actor.kind}) from None
    return {"approval_id": str(row["approval_id"]), "operator_id": operator, "access_minutes": minutes,
            "approved_by": str(row["approved_by"]), "expires_at": iso(row["expires_at"])}


def _use_approval(conn, approval_id, operator_id: str, access_id: uuid.UUID) -> dict:
    """Inside the entered organisation: spend a customer approval for this operator, or refuse by name."""
    aid = to_uuid(approval_id, "approval")
    row = conn.execute("SELECT * FROM consentvault.operator_access_approval WHERE org_id ="
                       " (SELECT consentvault.current_org()) AND approval_id = %s FOR UPDATE", (aid,)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such operator access approval in this organization")
    if row["used_at"] is not None:
        raise ApiError("validation_failed", "this approval was already used", {"approval_id": "used"})
    if row["operator_id"] != operator_id:
        raise ApiError("validation_failed", "this approval names another operator", {"approval_id": "other operator"})
    live = conn.execute("SELECT %s > clock_timestamp() AS ok", (row["expires_at"],)).fetchone()["ok"]
    if not live:
        raise ApiError("validation_failed", "this approval has expired", {"approval_id": "expired"})
    still = conn.execute("SELECT 1 FROM consentvault.member WHERE org_id = (SELECT consentvault.current_org())"
                         " AND member_id = %s AND role = 'admin'", (row["approved_by"],)).fetchone()
    if still is None:
        raise ApiError("validation_failed", "the approving member is no longer an admin of this organization",
                       {"approval_id": "approver not an admin"})
    conn.execute("UPDATE consentvault.operator_access_approval SET used_at = clock_timestamp(), access_id = %s"
                 " WHERE org_id = (SELECT consentvault.current_org()) AND approval_id = %s", (access_id, aid))
    return row


def open_operator_access(conn: psycopg.Connection, *, token_key: TokenKey, notifier, operator_id: str, request_id: str,
                         org_id, reason: str, approval_id=None, emergency: bool = False, legal_process_id=None,
                         approved_by_member=None, review_url: str = "https://app.consentvault.ai/settings") -> dict:
    """POST /v1/orgs/{id}/operator-access (operator): against a customer approval (``approval_id``, given by an admin in
    their own session) or as an emergency (admins notified first). The record expires after the approved minutes (4 hours
    by default); a typed member id (``approved_by_member``) approves nothing and is refused by name."""
    reason = need_text({"reason": reason}, "reason", max_len=500)
    if approved_by_member is not None:
        raise ApiError("validation_failed", "a customer approves operator access in their own signed-in session; pass "
                       "the approval_id it returned, never a member id", {"approved_by_member": "not accepted"})
    if (approval_id is None) == (not emergency):
        raise ApiError("validation_failed", "an access is opened against a customer approval or as an emergency, "
                       "exactly one", {"approval_id": "or emergency"})
    with operator_org(conn, token_key, org_id):
        aid = uuid.uuid4()
        approver, minutes, notified = None, ACCESS_DEFAULT_MINUTES, None
        if approval_id is not None:
            ap = _use_approval(conn, approval_id, operator_id, aid)
            approver, minutes, approval_id = ap["approved_by"], ap["access_minutes"], ap["approval_id"]
        lp = to_uuid(legal_process_id, "legal process") if legal_process_id is not None else None
        gagged = emergency and lp is not None and _notice_prohibited(conn, lp)
        if emergency and not gagged:
            try:
                notify_admins(conn, notifier, event=f"Emergency operator access opened: {reason}", review_url=review_url)
            except OffboardNoticeError as exc:
                raise AccessNoticeError(f"the emergency notice could not be sent ({describe(exc)}); no access was opened") from exc
            notified = dbclock.now(conn)
        row = conn.execute(
            "INSERT INTO consentvault.operator_access (org_id, access_id, operator_id, reason, approved_by_client,"
            " emergency, client_notified_at, legal_process_id, approval_id, opened_at, expires_at) VALUES"
            " ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s, %s, %s, %s, clock_timestamp(),"
            " clock_timestamp() + %s * interval '1 minute') RETURNING *",
            (aid, operator_id, reason, approver, emergency, notified, lp, approval_id, minutes)).fetchone()
        if not gagged:  # under a non-disclosure order the access is on the platform chain only
            audit_org(conn, actor_kind="operator", actor_id=operator_id, action="operator_access.opened",
                      target_kind="operator_access", target_id=aid, reason=reason, request_id=request_id)
        audit_platform(conn, operator_id=operator_id, action="operator_access.opened", target_kind="operator_access",
                       target_id=aid, reason=reason, request_id=request_id)
        return _access_obj(row)


def _notice_prohibited(conn, process_id) -> bool:
    """Inside the entered organisation: True when the legal process prohibits notice, False when the customer was
    notified. A process whose notice decision is still open refuses an emergency access by name: notifying could breach an
    order not yet recorded, and staying silent needs the recorded basis."""
    p = _load(conn, process_id)
    if p["notice_prohibited_basis"] is not None:
        return True
    if p["client_notified_at"] is not None:
        return False
    raise ApiError("validation_failed", "record the customer notice decision for this legal process before an emergency "
                   "access under it", {"notice": "undecided"})


def close_operator_access(conn: psycopg.Connection, *, token_key: TokenKey, operator_id: str, request_id: str, org_id,
                          access_id) -> dict:
    with operator_org(conn, token_key, org_id):
        row = conn.execute("UPDATE consentvault.operator_access SET closed_at = clock_timestamp()"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND access_id = %s AND closed_at IS NULL"
                           " RETURNING *", (to_uuid(access_id, "access"),)).fetchone()
        if row is None:
            raise ApiError("not_found", "no open operator access with that id in this organization")
        if row["emergency"] and row["client_notified_at"] is None:  # opened under a gag: the platform chain only
            audit_platform(conn, operator_id=operator_id, action="operator_access.closed", target_kind="operator_access",
                           target_id=row["access_id"], reason=None, request_id=request_id)
        else:
            audit_org(conn, actor_kind="operator", actor_id=operator_id, action="operator_access.closed",
                      target_kind="operator_access", target_id=row["access_id"], reason=None, request_id=request_id)
        return _access_obj(row)


def require_open_access(conn, operator_id: str) -> dict:
    """Inside the entered organisation: the operator's open, unexpired access record, or ``role_not_allowed``."""
    row = conn.execute("SELECT * FROM consentvault.operator_access WHERE org_id = (SELECT consentvault.current_org())"
                       " AND operator_id = %s AND closed_at IS NULL AND expires_at > clock_timestamp()"
                       " ORDER BY opened_at DESC LIMIT 1", (operator_id,)).fetchone()
    if row is None:
        raise ApiError("role_not_allowed", "an operator reads this organization's personal data only under an open, "
                       "unexpired, recorded access", {"role": "operator"})
    return _access_obj(row)
