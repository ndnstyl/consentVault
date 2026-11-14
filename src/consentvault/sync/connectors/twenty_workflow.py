"""The Twenty workflow credential (contract twenty.md 4.2): scope ``gate_check``, the one credential a Twenty workflow holds to ask
``POST /v1/permission`` before it sends an email. Twenty cannot run the token endpoint's signed-assertion flow, so the credential
is an opaque bearer (``cv_wf_`` plus 32 random bytes), shown once and stored only as its SHA-256. One per connected system,
issued by an admin only and only once an approved policy is in force; 90 days; a replacement from day 76 with a 14-day overlap;
revocable at once; 60 checks a minute; reminders at 14 and 3 days. The database holds every rule (migration 0061); this module
mints the secret and names each refusal.
"""

from __future__ import annotations

import base64
import hashlib
import os

import psycopg

from ...safelog import describe
from ..errors import SyncError

PREFIX = "cv_wf_"
PER_MINUTE = 60          # the contract's rate; the database function holds the same constant
SCOPE = "gate_check"


class WorkflowCredentialError(SyncError):
    """A workflow credential could not be issued (no policy in force, or a replacement before day 76)."""


class PolicyRequiredRefused(WorkflowCredentialError):
    """No approved policy is in force, so no gate credential is issued (SQLSTATE CVW01)."""


class DisconnectedRefused(WorkflowCredentialError):
    """The system is disconnected, so no gate credential is issued (SQLSTATE CVW02)."""


class ReplacementRefused(WorkflowCredentialError):
    """The system already has its gate credential; a replacement may be made from day 76 of the current one (SQLSTATE CVW03)."""


PolicyRequired = PolicyRequiredRefused


def secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def is_workflow_secret(bearer: str | None) -> bool:
    return isinstance(bearer, str) and bearer.startswith(PREFIX)


def issue(conn, system_id, *, created_by: str) -> dict:
    """Issue (or replace) the system's credential under an admin token, on the database's clock (no caller names its lifetime).
    Returns the secret, shown this once."""
    secret = PREFIX + base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    try:
        row = conn.execute("SELECT * FROM consentvault.workflow_credential_issue(%s, %s, %s)",
                           (system_id, secret_hash(secret), created_by)).fetchone()
    except psycopg.Error as exc:
        state = getattr(exc, "sqlstate", None)
        if state == "CVW01":
            raise PolicyRequiredRefused(f"policy_required: {describe(exc)}", code="twenty_gate_policy_required") from exc
        if state == "CVW02":
            raise DisconnectedRefused(f"system disconnected: {describe(exc)}", code="twenty_gate_system_disconnected") from exc
        if state == "CVW03":
            raise ReplacementRefused(f"replacement refused: {describe(exc)}", code="twenty_gate_credential_exists") from exc
        raise
    return {"credential_id": row["credential_id"], "secret": secret, "expires_at": row["expires_at"],
            "replaced": row["replaced"], "scope": SCOPE}


def revoke(conn, system_id, credential_id) -> bool:
    """Revoke the system's credential at once, on the database's clock. False when no unrevoked credential of that id belongs to
    the system."""
    return conn.execute("SELECT consentvault.workflow_credential_revoke(%s, %s) AS ok", (system_id, credential_id)).fetchone()["ok"]


def use(conn, secret: str) -> dict:
    """One check's use, before any tenant is entered, on the database's clock at 60 a minute: outcome ok, unknown, revoked,
    expired, disconnected (the system was disconnected) or rate_limited (with retry_after)."""
    return conn.execute("SELECT * FROM consentvault.workflow_credential_use(%s)", (secret_hash(secret),)).fetchone()


def reminders_due(conn) -> list[dict]:
    """The 14-day and 3-day reminders due now (each once), with the organisation's name and its admins' addresses; the caller
    emails them through the notifier inside the same transaction, so a failed send leaves the reminder due. The database's clock
    decides what is due; no caller names the time."""
    return conn.execute("SELECT * FROM consentvault.workflow_credential_reminders_due()").fetchall()


# ---- the admin routes (twenty.md 4.2, 9: admin only; every issue and revoke is an audit row) ------------------------------
def _system(ctx, system_id):
    from ...tenancy.admin_base import ApiError, to_uuid

    sid = to_uuid(system_id, "system")
    row = ctx.conn.execute("SELECT status FROM consentvault.connected_system WHERE org_id = (SELECT consentvault.current_org())"
                           " AND system_id = %s AND connector = 'twenty'", (sid,)).fetchone()
    if row is None or row["status"] == "disconnected":
        raise ApiError("not_found", "no connected Twenty system with that id in this organization")
    return sid


def admin_issue(ctx, system_id, body) -> dict:
    """POST /v1/systems/{id}/workflow-credential: issue the system's credential, or its replacement from day 76."""
    from ...tenancy.admin_base import ROLE_ADMIN, ApiError, body_dict, iso

    ctx.actor.require(ROLE_ADMIN)
    body_dict(body if body is not None else {})
    sid = _system(ctx, system_id)
    try:
        got = issue(ctx.conn, sid, created_by=str(ctx.actor.id))
    except PolicyRequiredRefused:  # loud-failure-exempt: answered 409 policy_required by name
        raise ApiError("policy_required", "no approved policy is in force, so no gate credential is issued") from None
    except DisconnectedRefused:  # loud-failure-exempt: answered 404 by name; a disconnect won the race
        raise ApiError("not_found", "no connected Twenty system with that id in this organization") from None
    except ReplacementRefused:  # loud-failure-exempt: answered 409 credential_exists by name
        raise ApiError("credential_exists", "this system already has its gate credential; a replacement may be made from day"
                       " 76 of the current one") from None
    ctx.audit("system.gate_credential_issued", "credential", str(got["credential_id"]),
              None if got["replaced"] is None else f"replaces {got['replaced']}", {"system_id": str(sid)})
    return {"credential_id": str(got["credential_id"]), "system_id": str(sid), "secret": got["secret"], "shown_once": True,
            "scope": SCOPE, "expires_at": iso(got["expires_at"]),
            "replaced": None if got["replaced"] is None else str(got["replaced"])}


def admin_revoke(ctx, system_id, credential_id, body) -> dict:
    """POST /v1/systems/{id}/workflow-credential/{credential_id}:revoke: stops the credential at once; a reason is required."""
    from ...tenancy.admin_base import ROLE_ADMIN, ApiError, body_dict, need_text, to_uuid

    ctx.actor.require(ROLE_ADMIN)
    reason = need_text(body_dict(body), "reason", max_len=500)
    sid = to_uuid(system_id, "system")
    cid = to_uuid(credential_id, "credential")
    try:
        ok = revoke(ctx.conn, sid, cid)
    except psycopg.errors.NoDataFound:  # loud-failure-exempt: answered 404 by name; the system is not this organisation's
        ok = False
    if not ok:
        raise ApiError("not_found", "no live gate credential with that id on this system")
    ctx.audit("system.gate_credential_revoked", "credential", str(cid), reason, {"system_id": str(sid)})
    return {"credential_id": str(cid), "system_id": str(sid), "revoked": True}
