"""The audit chains: one per organisation, plus a platform chain for operator actions on the platform itself.

Every write, every read of personal data, every credential issue and revoke, every role change and every policy
approval writes one row (contracts/README.md section 4). Rows are appended only through two owner-rights functions
that hold the chain's lock, read the head and compute the row hash in the database, so two writers can never fork a
chain and the application cannot choose a hash. A row never holds a contact point: where an action touched a
person's records the target is ``contact`` and the id is the first eight hex characters of the fingerprint.

- ``append(conn, ...)`` writes to the chain of the organisation the transaction entered (``current_org()``); it takes
  no organisation argument.
- ``append_platform(conn, ...)`` writes to the platform chain; the database grants it to the schema owner's operator
  console only.
- ``chain_breaks(conn)`` reads the verification view for the current organisation; an empty list is a chain that
  verifies. ``head(conn)`` and ``platform_head(conn)`` give the (seq, row_hash) the anchor job writes outside.
"""

from __future__ import annotations

import re
from typing import Optional

import psycopg

from .errors import TenancyError


class AuditError(TenancyError):
    """An audit row could not be written or read."""


# action name -> the label the portal's filter menu shows
ACTIONS: dict[str, str] = {
    "org.created": "Organization created",
    "org.status_changed": "Organization status changed",
    "brand.created": "Brand added",
    "source.created": "Capture source added",
    "source.updated": "Capture source changed",
    "credential.issued": "Credential issued",
    "credential.revoked": "Credential revoked",
    "retention.set": "Retention changed",
    "member.invited": "Person invited",
    "member.role_changed": "Role changed",
    "member.removed": "Person removed",
    "invite.accepted": "Invitation accepted",
    "invite.withdrawn": "Invitation withdrawn",
    "session.opened": "Signed in to the organization",
    "wording.registered": "Wording registered",
    "policy.drafted": "Policy drafted",
    "policy.updated": "Policy draft changed",
    "policy.approved": "Policy approved",
    "checklist.drafted": "Checklist drafted",
    "checklist.updated": "Checklist draft changed",
    "checklist.approved": "Checklist approved",
    "system.registered": "Connected system registered",
    "system.updated": "Connected system changed",
    "system.signal_bound": "Connected system signal credential bound",
    "system.signal_unbound": "Connected system signal credential unbound",
}

_ACTOR_KINDS = ("member", "credential", "operator", "system")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


def _check(actor_kind: str, action: str, request_id: str) -> None:
    if actor_kind not in _ACTOR_KINDS:
        raise AuditError(f"audit actor kind {actor_kind!r} is not one of {_ACTOR_KINDS}")
    if action not in ACTIONS:
        raise AuditError(f"audit action {action!r} is not in the action list (audit.ACTIONS); add it there first")
    if not isinstance(request_id, str) or not _REQUEST_ID.match(request_id):
        raise AuditError("an audit row needs the request id of the call that caused it")


def append(conn: psycopg.Connection, *, actor_kind: str, actor_id: Optional[str], action: str, target_kind: str,
           target_id: Optional[str] = None, reason: Optional[str] = None, request_id: str):
    """Append a row to the current organisation's chain. Needs an entered tenant; returns the audit id."""
    _check(actor_kind, action, request_id)
    try:
        row = conn.execute("SELECT consentvault.append_audit(%s, %s, %s, %s, %s, %s, %s) AS id",
                           (actor_kind, actor_id, action, target_kind, target_id, reason, request_id)).fetchone()
    except psycopg.Error as exc:
        raise AuditError(f"could not append audit row {action!r}: {exc}") from exc
    return row["id"]


def append_platform(conn: psycopg.Connection, *, operator_id: str, action: str, target_kind: str,
                    target_id: Optional[str] = None, reason: Optional[str] = None, request_id: str):
    """Append a row to the platform chain (operator console only)."""
    _check("operator", action, request_id)
    try:
        row = conn.execute("SELECT consentvault.append_platform_audit(%s, %s, %s, %s, %s, %s) AS id",
                           (operator_id, action, target_kind, target_id, reason, request_id)).fetchone()
    except psycopg.Error as exc:
        raise AuditError(f"could not append platform audit row {action!r}: {exc}") from exc
    return row["id"]


def head(conn: psycopg.Connection) -> Optional[dict]:
    """(seq, row_hash) of the current organisation's chain head, or None for an empty chain."""
    return conn.execute("SELECT seq, row_hash FROM consentvault.audit_head()").fetchone()


def platform_head(conn: psycopg.Connection) -> Optional[dict]:
    return conn.execute("SELECT seq, row_hash FROM consentvault.platform_audit_head()").fetchone()


def chain_breaks(conn: psycopg.Connection) -> list[dict]:
    """Every row of the current organisation's chain that fails verification (empty means it verifies)."""
    return conn.execute("SELECT seq, audit_id, reason FROM consentvault.audit_chain_breaks"
                        " WHERE org_id = (SELECT consentvault.current_org()) ORDER BY seq").fetchall()
