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
from typing import Any, Mapping, Optional

import psycopg
from psycopg.types.json import Jsonb

from ..safelog import describe
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
    "sso.updated": "Single sign-on setting changed",
    "sso.bound": "Company sign-in bound by the operator",
    "sso.unbound": "Company sign-in unbound by the operator",
    "sso.break_glass": "Operator lifted the company sign-in requirement",
    "sso.verified": "Company connection proved by an admin signing in through it",
    "member.invited": "Person invited",
    "member.role_changed": "Role changed",
    "member.removed": "Person removed",
    "invite.accepted": "Invitation accepted",
    "invite.withdrawn": "Invitation withdrawn",
    "session.opened": "Signed in to the organization",
    "proof.read": "Evidence looked up",
    "records.listed": "Contact records listed",
    "records.searched": "Contact record searched",
    "records.reveal_requested": "Full contact points requested",
    "records.revealed": "Full contact points shown",
    "records.reveal_volume_alarm": "Many full contact points shown in a short time",
    "records.export_requested": "Contact records list export requested",
    "records.export_built": "Contact records list export built",
    "records.export_downloaded": "Contact records list export downloaded",
    "records.export_store_failed": "Contact records list export could not be stored",
    "org.default_region_changed": "Organization phone region changed",
    "confirmations.settings_changed": "Confirmation message settings changed",
    "confirmations.account_connected": "Sending account connected",
    "confirmations.account_removed": "Sending account disconnected",
    "confirmations.inbound_verified": "Text replies proved to reach the vault",
    "confirmations.inbound_replayed": "A repeated text from the provider was ignored",
    "confirmations.link_host_set": "Wording link host set",
    "confirmations.link_host_verified": "Wording link host verified",
    "confirmations.registration_marked": "Texting registration marked complete",
    "confirmations.registration_withdrawn": "Texting registration withdrawn",
    "confirmations.rule_changed": "Confirmation rule changed",
    "confirmations.template_created": "Confirmation email template added",
    "confirmations.test_sent": "Test confirmation sent",
    "confirmations.reply_marked": "Reply marked as a stop or not a stop",
    "confirmations.sends_listed": "Confirmation sends listed",
    "confirmations.replies_listed": "Confirmation replies listed",
    "wording.registered": "Wording registered",
    "policy.drafted": "Policy drafted",
    "policy.updated": "Policy draft changed",
    "policy.approved": "Policy approved",
    "checklist.drafted": "Checklist drafted",
    "checklist.updated": "Checklist draft changed",
    "checklist.approved": "Checklist approved",
    "checklist.checked": "Records checked against a checklist",
    "erasure.requested": "Erasure requested",
    "erasure.confirmed": "Erasure confirmed",
    "erasure.completed": "Erasure completed",
    "erasure.declined": "Erasure declined",
    "erasure.held": "Erasure held",
    "legal_hold.set": "Legal hold placed",
    "legal_hold.released": "Legal hold released",
    "legal_process.logged": "Legal process logged",
    "legal_process.closed": "Legal process closed",
    "legal_process.customer_notified": "Customer told of legal process",
    "legal_process.notice_prohibited": "Legal process notice prohibited",
    "operator_access.approved": "Operator access approved",
    "operator_access.opened": "Operator access opened",
    "operator_access.closed": "Operator access closed",
    "offboarding.requested": "Offboarding requested",
    "offboarding.run": "Offboarding run started",
    "offboarding.final_export": "Final export taken",
    "offboarding.export_link_issued": "Final export link sent",
    "offboarding.export_delivered": "Final export delivered",
    "offboarding.credentials_revoked": "Credentials revoked for offboarding",
    "offboarding.destruction_scheduled": "Key destruction scheduled",
    "offboarding.destruction_held": "Key destruction held",
    "offboarding.key_destroyed": "Organization key destroyed",
    "org_key.rotation_started": "Organization key rotation started",
    "org_key.rewrapped": "Keys re-wrapped under the new organization key",
    "org_key.rotation_blocked": "Organization key rotation blocked",
    "org_key.version_retained": "Old organization key version kept for the lifecycle ledger",
    "org_key.version_retained_for_backups": "Old organization key version kept until the oldest backup ages out",
    "org_key.rotation_cancelled": "Organization key rotation cancelled",
    "org_key.version_destroyed": "Old organization key version destroyed",
    "restore.begun": "Restore begun",
    "restore.reconciled": "Restore reconciled",
    "restore.gap": "Restore gap recorded",
    "restore.erasure_replayed": "Erasure replayed after restore",
    "restore.stop_unconfirmed": "Unconfirmed erasure stop replayed after restore",
    "restore.stop_reingested": "Stop re-ingested after restore",
    "system.registered": "Connected system registered",
    "system.updated": "Connected system changed",
    "system.signal_bound": "Connected system signal credential bound",
    "system.signal_unbound": "Connected system signal credential unbound",
    "system.gate_credential_issued": "Connected system gate credential issued",
    "system.gate_credential_revoked": "Connected system gate credential revoked",
    "setup.step_skipped": "Setup step skipped",
    "setup.step_unskipped": "Setup step returned to to do",
}

# platform-chain-only actions: never shown in a portal's filter menu (the platform chain has no organisation)
PLATFORM_ACTIONS = ("operator.refused",)
_ACTOR_KINDS = ("member", "credential", "operator", "system")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


def _check(actor_kind: str, action: str, request_id: str, extra: tuple[str, ...] = ()) -> None:
    if actor_kind not in _ACTOR_KINDS:
        raise AuditError(f"audit actor kind {actor_kind!r} is not one of {_ACTOR_KINDS}", code="audit_actor_kind_unknown")
    if action not in ACTIONS and action not in extra:
        raise AuditError(f"audit action {action!r} is not in the action list (audit.ACTIONS); add it there first",
                         code="audit_action_unlisted")
    if not isinstance(request_id, str) or not _REQUEST_ID.match(request_id):
        raise AuditError("an audit row needs the request id of the call that caused it", code="audit_request_id_missing")


def append(conn: psycopg.Connection, *, actor_kind: str, actor_id: Optional[str], action: str, target_kind: str,
           target_id: Optional[str] = None, reason: Optional[str] = None, request_id: str,
           detail: Optional[Mapping[str, Any]] = None):
    """Append a row to the current organisation's chain. Needs an entered tenant; returns the audit id.

    ``detail`` is an optional JSON object (record ids, counts); the chain hashes it with the rest of the row. It never holds a
    contact point, a name, a company or a reply text: the caller passes ids and counts only."""
    _check(actor_kind, action, request_id)
    try:
        if detail is None:
            row = conn.execute("SELECT consentvault.append_audit(%s, %s, %s, %s, %s, %s, %s) AS id",
                               (actor_kind, actor_id, action, target_kind, target_id, reason, request_id)).fetchone()
        else:
            if not isinstance(detail, Mapping):
                raise AuditError("an audit detail is a JSON object")
            row = conn.execute("SELECT consentvault.append_audit_detailed(%s, %s, %s, %s, %s, %s, %s, %s) AS id",
                               (actor_kind, actor_id, action, target_kind, target_id, reason, request_id,
                                Jsonb(dict(detail)))).fetchone()
    except psycopg.Error as exc:
        raise AuditError(f"could not append audit row {action!r}: {describe(exc)}") from exc
    return row["id"]


def append_platform(conn: psycopg.Connection, *, operator_id: str, action: str, target_kind: str,
                    target_id: Optional[str] = None, reason: Optional[str] = None, request_id: str):
    """Append a row to the platform chain (operator console only)."""
    _check("operator", action, request_id, PLATFORM_ACTIONS)
    try:
        row = conn.execute("SELECT consentvault.append_platform_audit(%s, %s, %s, %s, %s, %s) AS id",
                           (operator_id, action, target_kind, target_id, reason, request_id)).fetchone()
    except psycopg.Error as exc:
        raise AuditError(f"could not append platform audit row {action!r}: {describe(exc)}") from exc
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
