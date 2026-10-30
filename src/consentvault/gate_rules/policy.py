"""Read the entered organisation's approved policy and its documentation-check results (tables of migration 0005)."""

from __future__ import annotations

import psycopg

from ..errors import ConsentVaultError
from .engine import ApprovedPolicy


class PolicyStoreError(ConsentVaultError):
    """The policy or the documentation-check results could not be read."""


def approved_policy(conn: psycopg.Connection) -> ApprovedPolicy | None:
    """The one approved policy of the entered organisation, or None when the client has approved none."""
    try:
        rows = conn.execute(
            "SELECT p.version, p.rules, a.approved_by::text AS approved_by, a.approved_at,"
            "       a.approval_id::text AS approval_id"
            "  FROM consentvault.policy p"
            "  JOIN consentvault.policy_approval a ON a.org_id = p.org_id AND a.version = p.version"
            " WHERE p.org_id = consentvault.current_org() AND p.status = 'approved'").fetchall()
    except psycopg.Error as exc:
        raise PolicyStoreError(f"the approved policy could not be read: {type(exc).__name__}") from exc
    if len(rows) > 1:
        raise PolicyStoreError("more than one approved policy is in force; the gate will not pick one")
    if not rows:
        return None
    r = rows[0]
    if not isinstance(r["rules"], dict):
        raise PolicyStoreError(f"policy version {r['version']} has rules that are not a JSON object")
    return ApprovedPolicy(r["version"], r["rules"], r["approved_by"], r["approved_at"], r["approval_id"])


def missing_elements(conn: psycopg.Connection, event_id: str, checklist_version: int) -> list[str]:
    """The checklist elements a record lacks (documentation completeness, never a legal test).

    A record never checked against that version answers ``["not_checked"]``. Raises ``PolicyStoreError`` when the
    results table does not exist yet or cannot be read: the gate then answers unavailable rather than guess.
    """
    try:
        present = conn.execute("SELECT to_regclass('consentvault.doc_check_result') AS t").fetchone()["t"]
        if present is None:
            raise PolicyStoreError("documentation-check results are not stored in this vault (no doc_check_result)")
        row = conn.execute(
            "SELECT missing FROM consentvault.doc_check_result WHERE org_id = consentvault.current_org()"
            " AND event_id = %s::uuid AND checklist_version = %s ORDER BY checked_at DESC, check_id DESC LIMIT 1",
            (event_id, checklist_version)).fetchone()
    except psycopg.Error as exc:
        raise PolicyStoreError(f"documentation-check results could not be read: {type(exc).__name__}") from exc
    if row is None:
        return ["not_checked"]
    return [str(m) for m in (row["missing"] or [])]
