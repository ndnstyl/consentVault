"""Operator alarms (migration 0010, ``consentvault.operator_alarm``): a row the operator watches, never only a log line.

``raise_operator_alarm`` runs inside an entered tenant (``tenancy.tokens.org_transaction``); row-level security pins
the row to that organisation. The row holds names and ids only: no contact point, no message text.
"""

from __future__ import annotations

import re
import uuid

import psycopg

from .errors import ConsentVaultError

_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,80}$")


class AlarmWriteError(ConsentVaultError):
    """The alarm row itself could not be written."""


def raise_operator_alarm(conn: psycopg.Connection, *, name: str, error_class: str, ref_kind: str | None = None,
                         ref_id: str | uuid.UUID | None = None, request_id: str | None = None) -> None:
    """Write one alarm row for the entered organisation. Raises ``AlarmWriteError`` when it cannot."""
    cls = error_class if _CLASS.match(error_class or "") else "UnnamedError"
    try:
        with conn.transaction():
            conn.execute(
                "INSERT INTO consentvault.operator_alarm (org_id, name, ref_kind, ref_id, error_class, request_id)"
                " VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s)",
                (name, ref_kind, uuid.UUID(str(ref_id)) if ref_id is not None else None, cls, request_id))
    except (psycopg.Error, ValueError) as exc:
        raise AlarmWriteError(f"operator alarm {name!r} could not be written: {type(exc).__name__}") from exc
