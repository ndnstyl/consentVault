"""Connected systems, sync side: open a system's signing credential and bind a signal credential to a system.

Registration and editing of systems belong to the admin lane (``tenancy/admin.py``), which holds the column grants on
``connected_system``. It seals the signing credential (an HMAC secret or an Ed25519 private key seed, 32 raw bytes
either way) with ``custody.wrap(str(org_id), secret)``: the organisation's own key, not a per-contact key, so the
credential dies with the organisation key and a database dump alone never signs a push. The worker opens it with the
same custody object (``consentvault.providers.keys.KeyProvider``: ``wrap(org_id: str, data: bytes) -> bytes`` and
``unwrap(org_id: str, wrapped: bytes) -> bytes``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

import psycopg

from ..safelog import caller_detail, describe
from .errors import CredentialError, SystemNotFoundError
from ..lengths import is_bytes_of_len


class Custody(Protocol):
    def wrap(self, org_id: str, data_key: bytes) -> bytes: ...

    def unwrap(self, org_id: str, wrapped: bytes) -> bytes: ...


def seal_credentials(custody: Custody, org_id, secret: bytes) -> bytes:
    if not is_bytes_of_len(secret, 32):
        raise CredentialError("a signing credential is 32 raw bytes (an HMAC secret or an Ed25519 seed)")
    return custody.wrap(str(org_id), secret)


def open_credentials(custody: Custody, org_id, system_id, blob) -> bytes:
    """The raw signing credential of one system. Any failure is a named ``CredentialError``."""
    if blob is None:
        raise CredentialError(f"system {system_id} has no signing credential; it cannot be pushed to")
    try:
        secret = custody.unwrap(str(org_id), bytes(blob))
    except Exception as exc:  # the custody provider's own error types differ; every one is named here and carried
        raise CredentialError(f"the credential of system {system_id} cannot be opened: {describe(exc)}",
                              code="credential_unopenable") from exc
    if not is_bytes_of_len(secret, 32):
        raise CredentialError(f"the credential of system {system_id} is not 32 bytes after opening")
    return secret


def bind_signal_credential(conn: psycopg.Connection, system_id, credential_id) -> None:
    """Make ``credential_id`` (a live ``capture`` credential) the one whose signals ``system_id`` sends. Run it inside
    ``org_transaction`` with an admin or developer token."""
    try:
        conn.execute("SELECT consentvault.sync_system_bind_credential(%s, %s)",
                     (uuid.UUID(str(system_id)), uuid.UUID(str(credential_id))))
    except psycopg.errors.NoDataFound as exc:
        raise SystemNotFoundError(caller_detail(exc)) from exc
    except psycopg.errors.UniqueViolation as exc:
        raise SystemNotFoundError("that credential already carries another system's signals") from exc


def unbind_signal_credential(conn: psycopg.Connection, system_id) -> uuid.UUID | None:
    """Clear the system's signal credential (back to none); returns the credential it carried, if any. Run it inside
    ``org_transaction`` with an admin or developer token."""
    try:
        return conn.execute("SELECT consentvault.sync_system_unbind_credential(%s) AS was",
                            (uuid.UUID(str(system_id)),)).fetchone()["was"]
    except psycopg.errors.NoDataFound as exc:
        raise SystemNotFoundError(caller_detail(exc)) from exc
