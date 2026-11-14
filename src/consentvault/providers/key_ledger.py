"""Where a cloud key provider keeps the destructions it scheduled: Postgres (migration 0028), never a task's disk.

``KeyLedgerStore`` is the interface a provider takes by injection: ``read()`` returns every org's entry (a JSON object),
``update(org_ref, change)`` applies ``change(entry)`` to one org's entry and stores it. ``PostgresKeyLedgerStore`` reads
and writes through ``consentvault.kms_key_ledger_read()`` / ``_write()``; only the operator console may write.
``MemoryKeyLedgerStore`` is for tests. Every failure is ``KeyProviderError`` naming what could not be done.
"""

from __future__ import annotations

import copy
import threading
from typing import Callable, Protocol

import psycopg
from psycopg.types.json import Jsonb

from ..safelog import describe
from .errors import KeyProviderError


class KeyLedgerStore(Protocol):
    def read(self) -> dict[str, dict]: ...

    def update(self, org_ref: str, change: Callable[[dict], None]) -> dict: ...


class MemoryKeyLedgerStore:
    def __init__(self) -> None:
        self._doc: dict[str, dict] = {}
        self._lock = threading.Lock()

    def read(self) -> dict[str, dict]:
        with self._lock:
            return copy.deepcopy(self._doc)

    def update(self, org_ref: str, change: Callable[[dict], None]) -> dict:
        with self._lock:
            entry = copy.deepcopy(self._doc.get(org_ref, {}))
            change(entry)
            self._doc[org_ref] = entry
            return copy.deepcopy(entry)


class PostgresKeyLedgerStore:
    """``connect`` returns an idle autocommit connection (the operator console's login to write)."""

    def __init__(self, connect: Callable[[], psycopg.Connection]):
        if not callable(connect):
            raise KeyProviderError("the key ledger store needs a connect callable")
        self._connect = connect

    def read(self) -> dict[str, dict]:
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT org_ref, entry FROM consentvault.kms_key_ledger_read()").fetchall()
        except psycopg.Error as exc:
            raise KeyProviderError(f"the key ledger cannot be read: {describe(exc)}") from exc
        return {r["org_ref"]: r["entry"] for r in rows}

    def update(self, org_ref: str, change: Callable[[dict], None]) -> dict:
        try:
            with self._connect() as conn, conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.kms_key_ledger:' || %s))", (org_ref,))
                row = next((r for r in conn.execute("SELECT org_ref, entry FROM consentvault.kms_key_ledger_read()")
                            if r["org_ref"] == org_ref), None)
                entry = dict(row["entry"]) if row else {}
                change(entry)
                conn.execute("SELECT consentvault.kms_key_ledger_write(%s, %s)", (org_ref, Jsonb(entry)))
        except psycopg.Error as exc:
            raise KeyProviderError(f"the key ledger entry for {org_ref} cannot be written: {type(exc).__name__}: "
                                   f"{describe(exc)}") from exc
        return entry
