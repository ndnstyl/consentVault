"""The retrieval log (gate 4, item 31): every read of the record that hands something over writes its own row first, in the read's
transaction. A read whose row cannot be written returns nothing and raises: the caller never sees a payload the log does not name.

``what`` is the ids the read returned. ``payload_sha256`` is the sha256 of the canonical JSON of the returned payload, without any
envelope field the export adds on top (``generated_at``), so two reads of the same record a minute apart log the same hash.
"""

from __future__ import annotations

import hashlib
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from . import safelog
from .errors import ConsentVaultError
from .ledger import canonical_dumps

_log = safelog.get("consentvault.retrieval")

ENVELOPE_KEYS = ("generated_at",)


class RetrievalLogError(ConsentVaultError):
    """The log row of a read could not be written, so the read returns nothing."""


def ids_in(payload: Any, keys: tuple[str, ...] = ("event_id", "post_id", "decision_id")) -> list[str]:
    """Every id the payload names, sorted and unique (what the read returned)."""
    found: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                if k in keys and v is not None:
                    found.add(str(v))
                else:
                    walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                walk(v)

    walk(payload)
    return sorted(found)


def payload_sha256(payload: Any) -> str:
    body = {k: v for k, v in payload.items() if k not in ENVELOPE_KEYS} if isinstance(payload, dict) else payload
    return hashlib.sha256(canonical_dumps(body).encode("utf-8")).hexdigest()


def log_retrieval(conn: psycopg.Connection, payload: Any, *, what: list[str] | None = None) -> None:
    """Write the log row for a read about to be returned. Raises ``RetrievalLogError`` (naming the cause class) when it cannot."""
    try:
        with conn.transaction():
            credential = conn.execute("SELECT consentvault.current_token_credential() AS c").fetchone()["c"]
            kind, actor = ("credential", credential) if credential else (
                "process", conn.execute("SELECT current_user AS u").fetchone()["u"])
            conn.execute("INSERT INTO consentvault.retrieval_log (actor_kind, actor_id, what, payload_sha256) VALUES (%s, %s, %s, %s)",
                         (kind, actor, Jsonb(ids_in(payload) if what is None else what), payload_sha256(payload)))
    except psycopg.Error as exc:
        _log.error("a read was refused because its retrieval log row could not be written", error=type(exc).__name__)
        raise RetrievalLogError("the retrieval could not be logged, so nothing was returned", code="retrieval_log_failed") from exc
