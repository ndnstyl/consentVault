"""The confirmation sender's writer inside the ledger transaction (confirmations.md section 5, core change R1)."""

from __future__ import annotations

import psycopg


def enqueue_confirmation_intents(conn: psycopg.Connection, *, event_id: str, contact_fp: str) -> int:
    """Insert one send intent per enabled rule of the grant's source, in the event's own transaction. Only a grant is confirmed;
    the function answers 0 for any other event. Returns the number of intents made."""
    return conn.execute("SELECT consentvault.confirmation_enqueue(%s, %s) AS n", (event_id, contact_fp)).fetchone()["n"]
