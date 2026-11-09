"""The row a confirmation or a reply rests on: an event of the frozen event table, or, after an organisation's cutover, a history row.
Readers ask for it by id and get the same fields either way."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any


def _uuid_list(values) -> list:
    return [uuid.UUID(str(v)) for v in (values or [])]


def _parse(text: str | None, fallback: datetime) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")) if text else fallback


def event_like(conn, org, event_id) -> dict | None:
    """The fields of the event (or, failing that, the history row) with this id in the organisation; None when neither exists."""
    ev = conn.execute("SELECT * FROM consentvault.event WHERE org_id = %s AND event_id = %s", (org, event_id)).fetchone()
    if ev is not None:
        return dict(ev)
    h = conn.execute("SELECT * FROM consentvault.post_history WHERE org_id = %s AND event_id = %s", (org, event_id)).fetchone()
    if h is None:
        return None
    return {"event_id": h["event_id"], "contact_fp": h["contact_fp"], "contact_kind": h["contact_kind_sent"], "contact_ct": h["contact_ct"],
            "event_type": h["event_type_sent"], "channels": h["channels_sent"] or [], "purposes": h["purposes_sent"] or [],
            "received_at": h["received_at"], "captured_at": _parse(h["captured_at_sent"], h["received_at"]),
            "disclosure_sha256": h["wording_sha256_sent"], "source_id": uuid.UUID(h["source_id_sent"]) if h["source_id_sent"] else None,
            "brand_ids": _uuid_list(h["brand_ids_sent"]), "seq": h["history_seq"], "row_hash": h["row_hash"]}


def latest_event_id_for_contact(conn, org, fp: str) -> Any:
    """The id of the newest event of a contact, from the frozen table or from history (whichever is newer by arrival)."""
    row = conn.execute(
        "SELECT event_id FROM (SELECT event_id, received_at FROM consentvault.event WHERE org_id = %s AND contact_fp = %s"
        " UNION ALL SELECT event_id, received_at FROM consentvault.post_history WHERE org_id = %s AND contact_fp = %s) x"
        " ORDER BY received_at DESC LIMIT 1", (org, fp, org, fp)).fetchone()
    return None if row is None else row["event_id"]
