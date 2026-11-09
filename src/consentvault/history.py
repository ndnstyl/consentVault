"""The pure fold: one history row per stored post, holding every value as sent (migration 0084).

It reads the post's stored bytes, the post's own facts and the request-key rows, and writes only ``post_history``. It opens no
lookup table, reads no clock and draws no random value; the database stamps the order, the link and the hash. It refuses nothing:
the sender's standing and whether the post is the first copy of its request are recorded, never used to drop a post.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Mapping

from psycopg.types.json import Jsonb

from . import safelog

_log = safelog.get("consentvault.history")

FOLD_CODE_VERSION = "fold-1"
RULE_SET_VERSION = "record-v1"
_NAMESPACE = uuid.UUID("5f0b1d52-7d0e-4c1c-9a53-3f1d2a6f9e01")

# gate 8: every element the record contract requires, and the field of the post it comes from
COMPLETENESS_ELEMENTS = {
    "contact": "contact", "event_type": "event_type", "channels": "channels", "purposes": "purposes", "method": "method",
    "origin": "origin", "wording": "disclosure_sha256", "captured_at": "captured_at", "session": "session_ref",
    "ip": "client_ip", "user_agent": "user_agent", "page": "page_url", "form_version": "form_version", "source": "source_id",
}


def event_id_of(post_id: str) -> str:
    """The event id of a post: derived from the post id, so a replay gives the same id and the id needs no lookup."""
    return str(uuid.uuid5(_NAMESPACE, str(post_id)))


def _as_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def completeness(fields: Mapping[str, Any]) -> dict:
    out = {}
    for element, source in COMPLETENESS_ELEMENTS.items():
        value = fields.get(source)
        out[element] = {"state": "absent" if value in (None, "", [], {}) else "present", "from": source}
    return out


def standing_of(reason: str | None) -> str:
    return "counts" if reason is None else reason


def write_row(conn, ctx: Callable, *, org_id: str, post_id: str, fields: Mapping[str, Any], reason: str | None,
              earliest_copy: bool, facts_read: list, intake_code_version: str | None) -> bool:
    """Write the history row of one stored post unless it has one. Returns True when a row was written."""
    with ctx():
        if conn.execute("SELECT 1 FROM consentvault.post_history WHERE org_id = %s AND post_id = %s",
                        (uuid.UUID(org_id), uuid.UUID(post_id))).fetchone():
            return False
        post = conn.execute(
            "SELECT rp.seq, rp.received_at, LEAST(rp.received_at, coalesce(oa.arrived_at, rp.received_at)) AS placed"
            " FROM consentvault.raw_post rp LEFT JOIN consentvault.raw_post_original_arrival oa"
            "   ON oa.org_id = rp.org_id AND oa.post_id = rp.post_id WHERE rp.org_id = %s AND rp.post_id = %s",
            (uuid.UUID(org_id), uuid.UUID(post_id))).fetchone()
        if post is None:
            raise LookupError("the post cannot be read in this context (a capture token writes but cannot read back)")
        conn.execute(
            "INSERT INTO consentvault.post_history (org_id, post_id, post_seq, placed_at, received_at, event_id, label,"
            " event_type_sent, channels_sent, purposes_sent, method_sent, origin_sent, contact_kind_sent, captured_at_sent,"
            " wording_sha256_sent, contact_verification_sent, source_id_sent, brand_ids_sent, standing, earliest_copy,"
            " completeness, facts_read, rule_set_version, intake_code_version, fold_code_version, hash_version)"
            " VALUES (%s, %s, %s, %s, %s, %s, 'projected', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 3)",
            (uuid.UUID(org_id), uuid.UUID(post_id), post["seq"], post["placed"], post["received_at"], uuid.UUID(event_id_of(post_id)),
             _text(fields.get("event_type")), _as_list(fields.get("channels")), _as_list(fields.get("purposes")),
             _text(fields.get("method")), _text(fields.get("origin")), _text(fields.get("contact_kind")),
             _text(fields.get("captured_at")), _text(fields.get("disclosure_sha256")), _text(fields.get("contact_verification")),
             _text(fields.get("source_id")), _as_list(fields.get("brand_ids")), standing_of(reason), earliest_copy,
             Jsonb(completeness(fields)), Jsonb(facts_read), RULE_SET_VERSION, intake_code_version, FOLD_CODE_VERSION))
    return True


def raw_fields(body: bytes) -> Mapping[str, Any]:
    """The fields as sent, for a body the reader could not make an event of: whatever the body says, best effort, never a refusal."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):  # loud-failure-exempt: an unreadable body has no fields; its row records every element absent
        return {}
    return data if isinstance(data, dict) else {}
