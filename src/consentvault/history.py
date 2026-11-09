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

FOLD_CODE_VERSION = "door-3"
RULE_SET_VERSION = "record-v1"
_NAMESPACE = uuid.UUID("5f0b1d52-7d0e-4c1c-9a53-3f1d2a6f9e01")

# gate 8: every element the record contract requires, and the field of the post it comes from
COMPLETENESS_ELEMENTS = {
    "wording": "disclosure_sha256", "act": "event_type", "timestamp": "captured_at", "contact": "contact", "business": "source_id",
    "ip": "client_ip", "user_agent": "user_agent", "page": "page_url", "form_version": "form_version",
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
        out[element] = {"state": "absent" if value in (None, "", [], {}) else "present", "source": source}
    return out


def standing_of(reason: str | None) -> str:
    return "counts" if reason is None else reason


def contact_of(fields: Mapping[str, Any], region: str | None, org_id: str, crypto: Any) -> tuple[str | None, str | None]:
    """The contact kind and its fingerprint, from the contact as sent. One of the fold's four allowed outside calls: the organisation's
    fingerprint secret, through the key provider. A contact that does not normalise has none, and the row records that; a key provider
    that fails raises, so the post waits alone and the next run tries again."""
    from .errors import NormalizationError
    from .normalize import normalize_contact

    contact = fields.get("contact")
    if crypto is None or not isinstance(contact, str) or not contact.strip():
        return None, None
    try:
        kind, norm = normalize_contact(contact, None, region)
    except NormalizationError:   # loud-failure-exempt: a contact point that is not a phone number or email has no fingerprint; the row records every value as sent
        return None, None
    return kind, crypto.contact_fingerprint(org_id, kind, norm)


def write_row(conn, ctx: Callable, *, org_id: str, post_id: str, fields: Mapping[str, Any], reason: str | None,
              earliest_copy: bool, facts_read: list, intake_code_version: str | None,
              contact: tuple[str | None, str | None] = (None, None)) -> bool:
    """Write the history row of one stored post unless it has one. Returns True when a row was written."""
    with ctx():
        if conn.execute("SELECT 1 FROM consentvault.post_history WHERE org_id = %s AND post_id = %s",
                        (uuid.UUID(org_id), uuid.UUID(post_id))).fetchone():
            return False
        post = conn.execute("SELECT post_seq AS seq, received_at, placed_at AS placed FROM consentvault.fold_post_place(%s)",
                            (uuid.UUID(post_id),)).fetchone()
        if post is None:
            raise LookupError("the post is not stored in the entered organisation")
        conn.execute(
            "INSERT INTO consentvault.post_history (org_id, post_id, post_seq, placed_at, received_at, event_id, label,"
            " event_type_sent, channels_sent, purposes_sent, method_sent, origin_sent, contact_kind_sent, captured_at_sent,"
            " wording_sha256_sent, contact_verification_sent, source_id_sent, brand_ids_sent, standing, earliest_copy,"
            " completeness, facts_read, rule_set_version, intake_code_version, fold_code_version, contact_fp, contact_key_ref, hash_version)"
            " VALUES (%s, %s, %s, %s, %s, %s, 'projected', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 3)",
            (uuid.UUID(org_id), uuid.UUID(post_id), post["seq"], post["placed"], post["received_at"], uuid.UUID(event_id_of(post_id)),
             _text(fields.get("event_type")), _as_list(fields.get("channels")), _as_list(fields.get("purposes")),
             _text(fields.get("method")), _text(fields.get("origin")), _text(fields.get("contact_kind")) or contact[0],
             _text(fields.get("captured_at")), _text(fields.get("disclosure_sha256")), _text(fields.get("contact_verification")),
             _text(fields.get("source_id")), _as_list(fields.get("brand_ids")), standing_of(reason), earliest_copy,
             Jsonb(completeness(fields)), Jsonb(facts_read), RULE_SET_VERSION, intake_code_version, FOLD_CODE_VERSION,
             contact[1], contact[1]))
    return True


def raw_fields(body: bytes) -> Mapping[str, Any]:
    """The fields as sent, for a body the reader could not make an event of: whatever the body says, best effort, never a refusal."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):  # loud-failure-exempt: an unreadable body has no fields; its row records every element absent
        return {}
    return data if isinstance(data, dict) else {}
