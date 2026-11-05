"""The one way a stop is lifted: a later consent post from the person, on the same contact point.

A stop (an event written by a stop page, a STOP text, an erasure or an import) is lifted by a raw post that

* is matched to the stop's own contact point (the same keyed fingerprint),
* arrived after the stop on the database's clock, and
* carries a consent value, copied as sent, that is byte-equal to the value its form's box sends when ticked
  (``consent_ticked_value`` of the form's field map, the customer's own statement of its form).

The lift is recorded as a link from the stop to the post (``consentvault.stop_lift``). Nothing is deleted and the stop stays
on the record. No admin, operator, customer, staff member, connector, review queue or text reply can lift a stop: this
module has no argument that names a person or a reason, and a text (START included) is stored as received and is not a
consent post, so it never reaches here. The vault does not read the post for meaning: it compares bytes.

The caller holds a read scope (the stop and the readings must be readable) and has entered the organisation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import psycopg

from . import extract
from .errors import ConsentVaultError
from .rawpost import RawPostWriter

SKIP_NO_TICKED_VALUE = "the form's map names no ticked value"
SKIP_NO_MATCH = "the post is matched to no contact point"
SKIP_NOT_ONE_VALUE = "the consent value was not sent exactly once"
SKIP_DIFFERENT_VALUE = "the consent value is not the form's ticked value"
SKIP_NO_STOP = "no stop is open on the contact point"


@dataclass(frozen=True)
class LiftResult:
    """The stops this post lifted, and why it lifted none when it did not. ``reason`` is a fact, never a verdict."""

    linked: tuple[str, ...] = ()
    reason: str | None = None
    already: tuple[str, ...] = field(default=())


def lift_stops_for_post(conn: psycopg.Connection, writer: RawPostWriter, *, org: uuid.UUID | str,
                        post_id: uuid.UUID | str, ticked_value: str | None) -> LiftResult:
    """Link every stop on the post's contact point that arrived before the post, when the post's consent value equals
    ``ticked_value``. Idempotent: a stop already linked to this post is reported in ``already``."""
    org, post_id = uuid.UUID(str(org)), uuid.UUID(str(post_id))
    if ticked_value is None:
        return LiftResult(reason=SKIP_NO_TICKED_VALUE)
    matches = conn.execute(
        "SELECT DISTINCT contact_kind, contact_fp FROM consentvault.raw_post_match"
        " WHERE org_id = %s AND post_id = %s AND status = 'matched' AND contact_fp IS NOT NULL", (org, post_id)).fetchall()
    if not matches:
        return LiftResult(reason=SKIP_NO_MATCH)
    reading = extract.read_stored_values(conn, org, post_id, "consent", data_key=writer.open_key(conn, org, post_id))
    if reading["state"] != extract.SENT or len(reading["values"]) != 1:
        return LiftResult(reason=SKIP_NOT_ONE_VALUE)
    if reading["values"][0] != ticked_value:
        return LiftResult(reason=SKIP_DIFFERENT_VALUE)
    linked: list[str] = []
    already: list[str] = []
    for m in matches:
        stops = conn.execute(
            "SELECT e.event_id::text AS event_id, EXISTS (SELECT 1 FROM consentvault.stop_lift l"
            "   WHERE l.org_id = e.org_id AND l.stop_event_id = e.event_id AND l.lifting_post_id = %s) AS done"
            " FROM consentvault.event e WHERE e.org_id = %s AND e.contact_kind = %s AND e.contact_fp = %s"
            " AND e.event_type IN ('revoke', 'suppress')"
            " AND coalesce((SELECT sp.received_at FROM consentvault.event_source_post s JOIN consentvault.raw_post sp"
            "               ON sp.org_id = s.org_id AND sp.post_id = s.post_id WHERE s.org_id = e.org_id AND s.event_id = e.event_id"
            "               AND s.role = 'trigger' LIMIT 1), e.received_at)"
            "     < (SELECT p.received_at FROM consentvault.raw_post p WHERE p.org_id = %s AND p.post_id = %s)"
            " ORDER BY e.seq", (post_id, org, m["contact_kind"], m["contact_fp"], org, post_id)).fetchall()
        for stop in stops:
            if stop["done"]:
                already.append(stop["event_id"])
                continue
            try:
                with conn.transaction():
                    conn.execute("INSERT INTO consentvault.stop_lift (org_id, stop_event_id, lifting_post_id, contact_fp)"
                                 " VALUES (%s, %s, %s, %s)", (org, stop["event_id"], post_id, m["contact_fp"]))
            except psycopg.Error as exc:
                raise ConsentVaultError(f"the lift of stop {stop['event_id']} by post {post_id} was refused by the database: "
                                        f"{type(exc).__name__}") from exc
            linked.append(stop["event_id"])
    if not linked and not already:
        return LiftResult(reason=SKIP_NO_STOP)
    return LiftResult(tuple(linked), None, tuple(already))
