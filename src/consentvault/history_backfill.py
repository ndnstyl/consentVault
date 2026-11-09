"""Shadow start: bring every post stored before migration 0082 under the pure fold (specs/capture-everything/pure-projection.md,
migration step 6).

Rows written before 0082 carry no status, so the pure fold never reads them. The backfill writes, for each such post, a full
status-bearing ``backfill`` fact set: first the post's own pre-0082 arrival fact of each name (status ``value``, the same value), then
``not_found`` for every name the fold reads that the post never had, so no post waits on a fact that will never come. It then writes the
post's history row. It touches no post, no old fact, and no event. Safe to run any number of times: a post with a status-bearing fact is
skipped.
"""

from __future__ import annotations

import json
import uuid
from typing import Callable

import psycopg

from . import door, history, safelog
from .rawpost import Fact, RawPostWriter, RawRequest

_log = safelog.get("consentvault.history_backfill")

# every fact name the fold reads (door.auth_from_facts, door.read_post's context, the settings the post arrived under)
# facts a post may still be given after it is stored: a backfilled not_found would turn the real answer into a lost race
LATE_NAMES = ("request_signature",)
FOLD_NAMES = ("request_signature", "authenticated_by", "tenant", "credential", "site_key_lookup", "edge_timestamp", "request_key",
              door.TENANT_SETTINGS_FACT, "projection_settings")


def backfill_post(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, org_id: str, post_id: str,
                  event: dict | None = None) -> int:
    """Write the backfill fact set of one post; returns the facts written (0 when the post already has status-bearing facts)."""
    org = uuid.UUID(org_id)
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        if conn.execute("SELECT 1 FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s AND status IS NOT NULL LIMIT 1",
                        (org, uuid.UUID(post_id))).fetchone():
            return 0
        old = writer.read_facts(conn, org, post_id)
        key = writer.open_key(conn, org, post_id)
    facts = [Fact(s, n, v, status="value", label="backfill") for (s, n), v in sorted(old.items())]
    facts += [Fact("vault", n, None, status="not_found", label="backfill") for n in FOLD_NAMES if ("vault", n) not in old and n not in LATE_NAMES]
    if event is not None:   # the legacy event rides as a fact, so the row it becomes is the fold's of the facts and replays the same
        facts.append(Fact("vault", LEGACY_EVENT_FACT, legacy_event_value(event), status="value", label="backfill"))
    writer.append_facts(conn, enter, org_id, post_id, key, facts)
    return len(facts)


LEGACY_EVENT_FACT = "legacy_event"
BACKFILL_FOLD_VERSION = "backfill-1"
_EVENT_COLUMNS = ("event_id", "event_type", "channels", "purposes", "method", "origin", "contact_kind", "captured_at", "received_at",
                  "disclosure_sha256", "contact_verification", "source_id", "brand_ids", "contact_fp", "contact_ct", "hash_version")


def legacy_event_value(e: dict) -> dict:
    """The legacy event as plain values (no personal field: the contact is its fingerprint and its sealed bytes)."""
    iso = lambda t: None if t is None else t.isoformat()  # noqa: E731
    return {"event_id": str(e["event_id"]), "event_type": e["event_type"], "channels": list(e["channels"]), "purposes": list(e["purposes"]),
            "method": e["method"], "origin": e["origin"], "contact_kind": e["contact_kind"], "captured_at": iso(e["captured_at"]),
            "received_at": iso(e["received_at"]), "disclosure_sha256": e["disclosure_sha256"],
            "contact_verification": e["contact_verification"], "source_id": None if e["source_id"] is None else str(e["source_id"]),
            "brand_ids": None if e["brand_ids"] is None else [str(b) for b in e["brand_ids"]], "contact_fp": e["contact_fp"],
            "contact_ct": None if e["contact_ct"] is None else bytes(e["contact_ct"]).hex(), "hash_version": e["hash_version"]}


def _legacy_events_without_a_post(conn: psycopg.Connection) -> list[dict]:
    return conn.execute(
        f"SELECT {', '.join('e.' + c for c in _EVENT_COLUMNS)} FROM consentvault.event e"
        " WHERE e.org_id = (SELECT consentvault.current_org())"
        "   AND NOT EXISTS (SELECT 1 FROM consentvault.event_source_post s WHERE s.org_id = e.org_id AND s.event_id = e.event_id"
        "                    AND s.role = 'trigger')"
        " ORDER BY e.seq").fetchall()


def store_legacy_event_post(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, event: dict) -> str:
    """An event the old system wrote with no post gets one, so every event has a post to hang its history row on. The body names the
    event by its id and fingerprint; it holds no personal data. Returns the new post's id."""
    body = json.dumps({"legacy_event_id": str(event["event_id"]), "contact_fp": event["contact_fp"], "event_type": event["event_type"]},
                      sort_keys=True).encode("utf-8")
    req = RawRequest(intake="legacy_event", method="POST", path="/legacy-event", query="", headers=(("content-type", "application/json"),),
                     body=body, headers_presented_by="backfill",
                     facts=(Fact("vault", "legacy_event_id", str(event["event_id"])),
                            Fact("vault", LEGACY_EVENT_FACT, legacy_event_value(event))))
    stored = writer.write(conn, enter, req)
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        conn.execute("INSERT INTO consentvault.event_source_post (org_id, event_id, post_id, role) VALUES"
                     " (consentvault.current_org(), %s, %s, 'trigger')", (event["event_id"], uuid.UUID(stored.post_id)))
    return stored.post_id


def shadow_start(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None) -> dict:
    """For the entered organisation: backfill every post that predates migration 0082, then write every missing history row."""
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        orphans = _legacy_events_without_a_post(conn)
    for ev in orphans:
        store_legacy_event_post(writer, conn, enter, ev)
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        posts = conn.execute(
            "SELECT p.org_id::text AS org, p.post_id::text AS post_id FROM consentvault.raw_post p"
            " WHERE p.org_id = (SELECT consentvault.current_org()) AND p.kind = 'post'"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.raw_post_fact f WHERE f.org_id = p.org_id AND f.post_id = p.post_id AND f.status IS NOT NULL)"
            " ORDER BY p.seq").fetchall()
    facts = 0
    for r in posts:
        with (enter(conn) if enter is not None else conn.transaction()):
            ev = conn.execute(
                f"SELECT {', '.join('e.' + c for c in _EVENT_COLUMNS)} FROM consentvault.event_source_post s JOIN consentvault.event e"
                " ON e.org_id = s.org_id AND e.event_id = s.event_id WHERE s.org_id = (SELECT consentvault.current_org())"
                " AND s.post_id = %s AND s.role = 'trigger'", (uuid.UUID(r["post_id"]),)).fetchone()
        facts += backfill_post(writer, conn, enter, r["org"], r["post_id"], ev)
    rows = door.history_catch_up(writer, conn, enter, every_post=True)
    _log.info("shadow start finished")
    return {"posts": len(posts), "legacy_event_posts": len(orphans), "facts": facts, "history_rows": rows}
