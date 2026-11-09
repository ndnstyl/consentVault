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


def backfill_post(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, org_id: str, post_id: str) -> int:
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
    writer.append_facts(conn, enter, org_id, post_id, key, facts)
    return len(facts)


BACKFILL_FOLD_VERSION = "backfill-1"
_EVENT_COLUMNS = ("event_id", "event_type", "channels", "purposes", "method", "origin", "contact_kind", "captured_at", "received_at",
                  "disclosure_sha256", "contact_verification", "source_id", "brand_ids", "contact_fp", "contact_ct", "hash_version")


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
                     facts=(Fact("vault", "legacy_event_id", str(event["event_id"])),))
    stored = writer.write(conn, enter, req)
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        conn.execute("INSERT INTO consentvault.event_source_post (org_id, event_id, post_id, role) VALUES"
                     " (consentvault.current_org(), %s, %s, 'trigger')", (event["event_id"], uuid.UUID(stored.post_id)))
    return stored.post_id


def write_backfill_row(conn: psycopg.Connection, enter: Callable | None, post_id: str, event: dict) -> bool:
    """The history row of a post that already has a legacy event: a copy of the event, label ``backfill`` (the database refuses a
    backfill row that does not match an event of the organisation). Returns True when written."""
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        if conn.execute("SELECT 1 FROM consentvault.post_history WHERE org_id = (SELECT consentvault.current_org()) AND post_id = %s",
                        (uuid.UUID(post_id),)).fetchone():
            return False
        seq = conn.execute("SELECT seq FROM consentvault.raw_post WHERE org_id = (SELECT consentvault.current_org()) AND post_id = %s",
                           (uuid.UUID(post_id),)).fetchone()["seq"]
        rule_set = "as-written-hash-v1" if event["hash_version"] == 1 else "as-written-hash-v2"
        conn.execute(
            "INSERT INTO consentvault.post_history (org_id, post_id, post_seq, placed_at, received_at, event_id, label, event_type_sent,"
            " channels_sent, purposes_sent, method_sent, origin_sent, contact_kind_sent, captured_at_sent, wording_sha256_sent,"
            " contact_verification_sent, source_id_sent, brand_ids_sent, standing, earliest_copy, contact_fp, contact_key_ref, contact_ct,"
            " completeness, facts_read, rule_set_version, fold_code_version, backfill_of_event_id, hash_version)"
            " VALUES (consentvault.current_org(), %s, %s, %s, %s, %s, 'backfill', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'counts', true,"
            " %s, %s, %s, '{}'::jsonb, '[]'::jsonb, %s, %s, %s, 3)",
            (uuid.UUID(post_id), seq, event["received_at"], event["received_at"], event["event_id"], event["event_type"],
             event["channels"], event["purposes"], event["method"], event["origin"], event["contact_kind"],
             None if event["captured_at"] is None else event["captured_at"].isoformat(), event["disclosure_sha256"],
             event["contact_verification"], None if event["source_id"] is None else str(event["source_id"]),
             None if event["brand_ids"] is None else [str(b) for b in event["brand_ids"]], event["contact_fp"], event["contact_fp"],
             event["contact_ct"], rule_set, BACKFILL_FOLD_VERSION, event["event_id"]))
    return True


def shadow_start(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None) -> dict:
    """For the entered organisation: backfill every post that predates migration 0082, then write every missing history row."""
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        orphans = _legacy_events_without_a_post(conn)
    for ev in orphans:
        post_id = store_legacy_event_post(writer, conn, enter, ev)
        write_backfill_row(conn, enter, post_id, ev)
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        posts = conn.execute(
            "SELECT p.org_id::text AS org, p.post_id::text AS post_id FROM consentvault.raw_post p"
            " WHERE p.org_id = (SELECT consentvault.current_org()) AND p.kind = 'post'"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.raw_post_fact f WHERE f.org_id = p.org_id AND f.post_id = p.post_id AND f.status IS NOT NULL)"
            " ORDER BY p.seq").fetchall()
    facts = 0
    legacy_rows = 0
    for r in posts:
        facts += backfill_post(writer, conn, enter, r["org"], r["post_id"])
        with (enter(conn) if enter is not None else conn.transaction()):
            ev = conn.execute(
                f"SELECT {', '.join('e.' + c for c in _EVENT_COLUMNS)} FROM consentvault.event_source_post s JOIN consentvault.event e"
                " ON e.org_id = s.org_id AND e.event_id = s.event_id WHERE s.org_id = (SELECT consentvault.current_org())"
                " AND s.post_id = %s AND s.role = 'trigger'", (uuid.UUID(r["post_id"]),)).fetchone()
        if ev is not None:
            legacy_rows += 1 if write_backfill_row(conn, enter, r["post_id"], ev) else 0
    rows = door.history_catch_up(writer, conn, enter, every_post=True)
    _log.info("shadow start finished")
    return {"posts": len(posts), "legacy_event_posts": len(orphans), "facts": facts, "history_rows": rows + legacy_rows}

