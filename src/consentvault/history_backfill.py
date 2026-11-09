"""Shadow start: bring every post stored before migration 0082 under the pure fold (specs/capture-everything/pure-projection.md,
migration step 6).

Rows written before 0082 carry no status, so the pure fold never reads them. The backfill writes, for each such post, a full
status-bearing ``backfill`` fact set: first the post's own pre-0082 arrival fact of each name (status ``value``, the same value), then
``not_found`` for every name the fold reads that the post never had, so no post waits on a fact that will never come. It then writes the
post's history row. It touches no post, no old fact, and no event. Safe to run any number of times: a post with a status-bearing fact is
skipped.
"""

from __future__ import annotations

import uuid
from typing import Callable

import psycopg

from . import door, safelog
from .rawpost import Fact, RawPostWriter

_log = safelog.get("consentvault.history_backfill")

# every fact name the fold reads (door.auth_from_facts, door.read_post's context, the settings the post arrived under)
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
    facts += [Fact("vault", n, None, status="not_found", label="backfill") for n in FOLD_NAMES if ("vault", n) not in old]
    writer.append_facts(conn, enter, org_id, post_id, key, facts)
    return len(facts)


def shadow_start(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None) -> dict:
    """For the entered organisation: backfill every post that predates migration 0082, then write every missing history row."""
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        posts = conn.execute(
            "SELECT p.org_id::text AS org, p.post_id::text AS post_id FROM consentvault.raw_post p"
            " WHERE p.org_id = (SELECT consentvault.current_org()) AND p.kind = 'post'"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.raw_post_fact f WHERE f.org_id = p.org_id AND f.post_id = p.post_id AND f.status IS NOT NULL)"
            " ORDER BY p.seq").fetchall()
    facts = sum(backfill_post(writer, conn, enter, r["org"], r["post_id"]) for r in posts)
    rows = door.history_catch_up(writer, conn, enter, every_post=True)
    _log.info("shadow start finished", posts=len(posts), facts=facts, history_rows=rows)
    return {"posts": len(posts), "facts": facts, "history_rows": rows}
