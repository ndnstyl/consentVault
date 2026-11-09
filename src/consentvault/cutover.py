"""The cutover window's per-organisation job (M2). At the cutover the watermark of an organisation is the highest raw-post sequence number
the old fold had finished (the post has an event link or a recorded outcome). It is written to ``effect_watermark``; then, because a fact's
value is encrypted under its post's own key, which the migration role cannot use, this job enters each organisation with its own token and
writes the fact ``effect_watermark`` = below on every stored post at or below the watermark and = above on every stored post above it (an
above post also gets the delivery targets as they stand now, so the fold can derive its effects from facts alone). Safe to run again: a post
that already has the fact is skipped."""

from __future__ import annotations

import uuid
from typing import Any

import psycopg

from .errors import ConsentVaultError
from .rawpost import Fact, RawPostWriter, RawRequest
from .safelog import describe
from .tenancy.errors import KeyProviderError
from .tenancy.tokens import mint_org_token, org_transaction

SCOPES = ["admin", "capture"]


def write_watermark_facts(owner_connect, token_key, custody, crypto) -> dict[str, Any]:
    totals: dict[str, Any] = {"organizations": 0, "below": 0, "above": 0, "failed": []}
    with owner_connect() as conn:
        orgs = [r["evidence_org_ids"] for r in conn.execute("SELECT consentvault.evidence_org_ids()")]
    for org in orgs:
        try:
            with owner_connect() as conn:
                one = _one_org(conn, token_key, crypto, org)
        except (psycopg.Error, KeyProviderError, ConsentVaultError) as exc:  # loud-failure-exempt: listed in the result's failed list; the caller exits non-zero on it
            totals["failed"].append({"org_id": str(org), "cause": describe(exc)})
            continue
        totals["organizations"] += 1
        totals["below"] += one["below"]
        totals["above"] += one["above"]
    if totals["failed"]:
        raise ConsentVaultError(f"the watermark facts could not be written for {len(totals['failed'])} organisation(s): {totals['failed']}",
                                code="watermark_incomplete")
    return totals


def _one_org(conn, token_key, crypto, org) -> dict[str, int]:
    token = mint_org_token(token_key, org, SCOPES, credential_id=None, ttl_seconds=300)
    writer = RawPostWriter(crypto=crypto)
    enter = lambda c: c.transaction()  # noqa: E731
    with org_transaction(conn, token):
        row = conn.execute("SELECT head_seq FROM consentvault.effect_watermark WHERE org_id = consentvault.current_org()").fetchone()
        if row is None:
            head = conn.execute(
                "SELECT coalesce(max(p.seq), 0) AS h FROM consentvault.raw_post p WHERE p.org_id = consentvault.current_org() AND p.kind = 'post'"
                " AND (EXISTS (SELECT 1 FROM consentvault.event_source_post s WHERE s.org_id = p.org_id AND s.post_id = p.post_id)"
                "      OR EXISTS (SELECT 1 FROM consentvault.projection_outcome o WHERE o.org_id = p.org_id AND o.post_id = p.post_id))"
            ).fetchone()["h"]
            conn.execute("INSERT INTO consentvault.effect_watermark (org_id, head_seq) VALUES (consentvault.current_org(), %s)", (head,))
        else:
            head = row["head_seq"]
    # the watermark is fixed before anything below can add a link or an outcome; then the shadow start brings every earlier post under the
    # fold (idempotent: a post it has already handled is skipped), and the facts follow
    from .history_backfill import shadow_start

    with org_transaction(conn, token):
        shadow_start(writer, conn, enter)
    with org_transaction(conn, token):
        posts = conn.execute("SELECT post_id::text AS post_id, seq FROM consentvault.raw_post WHERE org_id = consentvault.current_org()"
                             " AND kind = 'post' ORDER BY seq").fetchall()
    out = {"below": 0, "above": 0}
    above_facts = None
    for p in posts:
        with org_transaction(conn, token):
            key = writer.open_key(conn, uuid.UUID(str(org)), p["post_id"])
            have = writer.read_fold_facts(conn, uuid.UUID(str(org)), p["post_id"], key)
            if ("vault", "effect_watermark") in have:
                continue
            if p["seq"] <= head:
                facts, side = [Fact("vault", "effect_watermark", "below", status="value", label="backfill")], "below"
            else:
                if above_facts is None:
                    above_facts = RawPostWriter._cutover_facts(conn, enter, RawRequest(intake="cutover", method="POST", path="/", query="",
                                                                                        headers=(), body=b"", headers_presented_by="cutover", facts=()))
                facts, side = [Fact(f.source, f.name, f.value, status="value", label="backfill") for f in above_facts], "above"
            writer.append_facts(conn, enter, str(org), p["post_id"], key, facts)
            out[side] += 1
    return out
