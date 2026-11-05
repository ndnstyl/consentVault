"""``consentvault match-repair``: read and link every stored post that has no reading or no link under the map now in force.

Two things leave a post with no link: a step that failed after the post was stored (the alarm ``capture.link_failed`` or a
reading that could not be written), and a field map added later for the post's source. This run finds both with one rule:
for every stored post, the readings and the link rows under the map version in force for its source must exist, and where one
set is missing it is appended. A post that already has both is not touched. Rows are only ever appended: the post, its
facts, its earlier readings and its earlier link rows stay exactly as they were, and the history lists a re-read apart from
the reading made when the post arrived.

The run is safe to repeat. Each organisation runs under its own short admin token and one that fails is listed, the others
still run, and the run exits 1 naming each failure. It prints counts and organisation ids only, never a contact or a body.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable

import psycopg

from . import edge_envelope, extract, match
from .errors import ConsentVaultError
from .rawpost import COL_FACT, COL_HEADERS, ENC_NONE, RawPostWriter
from .safelog import describe
from .tenancy import crypto as tc
from .tenancy.tokens import mint_org_token, org_transaction

SCOPES = ["admin"]
BATCH = 200


def _facts(conn, org, post_id, key, encryption: str) -> dict[str, Any]:
    """The newest value of each fact name of one post."""
    out: dict[str, Any] = {}
    for r in conn.execute("SELECT name, value_ct FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s"
                          " ORDER BY recorded_at, fact_id", (org, post_id)).fetchall():
        blob = bytes(r["value_ct"])
        raw = blob if encryption == ENC_NONE else tc.decrypt_field(key, org, str(post_id), COL_FACT, blob)
        out[r["name"]] = json.loads(raw)
    return out


def _headers(row, key, org) -> tuple[tuple[str, str], ...]:
    blob = bytes(row["headers_ct"])
    raw = blob if row["encryption"] == ENC_NONE else tc.decrypt_field(key, org, str(row["post_id"]), COL_HEADERS, blob)
    return tuple((n, v) for n, v in json.loads(raw))


def _repair_post(writer: RawPostWriter, conn, enter: Callable, org: uuid.UUID, row, region, counts: dict) -> None:
    post_id = row["post_id"]
    with enter(conn):   # every read below runs inside the organisation
        key = None
        if row["encryption"] != ENC_NONE:
            key = writer.open_key(conn, org, post_id)
            if key is None:
                counts["erased"] += 1   # the key was erased: the bytes cannot be read and there is nothing to link
                return
        facts = _facts(conn, org, post_id, key, row["encryption"])
        source_id = facts.get("capture_source_id")
        fmap = extract.load_field_map(conn, source_id, row["intake"])
        mv = fmap.map_version if fmap else 0
        has_fields = conn.execute("SELECT 1 FROM consentvault.raw_post_field WHERE org_id = %s AND post_id = %s AND map_version = %s",
                                  (org, post_id, mv)).fetchone() is not None
        has_link = conn.execute("SELECT 1 FROM consentvault.raw_post_match WHERE org_id = %s AND post_id = %s AND map_version = %s",
                                (org, post_id, mv)).fetchone() is not None
        if has_fields and has_link:
            return
        body = writer.read_body(conn, org, post_id)
        headers = _headers(row, key, org)
    if facts.get("edge_envelope_signature") == "verified" and edge_envelope.looks_like_envelope(body):
        inner = edge_envelope.unpack(body)
        body, headers = inner.body, inner.headers
    content_type = next((v for n, v in headers if n.lower() == "content-type"), None)
    readings = extract.read_fields(body, content_type, fmap)
    if not has_fields:
        extract.write_readings(conn, enter, org=org, post_id=post_id, map_version=mv, readings=readings, data_key=key)
        counts["read"] += 1
    if not has_link:
        info = match.PostInfo(str(post_id), row["seq"], row["edge_received_at"] or row["received_at"], row["body_sha256"])
        match.link_post(writer, conn, enter, org=org, post=info, readings=readings,
                        contacts=match.find_contacts(body, content_type, fmap, region), map_version=mv,
                        source_id=source_id, data_key=key)
        counts["linked"] += 1


def _batch(conn, enter: Callable, org: uuid.UUID, after_seq: int) -> list:
    with enter(conn):
        return conn.execute("SELECT post_id, seq, intake, received_at, edge_received_at, body_sha256, encryption, headers_ct"
                            " FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post' AND seq > %s ORDER BY seq LIMIT %s",
                            (org, after_seq, BATCH)).fetchall()


def repair_org(writer: RawPostWriter, conn: psycopg.Connection, mint: Callable[[], str], org: uuid.UUID, *,
               region: str | None = None) -> dict:
    """Repair every post of one organisation. ``mint`` makes a fresh short token for each step, so a long run never outlives one.
    A post that cannot be repaired is listed and the rest still run."""
    counts: dict[str, Any] = {"read": 0, "linked": 0, "erased": 0, "failed": []}
    enter = lambda c: org_transaction(c, mint())  # noqa: E731
    rows = _batch(conn, enter, org, 0)
    while rows:   # the posts of one organisation are finite: each batch starts after the last sequence number seen
        for row in rows:
            try:
                _repair_post(writer, conn, enter, org, row, region, counts)
            except (ConsentVaultError, psycopg.Error) as exc:  # loud-failure-exempt: listed in the result's failed list and the run exits 1
                counts["failed"].append({"org_id": str(org), "post_id": str(row["post_id"]), "cause": type(exc).__name__})
        rows = _batch(conn, enter, org, rows[-1]["seq"])
    return counts


def repair_all(connect_app: Callable, owner_connect: Callable, token_key, writer: RawPostWriter, *, region: str | None = None) -> dict:
    """Run the repair for every organisation that is not closed. ``connect_app`` opens the runtime login (the only one that may
    append readings and links), ``owner_connect`` the operator login that lists the organisations."""
    totals: dict[str, Any] = {"organizations": 0, "read": 0, "linked": 0, "erased": 0, "failed": []}
    with owner_connect() as conn:
        orgs = [r["evidence_org_ids"] for r in conn.execute("SELECT consentvault.evidence_org_ids()")]
    for org in orgs:
        def mint(org=org):
            return mint_org_token(token_key, org, SCOPES, credential_id=None, ttl_seconds=300)
        try:
            with connect_app() as conn:
                one = repair_org(writer, conn, mint, org, region=region)
        except (ConsentVaultError, psycopg.Error) as exc:  # loud-failure-exempt: listed in the result's failed list and the run exits 1
            totals["failed"].append({"org_id": str(org), "cause": type(exc).__name__})
            continue
        totals["organizations"] += 1
        for k in ("read", "linked", "erased"):
            totals[k] += one[k]
        totals["failed"] += one["failed"]
    return totals


def main(argv=None, env=None) -> int:
    import os
    import sys

    from . import cmd_cloud, safelog as _safelog
    from .config import load_config
    from .db import connect
    from .errors import ConfigError
    from .tenancy.admin_routes import AdminApp

    _safelog.setup_process()
    env = os.environ if env is None else env
    try:
        settings = cmd_cloud.build_cloud(load_config(env=env), env)
        app = next(r._app for r in settings.routes if isinstance(getattr(r, "_app", None), AdminApp))
        writer = RawPostWriter(crypto=settings.crypto, store=settings.evidence_store, receipts=settings.receipts,
                               retain_years=settings.default_retain_years)
        result = repair_all(lambda: connect(settings.dsn), app._owner_connect, app._key, writer, region=settings.region)
    except (ConfigError, ConsentVaultError) as exc:
        print(f"consentvault.cmd_match_repair: {describe(exc)}", file=sys.stderr)
        return 2
    print(result)
    return 0 if not result["failed"] else 1


from .cli import EXIT_OK, register  # noqa: E402


def _run(args, cfg) -> int:
    return main()


register("match-repair", "link the stored posts that have no link or no reading under the map now in force", _run)
__all__ = ["EXIT_OK", "repair_all", "repair_org"]
