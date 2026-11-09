"""Load a store onto a fresh, migrated database at stored arrival, and project it (migration 0086; the proof of purity).

The loader reads the source as a superuser and writes the target through ``load_lookup_rows`` and ``load_stored_post``, which only
``consentvault_loader`` may call and which refuse unless the target carries the replay mark. It enters each organisation, one at a
time, with a short token the fresh database accepts. The source's chains are verified end to end before loading and the loaded chains
after: a break on either side raises.
"""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import door
from .rawpost import RawPostWriter, verify_raw_chain
from .tenancy.tokens import TokenKey, mint_org_token, org_transaction

_LOOKUPS = ("organization", "org_key", "org_fingerprint_secret", "org_display_key", "contact_key")


def _all(conn, query: str, params=()) -> list[dict]:
    return [r["j"] for r in conn.execute(f"SELECT row_to_json(t) AS j FROM ({query}) t", params).fetchall()]


def _orgs(src, home: str) -> list[str]:
    ids = [r["org_id"] for r in src.execute("SELECT org_id::text AS org_id FROM consentvault.organization ORDER BY org_id").fetchall()]
    return sorted(ids, key=lambda o: (o != home, o))


def load_store(source_dsn: str, target_dsn: str, *, token_key: TokenKey) -> dict:
    """Load every organisation of the source onto the target. Returns {"posts": n, "orgs": n}."""
    with psycopg.connect(source_dsn, autocommit=True, row_factory=dict_row) as src, \
            psycopg.connect(target_dsn, autocommit=True, row_factory=dict_row) as tgt:
        setting = src.execute("SELECT mode, home_org_id::text AS home FROM consentvault.tenancy_setting").fetchone()
        orgs = _orgs(src, setting["home"])
        for org in orgs:   # the source chains verify before anything is loaded
            with src.transaction():
                src.execute("SELECT consentvault.enter_org(%s)", (mint_org_token(token_key, org, ["admin"], credential_id=None),))
                breaks = verify_raw_chain(src)
            if breaks:
                raise RuntimeError(f"the source chain of organisation {org} is broken before loading: {breaks[0]}")
        with tgt.transaction():   # superuser break-glass on a throwaway database: its seed home organisation is replaced by the stored one
            tgt.execute("SET LOCAL session_replication_role = replica")
            tgt.execute("DELETE FROM consentvault.tenancy_setting")
            tgt.execute("DELETE FROM consentvault.organization")
            for row in _all(src, "SELECT * FROM consentvault.organization ORDER BY org_id"):
                tgt.execute("INSERT INTO consentvault.organization SELECT * FROM jsonb_populate_record(NULL::consentvault.organization, %s)", (Jsonb(row),))
            for row in _all(src, "SELECT * FROM consentvault.tenancy_setting"):
                tgt.execute("INSERT INTO consentvault.tenancy_setting SELECT * FROM jsonb_populate_record(NULL::consentvault.tenancy_setting, %s)", (Jsonb(row),))
            tgt.execute("INSERT INTO consentvault.tenant_token_key (key_id, secret) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                        (token_key.key_id, token_key.secret))
        tgt.execute("SET ROLE consentvault_loader")
        tgt.execute("INSERT INTO consentvault.replay_target DEFAULT VALUES")
        n = 0
        extra: dict[str, dict] = {}
        for org in orgs:
            token = mint_org_token(token_key, org, ["admin"], credential_id=None)
            lookups = {t: _all(src, f"SELECT * FROM consentvault.{t} WHERE org_id = %s", (org,)) for t in _LOOKUPS if t != "organization"}
            lookups["organization"] = []
            with org_transaction(tgt, token):
                tgt.execute("SELECT consentvault.load_lookup_rows(%s)", (Jsonb(lookups),))
                for p in _all(src, "SELECT * FROM consentvault.raw_post WHERE org_id = %s ORDER BY seq", (org,)):
                    pid = p["post_id"]
                    doc = {"post": p,
                           "key": next(iter(_all(src, "SELECT * FROM consentvault.raw_post_key WHERE org_id = %s AND post_id = %s", (org, pid))), None),
                           "facts": _all(src, "SELECT * FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s"
                                              " ORDER BY coalesce(fact_seq, 0), recorded_at", (org, pid)),
                           "requests": _all(src, "SELECT * FROM consentvault.raw_post_request WHERE org_id = %s AND post_id = %s", (org, pid)),
                           "original_arrival": _all(src, "SELECT * FROM consentvault.raw_post_original_arrival WHERE org_id = %s AND post_id = %s", (org, pid)),
                           "seals": _all(src, "SELECT * FROM consentvault.raw_post_seal WHERE org_id = %s AND post_id = %s", (org, pid))}
                    tgt.execute("SELECT consentvault.load_stored_post(%s)", (Jsonb(doc),))
                    n += 1
            extra[org] = {"reroutes": _all(src, "SELECT * FROM consentvault.raw_post_reroute WHERE from_org = %s", (org,)),
                          "anchors": _all(src, "SELECT * FROM consentvault.raw_post_chain_head WHERE org_id = %s ORDER BY seq", (org,))}
        for org in orgs:   # every post of every organisation is in: now the rows that cite two organisations, and the anchors
            with org_transaction(tgt, mint_org_token(token_key, org, ["admin"], credential_id=None)):
                tgt.execute("SELECT consentvault.load_stored_post(%s)", (Jsonb(extra[org]),))
        tgt.execute("RESET ROLE")
        for org in orgs:   # the loaded chains verify after
            with org_transaction(tgt, mint_org_token(token_key, org, ["admin"], credential_id=None)):
                breaks = verify_raw_chain(tgt)
            if breaks:
                raise RuntimeError(f"the loaded chain of organisation {org} is broken: {breaks[0]}")
        return {"posts": n, "orgs": len(orgs)}


def project_all(target_dsn: str, *, crypto: Any, evidence: Any = None, senders: Any = None) -> int:
    """Project every loaded post into the history with the pure fold. The fold reads the stored posts and facts only; it calls the key
    provider (``crypto``) for the post's own key, and nothing else. ``evidence`` and ``senders`` are stand-ins that must see no call."""
    with psycopg.connect(target_dsn, autocommit=True, row_factory=dict_row) as tgt:
        key_row = tgt.execute("SELECT key_id, secret FROM consentvault.tenant_token_key WHERE retired_at IS NULL ORDER BY created_at LIMIT 1").fetchone()
        key = TokenKey(key_row["key_id"], bytes(key_row["secret"]))
        orgs = [r["org_id"] for r in tgt.execute("SELECT org_id::text AS org_id FROM consentvault.organization ORDER BY org_id").fetchall()]
        total = 0
        writer = RawPostWriter(crypto=crypto)
        for org in orgs:
            # the token is stamped with the target database's own clock, never this process's: the fold reads no clock, and a replay run
            # with its process clock moved must still be admitted by the database that checks the token against its own
            now = tgt.execute("SELECT extract(epoch FROM clock_timestamp())::float8 AS now").fetchone()["now"]
            with org_transaction(tgt, mint_org_token(key, org, ["admin"], credential_id=None, now=now)):
                total += door.history_catch_up(writer, tgt, lambda _c: nullcontext(), every_post=True)
        return total
