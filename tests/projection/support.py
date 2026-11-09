"""Helpers for the pure-projection tests. Nothing here is product code.

Two rules every test in this folder follows:

1. It starts with a ``need_*`` precondition that reads the repository (the migration files, the module list) and fails with
   ``MISSING FEATURE: <what>`` when the feature the test is about is not built. A test never fails today on an import error, a
   fixture error or a bare SQL error, and never passes for the wrong reason (a refusal test whose column does not exist).
2. A scenario that happens "after cutover" runs where the old event table gets no row: ``cut_grant`` asserts the history row exists
   and the event count did not move, so a reader that still works from the event table cannot make a test pass.
"""

from __future__ import annotations

import functools
import hashlib
import importlib
import json
import re
import uuid
from pathlib import Path

import pytest

from consentvault import door
from consentvault.rawpost import Fact, RawPostWriter, RawRequest
from consentvault.tenancy.tokens import org_transaction

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations"
TODAYS_HEAD = 79   # the store of record today ends at 0079; every migration of this spec is numbered above it
PHONE = "+13055550142"
PHONE2 = "+13055550143"
EMAIL = "dana@example.com"


# ---- preconditions: a plain name for the missing piece ------------------------------------------------------------------

def missing(what: str):
    pytest.fail(f"MISSING FEATURE: {what}", pytrace=False)


@functools.lru_cache(maxsize=1)
def _sql() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(MIGRATIONS.glob("[0-9]*.sql")))


def need_sql(pattern: str, what: str) -> None:
    if not re.search(pattern, _sql(), re.I | re.S):
        missing(what)


def need_table(name: str) -> None:
    need_sql(rf"CREATE TABLE (IF NOT EXISTS )?consentvault\.{name}\b", f"table consentvault.{name} is created by no migration")


def need_function(name: str) -> None:
    need_sql(rf"CREATE (OR REPLACE )?FUNCTION consentvault\.{name}\b", f"function consentvault.{name} is created by no migration")


def need_columns(table: str, *cols: str) -> None:
    body = "".join(re.findall(rf"CREATE TABLE (?:IF NOT EXISTS )?consentvault\.{table}\s*\((.*?)\n\);", _sql(), re.I | re.S))
    alters = "".join(re.findall(rf"ALTER TABLE consentvault\.{table}\b([^;]*);", _sql(), re.I | re.S))
    for col in cols:
        if not re.search(rf"\b{col}\b", body + alters):
            missing(f"column consentvault.{table}.{col} is added by no migration")


def need_py(module: str, attr: str | None = None):
    try:
        mod = importlib.import_module(module)
    except ImportError as exc:
        missing(f"module {module} ({exc})")
    if attr is not None and not hasattr(mod, attr):
        missing(f"{module}.{attr}")
    return mod if attr is None else getattr(mod, attr)


def need_cutover() -> None:
    """The cutover migration (effect intents, the watermark, retired functions) is applied by every fresh database."""
    need_table("effect_intent")
    need_table("effect_watermark")
    need_table("post_history")


# ---- driving the one door as the world's organisation --------------------------------------------------------------------

def grant_fields(org, contact: str = PHONE, **kw) -> dict:
    f = dict(contact=contact, event_type="grant", channels=["sms"], purposes=["marketing"], method="checkbox", origin="consumer",
             source_id=uuid.UUID(org.web_id), disclosure_sha256=org.wording, brand_ids=[uuid.UUID(org.brand_id)],
             session_ref="s-" + uuid.uuid4().hex[:6], contact_verification="none")
    f.update(kw)
    return f


def stop_fields(org, contact: str = PHONE, **kw) -> dict:
    f = dict(contact=contact, event_type="revoke", channels=["sms"], purposes=["*"], method="keyword", origin="consumer",
             source_id=uuid.UUID(org.web_id))
    f.update(kw)
    return f


def good_facts() -> list:
    return [Fact("vault", "request_signature", "valid"), Fact("vault", "replay", "fresh"), Fact("vault", "authenticated_by", "system")]


def tenant_facts(credential: bool = True, lookup: str | None = None, edge: str | None = None) -> list:
    out = [Fact("vault", "request_signature", "valid"), Fact("vault", "tenant", True)]
    if credential:
        out.append(Fact("vault", "credential", {"state": "verified", "id": str(uuid.uuid4()), "scopes": ["capture"]}))
    if lookup:
        out.append(Fact("vault", "site_key_lookup", lookup))
    if edge:
        out.append(Fact("vault", "edge_timestamp", edge))
    return out


def door_post(world, org, fields: dict | None = None, *, facts: list | None = None, body: bytes | None = None,
              intake: str = "staff_marked", request_key: str | None = None) -> str:
    """Store one post through the one door, then project it, as ``door.record_observed`` does, but with the facts the case needs.
    Returns the post id. Nothing is read from the outcome: the history table and the intents are the answer."""
    writer = RawPostWriter(crypto=world.crypto)
    payload = body if body is not None else json.dumps(fields, sort_keys=True, default=door._json_default).encode("utf-8")
    vf = list(good_facts() if facts is None else facts)
    if request_key:
        vf.append(Fact("vault", "request_key", request_key))
    vf.append(door.settings_fact(region="US"))
    req = RawRequest(intake=intake, method="POST", path="/v1/events", query="", headers=(("content-type", "application/json"),),
                     body=payload, headers_presented_by="local-process", facts=tuple(vf))
    enter = lambda c: c.transaction()  # noqa: E731
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(org.org_id)):
        stored = door.store_raw(writer, c, enter, req)
        view = door.PostView(stored.org_id, stored.post_id, stored.seq, intake, payload,
                             {**{("vault", f.name): f.value for f in vf}, ("__key__", "data_key"): stored.data_key},
                             arrived_epoch=stored.received_at.timestamp())
        door.project_post(writer, c, enter, door.TenantLedgerBackend(world.crypto, region="US"), view, raise_errors=False)
    return str(stored.post_id)


# ---- reading the result (out of band, as the superuser) ------------------------------------------------------------------

def sql(env, query: str, params=()):
    """Read out of band as the superuser; ``env`` is the contract world (``.vault``) or the cloud (``.t``)."""
    factory = env.vault.superuser if hasattr(env, "vault") else env.t.superuser
    with factory() as su:
        return su.execute(query, params).fetchall()


def history_rows(world, org, **where) -> list[dict]:
    need_table("post_history")
    clause = "".join(f" AND {k} = %s" for k in where)
    return sql(world, "SELECT * FROM consentvault.post_history WHERE org_id = %s" + clause + " ORDER BY history_seq",
               (org.org_id, *where.values()))


def history_row(world, org, post_id: str) -> dict | None:
    rows = history_rows(world, org, post_id=post_id)
    return rows[0] if rows else None


def intents(world, org, post_id: str | None = None) -> list[dict]:
    need_table("effect_intent")
    if post_id is None:
        return sql(world, "SELECT * FROM consentvault.effect_intent WHERE org_id = %s ORDER BY state_at", (org.org_id,))
    return sql(world, "SELECT * FROM consentvault.effect_intent WHERE org_id = %s AND post_id = %s ORDER BY state_at", (org.org_id, post_id))


def event_count(world, org) -> int:
    return sql(world, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", (org.org_id,))[0]["n"]


def cut_grant(world, org, contact: str = PHONE, **kw) -> str:
    """A grant arrives after the cutover through the one door: stored, projected, present in history, and the frozen event table
    got nothing for it. A reader that still answers from the event table cannot satisfy a test that starts here."""
    need_cutover()
    before = event_count(world, org)
    post = door_post(world, org, grant_fields(org, contact, **kw))
    assert history_row(world, org, post) is not None, "the post has no history row"
    assert event_count(world, org) == before, "the frozen event table got a row after cutover"
    return post


def cut_stop(world, org, contact: str = PHONE, **kw) -> str:
    need_cutover()
    before = event_count(world, org)
    post = door_post(world, org, stop_fields(org, contact, **kw))
    assert history_row(world, org, post) is not None, "the stop has no history row"
    assert event_count(world, org) == before, "the frozen event table got a row after cutover"
    return post


# ---- fingerprints (gate 3 and the proof of purity) -----------------------------------------------------------------------

CHAIN_COLUMNS = {"history_seq", "prev_hash", "row_hash", "contact_ct", "display_ct", "nonce", "contact_nonce", "display_nonce"}


def history_fingerprint(rows: list[dict], *, label: str | None = None) -> str:
    """sha256 over the content columns of the rows in place order. The chain columns, ciphertexts and nonces are excluded by name:
    live append order may differ from replay order, so the chain is verified by gate 7, not compared here."""
    keep = sorted(k for k in (rows[0] if rows else {}) if k not in CHAIN_COLUMNS and not k.endswith(("_ct", "_nonce")))
    ordered = sorted((r for r in rows if label is None or r["label"] == label), key=lambda r: (r["placed_at"], r["post_seq"]))
    blob = json.dumps([[str(r[k]) for k in keep] for r in ordered], separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


# ---- loading a store onto a fresh database (migration 0084) --------------------------------------------------------------

def load_into_fresh(source_env, *, empty_lookups: bool = True):
    """Load the source database's stored posts onto a fresh database through ``load_stored_post`` and ``load_lookup_rows`` and
    return a handle on it. The call shapes of those two functions are not fixed by the design (it gives their guard and their
    effect, not their argument lists), so the adapter is written in the same change that creates them: until then every test that
    needs it fails here, at the precondition."""
    need_function("load_stored_post")
    need_function("load_lookup_rows")
    need_table("replay_target")
    pytest.fail("ADAPTER TO COMPLETE: map the stored rows of the source onto load_stored_post and load_lookup_rows", pytrace=False)


def two_stage_migrate(raw_dsn: str) -> list[str]:
    """Bring an empty database to today's store of record (every migration through 0079) and return the pending names, so a test
    can fill it as the old system fills it and then apply this spec's migrations on top (the 'copy of today's store')."""
    import shutil
    import tempfile

    from consentvault import db

    stage = Path(tempfile.mkdtemp(prefix="cv-today-"))
    try:
        for p in sorted(MIGRATIONS.glob("[0-9]*.sql")):
            if int(p.name[:4]) <= TODAYS_HEAD:
                shutil.copy(p, stage / p.name)
        if (MIGRATIONS / "down").exists():
            shutil.copytree(MIGRATIONS / "down", stage / "down")
        with db.connect(raw_dsn) as c:
            db.migrate(c, stage)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return sorted(p.name for p in MIGRATIONS.glob("[0-9]*.sql") if int(p.name[:4]) > TODAYS_HEAD)


# ---- the confirmation stack and a push target, for the effects tests -----------------------------------------------------

def add_push_target(org, name: str = "crm") -> str:
    """A connected system, registered the way the developer role does."""
    got = org.dev.ok("POST", "/v1/systems", body={"name": name, "kind": "crm", "endpoint": f"https://{name}.example/hook",
                                                  "signature": "hmac", "contact_form": "fingerprint"})
    return got["system_id"]


def force(world, query: str, params=()):
    """Change a row below the triggers, as a DBA could, to put a send-time condition in place after the grant arrived."""
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute(query, params)


def confirmation_intents(world, org, post_id: str | None = None) -> list[dict]:
    return [i for i in intents(world, org, post_id) if i["effect"] == "confirmation"]


def at(stack, y, m, d, h, mi=0):
    from datetime import datetime, timezone
    stack.clock.set(datetime(y, m, d, h, mi, tzinfo=timezone.utc))


# ---- roles, facts and concurrency ----------------------------------------------------------------------------------------

def login_in_group(world, group: str):
    """A fresh login that is a member of ``group`` on the world's database; returns a connected, autocommit connection."""
    from urllib.parse import urlparse

    from consentvault import db
    from isolation.harness import make_login_role

    u = urlparse(world.vault.super_dsn)
    return db.connect(make_login_role(u.port, u.path.lstrip("/"), group))


def write_fact(world, org, post_id: str, name: str, value, *, status: str | None = "value", label: str | None = "retry",
               extra: dict | None = None) -> dict:
    """Append one fact to a stored post as the runtime role does (status and label supplied, the computed columns not), and return
    the row as stored, read back. ``extra`` supplies more columns (a test of the grant passes the computed ones)."""
    from consentvault.rawpost import COL_FACT, canonical_dumps

    need_columns("raw_post_fact", "status", "label")
    writer = RawPostWriter(crypto=world.crypto)
    fact_id = uuid.uuid4()
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(org.org_id)):
        key = writer.open_key(c, uuid.UUID(org.org_id), post_id)
        ct = writer._seal(key, uuid.UUID(org.org_id), uuid.UUID(post_id), COL_FACT, canonical_dumps(value).encode("utf-8"))
        cols = {"org_id": org.org_id, "post_id": post_id, "fact_id": fact_id, "source": "vault", "name": name, "value_ct": ct,
                "status": status, "label": label, **(extra or {})}
        c.execute(f"INSERT INTO consentvault.raw_post_fact ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})", list(cols.values()))
    return sql(world, "SELECT * FROM consentvault.raw_post_fact WHERE org_id = %s AND fact_id = %s", (org.org_id, fact_id))[0]


def fact_chain(world, org, post_id: str) -> list[dict]:
    return sql(world, "SELECT * FROM consentvault.raw_post_fact WHERE org_id = %s AND post_id = %s AND prev_fact_sha256 IS NOT NULL"
                      " ORDER BY fact_seq", (org.org_id, post_id))


def in_threads(*fns):
    """Run the callables at once; re-raise the first error; return the results in order."""
    import threading

    out, errs = [None] * len(fns), []
    gate = threading.Barrier(len(fns))

    def run(i, fn):
        try:
            gate.wait(10)
            out[i] = fn()
        except BaseException as exc:  # noqa: BLE001  (carried to the test thread and re-raised there)
            errs.append(exc)

    ts = [threading.Thread(target=run, args=(i, f)) for i, f in enumerate(fns)]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    if errs:
        raise errs[0]
    return out


# ---- the proof of purity: what a fresh replay hands back --------------------------------------------------------------------

from dataclasses import dataclass, field  # noqa: E402


@dataclass
class Replayed:
    """What ``load_into_fresh`` and the replay return for one fresh database, so the proof reads it the same way for both.

    ``fingerprints`` maps a history label (projected, backfill) to the content fingerprint of that label's rows in place order;
    ``intent_keys`` is the sorted list of (post, effect, target, intent id); ``key_calls`` / ``evidence_calls`` / ``sender_calls`` are
    what the recording stand-ins saw (the four allowed key-provider calls are 'post_key', 'contact_key', 'fingerprint_secret',
    'display_key'); ``loaded`` is the stored-versus-loaded comparison of every post table."""
    fingerprints: dict = field(default_factory=dict)
    intent_keys: list = field(default_factory=list)
    key_calls: list = field(default_factory=list)
    evidence_calls: list = field(default_factory=list)
    sender_calls: list = field(default_factory=list)
    loaded: dict = field(default_factory=dict)
    posts: int = 0


ALLOWED_KEY_CALLS = {"post_key", "contact_key", "fingerprint_secret", "display_key"}


def purity_run(source) -> tuple[Replayed, Replayed, Replayed]:
    """Load the same store onto two fresh databases with the loader; refill the second's lookup tables with different rows and move
    its database and Python clocks together by one year; project both; return (store, first, second)."""
    load_into_fresh(source)
    pytest.fail("ADAPTER TO COMPLETE: purity_run needs the loader's call shape", pytrace=False)


def call_with_nulls(conn, fn: str):
    """Call a function with every argument NULL, to reach its guard before it reads any argument (the guard refuses first)."""
    row = conn.execute("SELECT pronargs FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'"
                       " AND p.proname = %s ORDER BY pronargs DESC LIMIT 1", (fn,)).fetchone()
    return conn.execute(f"SELECT consentvault.{fn}({', '.join(['NULL'] * row['pronargs'])})")


def history_event_id(world, org, post_id: str) -> str:
    return str(history_row(world, org, post_id)["event_id"])


def history_head(env) -> dict:
    need_function("history_head")
    return sql(env, "SELECT * FROM consentvault.history_head()")[0]


def integrity_conn(world):
    return login_in_group(world, "consentvault_integrity")
