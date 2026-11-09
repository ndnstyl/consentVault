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
    factory = env.vault.superuser if hasattr(env, "vault") else env.t.superuser if hasattr(env, "t") else env.superuser
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

CHAIN_COLUMNS = {"history_seq", "prev_hash", "row_hash", "recorded_at", "contact_ct", "display_ct", "nonce", "contact_nonce", "display_nonce"}


def history_fingerprint(rows: list[dict], *, label: str | None = None) -> str:
    """sha256 over the content columns of the rows in place order. The chain columns, ciphertexts and nonces are excluded by name:
    live append order may differ from replay order, so the chain is verified by gate 7, not compared here."""
    keep = sorted(k for k in (rows[0] if rows else {}) if k not in CHAIN_COLUMNS and not k.endswith(("_ct", "_nonce")))
    ordered = sorted((r for r in rows if label is None or r["label"] == label), key=lambda r: (r["placed_at"], r["post_seq"]))
    blob = json.dumps([[str(r[k]) for k in keep] for r in ordered], separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


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

def super_dsn_of(env) -> str:
    """The superuser DSN of a contract world (.vault), a cloud (.t) or a tenancy / sync environment (.super_dsn)."""
    if hasattr(env, "vault"):
        return env.vault.super_dsn
    if hasattr(env, "t"):
        return env.t.super_dsn
    return env.super_dsn


def login_in_group(world, group: str):
    """A fresh login that is a member of ``group`` on the world's database; returns a connected, autocommit connection."""
    from urllib.parse import urlparse

    from consentvault import db
    from isolation.harness import make_login_role

    u = urlparse(super_dsn_of(world))
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


# ---- CALL SHAPES FIXED BY THESE TESTS ----------------------------------------------------------------------------------------
# The design names behaviour, not signatures. These tests fix the shapes below; the build provides them.
#   consentvault.effects.run_once(conn, *, crypto, custody, transport, senders, clock)
#       the effects layer: claims pending intents, sends pushes through transport.send(PushRequest) with the header
#       "Idempotency-Key" equal to the intent id, sends every other effect through senders.send(effect=, intent_id=,
#       idempotency_key=), moves the state, refuses by name (error text contains "replay") on a replay database.
#   consentvault.cutover.write_watermark_facts(owner_connect, token_key, custody, crypto)
#       the per-organisation job that writes the effect_watermark fact on every stored post (below or above).
#   consentvault.replay_load.load_store(source_dsn, target_dsn, *, token_key)
#       loads a store onto a fresh, marked database through load_stored_post and load_lookup_rows.
#   consentvault.replay_load.project_all(target_dsn, *, crypto, evidence, senders)
#       the new fold over every loaded post; the effects layer is not started.

from dataclasses import dataclass, field  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

ALLOWED_KEY_CALLS = {"unwrap_data_key", "fingerprint_secret", "display_key"}   # post key and contact key are both unwrap_data_key


class RecordingKeyProvider:
    """Wraps a key provider and records every call by name. The methods are explicit so the provider-interface check sees them."""

    def __init__(self, inner):
        self.inner, self.log = inner, []

    def wrap_data_key(self, org_id, data_key):
        self.log.append("wrap_data_key")
        return self.inner.wrap_data_key(org_id, data_key)

    def unwrap_data_key(self, org_id, wrapped):
        self.log.append("unwrap_data_key")
        return self.inner.unwrap_data_key(org_id, wrapped)

    def fingerprint_secret(self, org_id):
        self.log.append("fingerprint_secret")
        return self.inner.fingerprint_secret(org_id)

    def display_key(self, org_id):
        self.log.append("display_key")
        return self.inner.display_key(org_id)


class RecordingEvidence:
    def __init__(self, inner):
        self.inner, self.log = inner, []

    def __getattr__(self, name):
        target = getattr(self.inner, name)

        def call(*a, **k):
            self.log.append((name, str(a[0]) if a else ""))
            return target(*a, **k)
        return call if callable(target) else target


class RecordingSenders:
    def __init__(self):
        self.calls = []

    def send(self, **kw):
        self.calls.append(kw)
        return {"provider_message_id": "stub-" + str(len(self.calls))}


class Transport:
    """Push transport stand-in (sync.support.FakeTransport): every request kept; the idempotency key is a header."""

    def __init__(self):
        from sync.support import FakeTransport
        self.t = FakeTransport()

    def send(self, request):
        return self.t.send(request)

    @property
    def sent(self):
        return self.t.sent

    def keys(self):
        return [r.headers.get("Idempotency-Key") for r in self.t.sent]


def run_effects(env, *, transport, senders, crypto, custody, clock=None):
    """Run the effects layer once as the worker role."""
    run_once = need_py("consentvault.effects", "run_once")
    conn = login_in_group(env, "consentvault_worker")
    return run_once(conn, crypto=crypto, custody=custody, transport=transport, senders=senders,
                    clock=clock or (lambda: datetime.now(timezone.utc)))


def reproject(world, org):
    """Run the fold again over every post that has no outcome yet (idempotent for the rest)."""
    from consentvault.tenancy.tokens import org_transaction
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(org.org_id)):
        door.project_pending(RawPostWriter(crypto=world.crypto), c, lambda cc: cc.transaction(), door.TenantLedgerBackend(world.crypto, region="US"))


@dataclass
class Replayed:
    fingerprints: dict = field(default_factory=dict)
    intent_keys: list = field(default_factory=list)
    key_calls: list = field(default_factory=list)
    evidence_calls: list = field(default_factory=list)
    sender_calls: list = field(default_factory=list)
    loaded: dict = field(default_factory=dict)


def _port_and_db(env):
    from urllib.parse import urlparse
    u = urlparse(super_dsn_of(env))
    return u.port, u.path.lstrip("/")


def _snapshot(dsn: str) -> tuple[dict, list]:
    """The stored-versus-loaded comparison set and the history fingerprints of one database."""
    import psycopg
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as c:
        posts = c.execute("SELECT org_id, post_id, seq, received_at, prev_hash, row_hash, body_sha256 FROM consentvault.raw_post ORDER BY org_id, seq").fetchall()
        arrivals = c.execute("SELECT org_id, post_id, arrived_at FROM consentvault.raw_post_original_arrival ORDER BY org_id, post_id").fetchall()
        hist = c.execute("SELECT * FROM consentvault.post_history ORDER BY org_id, history_seq").fetchall() if c.execute(
            "SELECT to_regclass('consentvault.post_history') IS NOT NULL AS t").fetchone()["t"] else []
        keys = c.execute("SELECT post_id, effect, target, intent_id FROM consentvault.effect_intent ORDER BY post_id, effect, target").fetchall() if c.execute(
            "SELECT to_regclass('consentvault.effect_intent') IS NOT NULL AS t").fetchone()["t"] else []
    loaded = {"posts": [tuple(p.values()) for p in posts], "arrivals": [tuple(a.values()) for a in arrivals]}
    fps = {lab: history_fingerprint(hist, label=lab) for lab in sorted({h["label"] for h in hist})}
    return loaded, fps, [tuple(str(v) for v in k.values()) for k in keys]


def store_snapshot(env) -> Replayed:
    loaded, fps, keys = _snapshot(super_dsn_of(env))
    return Replayed(fingerprints=fps, intent_keys=keys, loaded=loaded)


def load_into_fresh(env, *, refill: bool = False, shift_years: int = 0) -> Replayed:
    """Load the environment's store onto a new database with the loader, project it with stand-ins for the key provider, the evidence
    store and every sender, and return what that database holds. ``refill`` fills the lookup tables with different rows and
    ``shift_years`` moves the Python clocks (and the database clock seam) by that many years while the fold runs."""
    import unittest.mock as mock
    import uuid as _uuid

    import psycopg

    from conftest import MIGRATOR_ROLE, _dsn, create_vault_database, ensure_roles, pin_as_superuser
    from consentvault import db, dbclock
    from consentvault.tenancy.crypto import TenantCrypto

    need_function("load_stored_post")
    need_function("load_lookup_rows")
    need_table("replay_target")
    load_store = need_py("consentvault.replay_load", "load_store")
    project_all = need_py("consentvault.replay_load", "project_all")
    port, _ = _port_and_db(env)
    name = new_database(port)
    source = super_dsn_of(env)
    target = _dsn(port, name, "postgres")
    key = env.vault.key if hasattr(env, "vault") else env.t.key
    load_store(source, target, token_key=key)
    if refill:
        _refill_lookups(source, target)
    provider = env.vault.custody if hasattr(env, "vault") else env.t.provider
    keys = RecordingKeyProvider(provider)
    evidence = RecordingEvidence(getattr(env, "store", None) or getattr(getattr(env, "world", None), "store", None))
    senders = RecordingSenders()
    real_time = __import__("time").time
    shift = timedelta(days=365 * shift_years)
    with mock.patch("time.time", lambda: real_time() + shift.total_seconds()), \
            mock.patch.object(dbclock, "now", lambda conn: datetime.now(timezone.utc) + shift):
        project_all(target, crypto=TenantCrypto(keys), evidence=evidence, senders=senders)
    loaded, fps, intent_keys = _snapshot(target)
    return Replayed(fingerprints=fps, intent_keys=intent_keys, key_calls=keys.log, evidence_calls=evidence.log,
                    sender_calls=senders.calls, loaded=loaded)


def new_database(port: int) -> str:
    """A fresh, fully migrated, empty database on the test cluster; returns its name."""
    import uuid as _uuid

    from conftest import MIGRATOR_ROLE, _dsn, create_vault_database, ensure_roles, pin_as_superuser
    from consentvault import db

    name = "r_" + _uuid.uuid4().hex[:12]
    ensure_roles(port)
    create_vault_database(port, name)
    with db.connect(_dsn(port, name, MIGRATOR_ROLE)) as c:
        db.migrate(c)
    pin_as_superuser(_dsn(port, name, MIGRATOR_ROLE))
    return name


def _refill_lookups(source: str, target: str) -> None:
    import psycopg
    with psycopg.connect(source) as s, psycopg.connect(target, autocommit=True) as t:
        for table in ("brand", "capture_source"):
            cols = [r[0] for r in s.execute("SELECT column_name FROM information_schema.columns WHERE table_schema = 'consentvault' AND table_name = %s ORDER BY ordinal_position", (table,))]
            for row in s.execute(f"SELECT {', '.join(cols)} FROM consentvault.{table}").fetchall():
                vals = ["z-" + str(v) if c == "name" else v for c, v in zip(cols, row)]
                t.execute(f"INSERT INTO consentvault.{table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})", vals)


def purity_run(env) -> tuple[Replayed, Replayed, Replayed]:
    """The same store loaded onto two fresh databases; the second with refilled lookup tables and every clock moved a year."""
    return store_snapshot(env), load_into_fresh(env), load_into_fresh(env, refill=True, shift_years=1)


def call_fn(world, org, name: str, _scopes=("capture", "gate_read"), _as: str = "app", **values):
    """Call consentvault.<name> with arguments matched BY NAME (a leading p_ is ignored) to ``values``, entered as the organisation.
    An argument with no value is a defect in the test and fails loudly, naming it."""
    import json as _json
    from consentvault.tenancy.tokens import org_transaction

    with (login_in_group(world, "consentvault_worker") if _as == "worker" else world.vault.appconn()) as c:
        row = c.execute("SELECT proargnames AS n, pronargs FROM pg_proc WHERE pronamespace = 'consentvault'::regnamespace AND proname = %s"
                        " ORDER BY pronargs DESC LIMIT 1", (name,)).fetchone()
        assert row is not None, f"function consentvault.{name} does not exist"
        names = [n.removeprefix("p_") for n in (row["n"] or [])][: row["pronargs"]]
        absent = [n for n in names if n not in values]
        assert not absent, f"TEST ADAPTER: consentvault.{name} takes {absent} and the test supplies no value for it"
        token = world.capture_token(org.org_id, _scopes)
        if _as == "worker":   # the sync worker is handed a short token per organisation by the dispatcher
            token = next(r["token"] for r in c.execute("SELECT org_id, token FROM consentvault.dispatch_orgs('sync')").fetchall() if str(r["org_id"]) == str(org.org_id))
        with org_transaction(c, token):
            return c.execute(f"SELECT * FROM consentvault.{name}({', '.join(['%s'] * len(names))})", [values[n] for n in names]).fetchall()


def as_text(rows) -> str:
    import json as _json
    return _json.dumps(rows, default=str).lower()


def product_erase(env, org_id, contact: str) -> dict:
    """Erase a contact through the product's own path: the organisation's admin requests the erasure (request_erasure) and the
    operator confirms it (confirm_erasure). The SQL function erase_contact cannot write the erasure stop as a post, so tests never
    call it. ``env`` is the contract world or the cloud."""
    import tempfile
    from pathlib import Path

    from consentvault import db, dbclock
    from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
    from consentvault.tenancy import erasure
    from consentvault.tenancy.admin_base import ROLE_SCOPES, Ctx
    from consentvault.tenancy.erasure import LifecycleLedger
    from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX, actor_from_token
    from consentvault.tenancy.tokens import mint_org_token

    if hasattr(env, "vault"):
        app, operator, key, crypto, app_dsn, su = env.vault.appconn, env.vault.operator, env.vault.key, env.crypto, env.vault.app_dsn, env.vault.superuser
    else:
        app, operator, key, crypto, app_dsn, su = env.t.app, env.t.operator, env.t.key, env.t.crypto, env.t.app_dsn, env.t.superuser
    with su() as s:
        member = s.execute("SELECT member_id FROM consentvault.member WHERE org_id = %s AND role = 'admin' LIMIT 1", (org_id,)).fetchone()["member_id"]
    token = mint_org_token(key, org_id, ROLE_SCOPES["admin"], credential_id=MEMBER_CREDENTIAL_PREFIX + str(member))
    with app() as conn, org_transaction(conn, token):
        req = erasure.request_erasure(Ctx(conn, actor_from_token(conn), "req-test"), {"contact": contact, "reason": "the person asked"}, crypto=crypto)
    ledger = LifecycleLedger(LocalAppendOnlyEvidenceStore(Path(tempfile.mkdtemp(prefix="cv-ledger-"))),
                             clock=dbclock.datetime_clock(lambda: db.connect(app_dsn)))
    with operator() as c:
        return erasure.confirm_erasure(c, token_key=key, crypto=crypto, ledger=ledger, operator_id="op-1", request_id="req-op",
                                       org_id=org_id, erasure_id=req["erasure_id"])


def twenty_system(world, org, name: str = "crm") -> str:
    """A connected system the person-state reader accepts: sync_person_state is the Twenty connector's call, so the system is marked as one."""
    sid = add_push_target(org, name)
    force(world, "UPDATE consentvault.connected_system SET connector = 'twenty', contact_form = 'plaintext', signature = 'none' WHERE org_id = %s AND system_id = %s", (org.org_id, sid))
    return sid
