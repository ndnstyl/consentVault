"""A copy of today's store: a database at the migrations the store of record has (through 0079), filled the way the old system fills
it (events, queued pushes, queued confirmations), ready to have this spec's migrations applied on top of it.

Used by the cutover tests (send set, seeding, watermark). The old paths are used on purpose: this is what exists the moment before
the window opens."""

from __future__ import annotations

import uuid

import pytest

from consentvault import db
from isolation.harness import build_tenancy
from sync.support import SyncEnv, contact

from .support import need_function, sql, two_stage_migrate

OUTBOX_STATUSES = ("pending", "failed", "sent", "acknowledged", "dead", "superseded")
CONFIRMATION_STATUSES = ("intent", "sending", "sent", "delivered", "failed", "dead", "skipped")


def today_store(request, *, systems=("crm",)):
    """Returns (env, pending_migrations). Two organisations in multi mode, each with the connected systems named."""
    raw_dsn = request.getfixturevalue("raw_dsn")
    port = request.getfixturevalue("pg_server")["port"]
    pending = two_stage_migrate(raw_dsn)
    t = build_tenancy(raw_dsn, port)
    env = SyncEnv(t, port)
    for org in (t.a, t.b):
        for name in systems:
            env.add_system(org, name)
    return env, pending


def queue_every_status(env):
    """For each organisation, one grant per outbox status and per confirmation status, with the row put in that status below the
    triggers (a DBA's way; the old workers would have got there over time). Returns {org_name: {status: row id}}."""
    seen = {}
    for org in (env.t.a, env.t.b):
        rows = {}
        for i, status in enumerate(OUTBOX_STATUSES):
            ev, _ = env.grant(org, contact(100 + i if org is env.t.a else 200 + i))
            row = sql_one(env, "SELECT outbox_id FROM consentvault.outbox WHERE org_id = %s ORDER BY created_at DESC LIMIT 1", (org.org_id,))
            force_status(env, "outbox", "outbox_id", row["outbox_id"], status, org.org_id)
            rows["outbox:" + status] = row["outbox_id"]
        for i, status in enumerate(CONFIRMATION_STATUSES):
            ev, _ = env.grant(org, contact(300 + i if org is env.t.a else 400 + i))
            send = uuid.uuid4()
            with env.t.superuser() as su:
                su.execute("INSERT INTO consentvault.confirmation_send_intent (org_id, send_id, basis_event_id, contact_fp, channel, status,"
                           " created_at) VALUES (%s, %s, %s, %s, 'sms', 'intent', now())",
                           (org.org_id, send, ev.event_id, env.fp(org, contact(300 + i if org is env.t.a else 400 + i))))
            force_status(env, "confirmation_send_intent", "send_id", send, status, org.org_id)
            rows["confirmation:" + status] = send
        seen[org.name] = rows
    return seen


def sql_one(env, query, params=()):
    with env.t.superuser() as su:
        return su.execute(query, params).fetchone()


EXTRA = {("outbox", "sent"): ", claimed_until = now() + interval '1 minute'",
         ("outbox", "acknowledged"): ", finished_at = now()", ("outbox", "dead"): ", finished_at = now()",
         ("outbox", "superseded"): ", finished_at = now()",
         ("confirmation_send_intent", "skipped"): ", skip_reason = 'late'", ("confirmation_send_intent", "dead"): ", dead_cause = 'retries_exhausted'"}


def force_status(env, table, key, value, status, org_id):
    with env.t.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute(f"UPDATE consentvault.{table} SET status = %s{EXTRA.get((table, status), '')} WHERE org_id = %s AND {key} = %s",
                   (status, org_id, value))


def finish_migrations(request):
    """Apply this spec's migrations on top of the copy, as the cutover window does, and pin the guards."""
    from conftest import pin_as_superuser

    raw_dsn = request.getfixturevalue("raw_dsn")
    with db.connect(raw_dsn) as c:
        db.migrate(c)
    pin_as_superuser(raw_dsn)


def iso_grant_fields(org, contact_value: str) -> dict:
    return dict(contact=contact_value, event_type="grant", channels=["sms"], purposes=["marketing"], method="checkbox", origin="consumer",
                source_id=org.source_id, disclosure_sha256=org.disclosure, brand_ids=[org.brand_id], session_ref="s-q", contact_verification="none")


def store_unprojected(env, org, contact_value: str) -> str:
    """A post stored by the intake and never projected: the old fold had not reached it when it stopped."""
    import json as _json

    from consentvault import door
    from consentvault.rawpost import RawPostWriter, RawRequest
    from consentvault.tenancy.tokens import org_transaction
    body = _json.dumps(iso_grant_fields(org, contact_value), sort_keys=True, default=door._json_default).encode()
    req = RawRequest(intake="staff_marked", method="POST", path="/v1/events", query="", headers=(("content-type", "application/json"),),
                     body=body, headers_presented_by="local-process", facts=tuple(door_good_facts()))
    with env.t.app() as c, org_transaction(c, env.t.token(org)):
        return str(door.store_raw(RawPostWriter(crypto=env.t.crypto), c, lambda cc: cc.transaction(), req).post_id)


def door_good_facts():
    from .support import good_facts
    return good_facts() + [__import__("consentvault.door", fromlist=["x"]).settings_fact(region="US")]


def project_org(env, org) -> None:
    """The new fold over every post of one organisation that has no outcome yet."""
    from consentvault import door
    from consentvault.rawpost import RawPostWriter
    from consentvault.tenancy.tokens import org_transaction
    with env.t.app() as c, org_transaction(c, env.t.token(org)):
        door.project_pending(RawPostWriter(crypto=env.t.crypto), c, lambda cc: cc.transaction(), door.TenantLedgerBackend(env.t.crypto, region="US"))


def queue_quiet(env, org, n: int = 500) -> dict:
    """A grant the old fold finished whose queued push was already delivered and removed: a post with an event and no queued row."""
    from consentvault import door
    from consentvault.tenancy.tokens import org_transaction
    with env.t.app() as c, org_transaction(c, env.t.token(org)):
        out = door.record_observed(c, env.t.crypto, intake="staff_marked", enter=lambda cc: cc.transaction(), region="US",
                                   fields=iso_grant_fields(org, contact(n)))
    ev = type("E", (), {"event_id": out.event_id})
    with env.t.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("DELETE FROM consentvault.outbox WHERE org_id = %s AND outbox_id IN (SELECT outbox_id FROM consentvault.outbox WHERE org_id = %s"
                   " AND contact_fp = %s)", (org.org_id, org.org_id, env.fp(org, contact(n))))
        post = su.execute("SELECT post_id FROM consentvault.event_source_post WHERE org_id = %s AND event_id = %s", (org.org_id, ev.event_id)).fetchone()["post_id"]
    return {"post_id": str(post), "fp": env.fp(org, contact(n))}


def watermark_fact(env, org, post_id: str):
    from isolation.cloud_harness import facts_of
    with env.t.superuser() as su:
        row = su.execute("SELECT * FROM consentvault.raw_post WHERE org_id = %s AND post_id = %s", (org.org_id, post_id)).fetchone()
    return facts_of(env.t, row).get("effect_watermark")
