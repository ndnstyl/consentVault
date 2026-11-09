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
