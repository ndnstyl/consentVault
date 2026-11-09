"""The effects layer: it moves effect intents out (pushes from the intents the fold derived, then the older outbox through the sync
worker; confirmations go through the confirmation sender).

It refuses to run on a replay database: a throwaway database made by replaying the store holds derived intents, and sending them would
send the store's effects a second time (R8). A push is built from the history row alone and carries the intent's id as its idempotency
key, so a resend after a crash is the same request."""

from __future__ import annotations

import json
import uuid

import psycopg

from . import safelog
from .errors import ConsentVaultError
from .safelog import describe
from .sync.connectors import webhook
from .sync.systems import open_credentials
from .sync.worker import LoggingAlarmSink, SyncWorker
from .tenancy import crypto as tc
from .tenancy.keys_protocol import WrappedKey
from .tenancy.tokens import org_transaction

log = safelog.get("consentvault.effects")

BATCH = 50


class ReplayDatabaseRefused(ConsentVaultError):
    """The effects layer was started on a database that carries the replay mark."""


def _iso(t) -> str:
    return t.astimezone(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _push_one(conn, token, org_id, intent: dict, crypto, custody, transport) -> str:
    """Send one derived push. Returns the state it ends in. A transport error leaves it ``unknown``: never resent by itself."""
    with org_transaction(conn, token):
        conn.execute("SELECT consentvault.effect_intent_move(%s, 'claimed')", (intent["intent_id"],))
        m = conn.execute("SELECT * FROM consentvault.effect_push_material(%s)", (intent["intent_id"],)).fetchone()
    if m is None:
        return _finish(conn, token, intent, "failed:no_target")
    if m["system_status"] != "active":
        return _finish(conn, token, intent, "failed:system_paused")
    try:
        contact = m["contact_fp"]
        if m["contact_form"] == "plaintext":
            data_key = crypto.open_contact_key(org_id, WrappedKey(bytes(m["wrapped_key"]), m["key_version"]))
            contact = tc.decrypt_text(data_key, org_id, str(m["event_id"]), "contact_norm", bytes(m["contact_ct"]))
        secret = open_credentials(custody, org_id, m["system_id"], m["credentials_ct"])
    except Exception as exc:  # loud-failure-exempt: the intent ends failed with the cause class named; nothing is sent for it
        log.error("a derived push could not be prepared", error=type(exc).__name__)
        return _finish(conn, token, intent, "failed:prepare")
    body = json.dumps({"org_id": str(org_id), "contact": contact, "event_type": m["event_type"], "channels": list(m["channels"] or []),
                       "purposes": list(m["purposes"] or []), "basis_event_id": str(m["event_id"]), "at": _iso(m["placed_at"])},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = webhook.PushRequest(m["endpoint"], body, {
        webhook.HEADER_SIGNATURE: webhook.sign_body(m["signature"], secret, body), webhook.HEADER_DELIVERY: str(intent["intent_id"]),
        webhook.HEADER_IDEMPOTENCY: str(intent["intent_id"]), "Content-Type": "application/json"})
    try:
        result = transport.send(request)
    except Exception as exc:  # loud-failure-exempt: the intent is marked unknown (a person resolves it) and the cause class is logged
        log.error("a derived push met a transport error; the intent is unknown", error=type(exc).__name__)
        return _finish(conn, token, intent, "unknown")
    outcome = webhook.classify(result)
    if outcome.kind == "retry":   # the receiver asked for another try: back to pending, the next pass sends the same request
        return _finish(conn, token, intent, "pending")
    return _finish(conn, token, intent, "sent" if outcome.kind == "acknowledged" else "failed:" + (outcome.error_class or outcome.kind))


def _finish(conn, token, intent: dict, state: str) -> str:
    state = state if state in ("sent", "unknown", "pending") else "failed:" + "".join(c if c.isalnum() or c == "_" else "_" for c in state[7:])[:40].lower()
    with org_transaction(conn, token):
        conn.execute("SELECT consentvault.effect_intent_move(%s, %s)", (intent["intent_id"], state))
    return state


def run_once(conn: psycopg.Connection, *, crypto, custody, transport, senders=None, clock=None):
    """One pass: the derived pushes that are due, then the older outbox. Raises ``ReplayDatabaseRefused`` (sending nothing) on a replay
    database."""
    if conn.execute("SELECT consentvault.is_replay_database() AS r").fetchone()["r"]:
        raise ReplayDatabaseRefused("the effects layer will not run on a replay database: its intents are derived copies, not work to send",
                                    code="replay_database_refused")
    sent = 0
    for org_id in [r["org_id"] for r in conn.execute("SELECT * FROM consentvault.dispatch_org_ids('sync') AS org_id")]:
        token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]
        with org_transaction(conn, token):
            due = conn.execute("SELECT intent_id FROM consentvault.effect_intent WHERE org_id = consentvault.current_org()"
                               " AND effect = 'push' AND state = 'pending' AND post_id IS NOT NULL ORDER BY state_at, intent_id LIMIT %s",
                               (BATCH,)).fetchall()
        for intent in due:
            token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]
            try:
                _push_one(conn, token, org_id, intent, crypto, custody, transport)
                sent += 1
            except psycopg.Error as exc:
                raise ConsentVaultError(f"a derived push could not be recorded: {describe(exc)}") from exc
    worker = SyncWorker(crypto, custody, transport, LoggingAlarmSink(), clock=clock) if clock is not None else SyncWorker(
        crypto, custody, transport, LoggingAlarmSink())
    report = worker.run_once(conn)
    return {"derived_pushes": sent, "outbox": report}
