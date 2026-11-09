"""The effects layer: it moves effect intents out (pushes through the sync worker, confirmations through the confirmation sender).

It refuses to run on a replay database: a throwaway database made by replaying the store holds derived intents, and sending them would
send the store's effects a second time (R8)."""

from __future__ import annotations

import psycopg

from .errors import ConsentVaultError
from .sync.worker import LoggingAlarmSink, SyncWorker


class ReplayDatabaseRefused(ConsentVaultError):
    """The effects layer was started on a database that carries the replay mark."""


def run_once(conn: psycopg.Connection, *, crypto, custody, transport, senders=None, clock=None):
    """One pass of the push worker over the intents that are due. Raises ``ReplayDatabaseRefused`` (sending nothing) on a replay database."""
    if conn.execute("SELECT consentvault.is_replay_database() AS r").fetchone()["r"]:
        raise ReplayDatabaseRefused("the effects layer will not run on a replay database: its intents are derived copies, not work to send",
                                    code="replay_database_refused")
    worker = SyncWorker(crypto, custody, transport, LoggingAlarmSink(), clock=clock) if clock is not None else SyncWorker(
        crypto, custody, transport, LoggingAlarmSink())
    return worker.run_once(conn)
