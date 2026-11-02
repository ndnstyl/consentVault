"""The database's clock: the one time every decision is judged on. A worker or API host whose own clock is off cannot move a
window, an expiry or an age, because the decision reads the time inside the database that holds the record it decides about."""

from __future__ import annotations

from datetime import datetime


def now(conn) -> datetime:
    """clock_timestamp() of the database this connection talks to, as an aware datetime."""
    return conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]


def epoch(conn) -> float:
    """The same instant as seconds since the Unix epoch."""
    return now(conn).timestamp()


def datetime_clock(connect):
    """A clock for code that holds no connection of its own: each reading opens a short one from ``connect`` and reads the
    database's clock. A reading that cannot be had raises; it never falls back to this host's clock."""
    def read():
        conn = connect()
        try:
            return now(conn)
        finally:
            conn.close()
    return read


def epoch_clock(connect):
    """As ``datetime_clock``, in seconds since the Unix epoch."""
    read = datetime_clock(connect)
    return lambda: read().timestamp()
