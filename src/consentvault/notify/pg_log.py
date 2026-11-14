"""The Postgres send log (migration 0009, ``consentvault.notify_send_log``): platform scope, append-only.

One row per send attempt or bounce: template type, the recipient's domain, outcome, provider and provider message id.
No body, no subject, no full address. An address that slipped into the detail text is replaced before the write, and
the table's check refuses any that remain. A row that cannot be written raises ``SendLogError``: a send that leaves no
record is a failure, never a quiet success.
"""

from __future__ import annotations

import re
from typing import Callable

import psycopg

from .base import SendRecord
from .errors import SendLogError

_ADDRESS = re.compile(r"[^\s<>()\[\],;:\"']*@[^\s<>()\[\],;:\"']*")
DETAIL_MAX = 200


def scrub_detail(detail: str | None) -> str | None:
    """Replace anything shaped like an address, cap the length; empty becomes None."""
    if detail is None:
        return None
    text = _ADDRESS.sub("[address]", detail).replace("@", "[at]").strip()[:DETAIL_MAX]
    return text or None


class PostgresSendLog:
    """``SendLog`` over Postgres. ``connect`` returns a connection as the runtime or worker role; each append is its
    own transaction, so a send is logged whatever happens to the caller's transaction afterwards."""

    def __init__(self, connect: Callable[[], psycopg.Connection]) -> None:
        self._connect = connect

    def append(self, record: SendRecord) -> None:
        try:
            with self._connect() as conn, conn.transaction():
                # A bounce already recorded for this provider message (an event delivered again after its alarm could not
                # be published) is not written twice (migration 0063); every other row is written as it comes.
                # No conflict target: naming one needs SELECT on its columns, which this append-only login has not; the
                # only other unique key is the generated send_id, which an insert never supplies.
                conflict = " ON CONFLICT DO NOTHING" if record.outcome == "bounced" else ""
                conn.execute(
                    "INSERT INTO consentvault.notify_send_log (type, recipient_domain, outcome, provider,"
                    " provider_message_id, detail, at) VALUES (%s, %s, %s, %s, %s, %s, %s)" + conflict,
                    (record.type, record.recipient_domain.lower(), record.outcome, record.provider,
                     record.provider_message_id, scrub_detail(record.detail), record.at))
        except psycopg.Error as exc:
            raise SendLogError(f"the send log row for a {record.type} message ({record.outcome}) could not be written:"
                               f" {type(exc).__name__}") from exc
