"""Anchoring: write the current head of the chain somewhere the database owner cannot quietly rewrite.

``anchor`` records (seq, row_hash, time) in ``chain_head`` and in an external sink, a file path (one JSON
record appended per line) or an http(s) webhook that receives the same record as a JSON POST. ``verify_chain``
then fails when any row up to an anchor is missing or changed, which is what a truncated tail looks like.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import psycopg

from .errors import AnchorError, ChainError
from .ledger import verify_chain

HTTP_TIMEOUT_S = 20


def _is_url(sink: str) -> bool:
    return urllib.parse.urlparse(sink).scheme in ("http", "https")


def sink_label(sink: str) -> str:
    """What is stored in chain_head.sink: the path, or the URL without credentials or query string."""
    if not _is_url(sink):
        return sink
    u = urllib.parse.urlsplit(sink)
    host = u.hostname or ""
    if u.port:
        host += f":{u.port}"
    return f"{u.scheme}://{host}{u.path}"


def _write_file(path: str, line: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise AnchorError(f"cannot append to the anchor file {path}: {exc}") from exc


def _post(url: str, body: str) -> None:
    req = urllib.request.Request(
        url, data=body.encode("utf-8"), method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            if not 200 <= resp.status < 300:
                raise AnchorError(f"anchor webhook {sink_label(url)} answered HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        raise AnchorError(f"anchor webhook {sink_label(url)} answered HTTP {exc.code}") from exc
    except OSError as exc:
        raise AnchorError(f"anchor webhook {sink_label(url)} unreachable: {exc}") from exc


def anchor(conn: psycopg.Connection, sink: str, *, now: datetime | None = None) -> dict:
    """Anchor the current head. Refuses an empty or broken ledger; the sink is written before the database row."""
    if not sink:
        raise AnchorError("no anchor sink configured")
    breaks = verify_chain(conn)
    if breaks:
        raise ChainError(f"refusing to anchor a broken chain: {len(breaks)} break(s), first at seq {breaks[0].seq}")
    head = conn.execute("SELECT seq, row_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1").fetchone()
    if head is None:
        raise AnchorError("the ledger is empty; there is no head to anchor")
    when = now or datetime.now(timezone.utc)
    record = {"seq": head["seq"], "row_hash": head["row_hash"],
              "anchored_at": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    if _is_url(sink):
        _post(sink, line)
    else:
        _write_file(sink, line)
    try:
        conn.execute(
            "INSERT INTO consentvault.chain_head (seq, row_hash, sink, anchored_at) VALUES (%s, %s, %s, %s)",
            (head["seq"], head["row_hash"], sink_label(sink), when),
        )
    except psycopg.Error as exc:
        raise AnchorError(
            f"the head was written to the sink but chain_head refused it: {exc}") from exc
    return {**record, "sink": sink_label(sink)}
