"""``consentvault records-exports`` and ``consentvault records-backfill``: the records list jobs (migration 0044).

``records-exports`` is one pass of the export worker (scheduled every minute): it builds every list export still building,
one organization at a time, each under its own short token. An organization that fails does not stop the others; the run then
exits 2 naming each failed organization, so no heartbeat is sent. ``records-backfill`` is a one-shot run on demand: it makes the
display key and the record rows of organizations that predate the tables, and exits 1 naming any organization it could not
finish. Both read the server's configuration and print counts and organization ids only.
"""

from __future__ import annotations

from .cli import EXIT_OK, register


def _run_exports(args, cfg) -> int:
    from . import records_exports

    return records_exports.main()


def _run_backfill(args, cfg) -> int:
    from . import records_backfill

    return records_backfill.main()


register("records-exports", "build the records list exports that are still building (scheduled every minute)", _run_exports)
register("records-backfill", "one-shot: make display keys and record rows for organizations that predate them", _run_backfill)
__all__ = ["EXIT_OK"]
