"""``consentvault projection-rebuild``: project every stored post that has no event yet, in arrival order (the one door's rebuild).

A crash between a post's answer and its event, a database fault while the projection ran, or a post whose process had no writer
for its intake all leave a stored post with no outcome. This command finds them and projects them with the settings stored
beside each post. Run it from the scheduler (for example every 10 minutes); running it twice changes nothing.

It prints counts only: the posts it projected, the events it appended, the reasons it stored, and the posts it could not finish.
Exit 2 names how many posts it could not finish (a passing fault: they stay pending and the next run repeats them); nothing is
ever stored as refused for a fault that may pass. In multi-tenant mode it needs the same settings as ``serve-cloud``.
"""

from __future__ import annotations

import json
import os

from .cli import EXIT_ERROR, EXIT_OK, _connect, register


def _summary(mode: str, outcomes, failed) -> dict:
    return {"mode": mode, "projected": len(outcomes), "events": sum(1 for o in outcomes if o.event_id is not None),
            "reasons_stored": sum(1 for o in outcomes if o.event_id is None and not o.retry), "unfinished": len(failed)}


def _run(args, cfg) -> int:
    from . import door
    from .errors import ConsentVaultError

    with _connect(cfg) as conn:
        multi = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] is None
        if not multi:
            outcomes = door.rebuild(conn, backend=door.SingleBackend(cfg.default_region, cfg.purposes or None))
            failed = [o for o in outcomes if o.retry]
            print(json.dumps(_summary("single", outcomes, failed)))
            return EXIT_OK if not failed else _unfinished(len(failed))
    from . import api, cmd_cloud, db

    settings = cmd_cloud.build_cloud(cfg, os.environ)
    with db.connect(cfg.require_operator_dsn()) as owner:
        orgs = [r["org_id"] for r in owner.execute(
            "SELECT org_id FROM consentvault.organization WHERE status <> 'closed' ORDER BY org_id").fetchall()]
    outcomes: list = []
    api.rebuild_cloud(settings, orgs, outcomes=outcomes)
    failed = [o for o in outcomes if o.retry]
    print(json.dumps(_summary("multi-tenant", outcomes, failed)))
    if failed:
        return _unfinished(len(failed))
    return EXIT_OK


def _unfinished(n: int) -> int:
    import sys

    print(f"consentvault: {n} stored post(s) could not be projected now (a passing fault); they stay pending and the next run "
          "repeats them", file=sys.stderr)
    return EXIT_ERROR


register("projection-rebuild", "project every stored post that has no event, in arrival order (scheduled job)", _run)
