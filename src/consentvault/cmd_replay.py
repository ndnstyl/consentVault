"""``consentvault replay-sweep``: delete expired nonces from the replay guard (run it from the scheduler, for example every
hour). An expired nonce still counts as seen until this runs, so a late run never lets a replay through; it only keeps
the table small. Needs the worker login (``dsn`` is the worker's, as for ``sync-worker``)."""

from __future__ import annotations

import json

from .cli import EXIT_OK, _connect, register


def _run_replay_sweep(args, cfg) -> int:
    from .tenancy.replay import sweep

    with _connect(cfg) as conn:
        gone = sweep(conn)
    print(json.dumps({"swept": gone}))
    return EXIT_OK


register("replay-sweep", "delete expired nonces from the replay guard (scheduled job, worker login)", _run_replay_sweep)
