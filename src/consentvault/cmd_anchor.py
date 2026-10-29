"""``consentvault anchor``: write the current chain head to chain_head and to the configured external sink."""

from __future__ import annotations

import json

from .cli import EXIT_OK, _connect, register


def _run_anchor(args, cfg) -> int:
    from .anchor import anchor

    sink = args.sink or cfg.require_anchor_sink()
    with _connect(cfg) as conn:
        record = anchor(conn, sink)
    print(json.dumps(record, sort_keys=True))
    return EXIT_OK


def _anchor_args(p) -> None:
    p.add_argument("--sink", help="override the configured sink: a file path or an http(s) webhook URL")


register("anchor", "write the current chain head to chain_head and the external sink", _run_anchor, _anchor_args)
