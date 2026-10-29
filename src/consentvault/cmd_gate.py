"""CLI subcommands: ``may-contact`` and ``classify``."""

from __future__ import annotations

import argparse
import json

from .cli import EXIT_OK, register
from .db import connect

EXIT_DENIED = 1


def _may_contact_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--contact", required=True)
    p.add_argument("--channel", required=True)
    p.add_argument("--purpose", required=True)


def _run_may_contact(args, cfg) -> int:
    from .gate import REASON_DB_DOWN, may_contact

    try:
        conn = connect(cfg.require_dsn())
    except Exception as exc:  # fail closed: any connection fault is a named denial
        print(json.dumps({"allowed": False, "reason": f"{REASON_DB_DOWN}:{type(exc).__name__}",
                          "basis_event_ids": []}))
        return EXIT_DENIED
    with conn:
        decision = may_contact(conn, args.contact, args.channel, args.purpose, region=cfg.default_region)
    print(json.dumps({"allowed": decision.allowed, "reason": decision.reason,
                      "basis_event_ids": list(decision.basis_event_ids)}))
    return EXIT_OK if decision.allowed else EXIT_DENIED


def _classify_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("message", help="the inbound message text")


def _run_classify(args, cfg) -> int:
    from .stopwords import classify

    result = classify(args.message)
    print(json.dumps({"verdict": result.verdict, "reason": result.reason, "matched": result.matched}))
    return EXIT_OK


register("may-contact", "ask the gate whether a contact point may be contacted (exit 1 = no)",
         _run_may_contact, _may_contact_args)
register("classify", "classify an inbound message as stop / not_stop / needs_review",
         _run_classify, _classify_args)
