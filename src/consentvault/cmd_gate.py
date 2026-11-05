"""CLI subcommands: ``may-contact`` and ``classify``."""

from __future__ import annotations

import argparse
import json

from .cli import EXIT_OK, register
from .db import connect

EXIT_UNREAD = 1


def _may_contact_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--contact", required=True)


def _run_may_contact(args, cfg) -> int:
    from .gate import NOTICE, REASON_DB_DOWN, contact_facts, unavailable

    try:
        conn = connect(cfg.require_dsn())
    except Exception as exc:  # the record could not be reached: the answer says so, with the named cause
        print(json.dumps({**unavailable(f"{REASON_DB_DOWN}:{type(exc).__name__}").as_dict(), "notice": NOTICE}))
        return EXIT_UNREAD
    with conn:
        facts = contact_facts(conn, args.contact, region=cfg.default_region)
    print(json.dumps({**facts.as_dict(), "notice": NOTICE}))
    return EXIT_OK if facts.read else EXIT_UNREAD


def _classify_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("message", help="the inbound message text")


def _run_classify(args, cfg) -> int:
    from .stopwords import classify

    result = classify(args.message)
    print(json.dumps({"verdict": result.verdict, "reason": result.reason, "matched": result.matched}))
    return EXIT_OK


register("may-contact", "print the facts and history recorded for a contact point (exit 1 = the record could not be read)",
         _run_may_contact, _may_contact_args)
register("classify", "classify an inbound message as stop / not_stop / needs_review",
         _run_classify, _classify_args)
