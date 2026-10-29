"""CLI subcommands: ``disclosure register`` (store wording) and ``revoke`` (record a person's stop)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .cli import EXIT_OK, _connect, register
from .errors import InvalidEventError


def _disclosure_args(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="disclosure_command", required=True)
    _register_args(sub.add_parser("register", help="store the exact wording and print its sha256"))


def _register_args(p: argparse.ArgumentParser) -> None:
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--body", help="the exact wording shown to the person")
    src.add_argument("--body-file", help="read the exact wording from a file")
    p.add_argument("--label", required=True)
    p.add_argument("--keep-whitespace", action="store_true",
                   help="store the wording with its leading and trailing whitespace (refused by default; "
                        "the capture widget hashes the trimmed text)")
    p.add_argument("--locale", default="en")
    p.add_argument("--channel", action="append", default=[], dest="channels")
    p.add_argument("--purpose", action="append", default=[], dest="purposes")


def _run_disclosure(args, cfg) -> int:
    from . import disclosure

    if not args.channels or not args.purposes:
        raise InvalidEventError("a disclosure must name at least one --channel and one --purpose")
    body = args.body if args.body is not None else Path(args.body_file).read_text(encoding="utf-8")
    with _connect(cfg) as conn:
        sha = disclosure.register(conn, body, args.label, args.locale, args.channels, args.purposes,
                                  allowed_purposes=cfg.require_purposes(), strip=not args.keep_whitespace)
    print(json.dumps({"sha256": sha}))
    return EXIT_OK


def _revoke_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--contact", required=True)
    p.add_argument("--channel", action="append", default=[], dest="channels")
    p.add_argument("--purpose", action="append", default=[], dest="purposes")
    p.add_argument("--method", default="keyword")
    p.add_argument("--origin", default="consumer")
    p.add_argument("--source")
    p.add_argument("--session-ref")


def _run_revoke(args, cfg) -> int:
    from .ledger import record_event

    with _connect(cfg) as conn:
        ev = record_event(
            conn, contact=args.contact, event_type="revoke", channels=args.channels, purposes=args.purposes,
            method=args.method, origin=args.origin, region=cfg.default_region, source=args.source,
            session_ref=args.session_ref, allowed_purposes=cfg.require_purposes(),
        )
    print(json.dumps({"event_id": ev.event_id, "seq": ev.seq, "row_hash": ev.row_hash}))
    return EXIT_OK


register("disclosure", "manage the consent wording the vault holds (register)", _run_disclosure, _disclosure_args)
register("revoke", "record that a person withdrew consent", _run_revoke, _revoke_args)
