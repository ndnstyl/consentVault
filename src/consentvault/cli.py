"""Command line entry point with an extensible subcommand registry.

To add a subcommand, create a module named ``consentvault/cmd_<name>.py`` that calls
``register(...)`` at import time; ``main`` imports every such module.
"""

from __future__ import annotations

import argparse
import importlib
import json
import pkgutil
import sys
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Callable, Sequence

from . import config as config_mod
from .errors import ConsentVaultError, InvalidEventError, ReleaseFailedError

EXIT_OK = 0
EXIT_ERROR = 2
EXIT_BROKEN = 3


@dataclass(frozen=True)
class Command:
    name: str
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    run: Callable[[argparse.Namespace, config_mod.Config], int]


REGISTRY: dict[str, Command] = {}


def register(
    name: str,
    help: str,
    run: Callable[[argparse.Namespace, config_mod.Config], int],
    add_arguments: Callable[[argparse.ArgumentParser], None] | None = None,
) -> Command:
    """Register a subcommand. ``run(args, config)`` returns the process exit code."""
    if name in REGISTRY:
        raise ConsentVaultError(f"subcommand {name!r} is registered twice")
    cmd = Command(name, help, add_arguments or (lambda p: None), run)
    REGISTRY[name] = cmd
    return cmd


def _connect(cfg: config_mod.Config):
    from .db import connect

    return connect(cfg.require_dsn())


def _run_migrate(args, cfg) -> int:
    from .db import migrate

    from .db import connect

    with connect(cfg.require_owner_dsn()) as conn:
        applied = migrate(conn, args.dir or cfg.migrations_dir)
    print(json.dumps({"applied": applied}))
    return EXIT_OK


def _capture_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--contact", required=True)
    p.add_argument("--checked", action="store_true", help="the consent box was checked")
    p.add_argument("--disclosure", required=True, help="sha256 of the disclosure shown")
    p.add_argument("--channel", action="append", default=[], dest="channels")
    p.add_argument("--purpose", action="append", default=[], dest="purposes")
    p.add_argument("--method", default="checkbox")
    p.add_argument("--origin", default="consumer")
    p.add_argument("--session-ref")
    p.add_argument("--page-url")
    p.add_argument("--source")
    p.add_argument("--verification", choices=("otp", "inbound_keyword"),
                   help="how you verified that the person controls the contact point: 'otp' (you confirmed a one-time "
                        "code; the code check is yours, the vault only records that you did it) or 'inbound_keyword' "
                        "(the contact point sent a START-type message, passed with --inbound-message)")
    p.add_argument("--inbound-message", help="the START, UNSTOP or YES message the contact point sent")


def _run_capture(args, cfg) -> int:
    from .capture import capture_and_release, capture_verified

    extra = {}
    if args.verification:
        call, extra = capture_verified, {"verification": args.verification, "inbound_message": args.inbound_message}
    elif args.inbound_message is not None:
        raise InvalidEventError("--inbound-message goes with --verification inbound_keyword")
    else:
        call = capture_and_release
    method = args.method
    if args.verification == "inbound_keyword" and method == "checkbox":
        method = "keyword"
    with _connect(cfg) as conn:
        ev, release, release_error = call(
            conn,
            **extra,
            contact=args.contact,
            checked=args.checked,
            disclosure_sha256=args.disclosure,
            channels=args.channels,
            purposes=args.purposes,
            allowed_purposes=cfg.require_purposes(),
            method=method,
            origin=args.origin,
            region=cfg.default_region,
            session_ref=args.session_ref,
            page_url=args.page_url,
            source=args.source,
        )
    out = {"event_id": ev.event_id, "seq": ev.seq, "row_hash": ev.row_hash}
    if release is not None:
        out["release"] = release
    print(json.dumps(out))
    if release_error is not None:
        raise ReleaseFailedError(f"the grant {ev.event_id} was recorded but its release decision failed: {release_error}")
    return EXIT_OK


def _run_verify_chain(args, cfg) -> int:
    from .ledger import verify_chain

    webhook = bool(cfg.anchor_sink) and urlparse(cfg.anchor_sink).scheme.startswith("http")
    sink = cfg.anchor_sink if cfg.anchor_sink and not webhook else None
    with _connect(cfg) as conn:
        breaks = verify_chain(conn, sink_file=sink)
    out = {"ok": not breaks, "breaks": [b.__dict__ for b in breaks]}
    if webhook:
        out["sink_not_checked"] = True
        print("consentvault: sink_not_checked: the anchor sink is a webhook and cannot be read back; only the "
              "chain_head anchors in the database were checked", file=sys.stderr)
    print(json.dumps(out))
    return EXIT_OK if not breaks else EXIT_BROKEN


def _load_builtin() -> None:
    if "migrate" in REGISTRY:
        return
    register("migrate", "apply pending database migrations", _run_migrate,
             lambda p: p.add_argument("--dir", help="migrations directory"))
    register("capture", "record a checked consent box as a grant", _run_capture, _capture_args)
    register("verify-chain", "recompute the hash chain and report breaks", _run_verify_chain)
    package = importlib.import_module(__package__)
    for mod in pkgutil.iter_modules(package.__path__):
        if mod.name.startswith("cmd_"):
            importlib.import_module(f"{__package__}.{mod.name}")


def build_parser() -> argparse.ArgumentParser:
    _load_builtin()
    parser = argparse.ArgumentParser(prog="consentvault", description="consentvault consent vault")
    parser.add_argument("--config", help="path to consentvault.toml")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in sorted(REGISTRY):
        cmd = REGISTRY[name]
        cmd.add_arguments(sub.add_parser(name, help=cmd.help))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = config_mod.load_config(args.config)
        return REGISTRY[args.command].run(args, cfg)
    except ConsentVaultError as exc:
        print(f"consentvault: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
