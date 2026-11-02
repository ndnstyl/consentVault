#!/usr/bin/env python3
"""Write the self-host suites receipt that tests/traceability reads for every mapped test outside the checkpoint's run.

    write_receipt.py <junit.xml of the live provider tests> <receipt path> <exit code> [<section>=<passed|failed> ...]

The receipt (JSON, format "consentvault-selfhost-receipt/2"):
    {"format": "consentvault-selfhost-receipt/2", "finished_at": "<UTC ISO 8601>", "exit_code": <int>,
     "product_sha256": "<digest of the product files the run proved>",
     "manifest_sha256": "<SHA-256 of src/consentvault/data/security_manifest.sha256>",
     "sections": {"<section name>": "passed" | "failed", ...},
     "tests": {"tests/selfhost/<file>.py::<test>": "passed" | "failed" | "skipped", ...}}
The product digest (product_digest below) is a SHA-256 over "<sha256 of file>  <path>" lines, sorted by path, of every
file under PRODUCT_PATHS (the product source, the migrations, the database init files, the container and self-host
deployment files), skipping caches and the self-host secrets and settings, which are never read. Traceability accepts
the receipt only while both digests equal the current ones, so a receipt proves the code it ran against and goes stale
on any change to it.
Exit 2 when the junit file is missing or unreadable (the run produced no evidence), so run_suites.sh fails loudly.
"""
from __future__ import annotations

import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

FORMAT = "consentvault-selfhost-receipt/2"
REPO = Path(__file__).resolve().parents[2]
PRODUCT_PATHS = ("src/consentvault", "migrations", "docker", "Dockerfile", "docker-compose.yml", "pyproject.toml",
                 "deploy/selfhost")
MANIFEST = "src/consentvault/data/security_manifest.sha256"
_SKIP_NAMES = {"__pycache__", "node_modules", ".DS_Store", "secrets", "selfhost.settings", ".env"}


def _product_files(root: Path):
    for top in PRODUCT_PATHS:
        base = root / top
        if base.is_file():
            yield base
        elif base.is_dir():
            for path in sorted(base.rglob("*")):
                rel = path.relative_to(base).parts
                if any(part in _SKIP_NAMES for part in rel) or path.suffix == ".pyc" or not path.is_file():
                    continue
                yield path


def product_digest(root: Path = REPO) -> str:
    """The SHA-256 of the product files under ``root`` (see the module docstring)."""
    lines = []
    for path in _product_files(root):
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SystemExit(f"write_receipt: the product file {path} cannot be read: {exc}") from None
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {path.relative_to(root).as_posix()}\n")
    return hashlib.sha256("".join(sorted(lines, key=lambda l: l.split("  ", 1)[1])).encode("utf-8")).hexdigest()


def manifest_digest(root: Path = REPO) -> str | None:
    """The SHA-256 of the security manifest under ``root``, None when there is none."""
    path = root / MANIFEST
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def node_id(case: ET.Element) -> str:
    cls = case.get("classname") or ""
    parts = cls.split(".")
    # pytest's junit classname is the dotted module path, plus the class name when the test sits in a class
    for cut in range(len(parts), 0, -1):
        candidate = Path(*parts[:cut]).with_suffix(".py")
        if candidate.as_posix().startswith("tests/"):
            rest = parts[cut:]
            return "::".join([candidate.as_posix(), *rest, case.get("name") or ""])
    return f"{cls}::{case.get('name')}"


def outcome(case: ET.Element) -> str:
    if case.find("failure") is not None or case.find("error") is not None:
        return "failed"
    if case.find("skipped") is not None:
        return "skipped"
    return "passed"


def build(junit: Path, exit_code: int, sections: list[str]) -> dict:
    try:
        root = ET.parse(junit).getroot()
    except (OSError, ET.ParseError) as exc:
        raise SystemExit(f"write_receipt: no readable junit report at {junit}: {exc}") from None
    tests: dict[str, str] = {}
    for case in root.iter("testcase"):
        nid = node_id(case)
        tests[nid] = "failed" if tests.get(nid) == "failed" else outcome(case)
    named = {}
    for item in sections:
        name, _, status = item.rpartition("=")
        if status not in ("passed", "failed") or not name:
            raise SystemExit(f"write_receipt: a section is <name>=passed|failed, got {item!r}")
        named[name] = status
    manifest = manifest_digest(REPO)
    if manifest is None:
        raise SystemExit(f"write_receipt: no security manifest at {REPO / MANIFEST}; the run cannot name what it proved")
    return {"format": FORMAT, "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "exit_code": exit_code, "product_sha256": product_digest(REPO), "manifest_sha256": manifest,
            "sections": named, "tests": tests}


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    junit, receipt, code = Path(argv[0]), Path(argv[1]), int(argv[2])
    if not junit.is_file():
        print(f"write_receipt: the live provider tests left no junit report at {junit}", file=sys.stderr)
        return 2
    body = build(junit, code, argv[3:])
    receipt.parent.mkdir(parents=True, exist_ok=True)
    tmp = receipt.with_suffix(".tmp")
    tmp.write_text(json.dumps(body, indent=1, sort_keys=True) + "\n")
    tmp.replace(receipt)
    print(f"receipt: {receipt} ({sum(v == 'passed' for v in body['tests'].values())} passed of {len(body['tests'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
