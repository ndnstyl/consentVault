"""The events have one writer (specs/capture-everything/one-door.md, design points 3 and 5): the ledger append is called from the
door and nowhere else, and the code the design deleted stays deleted."""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "consentvault"
WRITERS = re.compile(r"(?<![\w.])(record_event|record_tenant_event)\(|\bledger\.(record_event|record_tenant_event)\(")
ALLOWED = {"ledger.py", "door.py"}
DELETED = ("_derive_event", "claim_request", "request_seen", "RequestSeenBefore", "tenant_capture", "capture_and_release")


def _sources():
    for p in sorted(SRC.rglob("*.py")):
        yield p, p.read_text(encoding="utf-8")


def test_the_ledger_append_is_called_from_the_door_and_the_ledger_only():
    offenders = []
    for p, text in _sources():
        if p.relative_to(SRC).as_posix() in ALLOWED or p.parts[-2] == "billing":
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if WRITERS.search(line) and not line.lstrip().startswith(("#", '"', "'")) and "def " not in line:
                offenders.append(f"{p.relative_to(SRC)}:{n}: {line.strip()[:80]}")
    assert offenders == [], offenders


def test_the_code_the_design_deleted_stays_deleted():
    found = []
    for p, text in _sources():
        for name in DELETED:
            if re.search(rf"(?<![\w]){name}(?![\w])", text):
                found.append(f"{p.relative_to(SRC)}: {name}")
    assert found == [], found
