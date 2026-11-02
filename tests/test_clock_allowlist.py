"""The structural guard on time: every database function that takes a date, a time or an interval, and every place the product
reads the process wall clock, is named in tests/clock_allowlist.json with its kind and reason (records, local, or open). A new
one fails here until it is listed, and a listed one that is gone fails too, so the list is the whole truth. A decision is
moved to the database's clock (connector_window_hit, connector_systems, db_now in the sender and the billing run), never
waved through by an entry."""

import ast
import json
import pathlib
import sys

import pytest

from consentvault import db

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "consentvault"
ALLOW = json.loads((REPO / "tests" / "clock_allowlist.json").read_text())
CLOCK = {"datetime.datetime.now", "datetime.datetime.utcnow", "datetime.datetime.today", "datetime.date.today",
         "time.time", "time.time_ns", "time.monotonic", "time.monotonic_ns", "time.perf_counter", "time.perf_counter_ns",
         "time.process_time", "time.gmtime", "time.localtime", "time.strftime", "time.ctime", "time.asctime"}
HELPERS = {"_dt", "_clock"}   # the confirmation service's own clock helper and the clock it is built on; a call is a read of the
# worker's clock unless its one argument is a literal time
HELPER_FILES = {   # outside the confirm package, the files whose decisions moved to the database's clock; every file inside it is scanned too
"sync/connectors/twenty.py", "sync/connectors/twenty_reconcile.py", "confirm/sender.py", "billing/usage.py",
                "sync/connectors/twenty_receiver.py"}


def _chain(n):
    """The dotted name of a Name or an Attribute chain, or None for anything else (a call result, a subscript)."""
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if not isinstance(n, ast.Name):
        return None
    return [n.id, *reversed(parts)]


def scan_source(text: str, rel: str) -> dict[str, set[str]]:
    """path::qualified function::clock expression -> that expression. Every distinct read in a function is its own key, so a listed
    read never covers a second, different one beside it. Names are resolved through the module's imports, so an aliased
    module, a from-import and a from-import under another name are all caught; a bare reference (a default bound to the clock)
    counts as much as a call."""
    tree = ast.parse(text)
    alias: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            for a in n.names:
                alias[a.asname or a.name] = f"{n.module}.{a.name}"
    sites: dict[str, set[str]] = {}
    stack: list[str] = []

    def add(expr: str) -> None:
        sites.setdefault(f"{rel}::{'.'.join(stack) or '<module>'}::{expr}", set()).add(expr)   # one key per clock read

    class Visitor(ast.NodeVisitor):
        def _scope(self, n):
            stack.append(n.name)
            self.generic_visit(n)
            stack.pop()

        visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

        def _resolved(self, n):
            chain = _chain(n)
            if chain is None:
                return None
            head = alias.get(chain[0])
            return ".".join([head, *chain[1:]]) if head else None

        def visit_Attribute(self, n):
            got = self._resolved(n)
            if got in CLOCK:
                add(got)
            self.generic_visit(n)

        def visit_Name(self, n):
            got = self._resolved(n)
            if got in CLOCK:
                add(got)

        def visit_Call(self, n):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if name in HELPERS and (rel.startswith("confirm/") or rel in HELPER_FILES):
                literal = (len(n.args) == 1 and not n.keywords and isinstance(n.args[0], ast.Constant)
                           and isinstance(n.args[0].value, (int, float)))
                if not literal:
                    add(f"{name}()" if not (n.args or n.keywords) else f"{name}(arg)")
            self.generic_visit(n)

    Visitor().visit(tree)
    return sites


def python_sites() -> dict[str, set[str]]:
    """path::qualified function::clock expression (a call, or a default bound to one)."""
    sites: dict[str, set[str]] = {}
    for p in sorted(SRC.rglob("*.py")):
        for k, v in scan_source(p.read_text(encoding="utf-8"), p.relative_to(SRC).as_posix()).items():
            sites.setdefault(k, set()).update(v)
    return sites


def sql_functions(dsn) -> set[str]:
    with db.connect(dsn) as c:
        rows = c.execute(
            "SELECT p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS sig"
            " FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname LIKE 'consentvault%%' AND EXISTS (SELECT 1 FROM unnest(p.proargtypes) t"
            " WHERE t IN ('timestamptz'::regtype, 'timestamp'::regtype, 'date'::regtype, 'interval'::regtype,"
            " 'time'::regtype, 'timetz'::regtype))").fetchall()
    return {r["sig"] for r in rows}


def _entries_are_well_formed(section: str) -> None:
    bad = [k for k, v in ALLOW[section].items()
           if not (isinstance(v, list) and len(v) == 2 and v[0] in ALLOW["kinds"] and isinstance(v[1], str) and len(v[1]) > 20)]
    assert bad == [], f"entries without a kind and a reason: {bad}"


def test_every_python_clock_read_is_listed_with_its_reason():
    _entries_are_well_formed("python")
    found, listed = set(python_sites()), set(ALLOW["python"])
    assert sorted(found - listed) == [], "a new read of the process clock: move the decision to the database's clock, or list it"
    assert sorted(listed - found) == [], "listed reads that no longer exist: remove them from tests/clock_allowlist.json"


def test_every_database_function_that_takes_a_time_is_listed_with_its_reason(dsn):
    _entries_are_well_formed("sql")
    found, listed = sql_functions(dsn), set(ALLOW["sql"])
    assert sorted(found - listed) == [], "a new database function takes a time: read clock_timestamp() inside, or list it"
    assert sorted(listed - found) == [], "listed functions that no longer exist: remove them from tests/clock_allowlist.json"
    assert all(kind == "records" for kind, _ in ALLOW["sql"].values()), "a database function decides only on its own clock"


def test_the_moved_decisions_stay_moved():
    """The decisions moved to the database's clock never come back to the process clock."""
    moved = {"sync/connectors/twenty.py", "sync/connectors/twenty_reconcile.py", "confirm/sender.py", "billing/usage.py",
             "sync/connectors/twenty_receiver.py"}
    back = [k for k, (kind, _) in ALLOW["python"].items() if k.split("::")[0] in moved and kind == "open"]
    assert back == []
    for path in ("sync/connectors/twenty.py", "sync/connectors/twenty_reconcile.py", "confirm/sender.py"):
        wall = [k for k, v in python_sites().items() if k.startswith(path + "::") and v - {"time.monotonic", "time.monotonic_ns"}]
        assert not wall, path   # an elapsed duration on the monotonic clock is local; a wall-clock read is not


PATTERNS = {
    "datetime.now": "import datetime\n\ndef f():\n    return datetime.datetime.now()\n",
    "from-import datetime.now": "from datetime import datetime\n\ndef f():\n    return datetime.now()\n",
    "datetime.utcnow": "from datetime import datetime\n\ndef f():\n    return datetime.utcnow()\n",
    "datetime.today": "from datetime import datetime\n\ndef f():\n    return datetime.today()\n",
    "date.today": "from datetime import date\n\ndef f():\n    return date.today()\n",
    "datetime.date.today": "import datetime\n\ndef f():\n    return datetime.date.today()\n",
    "time.time": "import time\n\ndef f():\n    return time.time()\n",
    "time.time_ns": "import time\n\ndef f():\n    return time.time_ns()\n",
    "time.monotonic": "import time\n\ndef f():\n    return time.monotonic()\n",
    "aliased module": "import time as t\n\ndef f():\n    return t.time()\n",
    "aliased datetime module": "import datetime as dt\n\ndef f():\n    return dt.datetime.now()\n",
    "aliased class": "from datetime import datetime as D\n\ndef f():\n    return D.now()\n",
    "from-import of the function": "from time import time\n\ndef f():\n    return time()\n",
    "from-import under another name": "from time import time as wall\n\ndef f():\n    return wall()\n",
    "from-import of monotonic": "from time import monotonic\n\ndef f():\n    return monotonic()\n",
    "time.perf_counter": "import time\n\ndef f():\n    return time.perf_counter()\n",
    "time.gmtime": "import time\n\ndef f():\n    return time.gmtime()\n",
    "time.localtime": "import time\n\ndef f():\n    return time.localtime()\n",
    "time.strftime": "import time\n\ndef f():\n    return time.strftime('%Y')\n",
    "time.ctime": "import time\n\ndef f():\n    return time.ctime()\n",
    "from-import of gmtime": "from time import gmtime\n\ndef f():\n    return gmtime()\n",
    "a default bound to the clock": "import time\n\ndef f(now=time.time):\n    return now()\n",
    "the service's own helper": "class S:\n    def f(self):\n        return self._dt()\n",
    "the service's own clock": "class S:\n    def f(self):\n        return self._clock()\n",
    "the helper given a worker time": "class S:\n    def f(self, ctx):\n        return self._dt(ctx.now())\n",
}
FILES = ["confirm/sender.py", "confirm/inbound.py", "confirm/jobs.py", "confirm/anything_else.py"]


@pytest.mark.parametrize("rel", FILES)
@pytest.mark.parametrize("name", sorted(PATTERNS))
def test_the_scan_catches_each_clock_pattern(name, rel, tmp_path, monkeypatch):
    """Each pattern, put in a file of its own (the inbound and jobs code among them), is found, and an unlisted find fails the
    allowlist test."""
    assert scan_source(PATTERNS[name], rel), f"the scan misses: {name}"
    (tmp_path / "confirm").mkdir()
    (tmp_path / rel).write_text(PATTERNS[name])
    monkeypatch.setattr(sys.modules[__name__], "SRC", tmp_path)
    monkeypatch.setitem(ALLOW, "python", {})
    with pytest.raises(AssertionError, match="a new read of the process clock"):
        test_every_python_clock_read_is_listed_with_its_reason()


def test_a_dt_call_with_a_literal_time_is_not_a_clock_read():
    assert scan_source("class S:\n    def f(self):\n        return self._dt(1700000000.0)\n", "confirm/inbound.py") == {}


def test_a_dt_call_outside_the_confirm_package_is_not_scanned():
    assert scan_source("class S:\n    def f(self):\n        return self._dt()\n", "tenancy/other.py") == {}


MOVED_PACKAGES = ("confirm/", "sync/connectors/", "billing/")


def test_no_decision_in_a_moved_package_is_listed_as_open():
    """The confirmation, connector and billing code decides on the database's clock: none of their sites is an open entry."""
    open_ = sorted(k for k, (kind, _) in ALLOW["python"].items() if kind == "open" and k.startswith(MOVED_PACKAGES))
    assert open_ == [], "a decision in a moved package is still on the host clock: move it to the database's clock"


def test_no_allowlist_entry_is_labelled_open():
    """Every site either reads the database's clock or records data and decides nothing: none is left open, and no reason
    still says a decision has not been moved."""
    open_ = sorted(f"{sec}:{k}" for sec in ("sql", "python") for k, (kind, _) in ALLOW[sec].items() if kind == "open")
    assert open_ == [], "an entry is labelled open: move the decision to the database's clock, or show it decides nothing"
    pending = sorted(f"{sec}:{k}" for sec in ("sql", "python") for k, (_, why) in ALLOW[sec].items()
                     if "not yet moved" in why.lower() or "still runs on the host clock" in why.lower())
    assert pending == [], "an entry's reason says its decision is not yet moved"
