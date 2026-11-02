"""No exception's text leaves the code that caught it: a taint rule over the AST of every file in src/ (except safelog.py).

An exception's message can quote a stored value (a duplicate-key error names the email and phone that collided), and a name in it
cannot be detected. So an exception is tainted, and a tainted value may only be:

* re-raised (``raise``, ``raise e``) or named as a cause (``raise X(...) from e``);
* checked: ``isinstance(e, ...)``, ``type(e)``, ``e is None``, ``if e:``;
* handed to safelog, the one module that reads exceptions (``describe``, ``caller_detail``, ``sqlstate``, ``constraint_name``,
  ``db_refusal_id``, ``text_has``, ``refusal_code``, ``error_code``);
* read for an allowlisted attribute that is a code or a status, never text (``ALLOWED_ATTRS``);
* passed to a function in src/ whose parameter is annotated as an exception, which this rule then checks in turn.

Tainted: every name an ``except`` (or ``except*``) clause binds; every alias assigned from a tainted value (``err = e``, a walrus);
``e.__cause__`` and ``e.__context__``; every parameter annotated with an exception type; ``sys.exc_info()``, ``sys.exception()`` and
``<future>.exception()``. Anything else a tainted value meets (a call, formatting, a container, a string method, another attribute,
``raise X(e)``) fails. So does logging with ``exc_info`` outside the allowlist logger, ``logger.exception``, and the traceback module."""

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
ALLOWED_MODULES = {"consentvault/safelog.py"}
SAFELOG_READERS = {"describe", "caller_detail", "sqlstate", "constraint_name", "db_refusal_id", "text_has", "refusal_code",
                   "error_code", "http_error_response", "bounded_http_error", "smtp_reply_code"}
# codes, statuses and the product's own structured fields (ids, counts, report rows), never text
ALLOWED_ATTRS = {"sqlstate", "pgcode", "code", "status", "status_code", "http_status", "kind", "attempts", "price_id", "fields",
                 "failures", "results", "report", "record", "error_name", "report_line", "check_problem", "skip_code",
                 # an API error's contract name, Retry-After seconds and the response it builds for the authenticated caller
                 "name", "retry_after", "body", "refusal_response",
                 # the sync connector's own outcome codes and a refusal's cause codes
                 "error_class", "outcome", "causes",
                 # the organisations a rotation failure concerns, as a field
                 "org_ids"}
PROPAGATE_ATTRS = {"__cause__", "__context__"}
CHECKS = {"isinstance", "issubclass", "type", "id", "hash", "callable"}
SOURCE_CALLS = {("sys", "exc_info"), ("sys", "exception")}


def _is_exception_annotation(node) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in ("type", "Type"):
        return False  # an exception class, not an exception: raising one of these is constructing a new error
    if isinstance(node, ast.Constant) and isinstance(node.value, str):  # a quoted annotation, read as the expression it holds
        try:
            node = ast.parse(node.value, mode="eval").body
        except SyntaxError:  # loud-failure-exempt: a string annotation that is not an expression names no exception type
            return False
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    return any(n in ("BaseException", "Exception") or n.endswith(("Error", "Exception", "Refused")) for n in names)


def _parents(tree):
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node  # noqa: SLF001


def _exception_helpers(trees) -> set[str]:
    """Functions in src/ that take an exception as an annotated parameter: passing a tainted value to one is checked there."""
    out = set()
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                if any(_is_exception_annotation(p.annotation) for p in a.posonlyargs + a.args + a.kwonlyargs):
                    out.add(node.name)
    return out


def _callee(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")


def _is_source_call(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and (f.value.id, f.attr) in SOURCE_CALLS:
        return True
    if isinstance(f, ast.Attribute) and f.attr == "exception" and not node.args:  # a future's or a task's exception
        return True
    name = _callee(node).lower()
    return name.startswith(("get_err", "get_exc", "last_err", "last_exc"))


CARRY_MARK = "# carry-to-raise:"


class _Scan:
    def __init__(self, where: str, helpers: set[str], safe_loggers: set[str], lines: list[str] | None = None):
        self.where, self.helpers, self.safe_loggers, self.lines = where, helpers, safe_loggers, lines or []
        self.found: set[tuple[int, str]] = set()

    def bad(self, node, why):
        self.found.add((getattr(node, "lineno", 0), why))

    # ---- what a tainted expression may meet -----------------------------------------------------------------------------------
    def check_use(self, node, tainted: set[str]) -> None:
        parent = getattr(node, "_parent", None)
        if isinstance(parent, ast.Raise):
            return  # raise e / raise X from e
        if isinstance(parent, ast.Attribute) and parent.value is node:
            if parent.attr in PROPAGATE_ATTRS:
                return self.check_use(parent, tainted)
            if parent.attr in ALLOWED_ATTRS:
                return
            return self.bad(parent, f"reads .{parent.attr} of an exception")
        if isinstance(parent, ast.Call) and node in parent.args:
            name = _callee(parent)
            if name in CHECKS and parent.args[0] is node and isinstance(parent.func, ast.Name):
                return
            if name == "getattr" and parent.args[0] is node and len(parent.args) >= 2 and isinstance(parent.args[1], ast.Constant) \
                    and parent.args[1].value in ALLOWED_ATTRS | PROPAGATE_ATTRS:
                return
            if name == "text_has" and not all(isinstance(m, ast.Constant) and isinstance(m.value, str) for m in parent.args[1:]):
                return self.bad(parent, "text_has() takes only literal markers: a computed one could probe the error's text")
            if name in SAFELOG_READERS:
                return
            if name in self.helpers:
                return
            return self.bad(parent, f"passes an exception to {name or 'a call'}()")
        if isinstance(parent, ast.Compare):
            if all(isinstance(op, (ast.Is, ast.IsNot)) for op in parent.ops):
                return
            return self.bad(parent, "compares an exception by value")
        if isinstance(parent, (ast.BoolOp, ast.If, ast.While, ast.IfExp)) or (isinstance(parent, ast.UnaryOp)
                                                                               and isinstance(parent.op, ast.Not)):
            if isinstance(parent, ast.IfExp) and parent.test is not node:
                return self.bad(parent, "returns an exception from a conditional expression")
            return
        if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and getattr(parent, "value", None) is node:
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            if all(isinstance(t, ast.Name) for t in targets):
                return  # an alias: tainted itself, and checked where it is used
            if CARRY_MARK in self.lines[parent.lineno - 1]:
                return  # carried unchanged to another thread, which re-raises it (CARRY_MARK on the line, counted below)
            return self.bad(parent, "stores an exception in an attribute, item or unpacked target")
        return self.bad(node, f"uses an exception in {type(parent).__name__ if parent else 'a statement'}")

    # ---- regions ----------------------------------------------------------------------------------------------------------------
    def aliases_in(self, body_nodes, seeds: set[str]) -> set[str]:
        tainted = set(seeds)
        nodes = [n for b in body_nodes for n in ast.walk(b)]
        changed = True
        while changed:
            changed = False
            for n in nodes:
                value = getattr(n, "value", None)
                targets = n.targets if isinstance(n, ast.Assign) else ([n.target] if isinstance(n, (ast.AnnAssign, ast.NamedExpr))
                                                                        else [])
                if value is not None and targets and self._tainted_expr(value, tainted):
                    for t in targets:
                        if isinstance(t, ast.Name) and t.id not in tainted:
                            tainted.add(t.id)
                            changed = True
        return tainted

    def scan_region(self, body_nodes, seeds: set[str]) -> None:
        tainted = set(seeds)
        nodes = [n for b in body_nodes for n in ast.walk(b)]
        changed = True
        while changed:  # aliases, to a fixed point (bounded: one name added per pass at most per assignment)
            changed = False
            for n in nodes:
                value = getattr(n, "value", None)
                targets = n.targets if isinstance(n, ast.Assign) else ([n.target] if isinstance(n, (ast.AnnAssign, ast.NamedExpr))
                                                                        else [])
                if value is not None and targets and self._tainted_expr(value, tainted):
                    for t in targets:
                        if isinstance(t, ast.Name) and t.id not in tainted:
                            tainted.add(t.id)
                            changed = True
        for n in nodes:
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in tainted:
                self.check_use(n, tainted)
            elif _is_source_call(n):
                self.check_use(n, tainted)
            elif isinstance(n, ast.Subscript) and _is_source_call(n.value):
                self.check_use(n, tainted)

    def _tainted_expr(self, node, tainted) -> bool:
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, ast.Attribute) and node.attr in PROPAGATE_ATTRS:
            return self._tainted_expr(node.value, tainted)
        if isinstance(node, ast.Subscript):
            return _is_source_call(node.value)
        return _is_source_call(node)


def _safe_loggers(tree) -> set[str]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) in ("safelog.get", "get"):
            out |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return out


def problems_in(source: str, where: str, helpers: set[str] | None = None) -> list[str]:
    if where in ALLOWED_MODULES:
        return []
    tree = ast.parse(source)
    _parents(tree)
    helpers = _exception_helpers([tree]) if helpers is None else helpers
    scan = _Scan(where, helpers, _safe_loggers(tree), source.split("\n"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.name:
            scan.scan_region(node.body, {node.name})
            # an alias made in the handler outlives it: track it across the whole enclosing function (or module)
            aliases = scan.aliases_in(node.body, {node.name}) - {node.name}
            if aliases:
                scope = node
                while getattr(scope, "_parent", None) is not None and not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                                              ast.Lambda, ast.Module)):
                    scope = scope._parent
                body = scope.body if isinstance(getattr(scope, "body", None), list) else [scope.body]
                scan.scan_region(body, aliases)
        elif isinstance(node, ast.ExceptHandler):
            scan.scan_region(node.body, set())  # sys.exc_info() and friends inside a handler with no name
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            seeds = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs if _is_exception_annotation(p.annotation)}
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seeds |= {t.target.id for t in ast.walk(node) if isinstance(t, ast.AnnAssign) and isinstance(t.target, ast.Name)
                          and _is_exception_annotation(t.annotation)}
            body = node.body if isinstance(node.body, list) else [node.body]
            scan.scan_region(body, seeds)
        elif isinstance(node, ast.Module):
            top = [n for n in node.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
            scan.scan_region(top, set())
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            if any(m == "traceback" or m.startswith("traceback.") for m in mods):
                scan.bad(node, "imports the traceback module, which turns exceptions into text")
        if isinstance(node, ast.Call):
            name = _callee(node)
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            on_safe = isinstance(receiver, ast.Name) and receiver.id in scan.safe_loggers
            if name == "exception" and node.args and isinstance(receiver, (ast.Name, ast.Attribute)) and not on_safe:
                scan.bad(node, "logger.exception() writes the exception's text")
            if any(k.arg == "exc_info" and not (isinstance(k.value, ast.Constant) and k.value.value in (False, None)) for k in node.keywords) \
                    and not on_safe:
                scan.bad(node, "exc_info= outside the allowlist logger writes the exception's text")
    return [f"{where}:{line}: {why}: use safelog.describe(e) (or caller_detail(e) in an API response)" for line, why in sorted(scan.found)]


def test_no_exception_text_leaves_the_code_that_caught_it():
    files = sorted(SRC.rglob("*.py"))
    trees = [ast.parse(p.read_text()) for p in files]
    helpers = _exception_helpers(trees)
    found = []
    for path in files:
        found += problems_in(path.read_text(), str(path.relative_to(SRC)), helpers)
    assert found == [], "\n".join(found)


T = "try:\n    x()\nexcept ValueError as e:\n    {}\n"
PLANTED = {
    "str(e)": T.format("m = str(e)"),
    "repr(e)": T.format("m = repr(e)"),
    "format(e)": T.format("m = format(e)"),
    "f-string": T.format("m = f'{e}'"),
    "f-string !r": T.format("m = f'{e!r}'"),
    "percent": T.format("m = '%s' % e"),
    "str.format": T.format("m = '{}'.format(e)"),
    "e.args": T.format("m = e.args[0]"),
    "e.pgerror": T.format("m = e.pgerror"),
    "e.diag": T.format("m = e.diag.message_primary"),
    "e.message": T.format("m = e.message"),
    "getattr pgerror": T.format("m = getattr(e, 'pgerror', None)"),
    "print(e)": T.format("print(e)"),
    "print(e, file=stderr)": T.format("import sys; print('x', e, file=sys.stderr)"),
    "alias err=e; str(err)": T.format("err = e\n    m = str(err)"),
    "str(e.__cause__)": T.format("m = str(e.__cause__)"),
    "f'{e.__context__}'": T.format("m = f'{e.__context__}'"),
    "e.strerror": T.format("m = e.strerror"),
    "e.reason": T.format("m = e.reason"),
    "e.msg": T.format("m = e.msg"),
    "e.detail": T.format("m = e.detail"),
    "e.stderr (CalledProcessError)": T.format("m = e.stderr"),
    "e.output": T.format("m = e.output"),
    "e.response.text": T.format("m = e.response.text"),
    "e.errors()": T.format("m = e.errors()"),
    "e.__dict__": T.format("m = e.__dict__"),
    "vars(e)": T.format("m = vars(e)"),
    "e.__str__()": T.format("m = e.__str__()"),
    "logger arg %s e": T.format("log.error('failed %s', e)"),
    "logger extra=e": T.format("log.error('failed', reason=e)"),
    "join of map str": T.format("m = ' '.join(map(str, [e]))"),
    "sys.exc_info()[1]": "import sys\ntry:\n    x()\nexcept ValueError:\n    m = str(sys.exc_info()[1])\n",
    "sys.exception()": "import sys\ntry:\n    x()\nexcept ValueError:\n    m = str(sys.exception())\n",
    "future.exception()": "m = str(fut.exception())\n",
    "comprehension over group": T.format("m = [str(x) for x in e.exceptions]"),
    "for x in e.exceptions": T.format("for x in e.exceptions:\n        m = str(x)"),
    "from traceback import format_exc": "from traceback import format_exc\nm = format_exc()\n",
    "import traceback as tb": "import traceback as tb\nm = tb.format_exc()\n",
    "TracebackException": T.format("import traceback; m = ''.join(traceback.TracebackException.from_exception(e).format())"),
    "exc_info=True to logging": T.format("import logging; logging.getLogger('x').error('y', exc_info=True)"),
    "logging.exception": T.format("import logging; logging.exception('y')"),
    "str.__mod__": T.format("m = '%s'.__mod__(e)"),
    "format_map": T.format("m = '{e}'.format_map({'e': e})"),
    "Template": T.format("import string; m = string.Template('$e').substitute(e=e)"),
    "json.dumps(e, default=str)": T.format("import json; m = json.dumps({'e': e}, default=str)"),
    "raise X(e)": T.format("raise RuntimeError(e)"),
    "raise X(*e.args)": T.format("raise RuntimeError(*e.args)"),
    "passed to a describe-unaware helper": T.format("alarm(e)"),
    "walrus": "if (e := get_err()):\n    m = str(e)\n",
    "except* group": "try:\n    x()\nexcept* ValueError as eg:\n    m = str(eg)\n",
    "dataclass field": T.format("m = Rec(error=e)"),
    "warnings.warn(e)": T.format("import warnings; warnings.warn(e)"),
    "sys.exit(e)": T.format("import sys; sys.exit(e)"),
    "SystemExit(e)": T.format("raise SystemExit(e)"),
    "e.add_note then raise": T.format("e.add_note('x'); raise"),
    "nested def closure": T.format("def g():\n        return str(e)"),
    "lambda": T.format("f = lambda: str(e)"),
    "typed parameter": "def alarm(exc: BaseException):\n    return f'failed: {exc}'\n",
    "typed union parameter": "def alarm(exc: 'psycopg.Error | None'):\n    return str(exc)\n",
    "stored in a list": T.format("errors.append(e)"),
    "stored in a tuple": T.format("out = (1, e)"),
    "returned": "def f():\n    try:\n        x()\n    except ValueError as e:\n        return e\n",
    "attribute store": T.format("self.last = e"),
    "alias used after its handler": "def f():\n    try:\n        x()\n    except ValueError as e:\n        saved = e\n"
                                    "    return str(saved)\n",
    "alias of an alias after the handler": "try:\n    x()\nexcept ValueError as e:\n    saved = e\nlater = saved\nm = repr(later)\n",
    "text_has with a computed marker": T.format("ok = text_has(e, str(org))"),
    "text_has with a name as marker": T.format("ok = text_has(e, marker)"),
}


@pytest.mark.parametrize("name", sorted(PLANTED))
def test_the_scan_refuses_each_planted_form(name):
    assert problems_in(PLANTED[name], "consentvault/x.py", helpers=set()), name


def test_the_scan_accepts_the_sanctioned_uses():
    ok = ("from .safelog import describe, caller_detail, sqlstate\n"
          "_log = safelog.get('x')\n"
          "def helper(exc: BaseException) -> str:\n    return describe(exc)\n"
          "try:\n    x()\nexcept ValueError as e:\n"
          "    a = describe(e)\n    b = caller_detail(e)\n    c = type(e).__name__\n    d = sqlstate(e)\n    s = e.sqlstate\n"
          "    if isinstance(e, KeyError) or e is None or not e:\n        raise\n    err = e\n    helper(err)\n"
          "    cause = e.__cause__\n    k = describe(cause)\n    _log.error('x', exc_info=True)\n    raise Other('x') from e\n")
    assert problems_in(ok, "consentvault/x.py") == []


def test_the_reviewers_planted_forms_are_all_here():
    """The 45 forms the review planted, plus this file's own: none may be dropped from the list."""
    review = {"print(e)", "print(e, file=stderr)", "alias err=e; str(err)", "str(e.__cause__)", "f'{e.__context__}'", "e.strerror",
              "e.reason", "e.msg", "e.detail", "e.stderr (CalledProcessError)", "e.output", "e.response.text", "e.errors()",
              "e.__dict__", "vars(e)", "e.__str__()", "logger arg %s e", "logger extra=e", "join of map str", "sys.exc_info()[1]",
              "sys.exception()", "future.exception()", "comprehension over group", "for x in e.exceptions",
              "from traceback import format_exc", "import traceback as tb", "TracebackException", "exc_info=True to logging",
              "logging.exception", "str.__mod__", "format_map", "Template", "json.dumps(e, default=str)", "raise X(e)",
              "raise X(*e.args)", "passed to a describe-unaware helper", "walrus", "except* group", "dataclass field",
              "warnings.warn(e)", "sys.exit(e)", "SystemExit(e)", "e.add_note then raise", "nested def closure", "lambda"}
    assert len(review) == 45 and review <= set(PLANTED)


@pytest.mark.parametrize("line", [26, 57])
def test_putting_a_seal_print_back_to_raw_text_fails_the_scan(line):
    """cmd_seal prints a failed run's error on stderr; reverting either print to the exception's text is caught."""
    lines = (SRC / "consentvault" / "cmd_seal.py").read_text().split("\n")
    printed = [i for i, ln in enumerate(lines) if "describe(exc)" in ln and "print(" in ln]
    assert printed, "cmd_seal no longer prints through describe"
    i = min(printed, key=lambda k: abs(k + 1 - line))
    lines[i] = lines[i].replace("describe(exc)", "exc")
    assert problems_in("\n".join(lines), "consentvault/cmd_seal.py")


def test_an_exception_is_carried_to_another_thread_only_where_it_is_marked_and_re_raised():
    """The one exemption: storing an exception unchanged for the calling thread to re-raise. Each is marked and counted."""
    marked = [(p, i + 1) for p in SRC.rglob("*.py") for i, ln in enumerate(p.read_text().split("\n")) if CARRY_MARK in ln]
    assert [(str(p.relative_to(SRC)), n) for p, n in marked] == [("consentvault/urlguard.py", marked[0][1])] if marked else True
    assert problems_in(T.format("box['err'] = e"), "consentvault/x.py", helpers=set())  # unmarked, it still fails
