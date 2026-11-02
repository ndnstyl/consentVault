"""Every logging call site in src/ takes a constant message and registered named fields (consentvault/safelog.py).

Scans the source, not the running code, so a call on a path no test reaches is still checked. Fails on: an f-string, a ``%``
or ``format`` interpolation, a placeholder or ``%`` inside the constant, a positional argument after the message, an unregistered
field, and a logger made with ``logging.getLogger`` outside the two modules that build logging itself."""

import ast
import pathlib

import pytest

from consentvault import safelog

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
LEVELS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "fatal"}
LOGGING_INFRA = {"consentvault/safelog.py", "consentvault/tenancy/logscrub.py"}


def _is_log_receiver(node: ast.AST) -> bool:
    name = ast.unparse(node).split(".")[-1].lower()
    return "log" in name


def problems_in(source: str, where: str) -> list[str]:
    found = []
    if where in LOGGING_INFRA:
        return found  # the two modules that build logging call the standard library on purpose
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            fn = ast.unparse(node.func)
            if node.func.attr == "getLogger":
                found.append(f"{where}:{node.lineno}: logging.getLogger outside the logging modules; use safelog.get")
                continue
            if node.func.attr not in LEVELS or not _is_log_receiver(node.func.value):
                continue
            at = f"{where}:{node.lineno}: {fn}"
            if not node.args:
                found.append(f"{at}: no message")
                continue
            msg = node.args[0]
            if isinstance(msg, ast.JoinedStr):
                found.append(f"{at}: an f-string message")
            elif isinstance(msg, ast.BinOp):
                found.append(f"{at}: a % or + built message")
            elif isinstance(msg, ast.Call):
                found.append(f"{at}: a message built by a call (format)")
            elif not (isinstance(msg, ast.Constant) and isinstance(msg.value, str)):
                found.append(f"{at}: the message is not a constant string")
            elif "%" in msg.value or "{" in msg.value or "}" in msg.value:
                found.append(f"{at}: a placeholder or % in the message")
            if len(node.args) > 1:
                found.append(f"{at}: positional arguments after the message")
            for kw in node.keywords:
                if kw.arg is None:
                    found.append(f"{at}: ** fields cannot be checked")
                elif kw.arg not in safelog.FIELDS and kw.arg not in safelog.CONTROL_KEYWORDS:
                    found.append(f"{at}: field {kw.arg!r} is not registered")
    return found


def test_every_log_call_site_in_src_takes_a_constant_message_and_registered_fields():
    found = []
    for path in sorted(SRC.rglob("*.py")):
        found += problems_in(path.read_text(), str(path.relative_to(SRC)))
    assert found == [], "\n".join(found)


def test_the_scan_finds_call_sites_at_all():
    sites = sum(1 for p in SRC.rglob("*.py") for n in ast.walk(ast.parse(p.read_text()))
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in LEVELS
                and _is_log_receiver(n.func.value))
    assert sites >= 25


@pytest.mark.parametrize("bad", [
    'log.error(f"sent to {to}")',
    'log.error("sent to %s" % to)',
    'log.error("sent to {}".format(to))',
    'log.error("sent to %s", to)',
    'log.error("sent to " + to)',
    'log.error("sent", phone=to)',
    'log.error("sent", **fields)',
    'log.error(msg)',
    '_log = logging.getLogger(__name__)',
    'self._log.warning("x {to}")',
])
def test_the_scan_refuses_each_unsafe_shape(bad):
    assert problems_in(bad, "consentvault/x.py")


def test_the_scan_accepts_the_safe_shape():
    assert problems_in('log.error("a send failed", send_id=sid, error=type(exc).__name__, exc_info=True)', "consentvault/x.py") == []


def test_a_field_value_that_is_not_its_kind_is_written_as_a_keyed_hash():
    line = safelog.render("x", {"send_id": "+18135550199", "error": "john@example.com", "count": True, "org_id": "not-a-uuid",
                                "request_id": "req-1a2b", "path": "/c/stop/abc", "reason": "bad_timestamp"})
    assert "8135550199" not in line and "john" not in line and "/c/stop" not in line and "not-a-uuid" not in line
    assert "request_id=req-1a2b" in line and "reason=bad_timestamp" in line and "count=<bool:" in line


def test_an_unregistered_field_is_refused_at_run_time():
    with pytest.raises(ValueError):
        safelog.render("x", {"phone": "+18135550199"})
