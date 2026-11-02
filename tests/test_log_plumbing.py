"""End to end: an exception carrying a phone number, an email address and a name, raised in each entry point and in a thread, leaves
none of them on stdout, stderr or any log handler. Each case runs in a fresh Python process, so the real exception hooks, the real
stderr and the real handlers are what is checked.

Entry points: the CLI (``consentvault ...``), ``serve`` and ``serve-cloud`` (through the CLI and through the server's error printer),
the jobs runner (``python -m consentvault.jobs``), the sync worker (``python -m consentvault.sync``), a thread, a library logger
logging with exc_info, a captured warning, and a handler added after start-up."""

import ast
import os
import re
import pathlib
import subprocess
import sys
import textwrap

import pytest

from consentvault import safelog

ROOT = pathlib.Path(__file__).resolve().parents[1]
PHONE, EMAIL, NAME = "+18135550199", "dana.whitfield@example.com", "Dana Whitfield"
SECRETS = ("8135550199", "813-555-0199", "dana.whitfield", "example.com", "Dana", "Whitfield")
PII = f"call {PHONE} or {EMAIL}, ask for {NAME}"

PRELUDE = f"""
import logging, sys, threading, warnings
PII = {PII!r}
class Boom(RuntimeError):
    pass
def boom(*a, **k):
    raise Boom(PII)
collected = []
class Keep(logging.Handler):
    # a handler that keeps everything a record carries: its formatted line and every attribute, extras included
    def emit(self, record):
        collected.append(self.format(record) + " " + repr(sorted(record.__dict__.items())))
import atexit
atexit.register(lambda: print("HANDLER:" + " || ".join(collected), file=sys.stderr))
"""


def _run(body: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    env.pop("CONSENTVAULT_LOG_FIELD_KEY", None)
    argv = [sys.executable, "-c", PRELUDE + textwrap.dedent(body)]
    return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60, cwd=ROOT)  # loud-failure-exempt: most cases end on an uncaught exception by design; every caller asserts on the output


def _clean(proc: subprocess.CompletedProcess, *, must_name: str) -> None:
    both = proc.stdout + proc.stderr
    for secret in SECRETS:
        assert secret not in both, (secret, both[-2000:])
    assert must_name in both, both[-2000:]  # the failure is still loud: its class is named


CASES = {
    "cli": """
        import consentvault.cli as cli, consentvault.config as cfg
        cfg.load_config = boom
        logging.getLogger().addHandler(Keep())
        cli.main(["proof", "x"])
    """,
    "serve": """
        import consentvault.cli as cli, consentvault.config as cfg
        cfg.load_config = boom
        cli.main(["serve"])
    """,
    "serve-cloud": """
        import consentvault.cli as cli, consentvault.config as cfg
        cfg.load_config = boom
        cli.main(["serve-cloud"])
    """,
    "jobs runner": """
        import consentvault.jobs as jobs, consentvault.config as cfg
        cfg.load_config = boom
        jobs.main(["seal"])
    """,
    "sync worker": """
        import runpy, consentvault.config as cfg
        cfg.load_config = boom
        sys.argv = ["consentvault.sync"]
        runpy.run_module("consentvault.sync", run_name="__main__")
    """,
    "thread": """
        from consentvault import safelog
        safelog.setup_process()
        t = threading.Thread(target=boom); t.start(); t.join()
        print("thread done", file=sys.stderr)
    """,
    "library logger with exc_info": """
        from consentvault import safelog
        safelog.setup_process()
        try:
            boom()
        except Boom:
            logging.getLogger("psycopg.pool").exception("a connection failed for " + PII)
            safelog.get("consentvault.test").error("a step failed", exc_info=True)
    """,
    "handler added after start-up": """
        from consentvault import safelog
        safelog.setup_process()
        logging.getLogger().handlers.insert(0, Keep())  # first in line, without the scrub filter the root handlers carry
        logging.getLogger("some.library").error("lookup failed: " + PII)
        try:
            boom()
        except Boom:
            logging.getLogger("other.library").error("failed", exc_info=True)
    """,
    "inside __del__": """
        from consentvault import safelog
        safelog.setup_process()
        class Holder:
            def __del__(self):
                raise Boom(PII)
        h = Holder()
        del h
    """,
    "inside an atexit callback": """
        import atexit
        from consentvault import safelog
        safelog.setup_process()
        atexit.register(boom)
    """,
    "extra fields": """
        from consentvault import safelog
        safelog.setup_process()
        logging.getLogger().handlers.insert(0, Keep())
        logging.getLogger("lib").error("Boom: hello", extra={"contact": PII, "who": PII})
    """,
    "logger adapter": """
        from consentvault import safelog
        safelog.setup_process()
        logging.getLogger().handlers.insert(0, Keep())
        logging.LoggerAdapter(logging.getLogger("lib"), {"contact": PII}).error("Boom: hello")
    """,
    "makeLogRecord": """
        from consentvault import safelog
        safelog.setup_process()
        logging.getLogger().handlers.insert(0, Keep())
        logging.getLogger("lib").handle(logging.makeLogRecord({"name": "lib", "msg": PII, "levelno": 40, "levelname": "ERROR",
                                                                "contact": PII, "exc_text": PII, "Boom": 1}))
    """,
    "a failing handler": """
        from consentvault import safelog
        safelog.setup_process()
        class Broken(logging.Handler):
            def emit(self, record):
                raise Boom(PII)
        logging.getLogger().addHandler(Broken())
        logging.getLogger("lib").error("hello")
    """,
    "warning": """
        from consentvault import safelog
        safelog.setup_process()
        warnings.warn(PII, UserWarning)
    """,
    "server error printer": """
        import socket
        from http.server import BaseHTTPRequestHandler
        from consentvault import safelog
        from consentvault.api import SafeHTTPServer
        safelog.setup_process()
        class Bad(BaseHTTPRequestHandler):
            def handle(self):
                boom()
        srv = SafeHTTPServer(("127.0.0.1", 0), Bad)
        t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
        with socket.create_connection(srv.server_address, timeout=5) as c:
            c.sendall(b"GET /?to=%2B18135550199 HTTP/1.0\\r\\n\\r\\n")
            c.recv(10)
        srv.shutdown(); srv.server_close()
    """,
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_an_exception_carrying_a_phone_an_email_and_a_name_leaves_none_of_them_anywhere(name):
    proc = _run(CASES[name])
    marker = {"warning": "UserWarning", "extra fields": "('name', 'lib')", "logger adapter": "('name', 'lib')",
              "makeLogRecord": "('name', 'lib')"}.get(name, "Boom")
    _clean(proc, must_name=marker)


@pytest.mark.parametrize("entry", ["cli", "jobs runner", "logged"])
def test_a_product_error_carrying_a_name_leaves_only_its_class_and_code(entry):
    """No error text reaches a log or the terminal, a product error's included: a name in it cannot be detected. The class and a
    stable code are printed; the readable detail is for the authenticated caller in an API response only."""
    run = {"cli": "sys.exit(cli.main(['proof', 'x']))", "jobs runner": "sys.exit(jobs.main(['seal']))",
           "logged": "safelog.setup_process()\ntry:\n    refuse()\nexcept ConfigError:\n"
                     "    safelog.get('consentvault.test').error('a step failed', exc_info=True)"}[entry]
    proc = _run(textwrap.dedent("""
        import consentvault.cli as cli, consentvault.jobs as jobs, consentvault.config as cfg
        from consentvault import safelog
        from consentvault.errors import ConfigError
        logging.getLogger().addHandler(Keep())
        def refuse(*a, **k):
            raise ConfigError("CONSENTVAULT_X is missing for " + PII)
        cfg.load_config = refuse
    """) + run)
    _clean(proc, must_name="ConfigError")
    assert "CONSENTVAULT_X" not in proc.stdout + proc.stderr
    if entry != "logged":
        assert proc.returncode != 0 and re.search(r"ConfigError \(code cv-[g-z]{10}\)", proc.stderr), proc.stderr


def test_the_error_code_is_stable_and_names_the_raise_site_not_the_message():
    from consentvault.errors import ConfigError

    def raise_it(text):
        raise ConfigError(text)
    codes = set()
    for text in ("Dana Whitfield", "someone else", PII):
        try:
            raise_it(text)
        except ConfigError as exc:
            codes.add(safelog.error_code(exc))
    assert len(codes) == 1 and re.fullmatch(r"cv-[g-z]{10}", codes.pop())


def test_both_servers_are_built_on_the_safe_server():
    tree = ast.parse((ROOT / "src" / "consentvault" / "api.py").read_text())
    built = [ast.unparse(n.value.func) for n in ast.walk(tree)
             if isinstance(n, ast.Return) and isinstance(n.value, ast.Call) and "Server" in ast.unparse(n.value.func)]
    assert built == ["SafeHTTPServer", "SafeHTTPServer"]


# ---- the reason and error fields take only a fixed list of codes ----------------------------------------------------------------
@pytest.mark.parametrize("field,value", [("error", "call Dana Whitfield"), ("error", "8135550199"), ("error", "NotARealExceptionClass"),
                                         ("reason", "contact dana.whitfield@example.com"), ("reason", "free text"),
                                         ("reason", "replay_guard_unavailable:Dana"), ("error_class", "Dana Whitfield")])
def test_free_text_in_a_reason_or_error_field_is_refused(field, value):
    line = safelog.render("x", {field: value})
    assert value not in line and f"{field}=<str:" in line


@pytest.mark.parametrize("field,value", [("error", "ValueError"), ("error", "TimeoutError"), ("reason", "bad_timestamp"),
                                         ("reason", "replay_guard_unavailable:TimeoutError")])
def test_a_listed_reason_or_a_real_exception_class_is_written(field, value):
    assert f"{field}={value}" in safelog.render("x", {field: value})


def test_an_exception_is_logged_as_its_class_and_frames_only():
    try:
        raise ValueError(PII)
    except ValueError as exc:
        line = safelog.render("x", {"error": type(exc).__name__, "trace": safelog.frames(exc.__traceback__)})
    assert "error=ValueError" in line and "trace=test_log_plumbing.py:" in line
    assert not any(s in line for s in SECRETS)


LAYERS = """
        logging.Handler.handle = getattr(logging.Handler.handle, "consentvault_plain", logging.Handler.handle)
        logging.setLogRecordFactory(logging.LogRecord)
"""


def test_setup_installs_every_layer_at_every_entry_point():
    """Removing any layer (the record factory, the emit-time scrub, a hook) fails here, whatever else still covers for it."""
    proc = _run("""
        from consentvault import safelog
        safelog.setup_process()
        checks = {
            "record factory": getattr(logging.getLogRecordFactory(), "consentvault_scrubs", False),
            "emit-time scrub": getattr(logging.Handler.handle, "consentvault_scrubs", False),
            "handler errors": logging.Handler.handleError is safelog._handle_error and logging.raiseExceptions is False,
            "excepthook": sys.excepthook is safelog._excepthook,
            "thread hook": threading.excepthook is safelog._thread_excepthook,
            "unraisable hook": sys.unraisablehook is safelog._unraisablehook,
            "warnings": logging.getLogger("py.warnings").propagate and warnings.showwarning is not warnings._showwarning_orig,
        }
        print("LAYERS", sorted(k for k, v in checks.items() if not v))
    """)
    assert "LAYERS []" in proc.stdout, proc.stdout + proc.stderr


@pytest.mark.parametrize("name", ["handler added after start-up", "extra fields", "logger adapter", "makeLogRecord"])
def test_the_late_handler_cases_do_see_a_leak_once_the_scrub_layers_are_removed(name):
    """The checks are live: the same case with the record factory and the emit-time scrub taken out leaks, and the test sees it."""
    body = textwrap.dedent(CASES[name])
    first, rest = body.split("safelog.setup_process()\n", 1)
    proc = _run(first + "safelog.setup_process()\n" + textwrap.dedent(LAYERS) + rest)
    with pytest.raises(AssertionError):
        _clean(proc, must_name="('name', 'lib')" if name != "handler added after start-up" else "Boom")


def test_a_duplicate_key_error_through_the_billing_alarm_leaves_no_email_or_phone():
    """The reviewer's path: a duplicate-key error (its text quotes the colliding email and phone) raised while counting usage goes
    through the default billing alarm and out of the process. Only the class and SQLSTATE are seen."""
    proc = _run("""
        from datetime import date
        import psycopg
        from consentvault import safelog
        from consentvault.billing import usage
        safelog.setup_process()
        class Worker:
            def execute(self, *a, **k):
                class R:
                    def fetchall(self):
                        return [{"org_id": "57116397-0e91-4287-aa19-c3b91592ca8d", "token": "t"}]

                    def fetchone(self):
                        from datetime import datetime, timezone
                        return {"t": datetime.now(timezone.utc)}
                return R()
        def collide(*a, **k):
            raise psycopg.errors.UniqueViolation('duplicate key value violates unique constraint "contact_email_key"'
                                                 ' DETAIL: Key (email, phone, name)=(dana.whitfield@example.com, +18135550199,'
                                                 ' Dana Whitfield) already exists.')
        usage._one_org = collide
        usage.run_daily_usage(Worker(), None, date(2026, 10, 30), gate_counter=lambda *a: 0)
    """)
    _clean(proc, must_name="UniqueViolation")
    both = proc.stdout + proc.stderr
    assert "alarm=usage_count_failed" in both and "sqlstate 23505" in both and "UsageReportError" in both
