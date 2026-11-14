"""Allowlist logging: the control that keeps personal data out of log lines. The text scrubber (tenancy/logscrub.py) is the backstop.

A log call takes a constant message and named fields, never an interpolated string:

    log.error("a public confirmation page could not be answered", error=type(exc).__name__)

Every field name is registered in ``FIELDS`` with a kind. A value of a safe kind (an id, a count, a code, a duration, the org id, a
timestamp) is written as it is, after a check that it really has that shape. Anything else (a field registered as ``hashed``, or a
value that fails its kind's check) is written as its type and a short keyed hash, so two lines about the same value can be matched
without the value ever being written. ``tests/test_log_call_sites.py`` scans every call site in src/ and fails on an f-string, a
``%`` or ``format`` interpolation, or an unregistered field.

The hash key comes from ``CONSENTVAULT_LOG_FIELD_KEY`` (hex) when set, so hashes match across processes; otherwise each process
draws its own, and hashes match within that process only.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import sys
import threading
import uuid
from datetime import date, datetime, timedelta
from typing import Any

ID, COUNT, CODE, DURATION, ORG_ID, TIMESTAMP, HASHED = "id", "count", "code", "duration", "org_id", "timestamp", "hashed"
ERROR, REASON, TRACE, DETAIL = "error", "reason", "trace", "detail"

FIELDS: dict[str, str] = {
    # ids
    "request_id": ID, "event_id": ID, "send_id": ID, "outbox_id": ID, "export_id": ID, "subscription_id": ID,
    "held_subscription_id": ID, "system_id": ID,
    # the organization
    "org_id": ORG_ID,
    # counts
    "count": COUNT, "attempt": COUNT, "cleared": COUNT,
    # codes: error classes, reasons, statuses, alarm kinds, provider codes
    "error": ERROR, "error_code": CODE, "reason": REASON, "status": CODE, "alarm": CODE, "provider_code": CODE, "error_class": ERROR,
    # where an exception was raised: file, line and function of each frame, never a message or a local
    "trace": TRACE,
    # an alarm's detail, written by the product from ids, days and an error's description; hashed unless it has that shape
    "detail": DETAIL,
    # durations and times
    "elapsed_s": DURATION, "oldest": TIMESTAMP,
    # free values that may be useful to match but never to read
    "path": HASHED, "store_key": HASHED, "system_name": HASHED,
}
CONTROL_KEYWORDS = frozenset({"exc_info", "stack_info"})

# The only reasons a log line may carry. A value off this list is hashed like any other free text.
REASONS = frozenset({"unsigned", "bad_signature", "bad_timestamp", "stale_timestamp", "replay"})
REASON_PREFIXES = ("replay_guard_unavailable:",)  # followed by an exception class name

_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_CODE = re.compile(r"[A-Za-z0-9_.:-]{1,80}")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONG_DIGITS = re.compile(r"\d{7}")
_TRACE = re.compile(r"[A-Za-z0-9_.<>:-]{1,4000}")
_KEY = bytes.fromhex(os.environ["CONSENTVAULT_LOG_FIELD_KEY"]) if os.environ.get("CONSENTVAULT_LOG_FIELD_KEY") else os.urandom(32)


def hashed(value: Any) -> str:
    digest = hmac.new(_KEY, repr(value).encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]
    return f"<{type(value).__name__}:{digest}>"


def _is_uuid(value: Any) -> bool:
    return isinstance(value, uuid.UUID) or (isinstance(value, str) and _UUID.fullmatch(value) is not None)


def exception_classes() -> frozenset[str]:
    """The names of the exception classes loaded in this process: the fixed list an ``error`` field is checked against."""
    seen, todo = set(), [BaseException]
    while todo:
        cls = todo.pop()
        if cls.__name__ not in seen:
            seen.add(cls.__name__)
            todo.extend(cls.__subclasses__())
    return frozenset(seen)


_CLASSES: dict[str, frozenset[str]] = {}


def _is_exception_class(value: Any) -> bool:
    if not isinstance(value, str) or not value.isidentifier():
        return False
    if value not in _CLASSES.get("names", frozenset()):
        _CLASSES["names"] = exception_classes()  # a class imported since the last look is picked up
    return value in _CLASSES["names"]


def _safe(kind: str, value: Any) -> bool:
    if kind == ERROR:
        return _is_exception_class(value)
    if kind == REASON:
        if value in REASONS:
            return True
        return isinstance(value, str) and any(value.startswith(p) and _is_exception_class(value[len(p):]) for p in REASON_PREFIXES)
    if kind == DETAIL:
        from .tenancy.logscrub import scrub
        return isinstance(value, str) and len(value) <= 500 and "@" not in value and scrub(value) == value
    if kind == TRACE:
        return isinstance(value, str) and _TRACE.fullmatch(value) is not None and _LONG_DIGITS.search(value) is None
    if kind == ORG_ID:
        return _is_uuid(value)
    if kind == ID:
        if _is_uuid(value):
            return True
        if isinstance(value, int) and not isinstance(value, bool):
            return 0 <= value < 10 ** 9
        return isinstance(value, str) and _TOKEN.fullmatch(value) is not None and _LONG_DIGITS.search(value) is None
    if kind == COUNT:
        return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10 ** 9
    if kind == CODE:
        return isinstance(value, str) and _CODE.fullmatch(value) is not None and _LONG_DIGITS.search(value) is None
    if kind == DURATION:
        return isinstance(value, (int, float, timedelta)) and not isinstance(value, bool)
    if kind == TIMESTAMP:
        return isinstance(value, (datetime, date))
    return False


def render(message: str, fields: dict[str, Any]) -> str:
    parts = []
    for name, value in fields.items():
        kind = FIELDS.get(name)
        if kind is None:
            raise ValueError(f"log field {name!r} is not registered in consentvault.safelog.FIELDS")
        if value is None:
            shown = "-"
        elif _safe(kind, value):
            shown = value.isoformat() if isinstance(value, (datetime, date)) else str(value)
        else:
            shown = hashed(value)
        parts.append(f"{name}={shown}")
    return message + (" | " + " ".join(parts) if parts else "")


class SafeLogger:
    """A logger whose calls take a constant message and registered named fields."""

    def __init__(self, name: str) -> None:
        self.logger = logging.getLogger(name)
        self.name = name

    def _emit(self, level: int, message: str, exc_info: Any = False, stack_info: bool = False, **fields: Any) -> None:
        if not isinstance(message, str):
            raise TypeError("a log message is a constant string")
        if not self.logger.isEnabledFor(level):
            return
        if exc_info:
            # an exception is written as its class and the frames it passed through: never its message, never a local
            exc = exc_info if isinstance(exc_info, BaseException) else (sys.exc_info()[1] if exc_info is True else exc_info[1])
            if exc is not None:
                fields.setdefault("error", type(exc).__name__)
                fields.setdefault("trace", frames(exc.__traceback__))
        # the rendered line is passed as an argument, never as the format, so nothing in it is interpolated
        from .tenancy.logscrub import SafeLine
        self.logger.log(level, SafeLine(render(message, fields)), stack_info=stack_info, stacklevel=3)

    def debug(self, message: str, /, **fields: Any) -> None:
        self._emit(logging.DEBUG, message, **fields)

    def info(self, message: str, /, **fields: Any) -> None:
        self._emit(logging.INFO, message, **fields)

    def warning(self, message: str, /, **fields: Any) -> None:
        self._emit(logging.WARNING, message, **fields)

    def error(self, message: str, /, **fields: Any) -> None:
        self._emit(logging.ERROR, message, **fields)

    def critical(self, message: str, /, **fields: Any) -> None:
        self._emit(logging.CRITICAL, message, **fields)


def get(name: str) -> SafeLogger:
    return SafeLogger(name)


# ---- exceptions and the process ------------------------------------------------------------------------------------------------
def frames(tb, functions: bool = True) -> str:
    """Where an exception went: ``file:line:function`` (or ``file:line``) for each frame, joined by ``>``. No source line, message or
    local."""
    out = []
    while tb is not None:
        code = tb.tb_frame.f_code
        out.append(f"{os.path.basename(code.co_filename)}:{tb.tb_lineno}" + (f":{code.co_name}" if functions else ""))
        tb = tb.tb_next
    return ">".join(out)[-4000:]


_LETTERS = str.maketrans("0123456789abcdef", "ghjkmnpqrstvwxyz")


def error_code(exc: BaseException) -> str:
    """A stable code for where an error was raised: a short hash of its class, the module and function that raised it, and the classes
    of the errors it was raised from. The same
    failure gives the same code on every run and after unrelated edits move its line; it carries no value from the error."""
    tb, site = exc.__traceback__, "unraised"
    while tb is not None:
        code = tb.tb_frame.f_code
        site = f"{tb.tb_frame.f_globals.get('__name__', '?')}.{code.co_qualname}"
        tb = tb.tb_next
    causes, cause = [], exc.__cause__
    while cause is not None and len(causes) < 3:  # one raise site that wraps different causes gives each its own code
        causes.append(type(cause).__qualname__)
        cause = cause.__cause__
    digest = hashlib.sha256(f"{type(exc).__qualname__}@{site}<{'<'.join(causes)}".encode()).hexdigest()[:10]
    return "cv-" + digest.translate(_LETTERS)  # letters only, so a code never reads as part of a number


def sqlstate(exc: BaseException) -> str | None:
    """A database error's SQLSTATE (five characters, a code, never text), or None."""
    state = getattr(exc, "sqlstate", None)
    return state if isinstance(state, str) and re.fullmatch(r"[0-9A-Z]{5}", state) else None


def constraint_name(exc: BaseException) -> str | None:
    """The name of the constraint a database error broke (a schema name, never a value), or None."""
    name = getattr(getattr(exc, "diag", None), "constraint_name", None)
    return name if isinstance(name, str) and re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name) else None


_REFUSAL_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def db_refusal_id(exc: BaseException, prefix: str) -> str | None:
    """The id a database refusal names after a fixed prefix (``legal_hold_active:<uuid>``), or None. Only a UUID is ever returned,
    never the message around it."""
    for text in (getattr(getattr(exc, "diag", None), "message_primary", None), str(exc)):
        if isinstance(text, str):
            at = text.find(prefix + ":")
            m = _REFUSAL_ID.match(text, at + len(prefix) + 1) if at != -1 else None
            if m:
                return m.group(0)
    return None


def text_has(exc: BaseException, *markers: str) -> bool:
    """Whether an error's text (its message, or a database error's primary message) contains any of these fixed markers, ignoring
    case. For code that must branch on what a library or the database said; it answers yes or no and never returns the text."""
    texts = [str(exc), getattr(getattr(exc, "diag", None), "message_primary", None) or ""]
    low = " ".join(texts).lower()
    return any(m.lower() in low for m in markers)


_DB_REFUSALS: dict[str, list[tuple[str, int, re.Pattern[str], str]]] = {}
_CONTEXT_FUNCTION = re.compile(r"PL/pgSQL function ([\w.]+)\(([^)]*)\) line (\d+)")
_CONTEXT_INLINE = re.compile(r"PL/pgSQL function inline_code_block line (\d+)")


def _db_refusals() -> dict[str, list[tuple[str, re.Pattern[str], str]]]:
    """The database refusal registry (data/refusal_codes.json): by bare function name, (signature, sentence pattern, code). A missing
    registry is an error, never a quiet fallback: without it no database refusal could be told from another."""
    if not _DB_REFUSALS:
        import json
        path = os.path.join(os.path.dirname(__file__), "data", "refusal_codes.json")
        with open(path, encoding="utf-8") as fh:
            sites = json.load(fh)["sites"]
        for site in sites:
            pieces = [re.escape(part).replace("%", ".*?") for part in site["template"].replace("%%", "\x00").split("\x00")]
            pattern = re.compile("%".join(pieces), re.S)
            _DB_REFUSALS.setdefault(site["function"].split(".")[-1], []).append((site["signature"], int(site["line"]), pattern,
                                                                                 site["code"]))
    return _DB_REFUSALS


def db_code(function: str, sentence: str) -> str:
    """The registered code of one database refusal site, by its function and exact sentence. Exactly one site must match: code that
    names a refusal by its code must name one that exists, and only one."""
    import json
    path = os.path.join(os.path.dirname(__file__), "data", "refusal_codes.json")
    with open(path, encoding="utf-8") as fh:
        found = [site["code"] for site in json.load(fh)["sites"]
                 if site["function"].split(".")[-1] == function and site["template"] == sentence]
    if len(found) != 1:
        raise LookupError(f"{len(found)} database refusal sites {function}: {sentence!r} in the registry; name exactly one")
    return found[0]


def _norm_types(args: str) -> str:
    return ",".join(re.sub(r"\s+", " ", a.strip().lower()) for a in args.split(",") if a.strip())


def refusal_code(exc: BaseException) -> str | None:
    """The registered code of a refusal raised by one of our own database functions, matched by the raising function, its argument
    types (overloads are told apart), the line of the RAISE in its body (two sentences of one function are never confused), and the
    sentence. Reads the database's own message to match it and
    returns only the code."""
    diag = getattr(exc, "diag", None)
    context, message = getattr(diag, "context", None), getattr(diag, "message_primary", None)
    if not isinstance(message, str) or not isinstance(context, str):
        return None
    inline = _CONTEXT_INLINE.search(context)
    if inline:
        function, signature, line = "inline_code_block", "", int(inline.group(1))
    else:
        m = _CONTEXT_FUNCTION.search(context)
        if m is None:
            return None
        function, signature, line = m.group(1).split(".")[-1], _norm_types(m.group(2)), int(m.group(3))
    for site_signature, site_line, pattern, code in _db_refusals().get(function, []):
        if site_signature == signature and site_line == line and pattern.fullmatch(message):
            return code
    return None


def _one(exc: BaseException) -> str:
    state = sqlstate(exc)
    if state:
        code = refusal_code(exc)
        return f"{type(exc).__name__} (sqlstate {state}" + (f", code {code})" if code else ")")
    raised = getattr(exc, "code", None)  # a stable code the raiser chose (ConsentVaultError(code=...)), shown in place of the hash
    if isinstance(raised, str) and re.fullmatch(r"[a-z][a-z0-9_]{1,63}", raised):
        return f"{type(exc).__name__} (code {raised})"
    return f"{type(exc).__name__} (code {error_code(exc)})"


def describe(exc: BaseException) -> str:
    """An error for a log, an operator's terminal or an alarm: its class and its SQLSTATE (with our database refusal code when one of
    our functions raised it) or a stable code, then the same for the errors it was raised from. Never a message: a name in a message
    cannot be detected, so no error text reaches a log, a terminal or an alarm."""
    out, cause, depth = [_one(exc)], exc.__cause__, 0
    while cause is not None and depth < 3:
        out.append(_one(cause))
        cause, depth = cause.__cause__, depth + 1
    return out[0] if len(out) == 1 else out[0] + " from " + " from ".join(out[1:])


def http_error_response(exc: BaseException, limit: int | None = None) -> tuple[int, dict, bytes]:
    """An HTTP error answer (urllib's HTTPError is also the response): its status, its headers (lower-cased names) and its body,
    read as response data for the code that parses it. Never written to a log, a terminal or an alarm."""
    headers = getattr(exc, "headers", None) or getattr(exc, "hdrs", None) or {}
    body = exc.read(limit) if limit is not None else exc.read()
    return int(exc.code), {k.lower(): v for k, v in headers.items()}, body


def bounded_http_error(exc: BaseException, limit: int) -> BaseException:
    """The same HTTP error answer with its body read once and capped at ``limit`` bytes, to hand to another thread."""
    import io
    import urllib.error
    try:
        body = exc.read(limit)
    except Exception:  # loud-failure-exempt: an unreadable error body is carried as empty; the status code is the answer
        body = b""
    return urllib.error.HTTPError(exc.url, exc.code, exc.msg, exc.hdrs, io.BytesIO(body))


def smtp_reply_code(exc: BaseException) -> int | None:
    """The SMTP reply code of a refusal, without its text or the refused addresses (which a recipients map holds)."""
    code = getattr(exc, "smtp_code", None)
    if isinstance(code, int):
        return code
    recipients = getattr(exc, "recipients", None)
    if isinstance(recipients, dict):
        codes = [v[0] for v in recipients.values() if isinstance(v, tuple) and v and isinstance(v[0], int)]
        return codes[0] if codes else None
    return None


def caller_detail(exc: BaseException) -> str:
    """The readable detail of an error, for the API response to the authenticated caller who made the request, and nowhere else (never
    a log, a terminal or an alarm). A product error's own message, which the product writes; any other error (a library's or the
    database's, whose text can quote a stored value) is its description only."""
    from .errors import ConsentVaultError
    from .tenancy.admin_base import ApiError
    if isinstance(exc, ApiError):
        return exc.detail  # the contract's own detail for the caller
    if isinstance(exc, ConsentVaultError):
        return str(exc)  # a product message never embeds another error's text (tests/test_exception_text.py refuses it)
    return describe(exc)


_process = get("consentvault.process")
_SETUP = {"done": False}


def _last_word(what: str, exc_type, tb) -> None:
    """A hook's own fallback when logging itself fails: one class-only line on stderr. A hook never raises, because Python would then
    print the original exception in full."""
    try:
        sys.stderr.write(f"{what} ({getattr(exc_type, '__name__', 'error')} at {frames(tb)})\n")
    except (OSError, ValueError):  # loud-failure-exempt: stderr itself is gone; there is no surface left to report on
        return


def _excepthook(exc_type, exc, tb) -> None:
    try:
        _process.critical("an uncaught exception ended the process", error=exc_type.__name__, error_code=error_code(exc),
                          trace=frames(tb))
    except Exception:  # loud-failure-exempt: reported class-only on stderr by _last_word
        _last_word("an uncaught exception ended the process", exc_type, tb)


def _thread_excepthook(args) -> None:
    if args.exc_type is SystemExit:
        return
    try:
        _process.critical("an uncaught exception ended a thread", error=args.exc_type.__name__, trace=frames(args.exc_traceback))
    except Exception:  # loud-failure-exempt: reported class-only on stderr by _last_word
        _last_word("an uncaught exception ended a thread", args.exc_type, args.exc_traceback)


def _unraisablehook(args) -> None:
    """An error Python cannot raise (in __del__, an atexit callback, a _thread function, a finaliser): its class and the file and line
    of each frame. Never its message, and never the object it came from (whose repr can carry a value)."""
    try:
        _process.critical("an exception could not be raised and was dropped", error=args.exc_type.__name__,
                          trace=frames(args.exc_traceback, functions=False))
    except Exception:  # loud-failure-exempt: reported class-only on stderr by _last_word
        _last_word("an exception could not be raised and was dropped", args.exc_type, args.exc_traceback)


def _handle_error(self, record) -> None:
    """A handler that failed to write a record: its class and frames on stderr, so the failure is seen, never the exception text or
    the record (Handler.handleError would print both)."""
    exc_type, _exc, tb = sys.exc_info()
    try:
        sys.stderr.write(f"logging: a handler failed to write a record ({getattr(exc_type, '__name__', 'error')} at {frames(tb)})\n")
    except (OSError, ValueError):  # loud-failure-exempt: stderr itself is gone; there is no surface left to report on
        return


def setup_process() -> None:
    """Every entry point calls this first. Every log record is scrubbed as it is made (a record factory), so every handler, including
    one added later, sees only the scrubbed record; the root handlers also carry the scrub filter (one on stderr when none is
    configured, so Python's last-resort handler, which has no filters, is never used); every handler scrubs again as it emits; a handler
    that fails prints its class and frames only; warnings go to logging; an uncaught exception in the process or a thread, and an
    exception Python cannot raise (__del__, atexit), is logged as its class and frames. Idempotent."""
    from .tenancy import logscrub
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        root.addHandler(handler)
    logscrub.install(root)
    current = logging.getLogRecordFactory()
    if not getattr(current, "consentvault_scrubs", False):
        scrub_filter = logscrub.ScrubFilter()

        def factory(*args, **kwargs):
            record = current(*args, **kwargs)
            scrub_filter.filter(record)  # scrubbed as it is made, so a handler added later sees only the scrubbed record
            return record
        factory.consentvault_scrubs = True
        logging.setLogRecordFactory(factory)
    if not getattr(logging.Handler.handle, "consentvault_scrubs", False):
        emit_filter, plain_handle = logscrub.ScrubFilter(), logging.Handler.handle

        def handle(self, record):
            emit_filter.filter(record)  # at emit time, on every handler, whenever it was added: never a flag set earlier
            try:
                return plain_handle(self, record)
            except Exception:  # loud-failure-exempt: a handler whose emit raised is reported by handleError (class and frames)
                self.handleError(record)
                return False
        handle.consentvault_scrubs = True
        handle.consentvault_plain = plain_handle
        logging.Handler.handle = handle
    logging.raiseExceptions = False
    logging.Handler.handleError = _handle_error
    logging.captureWarnings(True)
    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
    sys.unraisablehook = _unraisablehook
    _SETUP["done"] = True


__all__ = ["FIELDS", "SafeLogger", "describe", "frames", "get", "hashed", "render", "setup_process"]
