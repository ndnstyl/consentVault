"""An operator's terminal names a failure by its error class and a stable code, never its text (safelog.describe)."""

import re


def named(error_class: str, err: str) -> bool:
    return re.search(rf"\b{re.escape(error_class)} \((code (cv-[g-z]{{10}}|[a-z][a-z0-9_]{{1,40}})|sqlstate [0-9A-Z]{{5}})\)", err) is not None


def named_any(err: str) -> bool:
    return re.search(r"\b[A-Z][A-Za-z0-9_]* \((code (cv-[g-z]{10}|[a-z][a-z0-9_]{1,40})|sqlstate [0-9A-Z]{5})\)", err) is not None


def code_of(err: str) -> str:
    m = re.search(r"\(code (cv-[g-z]{10}|[a-z][a-z0-9_]{1,40})\)", err)
    assert m, err
    return m.group(1)


def db_codes(function: str, fragment: str) -> str:
    """A regex matching the registered code(s) of our database refusal(s) raised by ``function`` whose sentence contains ``fragment``
    (data/refusal_codes.json): a test names the exact check that fired, by its code, never by the database's text."""
    import json
    import pathlib
    registry = pathlib.Path(__file__).resolve().parents[1] / "src" / "consentvault" / "data" / "refusal_codes.json"
    codes = [s["code"] for s in json.loads(registry.read_text())["sites"]
             if s["function"].split(".")[-1] == function and fragment in s["template"]]
    assert codes, f"no registered refusal of {function} says {fragment!r}"
    return "(" + "|".join(re.escape(c) for c in codes) + ")"
