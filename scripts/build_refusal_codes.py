#!/usr/bin/env python3
"""Build the registry of database refusal codes from the migrations, or check the committed one is current.

    scripts/build_refusal_codes.py           write src/consentvault/data/refusal_codes.json
    scripts/build_refusal_codes.py --check   exit 1, naming the difference, when the committed file is stale

Every ``RAISE EXCEPTION '<sentence>'`` in a function is one refusal site, identified by the function (its qualified name and its
argument types, so overloads are told apart) and its sentence (the template, with ``%`` where a value is filled in). Each site gets a
stable code and the sentence as its one-line meaning. At run time ``safelog.describe`` matches a database refusal to its site by the
raising function and signature (from the error's context) and the template, and prints the code beside the class and SQLSTATE.

Only current definitions count: the migrations are read in file order and, within a file, statement by statement, so a later
``CREATE [OR REPLACE] FUNCTION`` supersedes every sentence of the one before and a ``DROP FUNCTION`` (one or several names, qualified
or not) removes a function until something creates it again. Every one-off migration block (``DO $$ ... $$``) keeps its sentences:
each runs once, during its migration. Two current sentences of one function that any single message could match are refused: a
code must name exactly one check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
# the trigger guard, installed by the superuser before the first migration: its refusals are registered too, read first
GUARD = ROOT / "docker" / "initdb" / "20-trigger-guard.sql"
OUT = ROOT / "src" / "consentvault" / "data" / "refusal_codes.json"
SCHEMA = "consentvault"  # the schema an unqualified function name resolves to in these migrations

_CREATE = re.compile(r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.\"]+)\s*\(", re.I)
_DROP = re.compile(r"DROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?(.+?)(?:\s+(?:CASCADE|RESTRICT))?\s*;", re.I | re.S)
_DO = re.compile(r"\bDO\s*(\$\w*\$)", re.I)
_DOLLAR = re.compile(r"\$(\w*)\$")
_RAISE = re.compile(r"RAISE\s+EXCEPTION\s+'((?:[^']|'')*)'", re.I)
_LETTERS = str.maketrans("0123456789abcdef", "ghjkmnpqrstvwxyz")
_TYPE_WORDS = {"uuid", "text", "integer", "int", "int2", "int4", "int8", "bigint", "smallint", "boolean", "bool", "bytea", "jsonb",
               "json", "timestamptz", "timestamp", "date", "interval", "numeric", "decimal", "double", "real", "character", "varchar",
               "char", "inet", "cidr", "oid", "regclass", "regrole", "regprocedure", "name", "time", "timetz", "bit", "anyelement",
               "anyarray", "record", "void", "float4", "float8", "money", "xml", "tsvector"}
_ALIASES = {"int": "integer", "int4": "integer", "int2": "smallint", "int8": "bigint", "bool": "boolean",
            "timestamptz": "timestamp with time zone", "timetz": "time with time zone", "varchar": "character varying",
            "float8": "double precision", "float4": "real", "decimal": "numeric"}
STAR = object()


# ---- names and signatures ---------------------------------------------------------------------------------------------------------
def norm_name(name: str) -> str:
    name = name.replace('"', "").strip().lower()
    return name if "." in name else f"{SCHEMA}.{name}"


def _split_top(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def norm_type(t: str) -> str:
    t = re.sub(r"\s+", " ", t.strip().lower()).replace("pg_catalog.", "")
    array = t.endswith("[]")
    t = t[:-2].strip() if array else t
    t = re.sub(r"\(\s*\d+(\s*,\s*\d+)?\s*\)", "", t).strip()  # varchar(64) -> varchar
    t = _ALIASES.get(t, t)
    return t + ("[]" if array else "")


def norm_signature(params: str, named: bool) -> str:
    """The argument types of a parameter list, in order (OUT parameters are not part of a function's identity)."""
    types = []
    for p in _split_top(params):
        p = re.split(r"\s+DEFAULT\s+|\s*=\s*", p.strip(), maxsplit=1, flags=re.I)[0].strip()
        if not p:
            continue
        words = p.split()
        mode = words[0].upper()
        if mode == "OUT":
            continue
        if mode in ("IN", "INOUT", "VARIADIC"):
            words = words[1:]
        if named and len(words) >= 2 and words[0].lower().strip('"') not in _TYPE_WORDS and not words[0].endswith("[]") \
                and "." not in words[0]:
            words = words[1:]  # the parameter's name
        types.append(norm_type(" ".join(words)))
    return ",".join(types)


def _balanced(sql: str, open_at: int) -> int:
    """The index of the parenthesis that closes the one at ``open_at``."""
    depth = 0
    for i in range(open_at, len(sql)):
        if sql[i] == "(":
            depth += 1
        elif sql[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    raise SystemExit(f"an unbalanced parameter list at offset {open_at}")


# ---- the statements of one migration, in order --------------------------------------------------------------------------------------
def _events(sql: str):
    """('create', key, templates) | ('drop', name, signature or None) | ('inline', None, templates), in file order."""
    out = []
    for m in _CREATE.finditer(sql):
        close = _balanced(sql, m.end() - 1)
        key = (norm_name(m.group(1)), norm_signature(sql[m.end():close], named=True))
        tag = _DOLLAR.search(sql, close)
        if tag is None:
            raise SystemExit(f"function {key[0]} has no dollar-quoted body")
        end = sql.find(tag.group(0), tag.end())
        if end == -1:
            raise SystemExit(f"function {key[0]} has an unclosed body")
        # the line of each RAISE in the body, as PL/pgSQL numbers it (from the line the body starts on): the error's context
        # names it ("... line N at RAISE"), so two sentences of one function are never confused, whatever their values
        templates = [(sql[tag.end():r.start()].count("\n") + 1, r.group(1).replace("''", "'"))
                     for r in _RAISE.finditer(sql, tag.end(), end)]
        out.append((m.start(), "create", key, templates))
    for m in _DROP.finditer(sql):
        for item in _split_top(m.group(1)):
            item = item.strip()
            if "(" in item:
                name, params = item.split("(", 1)
                out.append((m.start(), "drop", norm_name(name), norm_signature(params.rsplit(")", 1)[0], named=False)))
            else:
                out.append((m.start(), "drop", norm_name(item), None))
    for m in _DO.finditer(sql):
        end = sql.find(m.group(1), m.end())
        if end == -1:
            raise SystemExit("an unclosed DO block")
        # PL/pgSQL numbers a block's lines from the line its body starts on; the context names it ("inline_code_block line N")
        lines = [(sql[m.end():r.start()].count("\n") + 1, r.group(1).replace("''", "'")) for r in _RAISE.finditer(sql, m.end(), end)]
        out.append((m.start(), "inline", None, lines))
    return [e[1:] for e in sorted(out, key=lambda e: e[0])]


# ---- overlap: can one message match two templates? -------------------------------------------------------------------------------
def tokens(template: str) -> list:
    """A template as a pattern: its literal characters, and STAR for each ``%`` (any value); ``%%`` is a literal percent."""
    out, i = [], 0
    while i < len(template):
        if template.startswith("%%", i):
            out.append("%")
            i += 2
        elif template[i] == "%":
            out.append(STAR)
            i += 1
        else:
            out.append(template[i])
            i += 1
    return out


def intersects(a: str, b: str) -> bool:
    """Whether some single message matches both templates: a search over the product of the two patterns (state = a position in
    each), which accepts when both reach their end together. Exact, and bounded by (len(a) + 1) * (len(b) + 1) states."""
    ta, tb = tokens(a), tokens(b)
    seen, todo = {(0, 0)}, [(0, 0)]
    while todo:
        i, j = todo.pop()
        if i == len(ta) and j == len(tb):
            return True
        moves = []
        if i < len(ta) and ta[i] is STAR:
            moves.append((i + 1, j))  # a's value ends here
        if j < len(tb) and tb[j] is STAR:
            moves.append((i, j + 1))  # b's value ends here
        if i < len(ta) and j < len(tb):  # one character both can read
            ca, cb = ta[i], tb[j]
            if ca is STAR and cb is not STAR:
                moves.append((i, j + 1))
            elif cb is STAR and ca is not STAR:
                moves.append((i + 1, j))
            elif ca is not STAR and cb is not STAR and ca == cb:
                moves.append((i + 1, j + 1))
        for state in moves:
            if state not in seen:
                seen.add(state)
                todo.append(state)
    return False


# ---- the registry -----------------------------------------------------------------------------------------------------------------
def _code(identity: str, template: str) -> str:
    base = identity.split("(")[0].split(".")[-1].lower()
    slug = re.sub(r"[^a-z0-9]+", "_", base).strip("_")[:36] or "fn"
    digest = hashlib.sha256(f"{identity}\x00{template}".encode()).hexdigest()[:6].translate(_LETTERS)
    return f"db_{slug}_{digest}"


def build(migrations: Path = MIGRATIONS) -> list[dict]:
    live: dict[tuple[str, str], tuple[str, list[str]]] = {}
    inline: dict[tuple[int, str], str] = {}
    sources = ([GUARD] if migrations == MIGRATIONS else []) + sorted(migrations.glob("*.sql"))
    for path in sources:
        for kind, key, rest in _events(path.read_text()):
            if kind == "create":
                live[key] = (path.name, rest)
            elif kind == "drop":
                for k in [k for k in live if k[0] == key and (rest is None or k[1] == rest)]:
                    del live[k]
            else:
                for line, t in rest:
                    inline.setdefault((line, t), path.name)
    sites: dict[tuple, dict] = {}
    for (function, signature), (migration, templates) in live.items():
        for line, template in templates:
            sites.setdefault((function, f"{signature}|line {line}", template), {
                "code": _code(f"{function}({signature}) line {line}", template), "function": function, "signature": signature,
                "line": line, "template": template, "meaning": " ".join(template.split()), "defined_in": migration})
    for (line, template), migration in inline.items():
        sites.setdefault(("inline_code_block", f"|line {line}", template), {
            "code": _code(f"inline_code_block() line {line}", template), "function": "inline_code_block", "signature": "",
            "line": line, "template": template, "meaning": " ".join(template.split()), "defined_in": migration})
    # the line tells a function's sentences apart (the context names it); two RAISEs sharing one line can only be told apart by
    # their sentences, so those must never match one message
    by_identity: dict[tuple[str, str], list[str]] = {}
    for function, signature_line, template in sites:
        by_identity.setdefault((function, signature_line), []).append(template)
    for (function, signature), templates in by_identity.items():
        for x in range(len(templates)):
            for y in range(x + 1, len(templates)):
                if intersects(templates[x], templates[y]):
                    raise SystemExit(f"refusal sites overlap in {function}({signature}): {templates[x]!r} and {templates[y]!r} "
                                     "can match one message; a code must name one check")
    codes = [s["code"] for s in sites.values()]
    if len(codes) != len(set(codes)):
        raise SystemExit("two refusal sites hash to one code")
    return sorted(sites.values(), key=lambda s: s["code"])


def render(sites: list[dict]) -> str:
    return json.dumps({"about": "Database refusal codes: one per (raising function and signature, sentence), current definitions "
                                "only. Built by scripts/build_refusal_codes.py from the migrations; never edited by hand.",
                       "sites": sites}, indent=1, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    sites = build()
    text = render(sites)
    if args.check:
        have = OUT.read_text() if OUT.exists() else ""
        if have != text:
            print(f"FAIL: {OUT.relative_to(ROOT)} is stale; run scripts/build_refusal_codes.py", file=sys.stderr)
            return 1
        print(f"the refusal code registry matches the migrations ({len(sites)} sites)")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(sites)} sites)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
