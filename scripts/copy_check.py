#!/usr/bin/env python3
"""Copy check: user-facing text may not state a legal conclusion or overclaim, and may not carry an em dash.

Scans docs/, README.md, portal/app/src, the notify templates and the evidence export cover text.
A match inside a sentence that negates it ("does not prove consent") is a disclaimer, not a claim, and passes.
The em dash rule is unconditional. Exit 1 on any hit, listing file:line and the phrase.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BANNED = [
    ("proves consent", re.compile(r"\bprov(?:es|ed|ing)?\s+(?:that\s+)?(?:\w+\s+){0,3}?consent\b", re.I)),
    ("valid consent as a statement", re.compile(r"\bvalid\s+consent\b|\bconsent\s+is\s+valid\b|\bconsent\s+(?:was|were)\s+valid\b", re.I)),
    ("court-ready", re.compile(r"\bcourt[- ]ready\b", re.I)),
    ("guaranteed compliance", re.compile(r"\bguarantee[sd]?\s+(?:\w+\s+){0,2}?compliance\b|\bcompliance\s+(?:is\s+)?guarantee[sd]?\b", re.I)),
    ("certified compliant", re.compile(r"\bcertified\s+compliant\b|\bcertif(?:y|ies|ied)\s+(?:\w+\s+){0,2}?compliance\b", re.I)),
    ("compliant as a guarantee", re.compile(r"\b(?:guarantee[sd]?|ensures?|ensured|makes you|keeps you|stay)\s+(?:you\s+)?(?:\w+\s+){0,2}?compliant\b|\b100%\s+compliant\b|\bfully\s+compliant\b", re.I)),
]
NEGATION = re.compile(r"\bwhether\b|\b(?:not|never|no|cannot|can't|cannot|without|nor|neither|refuses?|refused|isn't|doesn't|don't|won't|n't)\b|\bnot\b", re.I)
EM_DASH = "—"

SCAN_FILES = [ROOT / "README.md", ROOT / "src/consentvault/notify/templates.py", ROOT / "src/consentvault/evidence.py"]
SCAN_DIRS = [(ROOT / "docs", {".md", ".txt", ".html"}), (ROOT / "portal/app/src", {".ts", ".tsx", ".md", ".css", ".json"})]
SKIP_NAMES = {"copycheck.ts"}  # holds the banned list itself


def sentences(line: str):
    for part in re.split(r"(?<=[.!?;:])\s+", line):
        yield part


def check_text(text: str, path: Path, line_no: int, hits: list[str], prev: str = "") -> None:
    rel = path.relative_to(ROOT)
    if EM_DASH in text:
        hits.append(f"{rel}:{line_no}: em dash in user-facing copy")
    for k, sent in enumerate(sentences(text)):
        for name, rx in BANNED:
            m = rx.search(sent)
            if not m:
                continue
            lead = sent[: m.start()] + " " + sent[m.start(): m.end()]
            if k == 0 and not re.search(r"[.!?]\s*$", prev.strip() or "."):
                lead = prev + " " + lead  # a sentence continued from the previous line
            if not NEGATION.search(lead):
                hits.append(f"{rel}:{line_no}: {name}: \"{sent.strip()[:120]}\"")


def py_strings(path: Path):
    tree = ast.parse(path.read_text())
    doc_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                doc_nodes.add(id(first.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in doc_nodes:
            for i, ln in enumerate(node.value.splitlines() or [""]):
                yield node.lineno + i, ln


def ts_lines(path: Path):
    in_block = False
    for i, ln in enumerate(path.read_text().splitlines(), 1):
        s = ln
        if in_block:
            if "*/" in s:
                s = s.split("*/", 1)[1]
                in_block = False
            else:
                continue
        s = re.sub(r"/\*.*?\*/", "", s)
        if "/*" in s:
            s = s.split("/*", 1)[0]
            in_block = True
        s = re.sub(r"(^|\s)//.*$", r"\1", s)
        yield i, s


def main() -> int:
    hits: list[str] = []
    files: list[Path] = [f for f in SCAN_FILES if f.exists()]
    for d, exts in SCAN_DIRS:
        if d.is_dir():
            files += [p for p in sorted(d.rglob("*")) if p.is_file() and p.suffix in exts and "node_modules" not in p.parts]
    scanned = 0
    for p in files:
        if p.name in SKIP_NAMES:
            continue
        scanned += 1
        if p.suffix == ".py":
            prev = ""
            for n, ln in py_strings(p):
                check_text(ln, p, n, hits, prev)
                prev = ln
        elif p.suffix in {".ts", ".tsx"}:
            prev = ""
            for n, ln in ts_lines(p):
                check_text(ln, p, n, hits, prev)
                prev = ln
        else:
            prev = ""
            for n, ln in enumerate(p.read_text().splitlines(), 1):
                check_text(ln, p, n, hits, prev)
                prev = ln
    for h in hits:
        print(h)
    print(f"copy check: {scanned} files, {len(hits)} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
