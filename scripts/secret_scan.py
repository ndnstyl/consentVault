#!/usr/bin/env python3
"""Stdlib secret scanner, the fallback when gitleaks is not installed.

Reads the allowlist regexes from .gitleaks.toml so both scanners agree on what is a published example value.
Exit 1 and the file:line (never the secret) on any hit.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "node_modules", ".venv", "out", ".next", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "shots"}
SKIP_FILES = {"uv.lock", "package-lock.json"}
MAX_BYTES = 2_000_000

RULES = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{10,}\b")),
    ("stripe-webhook-secret", re.compile(r"\bwhsec_[0-9A-Za-z]{16,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("cloudflare-or-generic-secret-assignment", re.compile(
        r"""(?i)\b(?:secret|api[_-]?key|access[_-]?key|auth[_-]?token|password|passwd)\b["']?\s*[:=]\s*["']([A-Za-z0-9/+_\-]{24,})["']""")),
]


def allowlist() -> list[re.Pattern]:
    cfg = ROOT / ".gitleaks.toml"
    if not cfg.exists():
        return []
    text = cfg.read_text()
    block = re.search(r"regexes\s*=\s*\[(.*?)^\]", text, re.S | re.M)  # the list ends at a line holding only "]", so a "]" inside a regex cannot cut it short
    return [re.compile(r) for r in re.findall(r"'''(.*?)'''", block.group(1))] if block else []


def looks_random(value: str) -> bool:
    return len(set(value)) >= 10 and not re.fullmatch(r"(?i)(x+|0+|example|placeholder|changeme)[A-Za-z0-9_-]*", value)


def main() -> int:
    allow = allowlist()
    hits: list[str] = []
    scanned = 0
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or p.name in SKIP_FILES or any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        for n, line in enumerate(text.splitlines(), 1):
            if any(a.search(line) for a in allow):
                continue
            for name, rx in RULES:
                m = rx.search(line)
                if not m:
                    continue
                if name.endswith("secret-assignment") and not looks_random(m.group(1)):
                    continue
                hits.append(f"{p.relative_to(ROOT)}:{n}: {name}")
    for h in hits:
        print(h)
    print(f"secret scan (stdlib): {scanned} files, {len(hits)} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
