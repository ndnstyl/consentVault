"""Guard: nothing in this repository names a private machine path or an unrelated company.

Scans every tracked file plus every new file git would pick up (untracked, not ignored), so a reference is caught
before it is committed. Fails naming each file, line and pattern.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve().relative_to(REPO).as_posix()

FORBIDDEN = [
    "/Users/",
    "oxfloors",
    "ox-floors",
    "Ox Floors",
    "FloorTek",
    "LeadPerfection",
    "ox-brain",
    "msoto",
]
PATTERN = re.compile("|".join(re.escape(p) for p in FORBIDDEN), re.IGNORECASE)


def repo_files() -> list[str]:
    if not (REPO / ".git").exists():
        pytest.skip(f"{REPO} has no .git: the file list comes from git, so this guard runs in a clone only")
    if shutil.which("git") is None:
        raise AssertionError("git is not on PATH: the guard cannot list the repository's files")
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True, check=False,
    )
    if out.returncode != 0:
        raise AssertionError(f"git ls-files failed ({out.returncode}): {out.stderr.decode(errors='replace')}")
    files = sorted({f for f in out.stdout.decode().split("\0") if f})
    if not files:
        raise AssertionError("git listed no files: the guard would pass on nothing")
    return files


def test_no_private_path_or_unrelated_company_is_named():
    hits = []
    for rel in repo_files():
        if rel == SELF:
            continue
        path = REPO / rel
        if not path.is_file():
            continue  # listed by git but deleted in the working tree
        text = path.read_bytes().decode("utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            for m in PATTERN.finditer(line):
                hits.append(f"{rel}:{n}: {m.group(0)!r}")
        if PATTERN.search(rel):
            hits.append(f"{rel}: the file name itself")
    assert not hits, f"{len(hits)} forbidden reference(s):\n  " + "\n  ".join(hits)
