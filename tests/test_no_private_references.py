"""Guard: nothing in this repository names a private machine path or an unrelated company.

Scans every tracked file plus every new file git would pick up (untracked, not ignored), so a reference is caught
before it is committed. Fails naming each file, line and the matched text.

The names themselves are never written here: this file is public, and listing them would publish what it guards. Each
forbidden name is kept only as (length, SHA-256 of its lowercase letters and digits). A line is reduced to its lowercase
letters and digits, so "Some Name", "some-name" and "SOMENAME" all reduce to the same string, and every window of each
listed length is hashed and compared.
"""
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve().relative_to(REPO).as_posix()

# The macOS home-folder path is matched exactly: a lowercase "/users/" is a web API route (an identity provider's
# user endpoint), not a machine path.
PATH_PATTERN = re.compile(re.escape("/Users/"))

# (length, sha256 hex) of each forbidden name, reduced to lowercase letters and digits.
FORBIDDEN_HASHES = {
    (5, "de9664aa5f6bf1769578fb47b95138cbb6d985bb2c91a0977da358372c39bbef"),
    (7, "28567c043fa48f31a2d5a8971d6d90f65565c6e9d9d7d040e74c781db5dfe208"),
    (8, "9f2b6667d40551f476409fa30093eeabd680be0b687a1349fb9062d8f3bc376d"),
    (8, "b224af306a00be31f125e3ee6f7beabcba82cd01bcc542696376bbf101f0c593"),
    (14, "7e8a8ed078e817b9cd2dc54c54331dc60186ec19835f01f4fca77b150112e9a3"),
}
_LENGTHS = sorted({n for n, _ in FORBIDDEN_HASHES})
_ALNUM = re.compile(r"[^a-z0-9]")


def forbidden_hits(s: str) -> list[str]:
    """Every forbidden match in s: the machine path, or any window whose reduced form hashes to a forbidden name."""
    hits = [m.group(0) for m in PATH_PATTERN.finditer(s)]
    reduced = _ALNUM.sub("", s.lower())
    for n in _LENGTHS:
        for i in range(0, len(reduced) - n + 1):
            w = reduced[i:i + n]
            if (n, hashlib.sha256(w.encode()).hexdigest()) in FORBIDDEN_HASHES:
                hits.append(f"a forbidden name ({n} letters)")
    return hits


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


def test_the_guard_catches_a_reduced_match_and_passes_clean_text():
    # Built from pieces so the guard's own self-test never spells a name either.
    sample = "Contact " + "Ox" + " " + "Floors" + " today"
    assert forbidden_hits(sample), "a spaced, capitalised forbidden name must be caught"
    assert not forbidden_hits("ConsentVault keeps a record of consent."), "clean text must pass"


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
            for h in forbidden_hits(line):
                hits.append(f"{rel}:{n}: {h}")
        for h in forbidden_hits(rel):
            hits.append(f"{rel}: the file name itself ({h})")
    assert not hits, f"{len(hits)} forbidden reference(s):\n  " + "\n  ".join(hits)
