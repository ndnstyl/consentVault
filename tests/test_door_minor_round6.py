"""Round-6 minors: the times a key is revoked and a source retired are stamped with the statement clock the arrival uses, and the
runbook sentence about the request key ends with a full stop."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_revoked_at_and_retired_at_use_clock_timestamp():
    src = (ROOT / "src/consentvault/tenancy/admin.py").read_text()
    assert "revoked_at = clock_timestamp()" in src and "THEN clock_timestamp() ELSE retired_at" in src
    assert "revoked_at = now()" not in src and "THEN now() ELSE retired_at" not in src


def test_the_runbook_row_for_the_rebuild_ends_its_sentences():
    row = next(l for l in (ROOT / "docs/deployment.md").read_text().split("\n") if l.startswith("| `projection-rebuild`"))
    assert "carries its key. A post that waits" in row
