"""The copy check: user-facing text carries no legal conclusion, no overclaim and no em dash."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("copy_check", REPO / "scripts" / "copy_check.py")
copy_check = importlib.util.module_from_spec(_spec)
sys.modules["copy_check"] = copy_check
_spec.loader.exec_module(copy_check)

README = REPO / "README.md"


def hits_for(text: str) -> list[str]:
    out: list[str] = []
    copy_check.check_text(text, README, 1, out)
    return out


def test_each_banned_claim_is_caught():
    for text in [
        "ConsentVault proves consent for every call.",
        "Your records are court-ready.",
        "We offer guaranteed compliance.",
        "Your program is certified compliant.",
        "This keeps you compliant.",
        "That is valid consent.",
        "A line with an em dash — here.",
    ]:
        assert hits_for(text), f"not caught: {text}"


def test_a_disclaimer_that_negates_the_claim_passes():
    for text in [
        "Storing a record does not prove consent.",
        "It is not a conclusion that consent was valid.",
        "We never offer guaranteed compliance.",
    ]:
        assert not hits_for(text), f"wrongly flagged: {text}"


def test_the_repo_copy_carries_no_legal_conclusion_overclaim_or_em_dash(capsys):
    code = copy_check.main()
    out = capsys.readouterr().out
    assert code == 0, out
