"""The widget sends the checkbox exactly as it is at submit, checked or unchecked, and never refuses to send."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "support" / "widget_harness.mjs"
WIDGET = Path(__file__).parent.parent / "edge" / "widget" / "consent-checkbox.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _run(box, **extra):
    proc = subprocess.run(
        ["node", str(HARNESS)],
        input=json.dumps({"widget": str(WIDGET), "attributes": {"data-disclosure": "I agree.", "data-channels": "sms",
                                                                "data-purposes": "marketing"}, "box": box, **extra}),
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _post(box):
    return _run(box)["posted"]


def test_a_checked_box_is_sent_as_checked():
    assert _post(True)["checked"] is True


def test_an_unchecked_box_is_sent_not_refused():
    assert _post(False)["checked"] is False


def test_the_decision_time_is_the_browser_clock_with_its_offset_and_the_wording_is_the_text_on_screen():
    import hashlib
    import re

    out = _run(False)
    posted = out["posted"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d", posted["decided_at"])
    assert posted["disclosure_text"] == out["shown"] == "I agree."
    assert posted["disclosure_sha256"] == hashlib.sha256(b"I agree.").hexdigest()


def test_the_widget_says_the_choice_was_recorded_for_both_box_values_and_queued_when_queued():
    for box in (True, False):
        assert _run(box)["status"] == "Your choice was recorded."
    queued = _run(False, answer={"status": 202, "body": {"stored": False, "queued": True, "queue_id": "q"}})
    assert queued["failed"] is None and queued["status"].startswith("Not yet stored, queued")
    down = _run(False, answer={"status": 503, "body": {"stored": False, "error": "store_unavailable"}})
    assert down["failed"] is not None and "could not be recorded" in down["status"]
