"""The widget sends the checkbox exactly as it is at submit, checked or unchecked, and never refuses to send."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "support" / "widget_harness.mjs"
WIDGET = Path(__file__).parent.parent / "edge" / "widget" / "consent-checkbox.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _post(box):
    proc = subprocess.run(
        ["node", str(HARNESS)],
        input=json.dumps({"widget": str(WIDGET), "attributes": {"data-disclosure": "I agree.", "data-channels": "sms",
                                                                "data-purposes": "marketing"}, "box": box}),
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["posted"]


def test_a_checked_box_is_sent_as_checked():
    assert _post(True)["checked"] is True


def test_an_unchecked_box_is_sent_not_refused():
    assert _post(False)["checked"] is False
