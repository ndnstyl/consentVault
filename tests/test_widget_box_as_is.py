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


# Certificate pass-through: the hidden values an issuer's script put in the host form are copied into the post as they are.
# Names are from the issuers' own pages (tests/fixtures/certificates/SOURCE.md).
TF = "xxTrustedFormCertUrl"
LEADID = "universal_leadid"
TF_URL = "https://cert.trustedform.com/454a35b802f3e7b63ffabb4efedb7c6ebe67886c"


def _pass(inputs, **attrs):
    return _run(True, inputs=inputs, **({"attributes": {"data-disclosure": "I agree.", **attrs}} if attrs else {}))


def test_two_filled_hidden_inputs_are_sent_in_document_order_under_third_party():
    out = _pass([{"name": LEADID, "value": "tok-1"}, {"name": TF, "value": TF_URL}])
    assert out["posted"]["third_party"] == [{"name": LEADID, "value": "tok-1"}, {"name": TF, "value": TF_URL}]


def test_a_value_with_spaces_and_a_newline_is_sent_unchanged():
    odd = "  https://cert.trustedform.com/abc \n"
    assert _pass([{"name": TF, "value": odd}])["posted"]["third_party"] == [{"name": TF, "value": odd}]


def test_an_empty_or_absent_input_is_left_out_and_the_key_is_absent_not_empty():
    assert "third_party" not in _pass([{"name": TF, "value": ""}])["posted"]
    assert "third_party" not in _pass([])["posted"]
    assert _pass([{"name": TF, "value": ""}, {"name": LEADID, "value": "tok"}])["posted"]["third_party"] == [
        {"name": LEADID, "value": "tok"}]


def test_the_same_name_twice_is_sent_twice_in_order():
    out = _pass([{"name": TF, "value": "first"}, {"name": TF, "value": "second"}])
    assert [e["value"] for e in out["posted"]["third_party"]] == ["first", "second"]


def test_a_listed_name_twice_does_not_double_send_and_a_data_passthrough_list_replaces_the_default():
    out = _pass([{"name": TF, "value": "a"}, {"name": "my_cert", "value": "b"}], **{"data-passthrough": "my_cert, my_cert"})
    assert out["posted"]["third_party"] == [{"name": "my_cert", "value": "b"}]


def test_nothing_is_fetched_from_any_issuer_and_the_fixed_body_fields_are_unchanged():
    out = _pass([{"name": TF, "value": TF_URL}])
    assert out["fetched"] == ["https://edge.example.com/consent"]
    plain = _run(True)["posted"]
    assert set(out["posted"]) - {"third_party"} == set(plain)
    assert {k: out["posted"][k] for k in ("contact", "checked", "disclosure_text", "page_url", "channels", "purposes")} == {
        k: plain[k] for k in ("contact", "checked", "disclosure_text", "page_url", "channels", "purposes")}


def test_a_one_megabyte_value_is_sent_whole():
    big = "x" * 1_000_000
    assert _pass([{"name": TF, "value": big}])["posted"]["third_party"][0]["value"] == big


def test_the_built_in_passthrough_case_passes():
    proc = subprocess.run(["node", str(HARNESS), "--case", "passthrough"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
