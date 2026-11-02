"""Disclosure registration: wording is stored and hashed as its exact bytes, the same bytes the capture widget hashes.

Ruled at the integration pass: one rule everywhere, nothing trims wording (this register, the admin lane's wording
versions, the widget). These tests replace the earlier "trimmed wording" rule.
"""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from consentvault import cli, disclosure
from consentvault.errors import InvalidEventError

WIDGET = Path(__file__).resolve().parents[1] / "edge" / "widget" / "consent-checkbox.js"
HARNESS = Path(__file__).parent / "support" / "widget_harness.mjs"
SHOWN = "I agree to receive texts about my account.\nReply STOP to end."


def _register(conn, body, **kw):
    return disclosure.register(conn, body, "form", "en", ["sms"], ["marketing"], **kw)


def test_wording_is_stored_and_hashed_as_its_exact_bytes(conn):
    for body in ("", "   ", "\n\t "):
        with pytest.raises(InvalidEventError, match="empty"):
            _register(conn, body)
    padded = SHOWN + "\n"
    sha = _register(conn, padded)
    assert sha == hashlib.sha256(padded.encode()).hexdigest()
    assert conn.execute("SELECT body FROM consentvault.disclosure WHERE sha256 = %s", (sha,)).fetchone()["body"] == padded
    exact = _register(conn, SHOWN)
    assert exact == hashlib.sha256(SHOWN.encode()).hexdigest() and exact != sha  # different bytes, different wording
    assert _register(conn, padded) == sha  # registering the same bytes again changes nothing
    with pytest.raises(TypeError):
        _register(conn, SHOWN, strip=True)  # the trimming switch is gone


def test_the_command_line_registers_a_wording_file_byte_for_byte(dsn, tmp_path, monkeypatch, capsys):
    wording = tmp_path / "wording.txt"
    wording.write_text(SHOWN + "\n", encoding="utf-8")
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    args = ["disclosure", "register", "--body-file", str(wording), "--label", "form", "--channel", "sms",
            "--purpose", "marketing"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["sha256"] == hashlib.sha256((SHOWN + "\n").encode()).hexdigest()


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_widget_and_the_server_agree_on_the_exact_bytes(dsn, conn, tmp_path, monkeypatch, capsys):
    padded = "  \n" + SHOWN + "\n  "  # as written in an HTML attribute or a template
    proc = subprocess.run(
        ["node", str(HARNESS)], capture_output=True, text=True, timeout=60,
        input=json.dumps({"widget": str(WIDGET), "attributes": {
            "data-channels": "sms", "data-purposes": "marketing", "data-disclosure": padded}}))
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["shown"] == padded  # the widget shows and hashes the text untrimmed
    wording = tmp_path / "wording.txt"
    wording.write_text(padded, encoding="utf-8")
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    assert cli.main(["disclosure", "register", "--body-file", str(wording), "--label", "form",
                     "--channel", "sms", "--purpose", "marketing"]) == 0
    registered = json.loads(capsys.readouterr().out)["sha256"]
    assert out["posted"]["disclosure_sha256"] == registered
    assert conn.execute("SELECT body FROM consentvault.disclosure WHERE sha256 = %s", (registered,)).fetchone()["body"] == padded
