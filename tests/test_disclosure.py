"""Disclosure registration: wording is stored exactly as the capture widget hashes it."""

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


def test_wording_with_surrounding_whitespace_is_refused_unless_stripped(conn):
    for body in (SHOWN + "\n", "  " + SHOWN, "\t" + SHOWN + " "):
        with pytest.raises(InvalidEventError, match="leading or trailing whitespace"):
            _register(conn, body)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 0
    sha = _register(conn, SHOWN + "\n", strip=True)
    assert sha == hashlib.sha256(SHOWN.encode()).hexdigest()
    assert conn.execute("SELECT body FROM consentvault.disclosure").fetchone()["body"] == SHOWN
    assert _register(conn, SHOWN) == sha  # exact wording registers as is, and again without change


def test_the_command_line_strips_a_wording_file_by_default(dsn, tmp_path, monkeypatch, capsys):
    wording = tmp_path / "wording.txt"
    wording.write_text(SHOWN + "\n", encoding="utf-8")
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    args = ["disclosure", "register", "--body-file", str(wording), "--label", "form", "--channel", "sms",
            "--purpose", "marketing"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["sha256"] == hashlib.sha256(SHOWN.encode()).hexdigest()
    assert cli.main(args + ["--keep-whitespace"]) == cli.EXIT_ERROR
    assert "leading or trailing whitespace" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_widgets_hash_is_the_hash_the_command_line_registers(dsn, conn, tmp_path, monkeypatch, capsys):
    padded = "  \n" + SHOWN + "\n  "  # as written in an HTML attribute or a template
    proc = subprocess.run(
        ["node", str(HARNESS)], capture_output=True, text=True, timeout=60,
        input=json.dumps({"widget": str(WIDGET), "attributes": {
            "data-channels": "sms", "data-purposes": "marketing", "data-disclosure": padded}}))
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["shown"] == SHOWN
    wording = tmp_path / "wording.txt"
    wording.write_text(padded, encoding="utf-8")
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    assert cli.main(["disclosure", "register", "--body-file", str(wording), "--label", "form",
                     "--channel", "sms", "--purpose", "marketing"]) == 0
    registered = json.loads(capsys.readouterr().out)["sha256"]
    assert out["posted"]["disclosure_sha256"] == registered
    assert conn.execute("SELECT body FROM consentvault.disclosure WHERE sha256 = %s", (registered,)).fetchone()["body"] == SHOWN
