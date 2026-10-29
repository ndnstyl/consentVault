"""The whole consent lifecycle through the real console entry point, one subprocess per command."""

import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

from test_seal import _TestTsa  # the local RFC 3161 authority used by the seal tests

PHONE = "+15555550100"
WORDING = "I agree to receive texts about my account. Reply STOP to end."


@pytest.fixture
def cli_dsns(raw_dsn, pg_server):
    """(owner DSN for migrate, restricted runtime DSN for everything else) on a fresh, unmigrated database."""
    import psycopg
    role = "cli_" + uuid.uuid4().hex[:10]
    with psycopg.connect(raw_dsn, autocommit=True) as c:
        c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_app') "
                  "THEN CREATE ROLE consentvault_app NOLOGIN; END IF; END $$")
        c.execute(f'CREATE ROLE "{role}" LOGIN IN ROLE consentvault_app')
    return raw_dsn, f"postgresql://{role}@127.0.0.1:{pg_server['port']}/{raw_dsn.rsplit('/', 1)[1]}"


@pytest.fixture
def tsa_authority():
    root = Path(tempfile.mkdtemp(prefix="consentvault-cli-tsa-"))
    server = _TestTsa(root)
    try:
        yield server
    finally:
        server.close()
        for p in root.iterdir():
            p.unlink()
        root.rmdir()


def test_full_lifecycle_through_the_console_script(cli_dsns, tsa_authority, tmp_path):
    exe = Path(sys.executable).parent / "consentvault"
    assert exe.is_file(), f"console script not installed next to the interpreter: {exe}"
    owner_dsn, app_dsn = cli_dsns
    anchor_file = tmp_path / "anchors.jsonl"
    settings = {**os.environ, "CONSENTVAULT_OWNER_DSN": owner_dsn, "CONSENTVAULT_DSN": app_dsn, "CONSENTVAULT_DEFAULT_REGION": "US",
                "CONSENTVAULT_PURPOSES": "marketing", "CONSENTVAULT_ANCHOR_SINK": str(anchor_file),
                "CONSENTVAULT_TSA_URL": tsa_authority.url, "CONSENTVAULT_TSA_CAFILE": str(tsa_authority.cafile)}
    for k in ("CONSENTVAULT_CONFIG", "CONSENTVAULT_MIGRATIONS"):
        settings.pop(k, None)

    def run(*argv, expect=0):
        proc = subprocess.run([str(exe), *argv], capture_output=True, text=True, env=settings,
                              cwd=str(tmp_path), timeout=120)
        assert proc.returncode == expect, f"consentvault {' '.join(argv)} -> {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        return json.loads(proc.stdout) if proc.stdout.lstrip().startswith("{") else proc.stdout

    assert run("migrate")["applied"]
    sha = run("disclosure", "register", "--body", WORDING, "--label", "cli-test", "--channel", "sms",
              "--purpose", "marketing")["sha256"]
    run("capture", "--contact", PHONE, "--checked", "--disclosure", sha, "--channel", "sms",
        "--purpose", "marketing", "--session-ref", "cli-1", "--page-url", "https://www.example.com/signup")

    allowed = run("may-contact", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing")
    assert allowed["allowed"] is True and allowed["reason"] == "granted"

    verdict = run("classify", "STOP")
    assert verdict["verdict"] == "stop"
    run("revoke", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing", "--session-ref", "cli-2")
    denied = run("may-contact", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing", expect=1)
    assert denied["allowed"] is False and denied["reason"] == "stopped:revoke"

    sealed = run("seal")
    assert sealed["sealed"] == 2 and sealed["unsealed_remaining"] == 0
    checked = run("verify-seals")
    assert checked["ok"] is True and checked["checked"] == 2
    assert run("verify-chain")["ok"] is True
    anchored = run("anchor")
    assert anchored["seq"] == 2 and json.loads(anchor_file.read_text().splitlines()[-1])["row_hash"] == anchored["row_hash"]
    assert run("verify-chain")["ok"] is True

    bundle = tmp_path / "bundle"
    exported = run("export", PHONE, "--out", str(bundle))
    assert exported["events"] == 2 and exported["seals"] == 2

    proc = subprocess.run([sys.executable, str(bundle / "verify.py"), "--cafile", str(tsa_authority.cafile),
                           "--anchors", str(anchor_file)],
                          capture_output=True, text=True,
                          cwd=str(bundle), timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT PASS" in proc.stdout and "FAIL" not in proc.stdout.replace("RESULT PASS", "")


def test_a_capture_runs_the_release_rule_and_verify_chain_names_an_unchecked_webhook_sink(dsn, monkeypatch, capsys, conn):
    from consentvault import cli, disclosure

    sha = disclosure.register(conn, WORDING, "cli-test", "en", ["sms"], ["marketing"])
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    capsys.readouterr()
    assert cli.main(["revoke", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing"]) == 0
    capsys.readouterr()
    assert cli.main(["capture", "--contact", PHONE, "--checked", "--disclosure", sha, "--channel", "sms",
                     "--purpose", "marketing", "--session-ref", "cli-3", "--verification", "otp"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["release"] == {"released_channels": ["sms"], "refusals": {}}
    assert cli.main(["may-contact", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing"]) == 0
    capsys.readouterr()

    monkeypatch.setenv("CONSENTVAULT_ANCHOR_SINK", "https://hooks.example.com/anchor")
    assert cli.main(["verify-chain"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["sink_not_checked"] is True
    assert "sink_not_checked" in captured.err
    monkeypatch.setenv("CONSENTVAULT_ANCHOR_SINK", "/nonexistent/anchors.jsonl")
    assert cli.main(["verify-chain"]) == 0
    assert "sink_not_checked" not in json.loads(capsys.readouterr().out)


def test_capture_with_an_inbound_keyword_lifts_a_stop_only_for_a_start_message(dsn, monkeypatch, capsys, conn):
    from consentvault import cli, disclosure

    sha = disclosure.register(conn, WORDING, "cli-test", "en", ["sms"], ["marketing"])
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    assert cli.main(["revoke", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing"]) == 0
    base = ["capture", "--contact", PHONE, "--checked", "--disclosure", sha, "--channel", "sms",
            "--purpose", "marketing", "--session-ref", "cli-4", "--verification", "inbound_keyword"]
    capsys.readouterr()
    assert cli.main(base + ["--inbound-message", "who is this"]) != 0
    assert cli.main(["may-contact", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing"]) == 1
    capsys.readouterr()
    assert cli.main(base + ["--inbound-message", "START"]) == 0
    assert json.loads(capsys.readouterr().out)["release"]["released_channels"] == ["sms"]
    assert cli.main(["may-contact", "--contact", PHONE, "--channel", "sms", "--purpose", "marketing"]) == 0
