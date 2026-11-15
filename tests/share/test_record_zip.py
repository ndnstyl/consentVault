"""T027: the one-record file verifies with Python and openssl and a trust root supplied from outside; it fails without one and
when any byte changes; the file and the page both say the record's place in the whole chain is not checked."""

import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from consentvault import share

from .conftest import admin, get, mint_link, text_of

NOT_CHECKED = "does not check where this record sits in the whole chain"


def _fixture(t, throwaway_tsa, routes, tmp_path, flags=None):
    made = mint_link(t, flags=flags or {})
    zipped = get(routes, made["link_id"], "/record.zip")
    assert zipped.status == 200 and zipped.headers["Content-Type"] == "application/zip"
    assert "attachment" in zipped.headers["Content-Disposition"]
    out = tmp_path / "one"
    out.mkdir()
    with zipfile.ZipFile(io.BytesIO(zipped.raw)) as zf:
        zf.extractall(out)
    return made, out


def _run(out, ca, *extra):
    cmd = [sys.executable, str(out / "verify_one.py")] + (["--cafile", str(ca)] if ca else []) + list(extra)
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(out))


def test_the_file_verifies_with_a_trust_root_from_outside(record, routes, throwaway_tsa, tmp_path):
    _, out = _fixture(record, throwaway_tsa, routes, tmp_path)
    done = _run(out, throwaway_tsa.ca)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "RESULT PASS" in done.stdout and "openssl ts -verify" in done.stdout
    assert NOT_CHECKED in done.stdout


def test_it_fails_without_a_trust_root_and_with_one_inside_the_folder(record, routes, throwaway_tsa, tmp_path):
    _, out = _fixture(record, throwaway_tsa, routes, tmp_path)
    assert _run(out, None).returncode != 0
    inside = out / "ca.pem"
    inside.write_bytes(Path(throwaway_tsa.ca).read_bytes())
    done = _run(out, inside)
    assert done.returncode == 1 and "FAIL trust root supplied from outside" in done.stdout


def test_a_changed_byte_in_any_file_fails_it(record, routes, throwaway_tsa, tmp_path):
    _, out = _fixture(record, throwaway_tsa, routes, tmp_path)
    for name in sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "verify_one.py"):
        path = out / name
        original = path.read_bytes()
        flipped = bytearray(original)
        flipped[len(flipped) // 2] ^= 1
        path.write_bytes(bytes(flipped))
        done = _run(out, throwaway_tsa.ca)
        assert done.returncode == 1, f"a changed byte in {name} was not caught"
        path.write_bytes(original)
    assert _run(out, throwaway_tsa.ca).returncode == 0


def test_the_file_holds_the_body_only_when_the_contact_is_shown(record, routes, throwaway_tsa, tmp_path):
    _, out = _fixture(record, throwaway_tsa, routes, tmp_path)
    assert not (out / "post_body.json").exists()
    assert "5555550142" not in "".join(p.read_text(errors="replace") for p in out.iterdir() if p.is_file() and p.suffix != ".tsr")


def test_with_the_contact_shown_the_body_is_carried_and_checked(record, routes, throwaway_tsa, tmp_path):
    (tmp_path / "w").mkdir()
    made = mint_link(record, flags={"show_contact": True}, ack=share.CONTACT_ACK)
    zipped = get(routes, made["link_id"], "/record.zip")
    out = tmp_path / "w" / "one"
    with zipfile.ZipFile(io.BytesIO(zipped.raw)) as zf:
        zf.extractall(out)
    assert (out / "post_body.json").exists()
    assert _run(out, throwaway_tsa.ca).returncode == 0
    body = out / "post_body.json"
    body.write_bytes(body.read_bytes().replace(b"checked", b"chacked"))
    assert _run(out, throwaway_tsa.ca).returncode == 1


def test_the_page_and_the_file_both_say_chain_position_is_not_checked(record, routes, throwaway_tsa, tmp_path):
    made, out = _fixture(record, throwaway_tsa, routes, tmp_path)
    assert NOT_CHECKED in text_of(get(routes, made["link_id"]))
    assert NOT_CHECKED in (out / "README.txt").read_text()


def test_the_file_is_the_same_bytes_every_time(record, routes):
    made = mint_link(record)
    a = get(routes, made["link_id"], "/record.zip").raw
    b = get(routes, made["link_id"], "/record.zip").raw
    assert a == b


def test_it_writes_the_fixture_for_the_offline_script(record, routes, throwaway_tsa, tmp_path):
    target = os.environ.get("OFFLINE_FIXTURE_DIR")
    if not target:
        pytest.skip("only the offline script asks for this fixture")
    _, out = _fixture(record, throwaway_tsa, routes, tmp_path)
    dest = Path(target)
    for p in out.iterdir():
        (dest / p.name).write_bytes(p.read_bytes())
    (dest / "tsa_root.pem").write_bytes(Path(throwaway_tsa.ca).read_bytes())
