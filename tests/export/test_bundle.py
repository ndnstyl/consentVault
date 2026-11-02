"""The multi-tenant evidence bundle and the exported verifier (hash version 2)."""

import json
import re
import sys
import subprocess

import pytest

from consentvault.evidence import COVER_STATEMENT, LocalEcdsaSigner, export_tenant, render_verifier
from consentvault.tenancy.tokens import org_transaction

from .support import PHONE, head_anchor, token


@pytest.fixture
def bundle(world, throwaway_tsa, tmp_path):
    t = world
    signer = LocalEcdsaSigner.generate("evidence-test", 3)
    out = tmp_path / "bundle"
    with t.app() as app, org_transaction(app, token(t, t.a)):
        summary = export_tenant(app, t.crypto, PHONE, out, signer=signer)
    pub = tmp_path / "evidence-key.pem"
    pub.write_bytes(signer.public_key_pem())
    return {"t": t, "dir": out, "pub": pub, "ca": throwaway_tsa.ca, "summary": summary, "signer": signer}


def verify(b, *, key=True, extra=()):
    cmd = [sys.executable, str(b["dir"] / "verify.py"), "--cafile", str(b["ca"]), "--anchor",
           head_anchor(b["t"], b["t"].a), *extra]
    if key:
        cmd += ["--evidence-key", str(b["pub"])]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(b["dir"]))


def fail_lines(proc):
    return [ln for ln in proc.stdout.splitlines() if ln.startswith("FAIL")]


def test_the_bundle_carries_wording_attribution_receipts_and_the_cover(bundle):
    data = json.loads((bundle["dir"] / "evidence.json").read_text())
    assert data["multi_tenant"] is True and data["org_id"] == str(bundle["t"].a.org_id)
    assert data["cover"]["statement"] == COVER_STATEMENT
    assert "not a conclusion that consent was valid" in COVER_STATEMENT
    assert (bundle["dir"] / "COVER.txt").read_text().strip() == COVER_STATEMENT
    grant = next(e for e in data["timeline"] if e["event_type"] == "grant")
    assert grant["attribution"] == {"campaign": "alpha-fall", "list": "spring"}
    assert grant["contact_norm"] == PHONE and grant["page_url"] == "https://alpha.example.com/signup"
    assert [d["version_label"] for d in data["disclosures"]] == ["alpha-form v2"]
    assert data["reviews"][0]["message"] == "please stop" and len(data["contact_log"]) == 1
    receipts = json.loads((bundle["dir"] / "receipts.json").read_text())
    assert {r["event_id"] for r in receipts} == {e["event_id"] for e in data["timeline"]}
    assert all(r["key_id"] == "evidence-test" and r["key_version"] == 3 for r in receipts)
    sig = json.loads((bundle["dir"] / "signature.json").read_text())
    assert sig["algorithm"] == "ECDSA_P256_SHA256" and sig["key_id"] == "evidence-test" and sig["key_version"] == 3
    assert len(list((bundle["dir"] / "seals").glob("*.tsr"))) == 2
    assert bundle["summary"]["events"] == 2


def test_the_verifier_accepts_a_multi_tenant_bundle(bundle):
    proc = verify(bundle)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT PASS" in proc.stdout and not fail_lines(proc)
    assert "cover statement present and unchanged" in proc.stdout
    assert "evidence.json signature verifies under the evidence key" in proc.stdout
    assert "evidence digest matches its plaintext fields" in proc.stdout


def test_a_multi_tenant_bundle_fails_without_the_evidence_key(bundle):
    proc = verify(bundle, key=False)
    assert proc.returncode != 0
    assert any("evidence public key supplied from outside the bundle" in ln for ln in fail_lines(proc))


def test_an_evidence_key_kept_inside_the_bundle_is_refused(bundle, tmp_path):
    inside = bundle["dir"] / "seals" / "evidence-key.pem"
    inside.write_bytes(bundle["pub"].read_bytes())
    b = {**bundle, "pub": inside}
    proc = verify(b)
    assert proc.returncode != 0
    assert any("evidence public key supplied from outside the bundle" in ln for ln in fail_lines(proc))


def test_another_organizations_key_does_not_verify_the_bundle(bundle, tmp_path):
    other = LocalEcdsaSigner.generate("someone-else")
    (tmp_path / "other.pem").write_bytes(other.public_key_pem())
    proc = verify({**bundle, "pub": tmp_path / "other.pem"})
    assert proc.returncode != 0
    assert any("evidence.json signature verifies under the evidence key" in ln for ln in fail_lines(proc))
    assert any("receipt signature verifies under the evidence key" in ln for ln in fail_lines(proc))


def _flip(path, marker=None, offset=0):
    raw = bytearray(path.read_bytes())
    idx = len(raw) // 2 if marker is None else raw.index(marker.encode()) + len(marker) + offset
    raw[idx] ^= 0x01
    path.write_bytes(bytes(raw))


FLIPS = [
    ("evidence.json", None, 0, "evidence.json unchanged since export"),
    ("DISCLOSURE", None, 0, "disclosure wording matches its hash"),
    ("SEAL", None, 40, "token file unchanged"),
    ("receipts.json", '"signature":"', 12, "receipt signature verifies under the evidence key"),
    ("signature.json", '"signature":"', 12, "evidence.json signature verifies under the evidence key"),
]


@pytest.mark.parametrize("name,marker,offset,check", FLIPS, ids=[f[3] for f in FLIPS])
def test_flipping_one_byte_fails_the_check_that_names_it(bundle, name, marker, offset, check):
    assert verify(bundle).returncode == 0
    if name == "DISCLOSURE":
        path = next((bundle["dir"] / "disclosures").glob("*.txt"))
    elif name == "SEAL":
        path = sorted((bundle["dir"] / "seals").glob("*.tsr"))[0]
    else:
        path = bundle["dir"] / name
    if marker is None and name == "SEAL":
        raw = bytearray(path.read_bytes())
        raw[offset] ^= 0x01
        path.write_bytes(bytes(raw))
    else:
        _flip(path, marker, offset)
    proc = verify(bundle)
    assert proc.returncode != 0 and "RESULT FAIL" in proc.stdout
    assert any(check in ln for ln in fail_lines(proc)), proc.stdout


def _reseal(bundle, mutate):
    """Rewrite evidence.json and the digest verify.py pins, the way a forger who controls the bundle would."""
    import hashlib

    from consentvault.ledger import canonical_dumps

    data = json.loads((bundle["dir"] / "evidence.json").read_text())
    mutate(data)
    new = (canonical_dumps(data) + "\n").encode()
    (bundle["dir"] / "evidence.json").write_bytes(new)
    v = (bundle["dir"] / "verify.py").read_text()
    v = re.sub(r'EVIDENCE_SHA256 = "[0-9a-f]+"', f'EVIDENCE_SHA256 = "{hashlib.sha256(new).hexdigest()}"', v)
    (bundle["dir"] / "verify.py").write_text(v)


def test_a_forger_who_rewrites_a_plaintext_field_and_repins_the_hash_is_still_caught(bundle):
    def mutate(d):
        d["timeline"][0]["client_ip"] = "198.51.100.9"

    _reseal(bundle, mutate)
    proc = verify(bundle)
    assert proc.returncode != 0
    names = " ".join(fail_lines(proc))
    assert "evidence digest matches its plaintext fields" in names
    assert "evidence.json signature verifies under the evidence key" in names


def test_a_rewritten_cover_statement_is_caught_even_when_the_hash_is_repinned(bundle):
    def mutate(d):
        d["cover"]["statement"] = "This package proves consent was valid."

    _reseal(bundle, mutate)
    proc = verify(bundle)
    assert proc.returncode != 0
    assert any("cover statement present and unchanged" in ln for ln in fail_lines(proc))


def test_an_event_moved_to_another_organization_is_caught(bundle):
    def mutate(d):
        d["timeline"][0]["org_id"] = str(bundle["t"].b.org_id)

    _reseal(bundle, mutate)
    proc = verify(bundle)
    assert proc.returncode != 0 and "RESULT FAIL" in proc.stdout


def test_the_exported_verifier_pins_hash_version_two_and_its_seal_columns():
    text = render_verifier("0" * 64)
    assert '"2": [' in text and "EVIDENCE_V2" in text
    assert "--evidence-key" in text
