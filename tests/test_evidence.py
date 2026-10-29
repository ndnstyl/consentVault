import hashlib
import inspect
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import pytest

import tsa as tsa_mod
from consentvault.capture import capture
from consentvault.evidence import export as _export_bundle, render_verifier
from consentvault import seal
from consentvault.ledger import (HASH_VERSIONS, _canon_value, compute_row_hash, content_sha256, contact_commitment,
                          record_event, subject_commitment)
from consentvault.proof import canonical_dumps, lookup

PHONE_A = "+12125550101"


@pytest.fixture(scope="module")
def throwaway_tsa(tmp_path_factory):
    tsa = tsa_mod.build(tmp_path_factory.mktemp("tsa"))
    if tsa is None:
        pytest.skip("this openssl cannot run 'ts -reply' / 'ts -verify'; seal verification not tested")
    return tsa


@pytest.fixture
def ca(throwaway_tsa):
    """The authority's root, kept outside every bundle directory (tmp_path of the test is separate)."""
    return str(throwaway_tsa.ca)


_HEADS = {}


def export(conn, query, out, *args, **kw):
    """Export a bundle and remember the chain head the vault held at that moment, the way a verifier would have
    taken it from the anchor sink."""
    summary = _export_bundle(conn, query, out, *args, **kw)
    head = conn.execute("SELECT seq, row_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1").fetchone()
    _HEADS[str(out)] = "%d:%s" % (head["seq"], head["row_hash"]) if head else None
    return summary


def _verify(out, ca, *extra):
    anchor = [] if any(x.startswith("--anchor") for x in extra) or _HEADS.get(str(out)) is None \
        else ["--anchor", _HEADS[str(out)]]
    return subprocess.run([sys.executable, str(out / "verify.py"), "--cafile", ca, *anchor, *extra],
                          capture_output=True, text=True, cwd=str(out))


def _seal_all(conn, tsa):
    for r in conn.execute("SELECT event_id FROM consentvault.unsealed_events ORDER BY seq").fetchall():
        _seal(conn, tsa, r["event_id"])


@pytest.fixture
def populated(conn, disclosure, throwaway_tsa):
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    record_event(conn, contact=PHONE_A, event_type="revoke", channels=["sms"], purposes=["marketing"],
                 method="keyword", origin="consumer")
    capture(conn, contact="+12125550102", checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    _seal_all(conn, throwaway_tsa)
    return conn


def _populated_unsealed(conn, disclosure):
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    record_event(conn, contact=PHONE_A, event_type="revoke", channels=["sms"], purposes=["marketing"],
                 method="keyword", origin="consumer")
    return conn


def _reseal_manifest(out, data):
    """Rewrite evidence.json and the digest verify.py pins, the way a forger who controls the bundle would."""
    new = (canonical_dumps(data) + "\n").encode()
    (out / "evidence.json").write_bytes(new)
    v = (out / "verify.py").read_text()
    v = re.sub(r'EVIDENCE_SHA256 = "[0-9a-f]+"', f'EVIDENCE_SHA256 = "{hashlib.sha256(new).hexdigest()}"', v)
    (out / "verify.py").write_text(v)


def test_bundle_matches_lookup_and_verifies(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    summary = export(populated, PHONE_A, out)
    assert summary["events"] == 2
    expected = (canonical_dumps(lookup(populated, PHONE_A)) + "\n").encode()
    assert (out / "evidence.json").read_bytes() == expected
    proc = _verify(out, ca)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT PASS" in proc.stdout
    assert "FAIL" not in proc.stdout.replace("RESULT PASS", "")
    assert list((out / "disclosures").glob("*.txt"))
    assert not list((out / "seals").glob("*.pem")), "a trust root must never be bundled"


def test_verifier_prints_each_events_times_beside_the_authoritys_signing_time(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    proc = _verify(out, ca)
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("INFO") and "tsa_gen_time=" in ln]
    assert len(lines) == 2
    for ln in lines:
        assert "captured_at=" in ln and "received_at=" in ln
    for e in lookup(populated, PHONE_A)["timeline"]:
        assert any(e["captured_at"] in ln and e["received_at"] in ln for ln in lines)


def test_a_missing_seal_is_a_failure(populated, ca, tmp_path):
    conn = populated
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=conn.execute(
        "SELECT sha256 FROM consentvault.disclosure").fetchone()["sha256"], channels=["sms"], purposes=["marketing"])
    out = tmp_path / "bundle"
    export(conn, PHONE_A, out)
    proc = _verify(out, ca)
    assert proc.returncode != 0 and "FAIL" in proc.stdout and "has an RFC 3161 timestamp seal" in proc.stdout


def test_a_verifier_without_a_cafile_refuses_to_run(populated, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    proc = subprocess.run([sys.executable, str(out / "verify.py")], capture_output=True, text=True, cwd=str(out))
    assert proc.returncode == 2 and "--cafile" in proc.stderr


def test_a_cafile_taken_from_inside_the_bundle_is_refused(populated, throwaway_tsa, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    inside = out / "seals" / "ca.pem"
    shutil.copyfile(throwaway_tsa.ca, inside)
    proc = _verify(out, str(inside))
    assert proc.returncode != 0 and "trust root supplied from outside the bundle" in proc.stdout
    assert "FAIL" in proc.stdout


def test_a_forged_bundle_with_no_seals_fails(tmp_path, ca):
    """A made-up event with a correct hash and a matching manifest digest, but no outside seal, fails."""
    hv = {c: None for c in HASH_VERSIONS[1]}
    ev = {**hv, "event_id": "00000000-0000-0000-0000-000000000001", "seq": 1, "subject_key": "x",
          "contact_kind": "phone", "contact_norm": PHONE_A, "contact_salt": "a" * 64, "contact_commit": contact_commitment("a" * 64, PHONE_A),
          "event_type": "grant", "channels": ["sms"],
          "purposes": ["marketing"], "method": "checkbox", "origin": "consumer",
          "captured_at": "2020-01-01T00:00:00.000000Z", "received_at": "2020-01-01T00:00:00.000000Z",
          "hash_version": 1}
    ev["prev_hash"] = "0" * 64
    ev["row_hash"] = compute_row_hash(ev["prev_hash"], ev, 1)
    ev["seals"] = []
    data = {"timeline": [ev], "disclosures": [], "chain": {
        "head": {"seq": 1, "row_hash": ev["row_hash"]}, "anchors": [],
        "path": [{"seq": 1, "prev_hash": ev["prev_hash"], "row_hash": ev["row_hash"],
                  "contact_commit": ev["contact_commit"], "subject_commit": subject_commitment("a" * 64, "x"),
                  "content_sha256": content_sha256(ev, 1), "subject": True}]}}
    raw = (canonical_dumps(data) + "\n").encode()
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "evidence.json").write_bytes(raw)
    (out / "verify.py").write_text(render_verifier(hashlib.sha256(raw).hexdigest()))
    proc = _verify(out, ca, "--anchor", "1:" + ev["row_hash"])
    assert proc.returncode != 0 and "has an RFC 3161 timestamp seal" in proc.stdout


def test_dropping_a_stop_from_the_bundle_breaks_the_chain_check(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    data = json.loads((out / "evidence.json").read_text())
    data["timeline"] = [e for e in data["timeline"] if e["event_type"] != "revoke"]
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0
    assert "subject flags match" in proc.stdout and "FAIL" in proc.stdout


def test_the_bundle_holds_full_content_for_every_subject_event(populated, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    data = json.loads((out / "evidence.json").read_text())
    marked = [p["seq"] for p in data["chain"]["path"] if p["subject"]]
    assert marked == [e["seq"] for e in data["timeline"]] and len(marked) == 2
    stop = next(e for e in data["timeline"] if e["event_type"] == "revoke")
    assert stop["method"] == "keyword" and stop["channels"] == ["sms"] and stop["purposes"] == ["marketing"]
    assert len(data["chain"]["path"]) == 3  # the other person's event is a hash-only link


def test_export_is_byte_identical_between_runs(populated, tmp_path):
    export(populated, PHONE_A, tmp_path / "a")
    export(populated, PHONE_A, tmp_path / "b")
    for name in ("evidence.json", "verify.py"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_tampered_evidence_fails(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    p = out / "evidence.json"
    text = p.read_text()
    assert '"method":"keyword"' in text
    p.write_text(text.replace('"method":"keyword"', '"method":"written"'))
    proc = _verify(out, ca)
    assert proc.returncode != 0
    assert "FAIL" in proc.stdout


def test_tampered_row_with_matching_manifest_still_fails_row_hash(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    p = out / "evidence.json"
    data = json.loads(p.read_text())
    data["timeline"][0]["client_ip"] = "198.51.100.9"
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0
    assert "row hash recomputes" in proc.stdout and "FAIL event" in proc.stdout


def test_tampered_disclosure_fails(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    f = next((out / "disclosures").glob("*.txt"))
    f.write_bytes(f.read_bytes() + b"x")
    proc = _verify(out, ca)
    assert proc.returncode != 0
    assert "FAIL" in proc.stdout and "disclosure" in proc.stdout


def test_missing_disclosure_fails(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    next((out / "disclosures").glob("*.txt")).unlink()
    assert _verify(out, ca).returncode != 0


def test_unknown_contact_bundle_says_no_record(conn, disclosure, ca, tmp_path):
    capture(conn, contact="+12125550102", checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    out = tmp_path / "bundle"
    summary = export(conn, "+12125550199", out)
    assert summary["found"] is False
    data = json.loads((out / "evidence.json").read_text())
    assert "No record" in data["message"]
    proc = _verify(out, ca)
    assert proc.returncode == 0
    assert "SKIP" in proc.stdout


def _seal(conn, tsa, event_id, *_ignored, hash_version=None):
    """Seal one event exactly the way the vault does: seal.digest over the columns the version names."""
    version = hash_version or seal.current_hash_version()
    row = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (event_id,)).fetchone()
    d = seal.digest(row, version)
    conn.execute(
        "INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token, gen_time)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (event_id, version, list(seal.SEAL_HASH_VERSIONS[version]), d, "https://tsa.example.com",
         tsa.stamp(d.hex()), datetime.now(timezone.utc)),
    )


def _seal_raw(conn, tsa, event_id, columns, digest_hex, hash_version=None):
    conn.execute(
        "INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token, gen_time)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (event_id, hash_version or seal.current_hash_version(), columns, bytes.fromhex(digest_hex),
         "https://tsa.example.com", tsa.stamp(digest_hex), datetime.now(timezone.utc)),
    )


@pytest.mark.parametrize("form", ["row_hash", "prev_plus_canon", "short_columns"])
def test_bundle_accepts_no_digest_but_the_vaults(conn, disclosure, throwaway_tsa, ca, tmp_path, form):
    populated = _populated_unsealed(conn, disclosure)
    import hashlib
    e = lookup(populated, PHONE_A)["timeline"][0]
    row = populated.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (e["event_id"],)).fetchone()
    cols = list(seal.SEAL_HASH_VERSIONS[seal.current_hash_version()])
    if form == "row_hash":
        _seal_raw(populated, throwaway_tsa, e["event_id"], cols, row["row_hash"])
    elif form == "prev_plus_canon":
        canon = canonical_dumps({c: _canon_value(row[c]) for c in cols})
        _seal_raw(populated, throwaway_tsa, e["event_id"], cols,
                  hashlib.sha256((row["prev_hash"] + canon).encode()).hexdigest())
    else:
        short = ["event_id", "row_hash"]
        canon = canonical_dumps({c: _canon_value(row[c]) for c in short})
        _seal_raw(populated, throwaway_tsa, e["event_id"], short, hashlib.sha256(canon.encode()).hexdigest())
    assert lookup(populated, PHONE_A)["timeline"][0]["seals"][0]["digest_binds_event"] is False
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    proc = _verify(out, ca)
    assert proc.returncode != 0 and "digest binds this event" in proc.stdout and "FAIL" in proc.stdout


def test_bundle_digest_is_the_vaults_digest(populated, ca, tmp_path):
    """The exported verifier and seal.digest agree on a sample row set."""
    rows = populated.execute("SELECT * FROM consentvault.event ORDER BY seq").fetchall()
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    ns = {"__file__": str(out / "verify.py")}
    src = (out / "verify.py").read_text()
    exec(compile(src.split("def main():")[0], "verify.py", "exec"), ns)
    for r in rows:
        for version in seal.SEAL_HASH_VERSIONS:
            mine, why = ns["seal_digest"]({c: _canon_value(v) for c, v in r.items()}, version,
                                          list(seal.SEAL_HASH_VERSIONS[version]))
            assert mine == seal.digest(r, version).hex(), why
    proc = _verify(out, ca)
    assert proc.returncode == 0, proc.stdout


def test_seals_verify_with_openssl_and_detect_tampering(populated, ca, tmp_path):
    res = lookup(populated, PHONE_A)
    assert all(e["seal_status"] == "sealed" and e["seals"][0]["digest_binds_event"] for e in res["timeline"])

    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    proc = _verify(out, ca)
    assert proc.returncode == 0, proc.stdout
    assert proc.stdout.count("openssl ts -verify") == 2 and "FAIL" not in proc.stdout.replace("RESULT PASS", "")

    token = next((out / "seals").glob("*.tsr"))
    raw = bytearray(token.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    token.write_bytes(bytes(raw))
    bad = _verify(out, ca)
    assert bad.returncode != 0 and "FAIL" in bad.stdout


def test_the_wrong_trust_root_fails_every_seal(populated, tmp_path_factory, tmp_path):
    other = tsa_mod.build(tmp_path_factory.mktemp("other-tsa"))
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    proc = _verify(out, str(other.ca))
    assert proc.returncode != 0 and "FAIL" in proc.stdout


def test_a_bundle_exported_after_the_tail_was_cut_fails_against_the_anchor(conn, disclosure, throwaway_tsa, ca, tmp_path):
    from consentvault import anchor as anchor_mod
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure, channels=["sms"], purposes=["marketing"])
    record_event(conn, contact=PHONE_A, event_type="revoke", channels=["sms"], purposes=["marketing"],
                 method="keyword", origin="consumer")
    _seal_all(conn, throwaway_tsa)
    anchor_mod.anchor(conn, str(tmp_path / "anchors.jsonl"))
    conn.execute("ALTER TABLE consentvault.seal DISABLE TRIGGER USER")
    conn.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
    conn.execute("DELETE FROM consentvault.seal WHERE event_id IN (SELECT event_id FROM consentvault.event WHERE seq = 2)")
    conn.execute("DELETE FROM consentvault.event WHERE seq = 2")
    out = tmp_path / "bundle"
    export(conn, PHONE_A, out)
    sink_line = json.loads((tmp_path / "anchors.jsonl").read_text().splitlines()[-1])
    proc = _verify(out, ca, "--anchor", "%d:%s" % (sink_line["seq"], sink_line["row_hash"]))
    assert proc.returncode != 0
    assert "FAIL the chain path reaches supplied anchor seq 2 with the same hash" in proc.stdout
    assert "the tail was cut" in proc.stdout


def _revoke_seq(data):
    return next(e["seq"] for e in data["timeline"] if e["event_type"] == "revoke")


def test_hiding_a_stop_and_unflagging_its_link_still_fails(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    data = json.loads((out / "evidence.json").read_text())
    seq = _revoke_seq(data)
    data["timeline"] = [e for e in data["timeline"] if e["event_type"] != "revoke"]
    for link in data["chain"]["path"]:
        if link["seq"] == seq:
            link["subject"] = False
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0
    assert "FAIL the chain path's subject flags match the links that belong to this subject" in proc.stdout


def test_hiding_a_stop_and_rewriting_its_commitment_breaks_the_link(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    data = json.loads((out / "evidence.json").read_text())
    seq = _revoke_seq(data)
    data["timeline"] = [e for e in data["timeline"] if e["event_type"] != "revoke"]
    for link in data["chain"]["path"]:
        if link["seq"] == seq:
            link["subject"] = False
            link["contact_commit"] = "f" * 64
            link["subject_commit"] = "e" * 64
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0
    assert "FAIL every chain-path link recomputes from its own commitments" in proc.stdout


def test_flipping_the_flag_of_a_link_that_belongs_to_the_subject_fails(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    data = json.loads((out / "evidence.json").read_text())
    for link in data["chain"]["path"]:
        if link["seq"] == data["timeline"][0]["seq"]:
            link["subject"] = False
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0 and "subject flags match" in proc.stdout


def test_flagging_another_persons_link_fails(populated, ca, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    data = json.loads((out / "evidence.json").read_text())
    other = next(p for p in data["chain"]["path"] if not p["subject"])
    other["subject"] = True
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0 and "subject flags match" in proc.stdout


def test_the_links_of_other_people_carry_only_commitments(populated, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    raw = (out / "evidence.json").read_text()
    assert "+12125550102" not in raw  # the other person's contact point is not in the bundle
    data = json.loads(raw)
    other = next(p for p in data["chain"]["path"] if not p["subject"])
    assert other["contact_commit"] != contact_commitment("", "+12125550102")
    assert set(other) == {"seq", "prev_hash", "row_hash", "contact_commit", "subject_commit", "content_sha256",
                          "subject"}


def _all_digests(texts):
    out = set()
    for t in texts:
        out.add(hashlib.sha256(t.encode("utf-8")).hexdigest())
        out.add(hashlib.sha256(hashlib.sha256(t.encode("utf-8")).hexdigest().encode("utf-8")).hexdigest())
    return out


def test_a_bundle_holds_no_unsalted_digest_of_another_contact(populated, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    raw = (out / "evidence.json").read_text()
    data = json.loads(raw)
    other_phone = "+12125550102"
    guesses = _all_digests([other_phone, other_phone.lstrip("+"), other_phone[2:], other_phone[-10:]])
    assert not any(g in raw for g in guesses)
    other = next(p for p in data["chain"]["path"] if not p["subject"])
    assert other["contact_commit"] not in guesses and other["subject_commit"] not in guesses
    own_salts = {e["contact_salt"] for e in data["timeline"]}
    for link in data["chain"]["path"]:
        if not link["subject"]:
            assert "contact_salt" not in link
    row = populated.execute("SELECT contact_salt FROM consentvault.event WHERE contact_norm = %s",
                            (other_phone,)).fetchone()
    assert row["contact_salt"] not in own_salts and row["contact_salt"] not in raw


def test_a_guessed_phone_cannot_be_matched_to_another_persons_link(populated, tmp_path):
    out = tmp_path / "bundle"
    export(populated, PHONE_A, out)
    data = json.loads((out / "evidence.json").read_text())
    other = next(p for p in data["chain"]["path"] if not p["subject"])
    guess = "+12125550102"
    salts = {e["contact_salt"] for e in data["timeline"]} | {""}
    assert all(contact_commitment(salt, guess) != other["contact_commit"] for salt in salts)
    assert all(subject_commitment(salt, guess) != other["subject_commit"] for salt in salts)
    assert all(subject_commitment(salt, hashlib.sha256(guess.encode()).hexdigest()) != other["subject_commit"]
               for salt in salts)


def test_one_contact_has_one_salt_and_two_contacts_have_different_ones(conn, disclosure):
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    record_event(conn, contact=PHONE_A, event_type="revoke", channels=["sms"], purposes=["marketing"],
                 method="keyword", origin="consumer")
    capture(conn, contact="+12125550102", checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    rows = conn.execute("SELECT contact_norm, contact_salt, contact_commit FROM consentvault.event ORDER BY seq").fetchall()
    assert rows[0]["contact_salt"] == rows[1]["contact_salt"] and rows[0]["contact_commit"] == rows[1]["contact_commit"]
    assert rows[2]["contact_salt"] != rows[0]["contact_salt"] and len(rows[0]["contact_salt"]) == 64
    assert conn.execute("SELECT count(*) AS n FROM consentvault.contact_salt").fetchone()["n"] == 2


# what the verifier needs from outside, and what it refuses to accept from the bundle --------------------------

def _prepare_staff_stop_bundle(conn, disclosure, tsa, tmp_path):
    record_event(conn, contact=PHONE_A, event_type="suppress", channels=["sms"], purposes=["*"], method="staff",
                 origin="staff")
    capture(conn, contact="+12125550102", checked=True, disclosure_sha256=disclosure, channels=["sms"],
            purposes=["marketing"])
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure, channels=["sms"],
            purposes=["marketing"], session_ref="s")
    _seal_all(conn, tsa)
    out = tmp_path / "bundle"
    export(conn, PHONE_A, out)
    return out


def test_the_chain_path_starts_at_the_first_event_of_the_ledger(conn, disclosure, throwaway_tsa, ca, tmp_path):
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    data = json.loads((out / "evidence.json").read_text())
    assert [p["seq"] for p in data["chain"]["path"]] == [1, 2, 3]
    assert data["chain"]["path"][0]["prev_hash"] == "0" * 64
    assert _verify(out, ca).returncode == 0


def test_starting_the_path_after_an_earlier_stop_is_refused(conn, disclosure, throwaway_tsa, ca, tmp_path):
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    data = json.loads((out / "evidence.json").read_text())
    data["timeline"] = [e for e in data["timeline"] if e["event_type"] != "suppress"]
    data["chain"]["path"] = [p for p in data["chain"]["path"] if p["seq"] >= 2]
    data["permissions"] = [dict(p, allowed=True, reason="granted") for p in data["permissions"]]
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0
    assert "FAIL chain path starts at seq 1 with the genesis previous hash" in proc.stdout


def test_a_path_that_stops_short_of_a_supplied_anchor_is_refused(conn, disclosure, throwaway_tsa, ca, tmp_path):
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    head = conn.execute("SELECT seq, row_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1").fetchone()
    data = json.loads((out / "evidence.json").read_text())
    data["timeline"] = data["timeline"][:-1]
    data["chain"]["path"] = [p for p in data["chain"]["path"] if p["seq"] <= 2]
    data["chain"]["head"] = {"seq": 2, "row_hash": data["chain"]["path"][-1]["row_hash"]}
    data["chain"]["anchors"] = []
    _reseal_manifest(out, data)
    proc = _verify(out, ca, "--anchor", "%d:%s" % (head["seq"], head["row_hash"]))
    assert proc.returncode != 0
    assert "FAIL the chain path reaches supplied anchor seq 3 with the same hash" in proc.stdout


def test_a_supplied_anchor_with_a_different_hash_is_refused(conn, disclosure, throwaway_tsa, ca, tmp_path):
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    proc = _verify(out, ca, "--anchor", "3:" + "ab" * 32)
    assert proc.returncode != 0 and "FAIL the chain path reaches supplied anchor seq 3" in proc.stdout


def test_the_verifier_will_not_run_without_an_anchor(conn, disclosure, throwaway_tsa, ca, tmp_path):
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    proc = subprocess.run([sys.executable, str(out / "verify.py"), "--cafile", ca], capture_output=True, text=True,
                          cwd=str(out))
    assert proc.returncode == 2 and "--anchor" in proc.stderr


def test_an_anchor_file_in_the_sinks_format_is_accepted(conn, disclosure, throwaway_tsa, ca, tmp_path):
    from consentvault import anchor as anchor_mod
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    sink = tmp_path / "sink" / "anchors.jsonl"
    sink.parent.mkdir()
    anchor_mod.anchor(conn, str(sink))
    proc = subprocess.run([sys.executable, str(out / "verify.py"), "--cafile", ca, "--anchors", str(sink)],
                          capture_output=True, text=True, cwd=str(out))
    assert proc.returncode == 0, proc.stdout
    assert "PASS the chain path reaches supplied anchor seq 3 with the same hash" in proc.stdout


def test_an_anchor_file_kept_inside_the_bundle_is_refused(conn, disclosure, throwaway_tsa, ca, tmp_path):
    from consentvault import anchor as anchor_mod
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    inside = out / "anchors.jsonl"
    anchor_mod.anchor(conn, str(inside))
    proc = subprocess.run([sys.executable, str(out / "verify.py"), "--cafile", ca, "--anchors", str(inside)],
                          capture_output=True, text=True, cwd=str(out))
    assert proc.returncode != 0 and "inside the bundle directory is refused" in proc.stdout


def test_a_bundled_anchor_that_is_not_on_the_path_is_refused(conn, disclosure, throwaway_tsa, ca, tmp_path):
    out = _prepare_staff_stop_bundle(conn, disclosure, throwaway_tsa, tmp_path)
    data = json.loads((out / "evidence.json").read_text())
    data["chain"]["anchors"] = [{"head_id": 9, "seq": 7, "row_hash": "cd" * 32, "sink": "x", "anchored_at": "t"}]
    _reseal_manifest(out, data)
    proc = _verify(out, ca)
    assert proc.returncode != 0 and "FAIL bundled anchor 9 (seq 7)" in proc.stdout
