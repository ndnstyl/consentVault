"""Evidence bundle export: JSON + disclosure wording + seal tokens + a standalone verifier."""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import io
import json
import os
import shutil
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

import psycopg
from psycopg import sql

from . import dbclock
from .safelog import describe
from .errors import ConsentVaultError
from .ledger import (EVIDENCE_V2, HASH_VERSIONS, _CIPHER_COLUMNS_V2, _canon_value, attribution_digest, canonical_dumps,
                     content_sha256, link_hash)
from .normalize import normalize_contact
from .proof import gather
from .seal import SEAL_HASH_VERSIONS

COVER_STATEMENT = (
    "This package is evidence of what was recorded in this consent vault about one contact point: the events as they "
    "were received, the wording that was shown, the attribution that came with each event, the timestamp seals, the "
    "published chain heads and the platform's signed receipts. It is not a conclusion that consent was valid. Whether "
    "a recorded event amounts to valid consent for a given contact, channel and purpose is a question for the "
    "organization and its advisers, not one this package answers."
)

VERIFY_TEMPLATE = r'''#!/usr/bin/env python3
"""Standalone verifier for a consentvault evidence bundle. Python 3 stdlib and the openssl CLI only.

Usage: python3 verify.py --cafile CA.pem (--anchor SEQ:ROW_HASH ... | --anchors FILE) [--untrusted CERTS.pem]
                         [--evidence-key PUBLIC.pem] [--openssl PATH] [--max-delay SECONDS]

--evidence-key is the platform's published evidence public key (PEM, ECDSA P-256), obtained by you from outside this
bundle. A multi-tenant bundle (hash version 2, evidence.json carries "multi_tenant": true) is signed with that key and
FAILS without it: the signature over evidence.json, the signed receipt of each event and, when the anchors file carries
signed records, each anchor signature are checked against it.

--cafile is required and must be the timestamp authority's root certificate, obtained by you from outside this
bundle. The bundle carries no trust root, so a bundle cannot vouch for itself.

--anchor (repeatable) or --anchors is required and names the chain heads you got from the anchor sink yourself, not
from whoever exported this bundle: SEQ:ROW_HASH, or the file the sink wrote (one JSON record per line with "seq" and
"row_hash"). The chain path must reach every anchor you supply with the same hash, which is what shows the end of the
chain was not cut off. The bundle's own anchors are not trusted; each one must lie on the path with a matching hash.

The chain path must start at seq 1 with the all-zero genesis previous hash and run without a gap to the head, so
nothing can be dropped from the front or the middle. Links of other people carry commitments only.

Recomputes every event row hash and every chain-path link from the link's own commitments, recomputes each
subject event's contact and subject-key commitments from the salt stored in its row (sha256 of the salt followed by
the value; salts are exported only for the subject's own rows, so other people's links carry commitments that
cannot be tested against a guessed contact point), then recomputes which chain-path links carry one of those
commitments and fails any link whose subject flag differs, or any such link whose event is not in the bundle with
full content. It checks each
disclosure file's sha256 and runs `openssl ts -verify` on each seal token. An event without a seal is a FAIL. Prints PASS or FAIL per check, and each event's captured_at,
received_at and the authority's signing time side by side; exits 1 on any FAIL.
It never touches a database or the network.
"""

import argparse
import hashlib
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from base64 import b64decode
from datetime import datetime, timedelta, timezone

HASH_VERSIONS = json.loads(r"""__HASH_VERSIONS__""")
SEAL_HASH_VERSIONS = json.loads(r"""__SEAL_HASH_VERSIONS__""")
EVIDENCE_V2 = json.loads(r"""__EVIDENCE_V2__""")
COVER_STATEMENT = json.loads(r"""
__COVER_STATEMENT__
""")
EVIDENCE_SHA256 = "__EVIDENCE_SHA256__"
GENESIS = "0" * 64
HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES = 0


def report(ok, label, detail=""):
    global FAILURES
    if not ok:
        FAILURES += 1
    print(("PASS " if ok else "FAIL ") + label + ((" -- " + detail) if detail else ""))


def skip(label, detail=""):
    print("SKIP " + label + ((" -- " + detail) if detail else ""))


def info(label, detail=""):
    print("INFO " + label + ((" -- " + detail) if detail else ""))


__CANONICAL_DUMPS__


__LINK_HASH__


def dumps(obj):
    return canonical_dumps(obj)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def salted(salt, text):
    """sha256(salt || text): how the vault commits to a contact point or subject key."""
    return sha256_text(salt + text)


def content_hash(event):
    cols = HASH_VERSIONS.get(str(event.get("hash_version")))
    if cols is None:
        return None
    try:
        return sha256_text(dumps({c: event[c] for c in cols}))
    except KeyError:
        return None


def row_hash(prev_hash, event):
    content = content_hash(event)
    if content is None:
        return None
    try:
        if str(event.get("hash_version")) == "2":
            return link_hash(prev_hash, event["contact_commit"], event["subject_commit"], content)
        return link_hash(prev_hash, event["contact_commit"], salted(event["contact_salt"], event["subject_key"]), content)
    except KeyError:
        return None


def check_signature(openssl, keyfile, message, signature_b64):
    """True when the ECDSA P-256 / SHA-256 signature (base64 DER) over message verifies under the PEM key."""
    try:
        sig = b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, AttributeError, UnicodeEncodeError) as exc:
        return False, "signature is not base64: %s" % exc
    with tempfile.TemporaryDirectory() as tmp:
        mpath, spath = os.path.join(tmp, "m"), os.path.join(tmp, "s")
        with open(mpath, "wb") as fh:
            fh.write(message)
        with open(spath, "wb") as fh:
            fh.write(sig)
        try:
            proc = subprocess.run([openssl, "dgst", "-sha256", "-verify", keyfile, "-signature", spath, mpath],
                                  capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, "openssl could not run: %s" % exc
    out = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0 and "OK" in out, out.splitlines()[-1] if out else "openssl exited %d" % proc.returncode


def seal_digest(event, hash_version, columns):
    """The digest a seal must carry: exactly the vault's algorithm, nothing else is accepted."""
    want = SEAL_HASH_VERSIONS.get(str(hash_version))
    if want is None:
        return None, "unknown seal hash_version %s" % hash_version
    if list(columns) != want:
        return None, "seal columns differ from the columns hash_version %s names" % hash_version
    try:
        return sha256_bytes(dumps({c: event[c] for c in want}).encode("utf-8")), ""
    except KeyError as exc:
        return None, "event lacks sealed column %s" % exc


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def ts_verify(openssl, token_path, digest, cafile, untrusted):
    last = ""
    for extra in ([], ["-token_in"]):
        cmd = [openssl, "ts", "-verify", "-in", token_path, "-digest", digest, "-CAfile", cafile] + extra
        if untrusted:
            cmd += ["-untrusted", untrusted]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, "openssl could not run: %s" % exc
        out = (proc.stdout + proc.stderr).strip()
        if proc.returncode == 0 and "OK" in out:
            return True, "Verification: OK"
        last = out.splitlines()[-1] if out else "openssl exited %d" % proc.returncode
    return False, last


_TIME_RE = re.compile(r"Time stamp:\s*(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(\d{4})")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_iso(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def token_gen_time(openssl, path):
    """The authority's signing time read out of the token itself, never from a field the bundle claims."""
    for extra in ([], ["-token_in"]):
        try:
            proc = subprocess.run([openssl, "ts", "-reply", "-in", path, "-text"] + extra,
                                  capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        m = _TIME_RE.search(proc.stdout + proc.stderr)
        if m and m.group(1) in _MONTHS:
            mon, day, hh, mm, ss, year = m.groups()
            return datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cafile", required=True,
                    help="the authority's root certificate, obtained from outside this bundle")
    ap.add_argument("--anchor", action="append", default=[], metavar="SEQ:ROW_HASH",
                    help="a chain head obtained from the anchor sink itself; repeatable")
    ap.add_argument("--anchors", metavar="FILE",
                    help="an anchor file in the format the sink writes: one JSON record per line with seq and row_hash")
    ap.add_argument("--untrusted")
    ap.add_argument("--evidence-key", metavar="PUBLIC.pem",
                    help="the platform's published evidence public key, obtained from outside this bundle")
    ap.add_argument("--openssl")
    ap.add_argument("--max-delay", type=int, default=86400,
                    help="most seconds a seal's signing time may come after the event's received_at")
    args = ap.parse_args()
    if not args.anchor and not args.anchors:
        ap.error("at least one --anchor SEQ:ROW_HASH or an --anchors FILE is required: "
                 "get the anchors from the anchor sink, not from the exporter")
    max_delay = timedelta(seconds=args.max_delay)

    cafile = os.path.realpath(args.cafile)
    inside = os.path.commonpath([os.path.realpath(HERE), cafile]) == os.path.realpath(HERE)
    report(os.path.isfile(cafile) and not inside, "trust root supplied from outside the bundle",
           "a --cafile inside the bundle directory is refused: the bundle cannot vouch for itself" if inside
           else ("not a file: " + cafile if not os.path.isfile(cafile) else ""))

    trusted_anchors, anchor_problems, anchor_records = [], [], []
    for item in args.anchor:
        seq_text, _, hash_text = item.partition(":")
        if seq_text.isdigit() and int(seq_text) >= 1 and re.fullmatch(r"[0-9a-f]{64}", hash_text):
            trusted_anchors.append((int(seq_text), hash_text))
        else:
            anchor_problems.append("--anchor %r is not SEQ:ROW_HASH (64 lowercase hex)" % item)
    if args.anchors:
        afile = os.path.realpath(args.anchors)
        if os.path.commonpath([os.path.realpath(HERE), afile]) == os.path.realpath(HERE):
            anchor_problems.append("an --anchors file inside the bundle directory is refused: get it from the sink")
        else:
            try:
                with open(afile, encoding="utf-8") as fh:
                    for n, line in enumerate(fh, 1):
                        if not line.strip():
                            continue
                        try:
                            rec = json.loads(line)
                            seq_v, hash_v = int(rec["seq"]), str(rec["row_hash"])
                            if seq_v < 1 or not re.fullmatch(r"[0-9a-f]{64}", hash_v):
                                raise ValueError("bad seq or row_hash")
                            trusted_anchors.append((seq_v, hash_v))
                            anchor_records.append(rec)
                        except (ValueError, KeyError, TypeError) as exc:
                            anchor_problems.append("anchors file line %d is not an anchor record: %s" % (n, exc))
            except OSError as exc:
                anchor_problems.append("cannot read the anchors file: %s" % exc)
    report(not anchor_problems and bool(trusted_anchors), "anchors supplied from outside the bundle",
           "; ".join(anchor_problems) if anchor_problems else ("none usable" if not trusted_anchors else
                                                              "%d anchor(s)" % len(set(trusted_anchors))))

    ev_path = os.path.join(HERE, "evidence.json")
    try:
        raw = read(ev_path)
    except OSError as exc:
        report(False, "evidence.json present", str(exc))
        return 1
    report(sha256_bytes(raw) == EVIDENCE_SHA256, "evidence.json unchanged since export")
    try:
        data = json.loads(raw.decode("utf-8"))
        timeline = data["timeline"]
        chain = data["chain"]
    except (ValueError, KeyError) as exc:
        report(False, "evidence.json parses", str(exc))
        return 1

    if not timeline:
        skip("no events in this bundle", data.get("message", ""))

    openssl = args.openssl or shutil.which("openssl")
    multi = bool(data.get("multi_tenant"))
    if multi:
        report(bool(data.get("org_id")),
               "multi-tenant bundle names its organization")
        keyfile = os.path.realpath(args.evidence_key) if args.evidence_key else None
        key_inside = bool(keyfile) and os.path.commonpath([os.path.realpath(HERE), keyfile]) == os.path.realpath(HERE)
        report(bool(keyfile) and os.path.isfile(keyfile) and not key_inside,
               "evidence public key supplied from outside the bundle",
               "pass --evidence-key with the platform's published public key" if not keyfile else
               ("a key inside the bundle directory is refused: the bundle cannot vouch for itself" if key_inside
                else ("not a file: " + keyfile if not os.path.isfile(keyfile) else "")))
        cover = data.get("cover") or {}
        report(cover.get("statement") == COVER_STATEMENT, "cover statement present and unchanged",
               "" if cover.get("statement") == COVER_STATEMENT else "the cover statement differs from the one this verifier pins")
        info("cover statement", str(cover.get("statement")))
        sig_ok_key = bool(keyfile) and os.path.isfile(keyfile) and not key_inside and bool(openssl)
        try:
            sig_doc = json.loads(read(os.path.join(HERE, "signature.json")).decode("utf-8"))
        except (OSError, ValueError) as exc:
            sig_doc = {}
            report(False, "signature.json present", str(exc))
        if sig_ok_key and sig_doc:
            ok, detail = check_signature(openssl, keyfile, raw, str(sig_doc.get("signature", "")))
            report(ok, "evidence.json signature verifies under the evidence key",
                   "" if ok else detail)
            report(sig_doc.get("signed_sha256") == sha256_bytes(raw), "signature names the evidence.json it signed")
        elif sig_doc:
            report(False, "evidence.json signature verifies under the evidence key",
                   "no usable evidence key or openssl, so the signature cannot be checked")
        try:
            receipts = json.loads(read(os.path.join(HERE, "receipts.json")).decode("utf-8"))
        except (OSError, ValueError) as exc:
            receipts = []
            report(False, "receipts.json present", str(exc))
        receipt_by_event = {r.get("event_id"): r for r in receipts if isinstance(r, dict)}
        for e in timeline:
            rtag = "event %s (seq %s) receipt" % (e["event_id"], e["seq"])
            r = receipt_by_event.get(e["event_id"])
            if r is None:
                report(False, rtag + " present")
                continue
            body = {"org_id": r.get("org_id"), "event_id": r.get("event_id"), "seq": r.get("seq"),
                    "row_hash": r.get("row_hash"), "received_at": r.get("received_at")}
            matches = (body["org_id"] == data.get("org_id") == e.get("org_id") and body["seq"] == e["seq"]
                       and body["row_hash"] == e["row_hash"] and body["received_at"] == e["received_at"])
            report(matches, rtag + " matches the event it names")
            if sig_ok_key:
                ok, detail = check_signature(openssl, keyfile, dumps(body).encode("utf-8"), str(r.get("signature", "")))
                report(ok, rtag + " signature verifies under the evidence key", "" if ok else detail)
        for rec in anchor_records:
            atag = "anchor seq %s" % rec.get("seq")
            if rec.get("org_id") is not None:
                report(rec.get("org_id") == data.get("org_id"), atag + " belongs to this bundle's organization")
            if rec.get("signature"):
                abody = {"org_id": rec.get("org_id"), "seq": rec.get("seq"), "row_hash": rec.get("row_hash"),
                         "anchored_at": rec.get("anchored_at")}
                if sig_ok_key:
                    ok, detail = check_signature(openssl, keyfile, dumps(abody).encode("utf-8"), str(rec["signature"]))
                    report(ok, atag + " signature verifies under the evidence key", "" if ok else detail)

    path = chain.get("path", [])
    head = chain.get("head")
    by_seq = {p["seq"]: p for p in path}
    contiguous = all(
        path[i]["seq"] == path[i - 1]["seq"] + 1 and path[i]["prev_hash"] == path[i - 1]["row_hash"]
        for i in range(1, len(path))
    )
    if timeline:
        report(bool(path) and path[0]["seq"] == 1 and path[0]["prev_hash"] == GENESIS,
               "chain path starts at seq 1 with the genesis previous hash",
               "" if path and path[0]["seq"] == 1 and path[0]["prev_hash"] == GENESIS
               else "the path starts at seq %s: the front of the chain was cut off" % (path[0]["seq"] if path else "none"))
        report(contiguous and bool(path), "chain path from seq 1 to head is contiguous",
               "%d link(s)" % len(path))
        report(bool(head) and bool(path) and path[-1]["row_hash"] == head["row_hash"]
               and path[-1]["seq"] == head["seq"], "chain path ends at the head hash")
        bad_links = [p.get("seq") for p in path
                     if link_hash(p.get("prev_hash", ""), p.get("contact_commit", ""), p.get("subject_commit", ""),
                                  p.get("content_sha256", "")) != p.get("row_hash")]
        report(not bad_links and bool(path), "every chain-path link recomputes from its own commitments",
               "" if not bad_links else "links that do not recompute: %s" % bad_links)
        salts = sorted(set(e["contact_salt"] for e in timeline))
        commits = set(salted(e["contact_salt"], e["contact_norm"]) for e in timeline)
        query = data.get("query") or {}
        key_commits = set(salted(sl, e["subject_key"]) for e in timeline for sl in salts)
        if query.get("subject_key"):
            key_commits |= set(salted(sl, query["subject_key"]) for sl in salts)
        if query.get("contact_norm"):
            commits |= set(salted(sl, query["contact_norm"]) for sl in salts)
        marked = sorted(p["seq"] for p in path if p.get("subject"))
        belongs = sorted(p["seq"] for p in path
                         if p.get("contact_commit") in commits or p.get("subject_commit") in key_commits)
        report(marked == belongs, "the chain path's subject flags match the links that belong to this subject",
               "" if marked == belongs else "flagged %s, belonging %s" % (marked, belongs))
        present = sorted(e["seq"] for e in timeline)
        report(marked == present, "every event the chain marks as this subject's is in the bundle with full content",
               "" if marked == present else "marked %s, present %s" % (marked, present))
        for a in chain.get("anchors", []):
            link = by_seq.get(a["seq"])
            report(link is not None and link["row_hash"] == a["row_hash"],
                   "bundled anchor %s (seq %s) lies on the chain path with the same hash" % (a.get("head_id"), a["seq"]),
                   "" if link is not None else "no link at that seq: the chain path was cut")
        for seq_a, hash_a in sorted(set(trusted_anchors)):
            link = by_seq.get(seq_a)
            report(link is not None and link["row_hash"] == hash_a,
                   "the chain path reaches supplied anchor seq %s with the same hash" % seq_a,
                   ("the path ends at seq %s, before the anchor: the tail was cut" % (path[-1]["seq"] if path else "none"))
                   if link is None else "")

    untrusted = args.untrusted or (os.path.join(HERE, "seals", "untrusted.pem")
                                   if os.path.exists(os.path.join(HERE, "seals", "untrusted.pem")) else None)

    for e in timeline:
        tag = "event %s (seq %s)" % (e["event_id"], e["seq"])
        want = row_hash(e["prev_hash"], e)
        report(want is not None and want == e["row_hash"], tag + " row hash recomputes",
               "unknown hash_version" if want is None else "")
        link = by_seq.get(e["seq"])
        report(link is not None and link["row_hash"] == e["row_hash"] and link["prev_hash"] == e["prev_hash"]
               and link.get("contact_commit") == e.get("contact_commit")
               and link.get("subject_commit") == salted(e["contact_salt"], e["subject_key"])
               and link.get("content_sha256") == content_hash(e),
               tag + " sits on the chain path")
        report(e.get("contact_commit") == salted(e["contact_salt"], e["contact_norm"]),
               tag + " contact commitment matches its salt and contact point")
        if str(e.get("hash_version")) == "2":
            report(e.get("subject_commit") == salted(e["contact_salt"], e["subject_key"]),
                   tag + " subject commitment matches its salt and subject key")
            try:
                digest_ok = e.get("evidence_sha256") == sha256_text(dumps({c: e[c] for c in EVIDENCE_V2}))
            except KeyError:
                digest_ok = False
            report(digest_ok, tag + " evidence digest matches its plaintext fields")
            attribution = e.get("attribution")
            report((e.get("attribution_sha256") is None and attribution is None)
                   or (attribution is not None and e.get("attribution_sha256") == sha256_text(dumps(attribution))),
                   tag + " attribution matches its digest")
            if multi:
                report(e.get("org_id") == data.get("org_id"), tag + " belongs to the bundle's organization")
        sha = e.get("disclosure_sha256")
        if sha:
            p = os.path.join(HERE, "disclosures", sha + ".txt")
            try:
                ok = sha256_bytes(read(p)) == sha
                report(ok, tag + " disclosure wording matches its hash", sha)
            except OSError as exc:
                report(False, tag + " disclosure file present", str(exc))
        seals = e.get("seals", [])
        if not seals:
            report(False, tag + " has an RFC 3161 timestamp seal", "no seal recorded for this event")
        for s in seals:
            stag = tag + " seal %s" % s["seal_id"]
            tok = os.path.join(HERE, s["file"])
            try:
                token = read(tok)
            except OSError as exc:
                report(False, stag + " token file present", str(exc))
                continue
            report(sha256_bytes(token) == s["token_sha256"], stag + " token file unchanged")
            want_digest, why = seal_digest(e, s["hash_version"], s["columns"])
            report(want_digest is not None and want_digest == s["digest"], stag + " digest binds this event", why)
            if not openssl:
                report(False, stag + " openssl ts -verify", "openssl not found; use --openssl")
            else:
                ok, detail = ts_verify(openssl, tok, s["digest"], cafile, untrusted)
                report(ok, stag + " openssl ts -verify", detail)
                gen = token_gen_time(openssl, tok)
                if gen is None:
                    report(False, stag + " signing time readable from the token")
                    continue
                info(stag + " times", "captured_at=%s received_at=%s tsa_gen_time=%s"
                     % (e["captured_at"], e["received_at"], gen.strftime("%Y-%m-%dT%H:%M:%SZ")))
                received = parse_iso(e["received_at"])
                report(gen >= received.replace(microsecond=0), stag + " signing time is not before received_at")
                report(gen - received <= max_delay, stag + " signing time is within the allowed delay after received_at",
                       "max %d s" % args.max_delay)

    print("RESULT " + ("PASS" if FAILURES == 0 else "FAIL (%d check(s) failed)" % FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def verifier_seal_versions() -> dict[int, tuple[str, ...]]:
    """The seal digest definitions the exported verifier pins. Version 2 (multi-tenant rows) covers every hash-version-2
    evidence column plus the chain links, unless the seal module already defines it."""
    versions = dict(SEAL_HASH_VERSIONS)
    versions.setdefault(2, tuple(HASH_VERSIONS[2]) + ("prev_hash", "row_hash"))
    return versions


def render_verifier(evidence_sha256: str) -> str:
    """The standalone verifier script for a bundle whose evidence.json has the given sha256."""
    return (
        VERIFY_TEMPLATE
        .replace("__HASH_VERSIONS__", json.dumps({str(k): list(v) for k, v in HASH_VERSIONS.items()}, sort_keys=True))
        .replace("__SEAL_HASH_VERSIONS__", json.dumps({str(k): list(v) for k, v in verifier_seal_versions().items()}, sort_keys=True))
        .replace("__EVIDENCE_V2__", json.dumps(list(EVIDENCE_V2)))
        .replace("__COVER_STATEMENT__", json.dumps(COVER_STATEMENT))
        .replace("__CANONICAL_DUMPS__", inspect.getsource(canonical_dumps).rstrip())
        .replace("__LINK_HASH__", inspect.getsource(link_hash).rstrip())
        .replace("__EVIDENCE_SHA256__", evidence_sha256)
    )


def export(
    conn: psycopg.Connection,
    query: str,
    out_dir: str | os.PathLike,
    region: str | None = None,
    untrusted: str | os.PathLike | None = None,
) -> dict:
    """Write a self-verifying evidence bundle for a contact. Returns a summary of what was written."""
    result, tokens = gather(conn, query, region)
    out = Path(out_dir)
    (out / "disclosures").mkdir(parents=True, exist_ok=True)
    (out / "seals").mkdir(parents=True, exist_ok=True)

    evidence_bytes = (canonical_dumps(result) + "\n").encode("utf-8")
    (out / "evidence.json").write_bytes(evidence_bytes)

    for d in result["disclosures"]:
        (out / "disclosures" / f"{d['sha256']}.txt").write_bytes(d["body"].encode("utf-8"))
    for name, token in tokens.items():
        (out / "seals" / name).write_bytes(token)
    if untrusted is not None:  # intermediate certificates only; a trust root is never bundled
        p = Path(untrusted)
        if not p.is_file():
            raise ConsentVaultError(f"certificate file not found: {p}")
        shutil.copyfile(p, out / "seals" / "untrusted.pem")

    evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
    script = render_verifier(evidence_sha256)
    verify = out / "verify.py"
    verify.write_text(script, encoding="utf-8")
    verify.chmod(0o755)
    return {
        "out_dir": str(out),
        "found": result["found"],
        "events": len(result["timeline"]),
        "disclosures": len(result["disclosures"]),
        "seals": len(tokens),
        "evidence_sha256": evidence_sha256,
    }


# ---------------------------------------------------------------------------------------------------------------------
# Multi-tenant evidence packages (hash version 2 rows, one organisation, one contact's own data in the clear)
# ---------------------------------------------------------------------------------------------------------------------

BUNDLE_VERSION = 2
SIGNATURE_ALGORITHM = "ECDSA_P256_SHA256"
PACKAGE_CACHE_DAYS = 7
LINK_TTL_SECONDS = 900
PROGRESS_STEPS = 4
_EVENT_COLUMNS_V2 = tuple(dict.fromkeys(tuple(HASH_VERSIONS[2]) + ("prev_hash", "row_hash")))
_ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def _update_sql(cols) -> sql.Composed:
    """UPDATE of export_job for ``cols``; every column is a quoted identifier, every value a parameter."""
    return sql.SQL("UPDATE consentvault.export_job SET {} WHERE org_id = (SELECT consentvault.current_org())"
                   " AND export_id = %s").format(sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(c)) for c in cols))


class ExportError(ConsentVaultError):
    """An evidence package could not be built or served. ``error_name`` is the contract's error name."""

    error_name = "export_failed"


class InvalidContactError(ExportError):
    error_name = "invalid_contact"


class NoRecordsError(ExportError):
    error_name = "no_records"


class KeyUnavailableError(ExportError):
    error_name = "key_unavailable"


class SigningUnavailableError(ExportError):
    error_name = "signing_unavailable"


class ExportIntegrityError(ExportError):
    error_name = "export_integrity_failed"


class ExportStorageError(ExportError):
    error_name = "export_storage_failed"


class OrgSuspendedError(ExportError):
    error_name = "org_suspended"


class OrgNotActiveError(ExportError):
    error_name = "org_not_active"


class ExportNotFoundError(ExportError):
    error_name = "not_found"


class ExportNotReadyError(ExportError):
    error_name = "export_not_ready"


class ExportNotResumableError(ExportError):
    error_name = "export_not_resumable"


class ExportExpiredError(ExportError):
    error_name = "export_expired"


class ExportLinkInvalidError(ExportError):
    error_name = "export_link_invalid"


class ExportLinkUsedError(ExportError):
    error_name = "export_link_used"


class ScopeRefusedError(ExportError):
    error_name = "role_not_allowed"


class ExportValidationError(ExportError):
    error_name = "validation_failed"


class InvalidCursorError(ExportError):
    error_name = "invalid_cursor"


@runtime_checkable
class EvidenceSigner(Protocol):
    """The platform evidence key: ECDSA P-256, signature over SHA-256 of the message, DER encoded (the shape KMS
    returns for an ECC_NIST_P256 key). ``key_id`` and ``key_version`` name which key made a signature."""

    key_id: str
    key_version: int

    def sign(self, message: bytes) -> bytes:
        ...


class LocalEcdsaSigner:
    """An in-process evidence key for the self-host and tests. Needs the ``cloud`` extra (cryptography)."""

    def __init__(self, private_key_pem: bytes, key_id: str, key_version: int = 1) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        try:
            key = serialization.load_pem_private_key(private_key_pem, password=None)
        except (ValueError, TypeError) as exc:
            raise SigningUnavailableError(f"the evidence signing key could not be loaded: {describe(exc)}") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise SigningUnavailableError("the evidence signing key must be an ECDSA P-256 key")
        self._key = key
        self.key_id, self.key_version = key_id, key_version

    @classmethod
    def generate(cls, key_id: str = "evidence-local", key_version: int = 1) -> "LocalEcdsaSigner":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        return cls(pem, key_id, key_version)

    def public_key_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        return self._key.sign(message, ec.ECDSA(hashes.SHA256()))


def _sign(signer: EvidenceSigner, message: bytes) -> str:
    """Base64 of the signer's DER signature. A signer that fails is a named error, never an unsigned package."""
    try:
        sig = signer.sign(message)
    except ConsentVaultError:
        raise
    except Exception as exc:
        raise SigningUnavailableError(f"the evidence key could not sign: {describe(exc)}") from exc
    if not isinstance(sig, bytes) or not sig:
        raise SigningUnavailableError("the evidence key returned no signature")
    return base64.b64encode(sig).decode("ascii")


def receipt_payload(org_id, event_id, seq, row_hash, received_at) -> dict:
    """The fields a capture receipt signs (contracts/capture.md): the platform key signs ``canonical_dumps`` of this."""
    return {"org_id": str(org_id), "event_id": str(event_id), "seq": seq, "row_hash": row_hash,
            "received_at": received_at}


def _canon_time(value) -> str:
    return value.astimezone(timezone.utc).strftime(_ISO)


def _tenant_org(conn: psycopg.Connection):
    from .tenancy.errors import TenantRequiredError

    org = conn.execute("SELECT consentvault.current_org() AS org").fetchone()["org"]
    if org is None:
        raise TenantRequiredError("no tenant entered: build the package inside tenancy.tokens.org_transaction")
    return org


def _require_proof_scope(conn: psycopg.Connection) -> None:
    """An evidence package is built only under a token that carries ``proof_read`` or ``admin``; ``gate_read`` can read
    evidence rows for a permission check, which is not leave to export a person's whole record."""
    scopes = conn.execute("SELECT consentvault.current_token_scopes() AS s").fetchone()["s"] or []
    if not set(scopes) & {"proof_read", "admin"}:
        raise ScopeRefusedError("this token may not build an evidence package")


def contact_fingerprint_of(crypto, org_id, contact: str, region: str | None = None) -> tuple[str, str, str]:
    """(contact_kind, contact_norm, contact_fp) for a contact point the caller typed. Raises InvalidContactError."""
    from .tenancy.errors import KeyProviderError

    try:
        kind, norm = normalize_contact(contact, None, region)
    except ConsentVaultError as exc:
        raise InvalidContactError("the contact point is not a valid phone number or email address") from exc
    try:
        return kind, norm, crypto.contact_fingerprint(org_id, kind, norm)
    except KeyProviderError as exc:
        raise KeyUnavailableError("the organization key could not be used to look this contact up") from exc


def _open_contact_key(conn: psycopg.Connection, crypto, org, fp: str):
    """(data_key, salt) for a contact, or None when the contact's key is gone (erased or never written)."""
    from .tenancy import crypto as tc
    from .tenancy.errors import FieldCryptoError, KeyProviderError
    from .tenancy.keys_protocol import WrappedKey

    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
    if held is None:
        return None
    try:
        data_key = crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
        salt = tc.decrypt_text(data_key, org, fp, "contact_salt", held["salt_ct"])
    except KeyProviderError as exc:
        raise KeyUnavailableError("the organization key could not be used to open this contact's data key") from exc
    except FieldCryptoError as exc:
        raise ExportIntegrityError("a contact's stored salt failed authentication") from exc
    return data_key, salt


def contact_has_records(conn: psycopg.Connection, crypto, fp: str) -> bool:
    """True when this organisation holds a readable event, contact-log entry or review for the fingerprint."""
    org = _tenant_org(conn)
    _require_proof_scope(conn)
    ev = conn.execute("SELECT 1 FROM consentvault.event WHERE org_id = (SELECT consentvault.current_org())"
                      " AND contact_fp = %s LIMIT 1", (fp,)).fetchone()
    if ev is not None:
        return _open_contact_key(conn, crypto, org, fp) is not None  # an erased contact reads as no records
    for table in ("contact_log", "review"):
        if conn.execute(f"SELECT 1 FROM consentvault.{table} WHERE org_id = (SELECT consentvault.current_org())"
                        " AND contact_fp = %s LIMIT 1", (fp,)).fetchone() is not None:
            return True
    return False


def gather_tenant(conn: psycopg.Connection, crypto, contact_fp: str) -> tuple[dict, dict[str, bytes]]:
    """Everything this organisation holds for one contact fingerprint, in the clear for that person only.

    Runs inside an entered tenant with a read scope (``proof_read`` or ``admin``). Returns (evidence structure, {seal
    file name: token bytes}). Other people's chain links carry commitments only. Raises NoRecordsError when nothing is
    held or the contact was erased, KeyUnavailableError when the organization key cannot be used.
    """
    from .tenancy import crypto as tc
    from .tenancy.errors import FieldCryptoError

    org = _tenant_org(conn)
    _require_proof_scope(conn)
    cur_org = "org_id = (SELECT consentvault.current_org())"

    fps, sfps = {contact_fp}, set()
    rows: dict[int, dict] = {}
    while True:
        found = conn.execute(
            f"SELECT * FROM consentvault.event WHERE {cur_org} AND (contact_fp = ANY(%s) OR subject_fp = ANY(%s))",
            (sorted(fps), sorted(sfps))).fetchall()
        before = len(rows)
        for r in found:
            rows[r["seq"]] = r
            fps.add(r["contact_fp"])
            sfps.add(r["subject_fp"])
        if len(rows) == before:
            break

    keys: dict[str, tuple[bytes, str]] = {}
    erased: set[str] = set()
    for fp in sorted({r["contact_fp"] for r in rows.values()}):
        opened = _open_contact_key(conn, crypto, org, fp)
        if opened is None:
            erased.add(fp)
        else:
            keys[fp] = opened
    if contact_fp in erased:
        raise NoRecordsError("no records for that contact in this organization")
    readable = sorted((r for r in rows.values() if r["contact_fp"] in keys), key=lambda r: r["seq"])

    contact_log = conn.execute(
        "SELECT contact_log_uuid, contact_kind, channel, purpose, contacted_at, outcome, ref, recorded_by, recorded_at"
        f" FROM consentvault.contact_log WHERE {cur_org} AND contact_fp = ANY(%s)"
        " ORDER BY contacted_at, contact_log_uuid", (sorted(keys) or [contact_fp],)).fetchall()
    reviews = conn.execute(
        "SELECT review_uuid, kind, contact_kind, contact_fp, message_ct, event_id, status, resolution, created_at,"
        f" resolved_at, resolved_by FROM consentvault.review WHERE {cur_org} AND contact_fp = ANY(%s)"
        " ORDER BY created_at, review_uuid", (sorted(keys) or [contact_fp],)).fetchall()
    if not readable and not contact_log and not reviews:
        raise NoRecordsError("no records for that contact in this organization")

    timeline: list[dict] = []
    for r in readable:
        data_key, salt = keys[r["contact_fp"]]
        rid = str(r["event_id"])
        try:
            plain = {f: (tc.decrypt_text(data_key, org, rid, f, r[col]) if r[col] is not None else None)
                     for f, col in _CIPHER_COLUMNS_V2.items()}
            attribution = json.loads(plain["attribution"]) if plain["attribution"] is not None else None
        except (FieldCryptoError, ValueError) as exc:
            raise ExportIntegrityError(f"event {rid} failed authentication or holds unreadable attribution") from exc
        if r["hash_version"] != 2:
            raise ExportIntegrityError(f"event {rid} is hash version {r['hash_version']}, not a multi-tenant row")
        entry = {c: _canon_value(r[c]) for c in _EVENT_COLUMNS_V2}
        entry.update(
            contact_norm=plain["contact_norm"], contact_salt=salt, subject_key=plain["subject_key"],
            page_url=plain["page_url"], client_ip=plain["client_ip"], user_agent=plain["user_agent"],
            session_ref=plain["session_ref"], attribution=attribution,
            attribution_sha256=attribution_digest(attribution))
        timeline.append(entry)

    event_ids = [e["event_id"] for e in timeline]
    seals = conn.execute(
        "SELECT seal_uuid, event_id, hash_version, columns, digest, tsa_url, token, gen_time, verified_at"
        f" FROM consentvault.seal WHERE {cur_org} AND event_id = ANY(%s::uuid[]) ORDER BY created_at, seal_uuid",
        (event_ids,)).fetchall() if event_ids else []
    tokens: dict[str, bytes] = {}
    seals_by_event: dict[str, list[dict]] = {}
    for s in seals:
        eid = str(s["event_id"])
        bucket = seals_by_event.setdefault(eid, [])
        name = f"{eid}.tsr" if not bucket else f"{eid}.{s['seal_uuid']}.tsr"
        token = bytes(s["token"])
        tokens[name] = token
        bucket.append({
            "seal_id": str(s["seal_uuid"]), "hash_version": s["hash_version"], "columns": list(s["columns"]),
            "digest": bytes(s["digest"]).hex(), "tsa_url": s["tsa_url"], "gen_time": _canon_value(s["gen_time"]),
            "verified_at": _canon_value(s["verified_at"]), "token_sha256": hashlib.sha256(token).hexdigest(),
            "file": f"seals/{name}"})
    for e in timeline:
        e["seals"] = seals_by_event.get(e["event_id"], [])
        e["seal_status"] = "sealed" if e["seals"] else "unsealed"
        e["known_hash_version"] = e["hash_version"] in HASH_VERSIONS

    all_wording = conn.execute(
        f"SELECT sha256, body, label, locale, channels, purposes, first_seen_at FROM consentvault.disclosure"
        f" WHERE {cur_org} ORDER BY first_seen_at, sha256").fetchall()
    version_of: dict[str, str] = {}
    counts: dict[str, int] = {}
    for d in all_wording:
        counts[d["label"]] = counts.get(d["label"], 0) + 1
        version_of[d["sha256"]] = f"{d['label']} v{counts[d['label']]}"
    used = {e["disclosure_sha256"] for e in timeline if e["disclosure_sha256"]}
    disclosures = [{**_canon_dict(d), "version_label": version_of[d["sha256"]]}
                   for d in all_wording if d["sha256"] in used]

    review_items = []
    for v in reviews:
        message = None
        if v["message_ct"] is not None:
            opened = keys.get(v["contact_fp"])
            if opened is None:
                raise NoRecordsError("a review of this contact cannot be read: the contact's key is gone")
            try:
                message = tc.decrypt_text(opened[0], org, str(v["review_uuid"]), "message", v["message_ct"])
            except FieldCryptoError as exc:
                raise ExportIntegrityError(f"review {v['review_uuid']} failed authentication") from exc
        review_items.append({"review_id": str(v["review_uuid"]), "kind": v["kind"], "contact_kind": v["contact_kind"],
                             "message": message, "event_id": _canon_value(v["event_id"]), "status": v["status"],
                             "resolution": v["resolution"], "created_at": _canon_value(v["created_at"]),
                             "resolved_at": _canon_value(v["resolved_at"]), "resolved_by": v["resolved_by"]})

    permissions = conn.execute(
        "SELECT contact_kind, channel, purpose, allowed, reason, deciding_event_id FROM consentvault.current_permission"
        f" WHERE {cur_org} AND contact_fp = ANY(%s) ORDER BY channel, purpose", (sorted(keys) or [contact_fp],)
    ).fetchall()

    subject_seqs = {e["seq"] for e in timeline}
    path = []
    for r in conn.execute(
            f"SELECT {', '.join(_EVENT_COLUMNS_V2)} FROM consentvault.event WHERE {cur_org} ORDER BY seq"):
        if r["hash_version"] != 2:
            raise ExportIntegrityError(f"chain link {r['seq']} is hash version {r['hash_version']}, not version 2")
        path.append({"seq": r["seq"], "prev_hash": r["prev_hash"], "row_hash": r["row_hash"],
                     "contact_commit": r["contact_commit"], "subject_commit": r["subject_commit"],
                     "content_sha256": content_sha256(r, 2), "subject": r["seq"] in subject_seqs})
    head = conn.execute("SELECT seq, row_hash FROM consentvault.ledger_head()").fetchone()
    anchors = [{"head_id": str(a["head_uuid"]), "seq": a["seq"], "row_hash": a["row_hash"], "sink": a["sink"],
                "anchored_at": _canon_value(a["anchored_at"])}
               for a in conn.execute(
                   f"SELECT head_uuid, seq, row_hash, sink, anchored_at FROM consentvault.chain_head WHERE {cur_org}"
                   " ORDER BY anchored_at, seq")]
    org_row = conn.execute(f"SELECT org_id, name FROM consentvault.organization WHERE {cur_org}").fetchone()

    first = next((e for e in timeline if e["contact_fp"] == contact_fp), None)
    kind = first["contact_kind"] if first else (contact_log[0]["contact_kind"] if contact_log else reviews[0]["contact_kind"])
    contacts = sorted({(e["contact_kind"], e["contact_norm"]) for e in timeline})
    result = {
        "bundle_version": BUNDLE_VERSION,
        "multi_tenant": True,
        "org_id": str(org),
        "organization": {"org_id": str(org), "name": org_row["name"] if org_row else None},
        "cover": {"statement": COVER_STATEMENT},
        "query": {"contact_kind": kind, "contact_norm": first["contact_norm"] if first else None,
                  "resolved_as": kind},
        "found": True,
        "message": f"{len(timeline)} consent event(s) found.",
        "tables_read": {"event": len(timeline), "seal": len(seals), "disclosure": len(disclosures),
                        "contact_log": len(contact_log), "review": len(review_items), "chain_head": len(anchors)},
        "erased_contacts_linked": len(erased),
        "contacts": [{"contact_kind": k, "contact_norm": n} for k, n in contacts],
        "subject_keys": sorted({e["subject_key"] for e in timeline}),
        "timeline": timeline,
        "permissions": [{**_canon_dict(p)} for p in permissions],
        "disclosures": disclosures,
        "contact_log": [{"contact_log_id": str(c["contact_log_uuid"]),
                         **_canon_dict({k: v for k, v in c.items() if k != "contact_log_uuid"})} for c in contact_log],
        "reviews": review_items,
        "chain": {"head": _canon_dict(head) if head else None,
                  "events": {e["event_id"]: {"seq": e["seq"], "row_hash": e["row_hash"]} for e in timeline},
                  "path": path, "anchors": anchors},
    }
    return result, tokens


def _canon_dict(row: dict) -> dict:
    return {k: _canon_value(v) for k, v in row.items()}


def build_tenant_files(result: dict, tokens: dict[str, bytes], signer: EvidenceSigner, *,
                       generated_at: datetime | None = None, untrusted: bytes | None = None) -> dict[str, bytes]:
    """Every file of a multi-tenant bundle, signed, as {relative name: bytes}. Nothing touches the disk."""
    result = dict(result)
    result["generated_at"] = _canon_time(generated_at or datetime.now(timezone.utc))
    evidence_bytes = (canonical_dumps(result) + "\n").encode("utf-8")
    evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
    files: dict[str, bytes] = {"evidence.json": evidence_bytes}
    for d in result["disclosures"]:
        files[f"disclosures/{d['sha256']}.txt"] = d["body"].encode("utf-8")
    for name, token in tokens.items():
        files[f"seals/{name}"] = token
    if untrusted is not None:
        files["seals/untrusted.pem"] = untrusted
    receipts = []
    for e in result["timeline"]:
        body = receipt_payload(result["org_id"], e["event_id"], e["seq"], e["row_hash"], e["received_at"])
        receipts.append({**body, "key_id": signer.key_id, "key_version": signer.key_version,
                         "signature": _sign(signer, canonical_dumps(body).encode("utf-8"))})
    files["receipts.json"] = (canonical_dumps(receipts) + "\n").encode("utf-8")
    files["signature.json"] = (canonical_dumps({
        "algorithm": SIGNATURE_ALGORITHM, "key_id": signer.key_id, "key_version": signer.key_version,
        "signed_sha256": evidence_sha, "signed_at": result["generated_at"],
        "signature": _sign(signer, evidence_bytes)}) + "\n").encode("utf-8")
    files["COVER.txt"] = (COVER_STATEMENT + "\n").encode("utf-8")
    files["verify.py"] = render_verifier(evidence_sha).encode("utf-8")
    return files


def write_files(files: dict[str, bytes], out_dir: str | os.PathLike) -> None:
    out = Path(out_dir)
    for name, data in files.items():
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (out / "verify.py").chmod(0o755)


def pack_files(files: dict[str, bytes]) -> bytes:
    """A deterministic zip of the bundle (sorted names, fixed timestamps), so the same bundle packs to the same bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if name == "verify.py" else 0o644) << 16
            zf.writestr(info, files[name])
    return buf.getvalue()


def export_tenant(conn: psycopg.Connection, crypto, contact: str, out_dir: str | os.PathLike, *,
                  signer: EvidenceSigner, region: str | None = None, untrusted: str | os.PathLike | None = None,
                  generated_at: datetime | None = None) -> dict:
    """Write a signed multi-tenant bundle for a contact into a directory. Runs inside an entered tenant."""
    org = _tenant_org(conn)
    _, _, fp = contact_fingerprint_of(crypto, org, contact, region)
    result, tokens = gather_tenant(conn, crypto, fp)
    extra = None
    if untrusted is not None:
        p = Path(untrusted)
        if not p.is_file():
            raise ConsentVaultError(f"certificate file not found: {p}")
        extra = p.read_bytes()
    files = build_tenant_files(result, tokens, signer, generated_at=generated_at, untrusted=extra)
    write_files(files, out_dir)
    return {"out_dir": str(out_dir), "found": True, "events": len(result["timeline"]),
            "disclosures": len(result["disclosures"]), "seals": len(tokens),
            "evidence_sha256": hashlib.sha256(files["evidence.json"]).hexdigest()}


# ---------------------------------------------------------------------------------------------------------------------
# The export service: jobs, the encrypted 7-day cache, one-time proxied download
# ---------------------------------------------------------------------------------------------------------------------

_JOB_FIELDS = ("export_id, contact_fp, status, progress_done, progress_total, failed_cause, requested_by, created_at,"
               " completed_at, package_object_key, package_sha256, signature, expires_at, downloaded_at")
CURSOR_TTL_SECONDS = 86400
_PACKAGE_COLUMN = "export_package"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Actor:
    """Who asked: a portal member (``member``) or a machine credential (``credential``), by id."""

    kind: str
    id: uuid.UUID

    def __post_init__(self) -> None:
        if self.kind not in ("member", "credential"):
            raise ExportError("an actor is a member or a credential")


FINAL_EXPORT_LINK_TTL_SECONDS = 23 * 3600


class ExportService:
    """Builds, caches and serves evidence packages for one vault. Holds no tenant state: every call enters the tenant
    with a short token minted for exactly the scope it needs.

    connect       -> a fresh runtime-role connection (autocommit, dict rows); the service closes it.
    mint_token    -> ``(org_id, scopes) -> token``; called only for a caller whose credential was already verified.
    store         -> an EvidenceStore holding the ciphertext cache; the package is encrypted under the contact's data key,
                     so erasing the contact (deleting its key row) makes the cached copy unreadable.
    link_secret   -> at least 32 bytes; signs download links.
    Every export action writes its audit row (``consentvault.append_audit``) in the same transaction as the action.
    dispatch      -> runs a build; the default runs it inline, the API lane may hand it to a queue.
    """

    def __init__(self, *, connect, mint_token, crypto, signer: EvidenceSigner, store, link_secret: bytes,
                 clock=None, region: str | None = None, dispatch=None, link_ttl: int = LINK_TTL_SECONDS,
                 cache_days: int = PACKAGE_CACHE_DAYS, download_path: str = "/v1/exports") -> None:
        if not isinstance(link_secret, bytes) or len(link_secret) < 32:
            raise ExportError("the export link secret must be at least 32 bytes")
        self._connect, self._mint, self._crypto, self._signer, self._store = connect, mint_token, crypto, signer, store
        self._secret = link_secret
        self._clock = clock or self._database_now   # a clock is injected by tests only; every judgement reads the database's
        self._region, self._link_ttl, self._cache_days, self._path = region, link_ttl, cache_days, download_path
        self._dispatch = dispatch or (lambda fn: fn())

    # plumbing -----------------------------------------------------------------------------------------------------

    def _database_now(self) -> datetime:
        """The database's clock on a short connection of its own, so link, cursor and cache expiry never follow this host's."""
        conn = self._connect()
        try:
            return dbclock.now(conn)
        finally:
            conn.close()

    def _tx(self, org_id, scopes=("proof_read",)):
        from contextlib import contextmanager

        from .tenancy.tokens import org_transaction

        @contextmanager
        def run():
            conn = self._connect()
            try:
                with org_transaction(conn, self._mint(org_id, tuple(scopes))):
                    yield conn
            finally:
                conn.close()

        return run()

    @staticmethod
    def _audit(conn: psycopg.Connection, kind: str, actor_id, action: str, export_id, request_id) -> None:
        conn.execute("SELECT consentvault.append_audit(%s, %s, %s, 'export', %s, NULL, %s)",
                     (kind, str(actor_id), action, str(export_id), request_id or f"export-{uuid.uuid4()}"))

    @staticmethod
    def _check_status(conn: psycopg.Connection, *, for_new_work: bool) -> None:
        row = conn.execute("SELECT status FROM consentvault.organization"
                           " WHERE org_id = (SELECT consentvault.current_org())").fetchone()
        if row is None:
            raise ExportNotFoundError("no such organization")
        if row["status"] == "closed":
            raise OrgNotActiveError("the organization is closed")
        if row["status"] == "suspended" and for_new_work:
            raise OrgSuspendedError("exports are paused while the organization is suspended")

    @staticmethod
    def _job(conn: psycopg.Connection, export_id) -> dict:
        try:
            eid = uuid.UUID(str(export_id))
        except ValueError:
            raise ExportNotFoundError("no such export") from None
        row = conn.execute(f"SELECT {_JOB_FIELDS} FROM consentvault.export_job"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND export_id = %s", (eid,)).fetchone()
        if row is None:
            raise ExportNotFoundError("no such export")
        return row

    def _update(self, conn: psycopg.Connection, export_id, **cols) -> None:
        n = conn.execute(_update_sql(cols), (*cols.values(), uuid.UUID(str(export_id)))).rowcount
        if n != 1:
            raise ExportNotFoundError("the export job vanished while it was being updated")

    # start, build, resume -----------------------------------------------------------------------------------------

    def start(self, org_id, actor: Actor, contact: str, *, request_id: str | None = None) -> dict:
        with self._tx(org_id) as conn:
            self._check_status(conn, for_new_work=True)
            _, _, fp = contact_fingerprint_of(self._crypto, org_id, contact, self._region)
            if not contact_has_records(conn, self._crypto, fp):
                raise NoRecordsError("no records for that contact in this organization")
            export_id, now = uuid.uuid4(), self._clock()
            conn.execute(
                "INSERT INTO consentvault.export_job (org_id, export_id, contact_fp, status, progress_done,"
                " progress_total, requested_by, created_at) VALUES (consentvault.current_org(), %s, %s, 'building', 0,"
                " %s, %s, %s)", (export_id, fp, PROGRESS_STEPS, actor.id, now))
            self._audit(conn, actor.kind, actor.id, "export.create", export_id, request_id)
        self._dispatch(lambda: self.build(org_id, export_id))
        return {"export_id": str(export_id), "status": "building", "created_at": _canon_time(now)}

    def resume(self, org_id, actor: Actor, export_id, *, request_id: str | None = None) -> dict:
        with self._tx(org_id) as conn:
            self._check_status(conn, for_new_work=True)
            job = self._job(conn, export_id)
            if job["status"] != "failed":
                raise ExportNotResumableError("only a failed build can be resumed")
            self._update(conn, job["export_id"], status="building", failed_cause=None, completed_at=None)
            self._audit(conn, actor.kind, actor.id, "export.resume", job["export_id"], request_id)
        self._dispatch(lambda: self.build(org_id, job["export_id"]))
        return {"export_id": str(job["export_id"]), "status": "building"}

    def build(self, org_id, export_id) -> None:
        """Run one build to its end. A named failure is recorded on the job; anything else is recorded and raised."""
        try:
            self._build(org_id, export_id)
        except ConsentVaultError as exc:
            self._fail(org_id, export_id, getattr(exc, "error_name", None) or type(exc).__name__)
        except Exception:
            self._fail(org_id, export_id, "internal_error")
            raise

    def _fail(self, org_id, export_id, cause: str) -> None:
        with self._tx(org_id) as conn:
            self._update(conn, export_id, status="failed", failed_cause=cause, completed_at=self._clock())

    def _progress(self, org_id, export_id, done: int) -> None:
        with self._tx(org_id) as conn:
            self._update(conn, export_id, progress_done=done)

    def _build(self, org_id, export_id) -> None:
        from .providers.errors import EvidenceExistsError, EvidenceNotFoundError, ProviderError
        from .tenancy import crypto as tc
        from .tenancy.errors import FieldCryptoError

        with self._tx(org_id) as conn:
            fp = self._job(conn, export_id)["contact_fp"]
        key_name = f"exports/{export_id}.pkg"

        try:
            cached = self._store.get(str(org_id), key_name)
        except EvidenceNotFoundError:
            cached = None
        except ProviderError as exc:
            raise ExportStorageError(f"the package cache could not be read: {type(exc).__name__}") from exc
        if cached is not None:  # an earlier attempt stored it before the job could be marked ready: keep that copy
            with self._tx(org_id) as conn:
                opened = _open_contact_key(conn, self._crypto, _tenant_org(conn), fp)
            if opened is None:
                raise NoRecordsError("no records for that contact in this organization")
            try:
                package = tc.decrypt_field(opened[0], org_id, str(export_id), _PACKAGE_COLUMN, cached)
                signature = json.loads(_unpack(package)["signature.json"])["signature"]
            except (FieldCryptoError, KeyError, ValueError, zipfile.BadZipFile) as exc:
                raise ExportIntegrityError("the cached package could not be read back") from exc
            self._finalize(org_id, export_id, key_name, package, signature)
            return

        with self._tx(org_id) as conn:
            result, tokens = gather_tenant(conn, self._crypto, fp)
        self._progress(org_id, export_id, 1)

        files = build_tenant_files(result, tokens, self._signer, generated_at=self._clock())
        package = pack_files(files)
        signature = json.loads(files["signature.json"])["signature"]
        self._progress(org_id, export_id, 2)

        with self._tx(org_id) as conn:
            opened = _open_contact_key(conn, self._crypto, _tenant_org(conn), fp)
        if opened is None:
            raise NoRecordsError("no records for that contact in this organization")
        sealed = tc.encrypt_field(opened[0], org_id, str(export_id), _PACKAGE_COLUMN, package)
        self._progress(org_id, export_id, 3)

        try:
            self._store.put(str(org_id), key_name, sealed, retain_until=self._clock() + timedelta(days=self._cache_days))
        except EvidenceExistsError as exc:
            raise ExportStorageError("another build stored a package for this export at the same time") from exc
        except ProviderError as exc:
            raise ExportStorageError(f"the package could not be stored: {type(exc).__name__}") from exc
        self._finalize(org_id, export_id, key_name, package, signature)

    def _finalize(self, org_id, export_id, key_name: str, package: bytes, signature: str) -> None:
        now = self._clock()
        with self._tx(org_id) as conn:
            self._update(conn, export_id, status="ready", progress_done=PROGRESS_STEPS, failed_cause=None,
                         completed_at=now, package_object_key=key_name,
                         package_sha256=hashlib.sha256(package).hexdigest(), signature=signature,
                         expires_at=now + timedelta(days=self._cache_days))

    # reads --------------------------------------------------------------------------------------------------------

    def _public(self, job: dict, *, url: str | None = None) -> dict:
        return {
            "export_id": str(job["export_id"]), "status": job["status"],
            "progress": {"done": job["progress_done"], "total": job["progress_total"]}
            if job["progress_total"] is not None else None,
            "failed_cause": job["failed_cause"], "download_url": url, "sha256": job["package_sha256"],
            "signature": job["signature"],
            "expires_at": _canon_time(job["expires_at"]) if job["expires_at"] else None,
            "downloaded_at": _canon_time(job["downloaded_at"]) if job["downloaded_at"] else None,
        }

    @staticmethod
    def _own(job: dict, requested_by) -> None:
        """A machine credential reads only the exports it created (same org by the tenant, same credential here);
        another one's job reads as absent, so its existence is not disclosed."""
        if requested_by is not None and str(job["requested_by"]) != str(requested_by):
            raise ExportNotFoundError("no such export")

    def status(self, org_id, actor: Actor, export_id, *, request_id: str | None = None, requested_by=None) -> dict:
        with self._tx(org_id) as conn:
            job = self._job(conn, export_id)
            self._own(job, requested_by)
            ready = job["status"] == "ready" and job["downloaded_at"] is None \
                and job["expires_at"] is not None and job["expires_at"] > self._clock()
            suspended = False
            if ready:
                try:
                    self._check_status(conn, for_new_work=True)
                except (OrgSuspendedError, OrgNotActiveError):
                    suspended = True
            url = None
            if ready and not suspended:
                url = self._new_link(org_id, job["export_id"])[0]
                self._audit(conn, actor.kind, actor.id, "export.link", job["export_id"], request_id)
        return self._public(job, url=url)

    def list_jobs(self, org_id, *, status: str | None = None, since: datetime | None = None, until: datetime | None = None,
             limit: int = 50, cursor: str | None = None) -> dict:
        if not 1 <= limit <= 200:
            raise ExportValidationError("limit must be 1 to 200")
        where, params = ["org_id = (SELECT consentvault.current_org())"], []
        if status is not None:
            if status not in ("building", "ready", "failed"):
                raise ExportValidationError("status must be building, ready or failed")
            where.append("status = %s")
            params.append(status)
        if since is not None:
            where.append("created_at >= %s")
            params.append(since)
        if until is not None:
            where.append("created_at <= %s")
            params.append(until)
        if cursor:
            try:
                c = json.loads(_unb64u(cursor))
                issued, at, eid = float(c["t"]), datetime.fromisoformat(c["c"]), uuid.UUID(c["i"])
            except (ValueError, KeyError, TypeError) as exc:
                raise InvalidCursorError("the cursor was not issued by this endpoint") from exc
            if self._clock().timestamp() - issued > CURSOR_TTL_SECONDS:
                raise InvalidCursorError("the cursor has expired")
            where.append("(created_at, export_id) < (%s, %s)")
            params += [at, eid]
        with self._tx(org_id) as conn:
            rows = conn.execute(
                f"SELECT {_JOB_FIELDS} FROM consentvault.export_job WHERE {' AND '.join(where)}"
                " ORDER BY created_at DESC, export_id DESC LIMIT %s", (*params, limit + 1)).fetchall()
        page, more = rows[:limit], len(rows) > limit
        items = [{"export_id": str(j["export_id"]), "status": j["status"], "requested_by": str(j["requested_by"]),
                  "created_at": _canon_time(j["created_at"]),
                  "completed_at": _canon_time(j["completed_at"]) if j["completed_at"] else None,
                  "progress": {"done": j["progress_done"], "total": j["progress_total"]}
                  if j["progress_total"] is not None else None,
                  "contact_fp_hint": j["contact_fp"][:8],
                  "downloaded_at": _canon_time(j["downloaded_at"]) if j["downloaded_at"] else None,
                  "expires_at": _canon_time(j["expires_at"]) if j["expires_at"] else None,
                  "sha256": j["package_sha256"]} for j in page]
        nxt = None
        if more:
            last = page[-1]
            nxt = _b64u(json.dumps({"c": last["created_at"].isoformat(), "i": str(last["export_id"]),
                                    "t": self._clock().timestamp()}).encode("utf-8"))
        return {"items": items, "next_cursor": nxt}

    # links and download -------------------------------------------------------------------------------------------

    def _new_link(self, org_id, export_id, *, path: str | None = None, ttl: int | None = None) -> tuple[str, datetime]:
        now = self._clock()
        expires = now + timedelta(seconds=self._link_ttl if ttl is None else ttl)
        body = json.dumps({"o": str(org_id), "e": str(export_id), "n": uuid.uuid4().hex, "i": now.timestamp(),
                           "x": expires.timestamp()}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self._secret, body, hashlib.sha256).digest()
        return f"{path or self._path + '/' + str(export_id) + '/download'}?link={_b64u(body)}.{_b64u(sig)}", expires

    def _read_link(self, token: str) -> dict:
        try:
            body_b, sig_b = token.split(".")
            body, sig = _unb64u(body_b), _unb64u(sig_b)
            fields = json.loads(body)
            org, eid = uuid.UUID(fields["o"]), uuid.UUID(fields["e"])
            nonce, issued, expires = str(fields["n"]), float(fields["i"]), float(fields["x"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ExportLinkInvalidError("the download link is not valid") from exc
        if not hmac.compare_digest(hmac.new(self._secret, body, hashlib.sha256).digest(), sig):
            raise ExportLinkInvalidError("the download link is not valid")
        if self._clock().timestamp() > expires:
            raise ExportLinkInvalidError("the download link has expired")
        return {"org": org, "export_id": eid, "nonce": nonce, "issued": issued, "expires": expires}

    def issue_link(self, org_id, actor: Actor, export_id, *, request_id: str | None = None, requested_by=None) -> dict:
        with self._tx(org_id) as conn:
            self._check_status(conn, for_new_work=True)
            job = self._job(conn, export_id)
            self._own(job, requested_by)
            if job["status"] != "ready":
                raise ExportNotReadyError("the package is still building or failed")
            if job["expires_at"] is None or job["expires_at"] <= self._clock():
                raise ExportExpiredError("the package is past its retention and can no longer be linked")
            opened = _open_contact_key(conn, self._crypto, _tenant_org(conn), job["contact_fp"])
            if opened is None:
                raise ExportExpiredError("the package can no longer be read: the contact was erased")
            url, expires = self._new_link(org_id, job["export_id"])
            self._audit(conn, actor.kind, actor.id, "export.link", job["export_id"], request_id)
        return {"download_url": url, "expires_at": _canon_time(expires)}

    def issue_final_export_link(self, org_id, offboarding_request_id) -> dict:
        """The one-time download link for an organisation's final export (offboarding). Same signed, single-use link as a
        contact's package; it names the organisation and the offboarding request, lives 23 hours (the replay guard's
        longest memory is a day) and is claimed once by ``claim_final_export_link``."""
        url, expires = self._new_link(org_id, offboarding_request_id, ttl=FINAL_EXPORT_LINK_TTL_SECONDS,
                                      path=f"/v1/offboarding/{offboarding_request_id}/final-export")
        return {"download_url": url, "expires_at": _canon_time(expires)}

    def claim_final_export_link(self, offboarding_request_id, token: str):
        """Check a final-export link and spend it. Returns the organisation id. A second use is ``ExportLinkUsedError``."""
        link = self._read_link(token)
        if str(link["export_id"]) != str(offboarding_request_id):
            raise ExportLinkInvalidError("the download link is not for this final export")
        conn = self._connect()
        try:
            claimed = conn.execute(
                "SELECT consentvault.claim_replay_nonce(%s, %s, %s) AS ok",
                (link["org"], "export-link:" + link["nonce"], datetime.fromtimestamp(link["expires"], timezone.utc)
                 + timedelta(minutes=1))).fetchone()["ok"]
        finally:
            conn.close()
        if not claimed:
            raise ExportLinkUsedError("this download link was already used")
        return link["org"], link["nonce"]

    def download(self, export_id, token: str, *, request_id: str | None = None) -> tuple[bytes, str]:
        """Serve the package once for a link. Returns (zip bytes, sha256). The link is the credential: it names the
        organization and is checked before anything is read, and its nonce is claimed once through the replay guard."""
        from .providers.errors import ProviderError
        from .tenancy import crypto as tc
        from .tenancy.errors import FieldCryptoError

        link = self._read_link(token)
        if str(link["export_id"]) != str(export_id):
            raise ExportLinkInvalidError("the download link is not for this package")
        org_id = link["org"]
        conn = self._connect()
        try:
            claimed = conn.execute(
                "SELECT consentvault.claim_replay_nonce(%s, %s, %s) AS ok",
                (org_id, "export-link:" + link["nonce"], datetime.fromtimestamp(link["expires"], timezone.utc)
                 + timedelta(minutes=1))).fetchone()["ok"]
        finally:
            conn.close()
        if not claimed:
            raise ExportLinkUsedError("this download link was already used")
        with self._tx(org_id) as conn:
            self._check_status(conn, for_new_work=True)
            job = self._job(conn, export_id)
            if job["status"] != "ready":
                raise ExportNotReadyError("the package is still building or failed")
            if job["expires_at"] is None or job["expires_at"] <= self._clock():
                raise ExportExpiredError("the package is past its retention")
            if job["downloaded_at"] is not None and link["issued"] <= job["downloaded_at"].timestamp():
                raise ExportLinkUsedError("this package was downloaded after this link was issued")
            opened = _open_contact_key(conn, self._crypto, _tenant_org(conn), job["contact_fp"])
            if opened is None:
                raise ExportExpiredError("the package can no longer be read: the contact was erased")
            try:
                sealed = self._store.get(str(org_id), job["package_object_key"])
            except ProviderError as exc:
                raise ExportStorageError(f"the cached package could not be read: {type(exc).__name__}") from exc
            try:
                package = tc.decrypt_field(opened[0], org_id, str(job["export_id"]), _PACKAGE_COLUMN, sealed)
            except FieldCryptoError as exc:
                raise ExportIntegrityError("the cached package failed authentication") from exc
            if not hmac.compare_digest(hashlib.sha256(package).hexdigest(), str(job["package_sha256"])):
                raise ExportIntegrityError("the cached package does not match its recorded sha256")
            self._update(conn, job["export_id"], downloaded_at=self._clock())
            self._audit(conn, "system", f"export-link:{link['nonce'][:8]}", "export.download", job["export_id"],
                        request_id)
        return package, job["package_sha256"]


def _unpack(package: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(package)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}
