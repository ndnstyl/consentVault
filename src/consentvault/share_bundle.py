"""The one-record file (``record.zip``) of a record link, and the small program inside it that checks it offline.

The file holds the sealed row, the seals' tokens, the registered wording, the stored post's hashes and its seal, the post body only
when the link shows the contact point, and ``verify_one.py``. The program needs Python 3 and the openssl command line, never a
database or the network, and a timestamp authority root certificate that the person checking obtains from outside the folder.

What it checks: each recomputation the page shows (the content hash and the row hash of the sealed row, each seal's digest, each
token against the root certificate, the signing time against the arrival time, the wording hash, the stored post's own hash and its
seal), and that no file in the folder changed since the file was made (``record.json`` by the hash pinned inside the program, every
other file by the list in ``record.json``). What it does not check: where this row sits in the whole chain, and whether a later
record exists. It says so in its output and in ``README.txt``; the full export bundle checks the chain.

The same bytes come out every time for the same record and settings: fixed file times, a fixed order, no clock.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import zipfile

from .ledger import HASH_VERSIONS, canonical_dumps, link_hash
from .share import CHAIN_NOT_CHECKED, CODE_VERSION, FORMAT_VERSION, RULE_SET
from .share_render import public_json

_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

VERIFY_ONE = r'''#!/usr/bin/env python3
"""Offline check of one consentvault record. Python 3 and the openssl command line only; no network, no database.

Usage: python3 verify_one.py --cafile ROOT.pem [--untrusted CERTS.pem] [--openssl PATH] [--max-delay SECONDS]

--cafile is required: the timestamp authority's root certificate, which you obtain yourself from outside this folder. A file
inside this folder is refused, because the folder cannot vouch for itself.

Prints PASS, FAIL or SKIP per check and "RESULT PASS" or "RESULT FAIL"; exits 1 on any FAIL.
This program does not check where this record sits in the whole chain, and it does not show whether a later record exists.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

HASH_VERSION_2_COLUMNS = json.loads(r"""__COLUMNS__""")
RECORD_SHA256 = "__RECORD_SHA256__"
CHAIN_NOT_CHECKED = __CHAIN_NOT_CHECKED__
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


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def read(name):
    with open(os.path.join(HERE, name), "rb") as fh:
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
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_iso(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def token_gen_time(openssl, path):
    """The authority's signing time read out of the token itself, never from a field the file claims."""
    for extra in ([], ["-token_in"]):
        try:
            proc = subprocess.run([openssl, "ts", "-reply", "-in", path, "-text"] + extra, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        m = _TIME_RE.search(proc.stdout + proc.stderr)
        if m and m.group(1) in _MONTHS:
            mon, day, hh, mm, ss, year = m.groups()
            return datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    return None


def check_seals(label, seals, canon, received_at, files, openssl, cafile, untrusted, max_delay):
    if not seals:
        report(False, label + " has a timestamp seal", "no seal recorded")
    for i, s in enumerate(seals):
        tag = label + " seal %d" % (i + 1)
        cols = list(s["columns"])
        try:
            want = sha256_text(canonical_dumps({c: canon[c] for c in cols}))
        except KeyError as exc:
            report(False, tag + " digest recomputes", "the file lacks sealed column %s" % exc)
            continue
        report(want == s["digest"], tag + " digest recomputes from the sealed columns")
        token = files.get(s["file"])
        if token is None:
            report(False, tag + " token file present", s["file"])
            continue
        path = os.path.join(HERE, s["file"])
        if not openssl:
            report(False, tag + " openssl ts -verify", "openssl not found; use --openssl")
            continue
        ok, detail = ts_verify(openssl, path, s["digest"], cafile, untrusted)
        report(ok, tag + " openssl ts -verify against the root you supplied", "" if ok else detail)
        gen = token_gen_time(openssl, path)
        if gen is None:
            report(False, tag + " signing time readable from the token")
            continue
        info(tag + " times", "received_at=%s tsa_gen_time=%s" % (received_at, gen.strftime("%Y-%m-%dT%H:%M:%SZ")))
        received = parse_iso(received_at)
        report(gen >= received.replace(microsecond=0), tag + " signing time is not before arrival")
        report(gen - received <= max_delay, tag + " signing time is within the allowed delay after arrival",
               "max %d s" % int(max_delay.total_seconds()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cafile", required=True, help="the authority's root certificate, obtained from outside this folder")
    ap.add_argument("--untrusted")
    ap.add_argument("--openssl")
    ap.add_argument("--max-delay", type=int, default=86400)
    args = ap.parse_args()
    max_delay = timedelta(seconds=args.max_delay)
    cafile = os.path.realpath(args.cafile)
    inside = os.path.commonpath([os.path.realpath(HERE), cafile]) == os.path.realpath(HERE)
    report(os.path.isfile(cafile) and not inside, "trust root supplied from outside the folder",
           "a --cafile inside the folder is refused: the folder cannot vouch for itself" if inside
           else ("not a file: " + cafile if not os.path.isfile(cafile) else ""))
    if inside or not os.path.isfile(cafile):
        print("RESULT FAIL (%d check(s) failed)" % FAILURES)
        return 1
    openssl = args.openssl or shutil.which("openssl")
    try:
        raw = read("record.json")
    except OSError as exc:
        report(False, "record.json present", str(exc))
        print("RESULT FAIL (%d check(s) failed)" % FAILURES)
        return 1
    report(sha256_bytes(raw) == RECORD_SHA256, "record.json unchanged since the file was made")
    try:
        rec = json.loads(raw.decode("utf-8"))
        event, flags = rec["event"], rec["flags"]
        manifest = rec["files"]
    except (ValueError, KeyError) as exc:
        report(False, "record.json parses", str(exc))
        print("RESULT FAIL (%d check(s) failed)" % FAILURES)
        return 1
    files = {}
    for name, digest in sorted(manifest.items()):
        try:
            data = read(name)
        except OSError as exc:
            report(False, name + " present", str(exc))
            continue
        files[name] = data
        report(sha256_bytes(data) == digest, name + " unchanged since the file was made")

    withheld = bool(rec.get("withheld"))
    if withheld:
        skip("content hash, row hash and seal digests", "this link withholds " + ", ".join(rec["withheld"]) + ", an input of those hashes")
    else:
        content = sha256_text(canonical_dumps({c: event[c] for c in HASH_VERSION_2_COLUMNS}))
        info("content hash", content)
        report(link_hash(event["prev_hash"], event["contact_commit"], event["subject_commit"], content) == event["row_hash"],
               "row hash recomputes from the previous hash, the two commitments and the content hash")
        check_seals("event", rec["seals"], event, event["received_at"], files, openssl, cafile, args.untrusted, max_delay)

    wording = files.get("wording.txt")
    if rec.get("wording_registered") is not None:
        report(wording is not None and sha256_bytes(wording) == event["disclosure_sha256"],
               "registered wording text hashes to the wording hash the row carries")
    post = rec.get("post")
    if post:
        canon = post["canonical"]
        report(sha256_text(canonical_dumps(canon)) == post["row_hash"], "stored post row hash recomputes from its columns")
        check_seals("post", post["seals"], canon, post["received_at"], files, openssl, cafile, args.untrusted, max_delay)
        body = files.get("post_body.json")
        if body is not None:
            report(sha256_bytes(body) == post["body_sha256"], "post body hashes to the body hash the post row carries")
        else:
            info("post body", "withheld on this link; its hash and seal are checked above")

    info("what this does not check", CHAIN_NOT_CHECKED)
    print("RESULT " + ("PASS" if FAILURES == 0 else "FAIL (%d check(s) failed)" % FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def render_verify_one(record_sha256: str) -> str:
    return (VERIFY_ONE
            .replace("__COLUMNS__", json.dumps(list(HASH_VERSIONS[2])))
            .replace("__RECORD_SHA256__", record_sha256)
            .replace("__CHAIN_NOT_CHECKED__", json.dumps(CHAIN_NOT_CHECKED))
            .replace("__CANONICAL_DUMPS__", inspect.getsource(canonical_dumps).rstrip())
            .replace("__LINK_HASH__", inspect.getsource(link_hash).rstrip()))


def _readme(view: dict) -> str:
    return (
        "Consent record: the one-record file\n\n"
        "This folder holds one sealed record, its timestamp seals and a small program that recomputes the checks on your own machine.\n"
        "It needs Python 3 and the openssl command line. It does not use a network.\n\n"
        "To run it, get the timestamp authority's root certificate yourself (not from this folder) and run:\n\n"
        "    python3 verify_one.py --cafile ROOT.pem\n\n"
        f"{view['statements']['one_record']}\n"
        f"{view['statements']['not_an_opinion']}\n"
        f"{CHAIN_NOT_CHECKED}\n\n"
        f"File format {FORMAT_VERSION}, code version {CODE_VERSION}, rule set {RULE_SET}.\n"
        + ("The body of the stored post is withheld on this link; its hash and its seal are checked.\n"
           if view["post"] and view["post"]["body_withheld"] else ""))


def build_record_zip(view: dict) -> bytes:
    """The one-record file for a view (see ``share.build_view``). Deterministic: the same view gives the same bytes."""
    raw = view["_raw"]
    files: dict[str, bytes] = {"README.txt": _readme(view).encode("utf-8")}
    seals = []
    for i, s in enumerate(view["seals"], 1):
        name = f"seal_{i}.tsr"
        files[name] = bytes.fromhex(s["token_hex"])
        seals.append({**{k: v for k, v in s.items() if k != "token_hex"}, "file": name})
    post = None
    if view["post"]:
        post = {k: v for k, v in view["post"].items() if k not in ("seals", "body_text")}
        post["seals"] = []
        for i, s in enumerate(view["post"]["seals"], 1):
            name = f"post_seal_{i}.tsr"
            files[name] = bytes.fromhex(s["token_hex"])
            post["seals"].append({**{k: v for k, v in s.items() if k != "token_hex"}, "file": name})
        if raw["body"] is not None:
            files["post_body.json"] = raw["body"]
    if raw["disclosure_body"] is not None:
        files["wording.txt"] = raw["disclosure_body"].encode("utf-8")
    doc = {**public_json(view), "seals": seals, "post": post, "files": {n: hashlib.sha256(b).hexdigest() for n, b in sorted(files.items())}}
    record = (canonical_dumps(doc) + "\n").encode("utf-8")
    files["record.json"] = record
    files["verify_one.py"] = render_verify_one(hashlib.sha256(record).hexdigest()).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if name == "verify_one.py" else 0o644) << 16
            zf.writestr(info, files[name])
    return buf.getvalue()
