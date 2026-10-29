"""Evidence bundle export: JSON + disclosure wording + seal tokens + a standalone verifier."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
from pathlib import Path

import psycopg

from .errors import ConsentVaultError
from .ledger import HASH_VERSIONS, canonical_dumps, link_hash
from .proof import gather
from .seal import SEAL_HASH_VERSIONS

VERIFY_TEMPLATE = r'''#!/usr/bin/env python3
"""Standalone verifier for a consentvault evidence bundle. Python 3 stdlib and the openssl CLI only.

Usage: python3 verify.py --cafile CA.pem (--anchor SEQ:ROW_HASH ... | --anchors FILE) [--untrusted CERTS.pem]
                         [--openssl PATH] [--max-delay SECONDS]

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
from datetime import datetime, timedelta, timezone

HASH_VERSIONS = json.loads(r"""__HASH_VERSIONS__""")
SEAL_HASH_VERSIONS = json.loads(r"""__SEAL_HASH_VERSIONS__""")
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
    return sha256_text(dumps({c: event[c] for c in cols}))


def row_hash(prev_hash, event):
    content = content_hash(event)
    if content is None:
        return None
    return link_hash(prev_hash, event["contact_commit"], salted(event["contact_salt"], event["subject_key"]), content)


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

    trusted_anchors, anchor_problems = [], []
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

    openssl = args.openssl or shutil.which("openssl")
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


def render_verifier(evidence_sha256: str) -> str:
    """The standalone verifier script for a bundle whose evidence.json has the given sha256."""
    return (
        VERIFY_TEMPLATE
        .replace("__HASH_VERSIONS__", json.dumps({str(k): list(v) for k, v in HASH_VERSIONS.items()}, sort_keys=True))
        .replace("__SEAL_HASH_VERSIONS__", json.dumps({str(k): list(v) for k, v in SEAL_HASH_VERSIONS.items()}, sort_keys=True))
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
