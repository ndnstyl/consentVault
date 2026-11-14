#!/usr/bin/env python3
"""Helpers for scripts/security_gate.sh: allowlist validation, per-tool severity bars, suppression check, evidence bundle.

Every failure path exits non-zero with a named reason. Output carries counts and rule ids, never a matched secret value.
Subcommands:
  check-allowlist FILE
  evaluate TOOL REPORT [--allowlist FILE] [--root DIR]     TOOL: bandit semgrep trivy npm pip-audit gitleaks zap
  suppressions ROOT
  gitleaks-config SRC DST
  bundle OUT RESULTS_JSONL ROOT TOOLS_JSON
"""
import datetime
import json
import os
import re
import subprocess
import sys

MAX_SHOW = 25
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", ".terraform", "out", ".next", "__pycache__", "dist", "build", ".security-evidence"}


def fail(msg, code=1):
    print(msg)
    sys.exit(code)


def load_allowlist(path):
    if not path or not os.path.exists(path):
        return []
    with open(path) as fh:
        data = json.load(fh)
    return data.get("entries", [])


def check_allowlist(path):
    today = datetime.date.today()
    problems = []
    entries = load_allowlist(path)
    seen = {}
    for i, e in enumerate(entries):
        where = f"entry {i} ({e.get('tool', '?')}/{e.get('id', '?')})"
        key = (e.get("tool"), e.get("id"), e.get("path"))
        if key in seen and e.get("path"):
            problems.append(f"{where}: more than one entry for {key[0]}/{key[1]} in {key[2]} (entry {seen[key]} already covers it; raise its count with a new reason instead)")
        seen.setdefault(key, i)
        if not (isinstance(e.get("count"), int) and not isinstance(e.get("count"), bool) and e["count"] > 0):
            problems.append(f"{where}: missing count (a positive integer: the most findings this entry may cover)")
        if not str(e.get("path", "")).strip():
            problems.append(f"{where}: missing path (the exact file the entry covers)")
        for key in ("tool", "id", "reason", "expires"):
            if not str(e.get(key, "")).strip():
                problems.append(f"{where}: missing {key}")
        if len(str(e.get("reason", "")).strip()) < 15:
            problems.append(f"{where}: reason too short to be a reason")
        try:
            exp = datetime.date.fromisoformat(str(e.get("expires", "")))
            if exp < today:
                problems.append(f"{where}: expired {exp}")
            elif (exp - today).days > 90:
                problems.append(f"{where}: expiry {exp} is more than 90 days out")
        except ValueError:
            problems.append(f"{where}: expires is not an ISO date")
    if problems:
        fail("allowlist invalid:\n  " + "\n  ".join(problems))
    print(f"allowlist ok: {len(entries)} entries, each with a reason and an unexpired date")


def suppressed(entries, tool, fid, path, used=None):
    """True when an unexpired entry covers this finding. An entry with ``count`` covers at most that many findings
    (per run), so a new unsafe line in an already-allowlisted file is not covered and fails the gate."""
    today = datetime.date.today()
    for e in entries:
        if e.get("tool") != tool or e.get("id") != fid:
            continue
        try:
            if datetime.date.fromisoformat(str(e.get("expires"))) < today:
                continue
        except ValueError:
            continue
        p, c = e.get("path"), e.get("count")
        if not p or not isinstance(c, int) or isinstance(c, bool) or c < 1:
            continue  # an entry with no path or no count covers nothing
        if re.sub(r":\d+$", "", str(path)) != p:
            continue
        if used is not None:
            if used.get(id(e), 0) >= c:
                continue
            used[id(e)] = used.get(id(e), 0) + 1
        return True
    return False


def norm_path(path, root):
    path = str(path)
    if root and path.startswith(root):
        path = path[len(root):].lstrip("/")
    return path


def findings(tool, report, root):
    out = []  # (id, severity, path, message)
    if tool == "bandit":
        for r in report.get("results", []):
            out.append((r["test_id"], r["issue_severity"].upper(), f'{norm_path(r["filename"], root)}:{r["line_number"]}', r["issue_text"]))
    elif tool == "semgrep":
        for e in report.get("errors", []):
            if e.get("level") == "error" and e.get("type") not in ("Lexical error",):
                out.append(("semgrep-scan-error", "CRITICAL", str(e.get("path", "")), str(e.get("message", ""))[:160]))
        for r in report.get("results", []):
            sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(r["extra"].get("severity", "INFO"), "LOW")
            out.append((r["check_id"].split(".")[-1], sev,
                        f'{norm_path(r["path"], root)}:{r["start"]["line"]}', r["extra"].get("message", "")[:120]))
    elif tool == "trivy":
        for res in report.get("Results", []) or []:
            for m in res.get("Misconfigurations", []) or []:
                out.append((m["ID"], m["Severity"], res["Target"], m.get("Title", "")))
            for v in res.get("Vulnerabilities", []) or []:
                out.append((v["VulnerabilityID"], v["Severity"], f'{res["Target"]} {v.get("PkgName", "")}', v.get("Title", "")))
    elif tool == "npm":
        if "error" in report:
            fail("npm audit could not run: " + json.dumps(report["error"])[:300])
        for name, v in (report.get("vulnerabilities") or {}).items():
            ids = [via["url"].rsplit("/", 1)[-1] for via in v.get("via", []) if isinstance(via, dict) and via.get("url")]
            out.append((ids[0] if ids else name, v["severity"].upper(), name, ",".join(ids)))
    elif tool == "pip-audit":
        for d in report.get("dependencies", []):
            for v in d.get("vulns", []):
                out.append((v["id"], "HIGH", f'{d["name"]}=={d["version"]}', "fix: " + ",".join(v.get("fix_versions", []) or ["none"])))
    elif tool == "gitleaks":
        for r in report if isinstance(report, list) else []:
            out.append((r.get("RuleID", "?"), "CRITICAL", f'{r.get("File", "?")}:{r.get("StartLine", "?")}', "secret-shaped value (redacted)"))
    elif tool == "zap":
        for site in report.get("site", []):
            for a in site.get("alerts", []):
                sev = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}.get(str(a.get("riskcode")), "INFO")
                out.append((str(a.get("pluginid")), sev, a.get("name", ""), a.get("name", "")))
    else:
        fail(f"unknown tool {tool}", 2)
    return out


BARS = {"bandit": {"MEDIUM", "HIGH", "CRITICAL"}, "semgrep": {"HIGH", "CRITICAL"}, "trivy": {"HIGH", "CRITICAL"},
        "npm": {"HIGH", "CRITICAL"}, "pip-audit": {"HIGH", "CRITICAL"}, "gitleaks": {"CRITICAL"}, "zap": {"MEDIUM", "HIGH", "CRITICAL"}}


def evaluate(tool, report_path, allow_path, root):
    try:
        with open(report_path) as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        fail(f"{tool}: report missing or unreadable ({report_path}): {exc}", 3)
    entries = load_allowlist(allow_path)
    counts, bar_hits, accepted, used = {}, [], 0, {}
    for fid, sev, path, msg in findings(tool, report, root):
        if suppressed(entries, "npm" if tool == "npm" else tool, fid, path, used):
            accepted += 1
            continue
        counts[sev] = counts.get(sev, 0) + 1
        if sev in BARS[tool]:
            bar_hits.append((fid, sev, path, msg))
    for fid, sev, path, msg in bar_hits[:MAX_SHOW]:
        print(f"  [{sev}] {fid}  {path}  {msg}")
    if len(bar_hits) > MAX_SHOW:
        print(f"  ... {len(bar_hits) - MAX_SHOW} more in {report_path}")
    print("COUNTS " + json.dumps({"by_severity": counts, "at_or_above_bar": len(bar_hits), "accepted": accepted}, sort_keys=True))
    sys.exit(1 if bar_hits else 0)


REASON = re.compile(r"(nosec|nosemgrep|noqa:\s*S\d+|eslint-disable[^\n]*security|gitleaks:allow)(?P<rest>.*)")


def suppressions(root):
    total, bare = 0, []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d not in ("tests", "test")]
        for f in files:
            if not f.endswith((".py", ".ts", ".tsx", ".js", ".mjs", ".sh", ".tf", ".yml", ".yaml")):
                continue
            full = os.path.join(dirpath, f)
            if os.path.abspath(full).endswith(("security/gate_lib.py", "security_gate.sh")):
                continue
            try:
                lines = open(full, errors="replace").read().splitlines()
            except OSError as exc:
                fail(f"cannot read {full}: {exc}", 3)
            for n, line in enumerate(lines, 1):
                if not re.search(r"(#|//|/\*)\s*(nosec|nosemgrep|noqa:\s*S\d+|eslint-disable|gitleaks:allow)", line):
                    continue
                m = REASON.search(line)
                if not m:
                    continue
                total += 1
                if not re.search(r"--\s*\S.{8,}", m.group("rest")):
                    bare.append(f"{norm_path(full, root)}:{n}")
    for b in bare[:MAX_SHOW]:
        print(f"  suppression without a reason (' -- why, at least 10 characters'): {b}")
    print("COUNTS " + json.dumps({"suppressions": total, "without_reason": len(bare)}))
    sys.exit(1 if bare else 0)


def gitleaks_config(src, dst):
    skip = ["\\.next/", "node_modules/", "\\.venv/", "(^|/)out/", "__pycache__/", "\\.git/", "\\.terraform/", "\\.security-evidence/",
            "(^|/)\\.credentials/", "(^|/)\\.cache/", "\\.pytest_cache/", "\\.ruff_cache/"]  # gitignored local folders; the history scan covers every tracked file
    paths = "paths = [" + ", ".join("'''" + s + "'''" for s in skip) + "]\n"
    text = open(src).read() if os.path.exists(src) else "[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"gate default\"\n"
    if "[allowlist]" not in text:
        text += "\n[allowlist]\ndescription = \"gate default\"\n"
    text = re.sub(r"(\[allowlist\]\n)", lambda m: m.group(1) + paths, text, count=1)
    open(dst, "w").write(text)


def bundle(out, results_path, root, tools_json):
    results = [json.loads(line) for line in open(results_path) if line.strip()]

    def git(*a):
        try:
            return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True, timeout=30).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    doc = {"run_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "repo": os.path.basename(os.path.abspath(root)), "git_head": git("rev-parse", "HEAD"),
           "working_tree_dirty": bool(git("status", "--porcelain")), "tools": json.loads(tools_json),
           "steps": results, "failed": [r["name"] for r in results if r["status"] == "FAIL"],
           "partial": [r["name"] for r in results if r["status"] == "PARTIAL"]}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    os.replace(tmp, out)
    os.chmod(out, 0o600)
    print(out)


def main(argv):
    if len(argv) < 2:
        fail(__doc__, 2)
    cmd, a = argv[1], argv[2:]
    if cmd == "check-allowlist":
        check_allowlist(a[0])
    elif cmd == "evaluate":
        opts = {"--allowlist": None, "--root": ""}
        rest = []
        i = 0
        while i < len(a):
            if a[i] in opts:
                opts[a[i]] = a[i + 1]
                i += 2
            else:
                rest.append(a[i])
                i += 1
        evaluate(rest[0], rest[1], opts["--allowlist"], opts["--root"])
    elif cmd == "suppressions":
        suppressions(a[0])
    elif cmd == "gitleaks-config":
        gitleaks_config(a[0], a[1])
    elif cmd == "bundle":
        bundle(*a)
    else:
        fail(f"unknown subcommand {cmd}", 2)


if __name__ == "__main__":
    main(sys.argv)
