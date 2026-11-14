"""Every requirement and success criterion in the spec maps to tests that exist, or names who proves it.

The map is requirements_map.json beside this file. A requirement fails here when it has no mapped test and no named
owner, or when a mapped test does not exist. A requirement with an owner and no tests is reported, not hidden.

A mapped test that cannot pass in the checkpoint's run proves nothing there, so it is held to more:
- one under a path pytest ignores (pyproject addopts --ignore, today tests/selfhost) needs its requirement to name an
  ``owner`` and a ``receipt``: the file tests/selfhost/run_suites.sh writes (SELFHOST_RECEIPT; format in
  tests/selfhost/write_receipt.py). When that receipt exists, every such test must read "passed" in it, and the receipt
  itself must be a clean run of this code: exit code 0, every section run_suites.sh runs passed, and its product and
  security manifest digests equal to the current ones. A stale, failed or forged receipt is a problem, never a pass.
- one that did not pass in the checkpoint's python run (skipped, deselected or failed; the run report the suite writes
  under CONSENTVAULT_RUN_REPORT_OUT, read here from CONSENTVAULT_RUN_REPORT_IN) needs either the owner and receipt above
  or ``covered_by`` naming tests of the same requirement that did pass in that run and prove it without the network.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import shlex
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MAP = Path(__file__).with_name("requirements_map.json")
# The cloud specification is a private planning document outside this repository. Point CONSENTVAULT_SPEC at it to check
# the map against it; unset, that one check is skipped with the reason printed.
SPEC_ENV = "CONSENTVAULT_SPEC"
SPEC = Path(os.environ[SPEC_ENV]) if os.environ.get(SPEC_ENV) else None
ID_RE = re.compile(r"^- \*\*((?:FR|SC)-\d{3})\*\*:", re.M)
SELFHOST_RECEIPT = "tests/selfhost/receipts/selfhost-suites.json"
RECEIPT_FORMAT = "consentvault-selfhost-receipt/2"
RUN_REPORT_IN = "CONSENTVAULT_RUN_REPORT_IN"
RUNNER = "tests/selfhost/run_suites.sh"


def _writer():
    path = REPO / "tests/selfhost/write_receipt.py"
    spec = importlib.util.spec_from_file_location("consentvault_selfhost_write_receipt", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"the receipt writer cannot be loaded from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_W = _writer()
product_digest = _W.product_digest
manifest_digest = _W.manifest_digest
assert _W.FORMAT == RECEIPT_FORMAT, f"the receipt writer writes {_W.FORMAT}, traceability reads {RECEIPT_FORMAT}"


def runner_sections(root: Path = REPO) -> list[str]:
    """The sections run_suites.sh runs, in order. A runner that names none is an error, never an empty list."""
    path = root / RUNNER
    if not path.is_file():
        raise AssertionError(f"the self-host runner is missing at {path}")
    names = re.findall(r'^section "([^"]+)"', path.read_text(), re.M)
    if not names:
        raise AssertionError(f"the self-host runner at {path} names no section")
    return names


def load_map() -> dict:
    return json.loads(MAP.read_text())


def spec_ids() -> list[str]:
    return sorted(set(ID_RE.findall(SPEC.read_text())))


def python_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def node_exists(node_id: str, root: Path = REPO) -> bool:
    if "::" not in node_id:
        return False
    rel, name = node_id.split("::", 1)
    path = root / rel
    if not path.is_file():
        return False
    if path.suffix == ".py":
        return name in python_functions(path)
    return name in path.read_text()


def audit(requirements: dict, root: Path = REPO) -> dict:
    unmapped, missing, owned_only = [], [], []
    for rid, row in sorted(requirements.items()):
        tests = row.get("tests", [])
        if not tests and not row.get("owner"):
            unmapped.append(rid)
        elif not tests:
            owned_only.append(rid)
        for t in tests:
            if not node_exists(t, root):
                missing.append(f"{rid}: {t}")
    return {"unmapped": unmapped, "missing": missing, "owned_only": owned_only}


def ignored_paths(root: Path = REPO) -> list[str]:
    """The paths pytest's configured addopts ignore (--ignore=X / --ignore X), relative to the repository."""
    opts = tomllib.loads((root / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"].get("addopts", "")
    args = shlex.split(opts if isinstance(opts, str) else " ".join(opts))
    out = []
    for i, a in enumerate(args):
        if a.startswith("--ignore="):
            out.append(a.split("=", 1)[1])
        elif a == "--ignore" and i + 1 < len(args):
            out.append(args[i + 1])
    return [p.rstrip("/") for p in out]


def _key(node_id: str) -> tuple[str, str]:
    """(file, function) of a node id, without class or parameters, the grain the map names tests at."""
    rel, _, rest = node_id.partition("::")
    return rel, rest.split("::")[-1].split("[", 1)[0]


def _run_outcomes(report: dict) -> dict[tuple[str, str], str]:
    """Per (file, function): passed only when every collected instance passed."""
    out: dict[tuple[str, str], str] = {}
    for nid, outcome in report.get("tests", {}).items():
        k = _key(nid)
        out[k] = outcome if out.get(k, "passed") == "passed" else out[k]
    return out


def _receipt(path: Path) -> dict | None:
    """A self-host receipt's body, None when it does not exist. A body that is not a receipt is an error."""
    if not path.is_file():
        return None
    try:
        body = json.loads(path.read_text())
    except ValueError as exc:
        raise AssertionError(f"{path} is not JSON: {exc}") from None
    if not isinstance(body, dict) or not isinstance(body.get("tests"), dict):
        raise AssertionError(f"{path} is not a self-host receipt (no tests)")
    return body


def _receipt_outcomes(path: Path) -> dict[tuple[str, str], str] | None:
    """The outcomes a self-host receipt records, None when it does not exist."""
    body = _receipt(path)
    return None if body is None else _run_outcomes(body)


def receipt_problems(body: dict, root: Path = REPO) -> list[str]:
    """Why a receipt does not prove this code passed the self-host run: empty only for a clean run of the current code."""
    from datetime import datetime, timedelta, timezone

    rerun = f"; rerun {RUNNER} against the self-host stack"
    out = []
    if body.get("format") != RECEIPT_FORMAT:
        out.append(f"{SELFHOST_RECEIPT} is format {body.get('format')!r}, not {RECEIPT_FORMAT}{rerun}")
    if body.get("exit_code") != 0:
        out.append(f"{SELFHOST_RECEIPT} records exit code {body.get('exit_code')!r}: the self-host run failed{rerun}")
    sections = body.get("sections")
    if not isinstance(sections, dict) or not sections:
        out.append(f"{SELFHOST_RECEIPT} records no section results{rerun}")
    else:
        for name in runner_sections(root):
            if sections.get(name) != "passed":
                out.append(f"{SELFHOST_RECEIPT}: section {name!r} reads {sections.get(name, 'absent')!r}{rerun}")
        for name, status in sorted(sections.items()):
            if status != "passed":
                out.append(f"{SELFHOST_RECEIPT}: section {name!r} reads {status!r}{rerun}")
    product = product_digest(root)
    if body.get("product_sha256") != product:
        out.append(f"{SELFHOST_RECEIPT} proves product files {body.get('product_sha256', 'absent')!r}, the product files "
                   f"now read {product!r}: the receipt is stale or forged{rerun}")
    manifest = manifest_digest(root)
    if manifest is None:
        out.append(f"there is no security manifest under {root} to compare the receipt with")
    elif body.get("manifest_sha256") != manifest:
        out.append(f"{SELFHOST_RECEIPT} proves security manifest {body.get('manifest_sha256', 'absent')!r}, the security "
                   f"manifest now reads {manifest!r}: the receipt is stale or forged{rerun}")
    try:
        finished = datetime.fromisoformat(str(body.get("finished_at")).replace("Z", "+00:00"))
        if finished.tzinfo is None:
            raise ValueError("no time zone")
    except ValueError as exc:
        out.append(f"{SELFHOST_RECEIPT} finished_at {body.get('finished_at')!r} is not a UTC time: {exc}")
    else:
        if finished > datetime.now(timezone.utc) + timedelta(minutes=5):
            out.append(f"{SELFHOST_RECEIPT} finished_at {body.get('finished_at')} is in the future: the receipt is forged")
    return out


def out_of_run(requirements: dict, *, root: Path = REPO, run: dict | None = None) -> dict:
    """Every mapped test the checkpoint's run cannot vouch for, and whether its requirement accounts for it."""
    ignored = ignored_paths(root)
    ran = _run_outcomes(run) if run is not None else None
    body = _receipt(root / SELFHOST_RECEIPT)
    receipt = None if body is None else _run_outcomes(body)
    problems, pending = [], []
    if body is not None:
        problems += receipt_problems(body, root)
    for rid, row in sorted(requirements.items()):
        names_receipt = bool(row.get("owner")) and row.get("receipt") == SELFHOST_RECEIPT
        if row.get("receipt") not in (None, SELFHOST_RECEIPT):
            problems.append(f"{rid}: names receipt {row['receipt']!r}; the only receipt a run writes is {SELFHOST_RECEIPT}")
        covered = row.get("covered_by", {})
        for t in row.get("tests", []):
            rel = t.split("::", 1)[0]
            if not rel.endswith(".py"):
                continue  # dashboard and edge tests run in their own checkpoint stages
            if any(rel == p or rel.startswith(p + "/") for p in ignored):
                if not names_receipt:
                    problems.append(f"{rid}: {t} lives under an ignored path; the requirement names no owner and "
                                    f"receipt ({SELFHOST_RECEIPT})")
                elif receipt is None:
                    pending.append(f"{rid}: {t} (no receipt yet at {SELFHOST_RECEIPT})")
                elif receipt.get(_key(t)) != "passed":
                    problems.append(f"{rid}: {t} reads {receipt.get(_key(t), 'absent')!r} in {SELFHOST_RECEIPT}")
                continue
            if ran is None or ran.get(_key(t)) == "passed":
                continue
            by = covered.get(t, [])
            if by and all(ran.get(_key(c)) == "passed" and c in row.get("tests", []) for c in by):
                continue
            if names_receipt and receipt is not None and receipt.get(_key(t)) == "passed":
                continue
            problems.append(f"{rid}: {t} did not pass in this run ({ran.get(_key(t), 'not run')}); the requirement "
                            "names no receipt showing it passed and no covered_by test of its own that passed here")
    return {"problems": problems, "pending": pending}


def test_the_map_covers_exactly_the_requirements_in_the_spec():
    if SPEC is None:
        pytest.skip(f"{SPEC_ENV} is not set: the map is not checked against the cloud specification in this run")
    assert SPEC.is_file(), f"spec not readable at {SPEC} ({SPEC_ENV}); the map cannot be checked against it"
    in_map = set(load_map()["requirements"])
    in_spec = set(spec_ids())
    assert in_map == in_spec, f"in spec not in map: {sorted(in_spec - in_map)}; in map not in spec: {sorted(in_map - in_spec)}"


def test_every_requirement_has_a_mapped_test_that_exists_or_a_named_owner():
    result = audit(load_map()["requirements"])
    if result["owned_only"]:
        print("proved outside this repo (owner named, no local test):", ", ".join(result["owned_only"]))
    problems = []
    if result["unmapped"]:
        problems.append(f"{len(result['unmapped'])} requirement(s) with no test and no owner: {', '.join(result['unmapped'])}")
    if result["missing"]:
        problems.append(f"{len(result['missing'])} mapped test(s) that do not exist:\n  " + "\n  ".join(result["missing"]))
    assert not problems, "\n".join(problems)


def test_the_audit_flags_an_unmapped_requirement_and_a_missing_test(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t/test_a.py").write_text("def test_real():\n    pass\n")
    (tmp_path / "t/a.test.ts").write_text("test('a real title', () => {})\n")
    reqs = {
        "FR-901": {"tests": []},
        "FR-902": {"tests": ["t/test_a.py::test_real", "t/a.test.ts::a real title"]},
        "FR-903": {"tests": ["t/test_a.py::test_gone", "t/nothing.py::test_x", "t/a.test.ts::another title"]},
        "FR-904": {"tests": [], "owner": "Mike"},
    }
    got = audit(reqs, tmp_path)
    assert got["unmapped"] == ["FR-901"]
    assert got["owned_only"] == ["FR-904"]
    assert len(got["missing"]) == 3 and all(m.startswith("FR-903") for m in got["missing"])


def test_every_mapped_test_outside_the_ignore_list_or_with_a_receipt_names_its_owner_and_receipt():
    result = out_of_run(load_map()["requirements"])
    assert not result["problems"], "\n".join(result["problems"])
    assert not result["pending"], ("proved only by the self-host run, and its receipt is not written here: run "
                                   "tests/selfhost/run_suites.sh against the self-host stack\n  "
                                   + "\n  ".join(result["pending"]))


def test_every_mapped_test_passed_in_the_checkpoint_run_or_is_accounted_for():
    path = os.environ.get(RUN_REPORT_IN)
    if not path:
        pytest.skip(f"runs in the checkpoint's traceability stage, which names the python suite's run report in "
                    f"{RUN_REPORT_IN}")
    report_path = Path(path)
    assert report_path.is_file(), f"{RUN_REPORT_IN} names {report_path}, which the python suite did not write"
    run = json.loads(report_path.read_text())
    assert run.get("tests"), f"the run report {report_path} records no tests"
    result = out_of_run(load_map()["requirements"], run=run)
    assert not result["problems"], "\n".join(result["problems"])


def test_the_out_of_run_audit_flags_an_unaccounted_test(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\naddopts = "--ignore=t/live"\n')
    for f in ("t/live/test_l.py", "t/test_a.py"):
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("def test_x():\n    pass\ndef test_net():\n    pass\n")
    run = {"tests": {"t/test_a.py::test_x": "passed", "t/test_a.py::test_net": "skipped"}}
    reqs = {
        "FR-901": {"tests": ["t/live/test_l.py::test_x"]},                                  # no owner, no receipt
        "FR-902": {"tests": ["t/live/test_l.py::test_x"], "owner": "ops", "receipt": SELFHOST_RECEIPT},
        "FR-903": {"tests": ["t/test_a.py::test_x", "t/test_a.py::test_net"]},              # skipped, nothing covers it
        "FR-904": {"tests": ["t/test_a.py::test_x", "t/test_a.py::test_net"],
                   "covered_by": {"t/test_a.py::test_net": ["t/test_a.py::test_x"]}},
        "FR-905": {"tests": ["t/test_a.py::test_net"], "covered_by": {"t/test_a.py::test_net": ["t/test_a.py::test_x"]}},
        "FR-906": {"tests": ["t/test_a.py::test_x"], "owner": "ops", "receipt": "elsewhere.json"},
    }
    got = out_of_run(reqs, root=tmp_path, run=run)
    flagged = sorted({p.split(":")[0] for p in got["problems"]})
    assert flagged == ["FR-901", "FR-903", "FR-905", "FR-906"], got
    assert [p.split(":")[0] for p in got["pending"]] == ["FR-902"]
    receipt = tmp_path / SELFHOST_RECEIPT
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({"format": RECEIPT_FORMAT, "tests": {"t/live/test_l.py::test_x": "failed"}}))
    got = out_of_run(reqs, root=tmp_path, run=run)
    assert any(p.startswith("FR-902") and "'failed'" in p for p in got["problems"]) and not got["pending"]
    receipt.write_text(json.dumps({"format": RECEIPT_FORMAT, "tests": {"t/live/test_l.py::test_x": "passed"}}))
    assert not [p for p in out_of_run(reqs, root=tmp_path, run=run)["problems"] if p.startswith("FR-902")]


def test_the_self_host_runner_writes_the_receipt_this_test_reads():
    runner = (REPO / "tests/selfhost/run_suites.sh").read_text()
    assert "tests/selfhost/receipts/selfhost-suites.json" in runner and "write_receipt.py" in runner
    assert SELFHOST_RECEIPT == "tests/selfhost/receipts/selfhost-suites.json"


def test_the_receipt_writer_records_each_live_test_by_node_id(tmp_path):
    import subprocess
    import sys

    junit = tmp_path / "j.xml"
    junit.write_text('<testsuites><testsuite><testcase classname="tests.selfhost.test_openbao_keys" name="test_a"/>'
                     '<testcase classname="tests.selfhost.test_openbao_keys" name="test_b"><failure/></testcase>'
                     '<testcase classname="tests.selfhost.test_vault_service" name="test_c"><skipped/></testcase>'
                     '</testsuite></testsuites>')
    out = tmp_path / "r.json"
    done = subprocess.run([sys.executable, str(REPO / "tests/selfhost/write_receipt.py"), str(junit), str(out), "1",
                           "isolation=passed", "live providers: x, y=failed"], capture_output=True, text=True,
                          cwd=REPO)
    assert done.returncode == 0, done.stderr
    body = json.loads(out.read_text())
    assert body["format"] == RECEIPT_FORMAT and body["exit_code"] == 1
    assert body["tests"] == {"tests/selfhost/test_openbao_keys.py::test_a": "passed",
                             "tests/selfhost/test_openbao_keys.py::test_b": "failed",
                             "tests/selfhost/test_vault_service.py::test_c": "skipped"}
    assert body["sections"] == {"isolation": "passed", "live providers: x, y": "failed"}
    missing = subprocess.run([sys.executable, str(REPO / "tests/selfhost/write_receipt.py"), str(tmp_path / "no.xml"),
                              str(out), "0"], capture_output=True, text=True, cwd=REPO)
    assert missing.returncode == 2
