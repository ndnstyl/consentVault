"""Every start-up, role, migration, notification and database refusal has its own stable code, registered with a one-line meaning,
so an operator can tell which check fired without reading an error's text (consentvault/refusals.py, data/refusal_codes.json)."""

import ast
import json
import pathlib
import re
import subprocess
import sys

import pytest

from consentvault import safelog
from consentvault.refusals import PYTHON_REFUSALS

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
REGISTRY = SRC / "consentvault" / "data" / "refusal_codes.json"
REFUSAL = re.compile(r"^(StartupRefusedError|MigrationError|MigrationDriftError|\w*LoginRefused|\w*Refused)$")
CODE = re.compile(r"[a-z][a-z0-9_]{1,63}")


def _python_sites():
    """(file, line, code or None) for every raise of a refusal class in src/."""
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name) \
                    and REFUSAL.match(node.exc.func.id):
                code = next((k.value for k in node.exc.keywords if k.arg == "code"), None)
                if isinstance(code, ast.Call) and ast.unparse(code.func) == "startup_check_code":
                    yield str(path.relative_to(SRC)), node.lineno, "<check family>"  # one code per check sentence
                    continue
                literal = code.value if isinstance(code, ast.Constant) and isinstance(code.value, str) else None
                yield str(path.relative_to(SRC)), node.lineno, literal


def test_the_database_registry_matches_the_migrations():
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_refusal_codes.py"), "--check"], capture_output=True,
                          text=True, timeout=120, check=False)  # loud-failure-exempt: the exit code is the assertion below
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_no_two_database_refusal_sites_share_a_code():
    sites = json.loads(REGISTRY.read_text())["sites"]
    codes = [s["code"] for s in sites]
    assert len(codes) == len(set(codes)) and all(CODE.fullmatch(c) for c in codes)
    assert len({(s["function"], s["signature"], s["template"]) for s in sites}) == len(sites)
    assert all(s["meaning"] and "\n" not in s["meaning"] for s in sites)


def test_every_python_refusal_site_passes_its_own_registered_code():
    sites = list(_python_sites())
    assert len(sites) >= 30
    uncoded = [f"{f}:{ln}" for f, ln, code in sites if code is None]
    assert uncoded == [], f"refusal sites with no literal code=: {uncoded}"
    sites = [s for s in sites if s[2] != "<check family>"]
    unregistered = [f"{f}:{ln} {code}" for f, ln, code in sites if code not in PYTHON_REFUSALS]
    assert unregistered == []
    used = [code for _f, _ln, code in sites]
    shared = sorted({c for c in used if used.count(c) > 1})
    assert shared == [], f"codes used at more than one refusal site: {shared}"
    orphans = sorted(set(PYTHON_REFUSALS) - set(used))
    assert orphans == [], f"registered codes no site raises: {orphans}"


def test_python_and_database_codes_never_collide_and_each_has_a_one_line_meaning():
    db = {s["code"] for s in json.loads(REGISTRY.read_text())["sites"]}
    assert not db & set(PYTHON_REFUSALS)
    assert all(CODE.fullmatch(c) and m and "\n" not in m for c, m in PYTHON_REFUSALS.items())


@pytest.mark.parametrize("function,message,want", [
    ("consentvault.require_multi_tenant", "consentvault tenancy: this vault is in single mode; a multi-tenant service must not serve it",
     True),
    ("consentvault.require_multi_tenant", "something else entirely", False),
])
def test_a_database_refusal_is_matched_to_its_code_by_function_and_sentence(function, message, want):
    sites = json.loads(REGISTRY.read_text())["sites"]
    site = next((s for s in sites if s["function"] == function and "single mode" in s["template"]), None)

    class Diag:
        context = f"PL/pgSQL function {function}() line {site['line'] if site else 3} at RAISE"
        message_primary = message

    class Refused(Exception):
        sqlstate = "55000"
        diag = Diag()
    code = safelog.refusal_code(Refused())
    sites = json.loads(REGISTRY.read_text())["sites"]
    expected = next((s["code"] for s in sites if s["function"] == function and "single mode" in s["template"]), None)
    assert (code == expected and code is not None) if want else code is None


def test_every_start_up_check_sentence_has_its_own_code():
    """The owner-rights and guard checks each report a fixed sentence; distinct sentences give distinct codes, all valid codes."""
    from consentvault.api import startup_check_code
    sentences = set()
    for path in [*(ROOT / "migrations").glob("*.sql"), ROOT / "docker" / "initdb" / "20-trigger-guard.sql"]:
        sentences |= set(re.findall(r"'((?:the|an?) [^']{20,})'", path.read_text()))
    codes = {startup_check_code(s) for s in sentences}
    assert len(codes) == len(sentences) and all(CODE.fullmatch(c) for c in codes)
    assert not codes & set(PYTHON_REFUSALS)


def _build(tmp_path, *files):
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_refusal_codes as b
    for i, sql in enumerate(files, 1):
        (tmp_path / f"{i:04d}_m.sql").write_text(sql)
    return b.build(tmp_path)


def _fn(name, *sentences):
    raises = "\n".join(f"    RAISE EXCEPTION '{s}';" for s in sentences)
    return f"CREATE OR REPLACE FUNCTION cv.{name}() RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n{raises}\nEND;\n$$;\n"


def test_a_redefinition_supersedes_every_sentence_of_the_one_before(tmp_path):
    sites = _build(tmp_path, _fn("check", "old refusal %"), _fn("check", "new refusal %"))
    assert [s["template"] for s in sites] == ["new refusal %"] and sites[0]["defined_in"] == "0002_m.sql"


def test_a_dropped_function_has_no_live_code(tmp_path):
    sites = _build(tmp_path, _fn("gone", "refused"), "DROP FUNCTION IF EXISTS cv.gone();\n", _fn("kept", "kept refusal"))
    assert [s["function"] for s in sites] == ["cv.kept"]


def _one_line(name, *sentences):
    """Two RAISEs on one line: the line cannot tell them apart, so only the sentences can."""
    raises = " ".join(f"RAISE EXCEPTION '{x}';" for x in sentences)
    return f"CREATE OR REPLACE FUNCTION cv.{name}() RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n    {raises}\nEND;\n$$;\n"


def test_two_live_sentences_one_message_could_match_are_refused(tmp_path):
    with pytest.raises(SystemExit, match="overlap"):
        _build(tmp_path, _one_line("check", "consentvault: % refused", "consentvault: role refused"))


def test_the_committed_registry_holds_no_superseded_sentence():
    """Every registered function sentence comes from that function's latest definition in the migrations."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_refusal_codes as b
    current = {(s["function"], s["signature"], s["template"]) for s in b.build()}
    committed = {(s["function"], s["signature"], s["template"]) for s in json.loads(REGISTRY.read_text())["sites"]}
    assert committed == current


def _gen():
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_refusal_codes as b
    return b


def _fn_sig(name, params, *sentences, schema="cv."):
    raises = "\n".join(f"    RAISE EXCEPTION '{x}';" for x in sentences)
    return f"CREATE OR REPLACE FUNCTION {schema}{name}({params}) RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n{raises}\nEND;\n$$;\n"


def test_a_two_sided_overlap_is_found_by_intersection():
    """Neither template's sample matches the other, yet one message ("consentvault: role refused") matches both."""
    b = _gen()
    assert b.intersects("consentvault: % refused", "consentvault: role %")
    assert b.intersects("consentvault: role %", "consentvault: % refused")


@pytest.mark.parametrize("a,c", [("a % b", "c % d"), ("vault is % here", "vault was % here"), ("x%%y %", "x y %")])
def test_templates_no_message_can_match_both_do_not_overlap(a, c):
    assert not _gen().intersects(a, c)


def test_the_two_sided_pair_is_refused_by_the_build(tmp_path):
    with pytest.raises(SystemExit, match="overlap"):
        _build(tmp_path, _one_line("check", "consentvault: % refused", "consentvault: role %"))


def test_overlapping_sentences_on_their_own_lines_are_told_apart_by_the_line(tmp_path):
    """The database names the line of the RAISE, so one message is never ambiguous between two lines: two codes, no refusal."""
    sites = _build(tmp_path, _fn("check", "consentvault: % refused", "consentvault: role %"))
    assert len({x["code"] for x in sites}) == 2 and sorted(x["line"] for x in sites) == [3, 4]


def test_overloads_are_told_apart_by_their_argument_types(tmp_path):
    sites = _build(tmp_path, _fn_sig("f", "p_id uuid", "by id %"), _fn_sig("f", "p_name text", "by name %"),
                   "DROP FUNCTION cv.f(text);\n")
    assert [(x["signature"], x["template"]) for x in sites] == [("uuid", "by id %")]


def test_an_unqualified_create_is_dropped_by_its_qualified_name_and_the_reverse(tmp_path):
    sites = _build(tmp_path, _fn_sig("g", "", "g refused", schema=""), "DROP FUNCTION consentvault.g();\n",
                   _fn_sig("h", "", "h refused", schema="consentvault."), "DROP FUNCTION IF EXISTS h();\n",
                   _fn_sig("k", "", "k refused", schema=""))
    assert [x["function"] for x in sites] == ["consentvault.k"]


def test_a_multi_name_drop_removes_every_named_function(tmp_path):
    sites = _build(tmp_path, _fn_sig("a", "", "a refused"), _fn_sig("b", "x integer", "b refused"),
                   _fn_sig("c", "", "c refused"), "DROP FUNCTION cv.a(), cv.b(int) CASCADE;\n")
    assert [x["function"] for x in sites] == ["cv.c"]


def test_a_create_after_a_drop_in_one_file_is_live_and_a_drop_after_a_create_is_not(tmp_path):
    sites = _build(tmp_path, _fn_sig("h", "", "old"),
                   "DROP FUNCTION cv.h();\n" + _fn_sig("h", "", "recreated") + _fn_sig("j", "", "j refused") + "DROP FUNCTION cv.j();\n")
    assert [(x["function"], x["template"]) for x in sites] == [("cv.h", "recreated")]


def test_the_runtime_match_picks_the_overload_that_raised(monkeypatch):
    sites = [{"code": "db_f_aaa", "function": "consentvault.f", "signature": "uuid", "line": 2, "template": "refused %"},
             {"code": "db_f_bbb", "function": "consentvault.f", "signature": "text", "line": 2, "template": "refused %"},
             {"code": "db_f_ccc", "function": "consentvault.f", "signature": "text", "line": 4, "template": "refused % again"}]
    monkeypatch.setattr(safelog, "_DB_REFUSALS", {})
    import io as _io
    monkeypatch.setattr("builtins.open", lambda *a, **k: _io.StringIO(json.dumps({"sites": sites})) if str(a[0]).endswith(
        "refusal_codes.json") else _real_open(*a, **k))

    class Diag:
        message_primary = "refused 7"
        context = "PL/pgSQL function consentvault.f(text) line 2 at RAISE"

    class E(Exception):
        sqlstate = "P0001"
        diag = Diag()
    assert safelog.refusal_code(E()) == "db_f_bbb"
    Diag.context = "PL/pgSQL function consentvault.f(uuid) line 2 at RAISE"
    assert safelog.refusal_code(E()) == "db_f_aaa"
    Diag.context, Diag.message_primary = "PL/pgSQL function consentvault.f(text) line 4 at RAISE", "refused 7 again"
    assert safelog.refusal_code(E()) == "db_f_ccc"  # same function, the line tells the two sentences apart


_real_open = open


def test_every_trigger_guard_refusal_has_its_own_registered_code():
    """The trigger guard (docker/initdb/20-trigger-guard.sql) is installed before the migrations; each of its refusals is a site."""
    guard = ROOT / "docker" / "initdb" / "20-trigger-guard.sql"
    raised = set(re.findall(r"RAISE\s+EXCEPTION\s+'((?:[^']|'')*)'", guard.read_text(), re.I))
    sites = [s for s in json.loads(REGISTRY.read_text())["sites"] if s["defined_in"] == guard.name]
    assert len(raised) >= 15 and {s["template"].replace("'", "''") for s in sites} == raised
    codes = [s["code"] for s in json.loads(REGISTRY.read_text())["sites"]]
    assert len(codes) == len(set(codes))


def test_no_registered_database_refusal_names_a_release_decision_that_can_no_longer_be_made():
    templates = [s["template"] for s in json.loads(REGISTRY.read_text())["sites"]]
    assert not [t for t in templates if "a release must decide" in t or "a release may name only" in t]
    assert any("no release event can be written" in t for t in templates)
    assert sum("stop lift:" in t for t in templates) == 3


def test_every_registered_python_refusal_is_still_raised_and_the_release_failure_is_gone():
    from consentvault import errors
    assert not hasattr(errors, "ReleaseFailedError")
    assert not any("release" in code for code in PYTHON_REFUSALS)


def test_the_portal_help_lists_only_answers_a_capture_can_still_return():
    """Every intake stores the post and answers 201, 202 or 503 store_unavailable (contracts/capture-api.md); the token request
    can still answer 401 invalid_client. The refusals that were removed from intake are not in the help copy."""
    copy = (ROOT / "portal" / "app" / "src" / "lib" / "copy.ts").read_text()
    block = copy[copy.index("export const CAPTURE_REFUSALS"):]
    block = block[:block.index("];")]
    answers = re.findall(r"answer: '(\d{3}) (\w+)'", block)
    assert answers == [("401", "invalid_client"), ("503", "store_unavailable")]
    source = "".join(p.read_text() for p in SRC.rglob("*.py"))
    for _status, name in answers:
        assert name in source, f"the help names an answer no code returns: {name}"
    for removed in ("UncheckedConsentError", "UnknownDisclosureError", "UnknownPurposeError", "GrantScopeError",
                    "source_not_allowed", "brand_not_allowed", "org_not_active", "rate_limited", "key_unavailable"):
        assert removed not in block, removed
