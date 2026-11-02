"""deploy/cloud-settings.json is the one list of every setting, secret and file the product reads, per service and job.

Two directions: every name the product's code reads is on the list, and every product name on the list is read by the
code. The cloud entrypoint writes every listed secret file under /tmp/cv (mode 600) from its injected value and removes
that value from the environment, and handles nothing the list does not name.
"""

import json
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIST = ROOT / "deploy" / "cloud-settings.json"
SRC = ROOT / "src" / "consentvault"
ENTRYPOINT = ROOT / "docker" / "cloud-entrypoint.sh"
NAME = re.compile(r"[\"'](?P<n>(?:CONSENTVAULT|CV|AWS)_[A-Z0-9_]+)[\"']")
KINDS = {"setting", "secret_value", "secret_file", "file", "directory", "platform"}


def _list():
    return json.loads(LIST.read_text(encoding="utf-8"))["settings"]


def _read_by_code() -> set[str]:
    return {m.group("n") for p in SRC.rglob("*.py") for m in NAME.finditer(p.read_text(encoding="utf-8"))}


def test_every_entry_is_complete():
    jobs_or_services = re.compile(r"^(vault|sync|migrate|job:(\*|[a-z-]+))$")
    for e in _list():
        assert e["kind"] in KINDS, e["name"]
        assert e["read_by"] in ("product", "kms-plugin"), e["name"]
        assert e["used_by"] and all(jobs_or_services.match(u) for u in e["used_by"]), e["name"]
        assert set(e["deployments"]) <= {"cloud", "self-host"} and e["deployments"], e["name"]
        assert "required" in e, e["name"]
        if e["kind"] == "secret_file" and "cloud" in e["deployments"]:
            assert e["path"].startswith("/tmp/cv/") and re.fullmatch(r"CV_[A-Z0-9_]+", e["injected_as"]), e["name"]


def test_every_name_the_product_reads_is_listed_and_every_listed_name_is_read():
    listed = {e["name"] for e in _list() if e["read_by"] == "product"}
    code = _read_by_code()
    assert code - listed == set(), f"read by the product but not on deploy/cloud-settings.json: {sorted(code - listed)}"
    assert listed - code == set(), f"on the list but never read by the product: {sorted(listed - code)}"


def test_every_scheduled_job_on_the_list_exists():
    from consentvault.jobs import JOBS

    named = {u.split(":", 1)[1] for e in _list() for u in e["used_by"] if u.startswith("job:") and u != "job:*"}
    assert named <= set(JOBS), named - set(JOBS)


def _secret_files():
    return [e for e in _list() if e["kind"] == "secret_file" and "cloud" in e["deployments"]]


def test_the_entrypoint_handles_exactly_the_listed_secret_files():
    text = ENTRYPOINT.read_text(encoding="utf-8")
    handled = dict(re.findall(r"^put (CV_[A-Z0-9_]+) (\S+)$", text, re.M))
    want = {e["injected_as"]: e["path"].rsplit("/", 1)[1] for e in _secret_files()}
    assert handled == want
    unset = set(re.search(r"^unset (.+)$", text, re.M).group(1).split())
    assert unset == set(want)


def test_the_entrypoint_writes_every_listed_secret_file_and_removes_it_from_the_environment(tmp_path):
    out = tmp_path / "cv"
    values = {e["injected_as"]: ("ab" * 32 if e["injected_as"].endswith("_HEX") else f"value-of-{e['injected_as']}")
              for e in _secret_files()}
    env = {"PATH": os.environ["PATH"], "CV_FILES_DIR": str(out), **values}
    res = subprocess.run([str(ENTRYPOINT), "sh", "-c", "env"], env=env, capture_output=True, text=True)  # loud-failure-exempt: asserted below
    assert res.returncode == 0, res.stderr
    for e in _secret_files():
        f = out / e["path"].rsplit("/", 1)[1]
        assert f.read_text() == values[e["injected_as"]], e["name"]
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, e["name"]
        assert f"{e['injected_as']}=" not in res.stdout, f"{e['injected_as']} is still in the environment"


def test_a_hex_secret_that_is_not_hex_stops_the_task(tmp_path):
    for e in _secret_files():
        if not e["injected_as"].endswith("_HEX"):
            continue
        res = subprocess.run([str(ENTRYPOINT), "true"], capture_output=True, text=True,  # loud-failure-exempt: asserted below
                             env={"PATH": os.environ["PATH"], "CV_FILES_DIR": str(tmp_path), e["injected_as"]: "zz"})
        assert res.returncode == 2 and e["injected_as"] in res.stderr, e["injected_as"]


class _Recorder(dict):
    """An environment that remembers every name read from it."""

    def __init__(self, *a):
        super().__init__(*a)
        self.read = set()

    def get(self, k, d=None):
        self.read.add(k)
        return super().get(k, d)

    def __getitem__(self, k):
        self.read.add(k)
        return super().__getitem__(k)

    def __contains__(self, k):
        self.read.add(k)
        return super().__contains__(k)


def test_the_records_export_job_starts_with_exactly_the_settings_the_list_gives_it():
    """The export job stores files in the evidence bucket only: its store setup reads no archive or lifecycle-ledger bucket,
    and every name it does read is listed for job:records-exports (or every job)."""
    import types

    from consentvault import cmd_cloud

    listed = {e["name"] for e in _list() if {"job:records-exports", "job:*"} & set(e["used_by"])
              and "cloud" in e["deployments"]}
    assert "CONSENTVAULT_EVIDENCE_BUCKET" in listed
    assert not {"CONSENTVAULT_ARCHIVE_BUCKET", "CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET"} & listed
    env = _Recorder({"CONSENTVAULT_EVIDENCE_BUCKET": "evidence-bucket", "AWS_REGION": "us-east-1"})
    cmd_cloud.evidence_store_only(types.SimpleNamespace(db_auth="iam"), env)
    refusal = {"CONSENTVAULT_EVIDENCE_DIR"}  # read only to refuse a local folder in the cloud; a self-host setting
    assert env.read <= listed | refusal | {"AWS_REGION"} | {e["name"] for e in _list() if e["kind"] == "platform"}, env.read - listed
    assert not {"CONSENTVAULT_ARCHIVE_BUCKET", "CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET"} & env.read
