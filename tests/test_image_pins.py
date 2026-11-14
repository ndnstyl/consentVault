"""The product image is reproducible and carries what the cloud task definitions require, each pinned and verified at
build: the base image by digest, every Python package by hash, the trigger guard SQL the migration task runs, and AWS's
RDS global CA bundle the IAM sign-in verifies against. The cloud target adds the private KMS key provider from a named
build context (never published) and an entrypoint that writes the injected secrets to the /tmp/cv files the tasks name.

Nothing here reads outside this repository; the cloud setup checks its own pin of the guard against this repository.
"""

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
GUARD = ROOT / "docker" / "initdb" / "20-trigger-guard.sql"
ENTRYPOINT = ROOT / "docker" / "cloud-entrypoint.sh"
RDS_BUNDLE_SHA256 = "90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b"
RDS_BUNDLE_PATH = "/etc/consentvault/rds-global-bundle.pem"
GUARD_PATH = "/app/docker/initdb/20-trigger-guard.sql"


def _docker() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _steps() -> list[str]:
    return re.split(r"\n(?=(?:RUN|COPY|FROM|ENV|USER|WORKDIR|EXPOSE|CMD|ADD|ENTRYPOINT|ARG) )", _docker())


def _run(args, env):
    return subprocess.run(args, env=env, capture_output=True, text=True)  # loud-failure-exempt: every caller asserts the exit code


CLOUD = ROOT / "docker" / "cloud.Dockerfile"
BUILD_CLOUD = ROOT / "scripts" / "build_cloud_image.sh"


def test_the_product_dockerfile_is_one_open_stage_any_builder_can_build():
    text = _docker()
    assert len(re.findall(r"^FROM\s", text, re.M)) == 1
    instructions = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("kmsplugin" in ln or "--from=" in ln for ln in instructions), "nothing private in the open image"


def test_every_base_image_is_pinned_by_digest():
    froms = [f for f in re.findall(r"^FROM\s+(\S+)", _docker(), re.M) if f not in ("base",)]
    assert froms, "the Dockerfile names no base image"
    for ref in froms:
        assert re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", ref), f"{ref} is not pinned by digest"


def test_every_package_is_installed_from_a_hash_locked_file():
    lines = [ln for s in _steps() for ln in re.findall(r"pip install[^\n&\\]*", s)]
    assert lines
    for line in lines:
        assert "--require-hashes" in line or ("--no-deps" in line and "--no-build-isolation" in line
                                              and "--no-index" in line), line
    for lock in ("requirements.lock", "requirements-build.lock"):
        blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", (ROOT / lock).read_text(encoding="utf-8"))
        pinned = [b for b in blocks if re.match(r"[A-Za-z0-9_.-]+==", b)]
        assert pinned, lock
        for b in pinned:
            assert "--hash=sha256:" in b, (lock, b.splitlines()[0])


def test_the_runtime_lock_is_the_lockfile_exported():
    uv = os.environ.get("UV") or str(Path.home() / ".local/bin/uv")
    out = subprocess.run([uv, "export", "--frozen", "--no-dev", "--extra", "cloud", "--no-emit-project",
                          "--format", "requirements-txt"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    strip = lambda t: [ln for ln in t.splitlines() if not ln.startswith("#")]
    assert strip(out) == strip((ROOT / "requirements.lock").read_text(encoding="utf-8")), \
        "requirements.lock is stale: uv export --frozen --no-dev --extra cloud --no-emit-project -o requirements.lock"


def test_the_dockerfile_ships_the_trigger_guard_and_verifies_its_hash_at_build():
    text = _docker()
    assert re.search(r"^COPY\s+docker/initdb/20-trigger-guard\.sql\s+" + re.escape(GUARD_PATH) + r"\s*$", text, re.M)
    digest = hashlib.sha256(GUARD.read_bytes()).hexdigest()
    assert f"{digest}  {GUARD_PATH}" in text, "the Dockerfile pins the guard's current sha256 and checks it"
    assert re.search(r"sha256sum\s+-c\b", text)


def test_the_dockerfile_fetches_the_rds_bundle_pinned_and_fails_the_build_on_mismatch():
    text = _docker()
    assert "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem" in text
    step = next(s for s in _steps() if RDS_BUNDLE_SHA256 in s)
    assert "sha256sum -c" in step and "|| true" not in step and RDS_BUNDLE_PATH in step


def test_the_cloud_image_adds_the_private_key_provider_and_the_entrypoint_on_top_of_the_open_image():
    cloud = CLOUD.read_text(encoding="utf-8")
    assert re.findall(r"^FROM\s+(\S+)", cloud, re.M) == ["${BASE_IMAGE}"]
    copy = re.search(r"^COPY\s+--from=kmsplugin\s+consentvault_kms/?\s+(\S*site-packages/consentvault_kms/)\s*$", cloud, re.M)
    assert copy, "the plugin package is copied whole, never as a hand-kept file list that can fall behind"
    for test_only in ("fake.py", "contract.py"):  # the test fake and its contract factory are removed, then proved absent
        assert re.search(rf"rm\s+-f[^\n]*consentvault_kms/{re.escape(test_only)}", cloud), test_only
        assert re.search(rf"test\s+!\s+-e\s+\S*consentvault_kms/{re.escape(test_only)}", cloud), test_only
    assert re.search(r"python -c \"[^\"]*from consentvault_kms import KmsEvidenceSigner, KmsKeyProvider", cloud), \
        "the build imports every class the task settings name"
    assert "docker/cloud-entrypoint.sh" in cloud and re.search(r'^ENTRYPOINT \["/usr/local/bin/cv-entrypoint"\]', cloud, re.M)
    script = BUILD_CLOUD.read_text(encoding="utf-8")
    assert BUILD_CLOUD.stat().st_mode & stat.S_IXUSR
    assert "docker build" in script and "-f docker/cloud.Dockerfile" in script
    assert re.search(r'--build-context "?kmsplugin=', script)
    # the cloud layer is built FROM the exact open image just built: a tag made from its image id, checked after
    assert re.search(r'BASE_IMAGE=consentvault-open:\$\{?base_id#sha256:', script.replace('"', ""))
    assert "consentvault:open-for-cloud" not in script
    assert "set -eu" in script


def test_the_entrypoint_writes_the_injected_secrets_to_the_tmp_cv_files_then_runs_the_command(tmp_path):
    assert ENTRYPOINT.stat().st_mode & stat.S_IXUSR
    out = tmp_path / "cv"
    env = {"PATH": os.environ["PATH"], "CV_FILES_DIR": str(out), "CV_ORG_KEY_POLICY_JSON": '{"Statement": []}',
           "CV_TENANT_TOKEN_KEY_HEX": "ab" * 32, "CV_EGRESS_SECRET": "egress"}
    res = _run([str(ENTRYPOINT), "sh", "-c", "echo ran; env | grep -c '^CV_TENANT_TOKEN_KEY_HEX=' || true"], env)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["ran", "0"], "the secrets are dropped from the environment before the command runs"
    assert (out / "org-key-policy.json").read_text() == '{"Statement": []}'
    assert (out / "tenant-token-key.hex").read_text() == "ab" * 32
    assert (out / "egress-secret").read_text() == "egress"
    for f in out.iterdir():
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f


SECRETS = {"CV_ORG_KEY_POLICY_JSON": ("org-key-policy.json", '{"Statement": []}'),
           "CV_TENANT_TOKEN_KEY_HEX": ("tenant-token-key.hex", "cd" * 32),
           "CV_EGRESS_SECRET": ("egress-secret", "egress"),
           "CV_STRIPE_SECRET_KEY": ("stripe-secret-key", "rk_test_" + "x" * 24)}


def test_every_injected_secret_is_written_to_its_file_mode_600_and_removed_from_the_environment(tmp_path):
    out = tmp_path / "cv"
    env = {"PATH": os.environ["PATH"], "CV_FILES_DIR": str(out), **{k: v for k, (_, v) in SECRETS.items()}}
    res = _run([str(ENTRYPOINT), "sh", "-c", "env"], env)
    assert res.returncode == 0, res.stderr
    for name, (file, value) in SECRETS.items():
        assert (out / file).read_text() == value, name
        assert stat.S_IMODE((out / file).stat().st_mode) == 0o600, name
        assert f"{name}=" not in res.stdout and value not in res.stdout, f"{name} is still in the environment"


def test_the_stripe_key_lands_where_the_billing_jobs_read_it():
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert re.search(r"^put CV_STRIPE_SECRET_KEY stripe-secret-key$", text, re.M)
    from consentvault import cmd_usage
    assert cmd_usage.ENV_STRIPE_KEY_FILE == "CONSENTVAULT_STRIPE_SECRET_KEY_FILE"


def test_the_entrypoint_writes_nothing_it_was_not_given(tmp_path):
    out = tmp_path / "cv"
    res = _run([str(ENTRYPOINT), "true"], {"PATH": os.environ["PATH"], "CV_FILES_DIR": str(out)})
    assert res.returncode == 0, res.stderr
    assert sorted(p.name for p in out.iterdir()) == []


def test_the_entrypoint_refuses_a_token_key_that_is_not_hex(tmp_path):
    res = _run([str(ENTRYPOINT), "true"], {"PATH": os.environ["PATH"], "CV_FILES_DIR": str(tmp_path),
                                            "CV_TENANT_TOKEN_KEY_HEX": "not hex"})
    assert res.returncode != 0 and "CV_TENANT_TOKEN_KEY_HEX" in res.stderr


PLUGIN = Path(os.environ.get("KMS_PLUGIN_DIR") or Path("/Users/oxfloors/ConsentVault/operations/provider")) / "consentvault_kms"


def _relative_imports(path: Path) -> set[str]:
    import ast

    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            names.add(node.module.split(".")[0] if node.module else "")
    return names


def test_every_module_the_plugin_package_imports_reaches_the_image():
    """Everything __init__ imports, and everything those import in turn, is a module the copied package keeps: none is a
    test-only file the build removes, and every one exists. A new module therefore can never be left out of the image."""
    if not PLUGIN.is_dir():
        import pytest
        pytest.fail(f"the KMS plugin package is not at {PLUGIN} (set KMS_PLUGIN_DIR)")
    removed = set(re.findall(r"consentvault_kms/(\w+)\.py", CLOUD.read_text(encoding="utf-8").split("COPY --from=kmsplugin", 1)[1]))
    seen, todo = set(), ["__init__"]
    while todo:
        mod = todo.pop()
        if mod in seen:
            continue
        seen.add(mod)
        f = PLUGIN / f"{mod}.py"
        assert f.is_file(), f"consentvault_kms imports {mod!r}, which does not exist"
        assert mod not in removed, f"consentvault_kms imports {mod!r}, which the cloud image build removes"
        todo.extend(_relative_imports(f) - {""})
    assert {"signer", "provider", "kms", "sts"} <= seen
