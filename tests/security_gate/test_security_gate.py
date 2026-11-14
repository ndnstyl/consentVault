"""Each scanner in scripts/security_gate.sh is proven to fail on one planted known-bad sample, and to pass a clean one.

Samples live in a temporary folder (never in the repository). Secret-shaped strings are assembled at run time so this
file itself stays clean under the secret scan. The tests need network (tool download, advisory databases).
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

import pytest

pytestmark = pytest.mark.network

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
GATE = SCRIPTS / "security_gate.sh"
LIB = SCRIPTS / "security" / "gate_lib.py"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1500, **kw)  # loud-failure-exempt: every caller asserts on the exit code, which is the behaviour under test


def docker_up():
    return shutil.which("docker") is not None and run(["docker", "info"]).returncode == 0


class GateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "sample"
        self.root.mkdir()
        self.addCleanup(self.tmp.cleanup)

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def gate(self, steps, allowlist=None, extra_env=None):
        env = dict(os.environ, SECURITY_GATE_ROOT=str(self.root), SECURITY_GATE_STEPS=steps,
                   SECURITY_GATE_EVIDENCE_DIR=str(Path(self.tmp.name) / "evidence"))
        env.pop("CV_GATE_STRICT", None)
        p = Path(self.tmp.name) / "allow.json"
        p.write_text(json.dumps({"entries": allowlist or []}))
        env["SECURITY_GATE_ALLOWLIST"] = str(p)
        env.update(extra_env or {})
        r = run(["bash", str(GATE)], env=env)
        return r.returncode, r.stdout + r.stderr


class StaticAnalysis(GateCase):
    def test_python_bad_sample_fails_both_analyzers(self):
        self.write("src/bad.py", "import subprocess, hashlib\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n    return hashlib.md5(cmd.encode()).hexdigest()\n")
        rc, out = self.gate("sast")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("FAIL     sast-bandit", out)
        self.assertIn("FAIL     sast-semgrep", out)

    def test_typescript_bad_sample_fails(self):
        self.write("edge/src/bad.ts", "export function f(signature: string, expected: string, el: HTMLElement, s: string) {\n"
                   "  el.innerHTML = s;\n  eval(s);\n  return signature === expected;\n}\n")
        rc, out = self.gate("sast")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("FAIL     sast-semgrep", out)
        self.assertIn("nonconstant-time-compare-ts", out)

    def test_constant_time_rule_names_python_compare(self):
        self.write("src/sig.py", "def ok(signature, expected):\n    return signature == expected\n")
        rc, out = self.gate("sast")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("nonconstant-time-compare-py", out)

    def test_clean_sample_passes(self):
        self.write("src/ok.py", "import hmac\n\ndef ok(signature, expected):\n    return hmac.compare_digest(signature, expected)\n")
        self.write("edge/src/ok.ts", "export const add = (a: number, b: number) => a + b;\n")
        rc, out = self.gate("sast")
        self.assertEqual(rc, 0, out)


class Dependencies(GateCase):
    def test_npm_known_vulnerable_dependency_fails(self):
        self.write("edge/package.json", json.dumps({"name": "x", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}}))
        r = run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=self.root / "edge")
        self.assertEqual(r.returncode, 0, r.stderr)
        rc, out = self.gate("npm-audit")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("FAIL     npm-audit", out)

    def test_npm_dependencies_without_lock_file_fail_loudly(self):
        self.write("edge/package.json", json.dumps({"name": "x", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}}))
        rc, out = self.gate("npm-audit")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("no lock file", out)

    def test_npm_without_dependencies_passes_and_says_so(self):
        self.write("edge/package.json", json.dumps({"name": "x", "version": "1.0.0"}))
        rc, out = self.gate("npm-audit")
        self.assertEqual(rc, 0, out)
        self.assertIn("no dependencies declared", out)

    def test_pip_audit_known_vulnerable_pin_fails(self):
        self.write("requirements.lock", "requests==2.19.0\n")
        rc, out = self.gate("pip-audit")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("FAIL     pip-audit", out)


class Secrets(GateCase):
    def test_planted_value_fails_and_is_not_echoed(self):
        planted = "ghp_" + "R4nd0mT0k3nValu3Zq8Xw2Lm9Pk5Vb7Nc3Hd"
        self.write("src/cfg.py", f'GITHUB = "{planted}"\n')
        rc, out = self.gate("secrets")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("FAIL     secrets", out)
        self.assertNotIn(planted, out)

    def test_clean_folder_passes(self):
        self.write("src/ok.py", "x = 1\n")
        rc, out = self.gate("secrets")
        self.assertEqual(rc, 0, out)


class InfrastructureAndImage(GateCase):
    def test_dockerfile_and_tofu_bad_samples_fail(self):
        self.write("Dockerfile", "FROM ubuntu:latest\nADD http://example.com/x /x\nRUN chmod 777 /x\n")
        self.write("tofu/main.tf", 'resource "aws_security_group" "open" {\n  description = "open"\n  ingress {\n    description = "all"\n'
                   '    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        rc, out = self.gate("iac")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("FAIL     iac", out)

    def test_clean_dockerfile_passes(self):
        self.write("Dockerfile", "FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159\n"
                   "RUN useradd -m app\nUSER app\nHEALTHCHECK CMD true\n")
        rc, out = self.gate("iac")
        self.assertEqual(rc, 0, out)

    @unittest.skipIf(docker_up(), "a Docker daemon is up; the PARTIAL path is the no-daemon path")
    def test_image_step_without_docker_is_partial_not_silent(self):
        self.write("Dockerfile", "FROM scratch\n")
        rc, out = self.gate("image")
        self.assertEqual(rc, 0, out)
        self.assertIn("PARTIAL  image", out)
        self.assertIn("Docker daemon unreachable", out)
        rc, out = self.gate("image", extra_env={"CV_GATE_STRICT": "1"})
        self.assertNotEqual(rc, 0, out)

    def test_dast_not_run_is_partial_and_strict_fails(self):
        rc, out = self.gate("dast")
        self.assertEqual(rc, 0, out)
        self.assertIn("PARTIAL  dast", out)
        rc, out = self.gate("dast", extra_env={"CV_GATE_STRICT": "1"})
        self.assertNotEqual(rc, 0, out)

    def test_zap_report_with_medium_alert_fails_the_bar(self):
        rep = Path(self.tmp.name) / "zap.json"
        rep.write_text(json.dumps({"site": [{"alerts": [{"pluginid": "10038", "riskcode": "2", "name": "Content Security Policy Header Not Set"}]}]}))
        self.assertEqual(run(["python3", str(LIB), "evaluate", "zap", str(rep)]).returncode, 1)
        rep.write_text(json.dumps({"site": [{"alerts": [{"pluginid": "1", "riskcode": "1", "name": "low"}]}]}))
        self.assertEqual(run(["python3", str(LIB), "evaluate", "zap", str(rep)]).returncode, 0)


class AllowlistAndSuppressions(GateCase):
    def entry(self, **kw):
        e = {"tool": "semgrep", "id": "cv-shell-true-py", "path": "src/bad.py", "count": 1, "reason": "planted sample accepted for the test only", "expires": str(date.today() + timedelta(days=30))}
        e.update(kw)
        return e

    def test_entry_without_reason_fails(self):
        rc, out = self.gate("allowlist", allowlist=[self.entry(reason="")])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("missing reason", out)

    def test_expired_entry_fails(self):
        rc, out = self.gate("allowlist", allowlist=[self.entry(expires=str(date.today() - timedelta(days=1)))])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("expired", out)

    def test_entry_without_date_or_beyond_ninety_days_fails(self):
        rc, out = self.gate("allowlist", allowlist=[self.entry(expires="")])
        self.assertNotEqual(rc, 0, out)
        rc, out = self.gate("allowlist", allowlist=[self.entry(expires=str(date.today() + timedelta(days=200)))])
        self.assertNotEqual(rc, 0, out)

    def test_valid_entry_suppresses_one_finding_and_is_counted(self):
        self.write("src/bad.py", "import os\n\ndef run(c):\n    os.system(c)\n")
        rc, out = self.gate("sast", allowlist=[self.entry(), self.entry(tool="bandit", id="B605")])
        self.assertEqual(rc, 0, out)
        self.assertIn('"accepted": 1', out)

    def test_suppression_without_reason_fails_and_with_reason_passes(self):
        self.write("src/a.py", "import os\nos.system('ls')  # nosec\n")
        rc, out = self.gate("suppressions")
        self.assertNotEqual(rc, 0, out)
        self.write("src/a.py", "import os\nos.system('ls')  # nosec -- fixed literal command, no input reaches it\n")
        rc, out = self.gate("suppressions")
        self.assertEqual(rc, 0, out)


class SecretsGitScope(GateCase):
    PLANTED = "ghp_" + "R4nd0mT0k3nValu3Zq8Xw2Lm9Pk5Vb7Nc3Hd"

    def git(self, *a):
        r = run(["git", "-C", str(self.root), "-c", "user.email=t@example.com", "-c", "user.name=t", *a])
        self.assertEqual(r.returncode, 0, r.stderr)

    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        self.write(".gitignore", "ignored.env\n")
        self.write("src/ok.py", "x = 1\n")
        self.git("add", ".gitignore", "src/ok.py")
        self.git("commit", "-q", "-m", "base")

    def test_secret_in_ignored_file_passes(self):
        self.write("ignored.env", f'TOKEN="{self.PLANTED}"\n')
        rc, out = self.gate("secrets")
        self.assertEqual(rc, 0, out)

    def test_secret_in_tracked_file_fails(self):
        self.write("src/cfg.py", f'TOKEN = "{self.PLANTED}"\n')
        self.git("add", "src/cfg.py")
        rc, out = self.gate("secrets")
        self.assertNotEqual(rc, 0, out)
        self.assertNotIn(self.PLANTED, out)

    def test_secret_in_past_commit_fails(self):
        self.write("src/cfg.py", f'TOKEN = "{self.PLANTED}"\n')
        self.git("add", "src/cfg.py")
        self.git("commit", "-q", "-m", "oops")
        self.write("src/cfg.py", "TOKEN = None\n")
        self.git("add", "src/cfg.py")
        self.git("commit", "-q", "-m", "removed")
        rc, out = self.gate("secrets")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("history scan", out)
