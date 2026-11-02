#!/usr/bin/env bash
# The checkpoint gate: every stage runs, none stops the others, one PASS or FAIL line each, non-zero exit if any failed.
#   scripts/checkpoint.sh            (from anywhere; logs land in a temp folder named in the summary)
set -u  # loud-failure-exempt: no set -e by design, every stage's exit code is captured and reported, then the script exits non-zero
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root" || exit 2
if [ -z "${PG_BIN:-}" ]; then
  if command -v pg_config >/dev/null 2>&1; then
    PG_BIN=$(pg_config --bindir) || { echo "FAIL  pg_config --bindir failed; set PG_BIN to the PostgreSQL bin directory" >&2; exit 2; }
  else
    echo "FAIL  PostgreSQL binaries not found: set PG_BIN, or put pg_config on PATH" >&2; exit 2
  fi
fi
[ -x "$PG_BIN/initdb" ] || { echo "FAIL  no initdb in PG_BIN ($PG_BIN)" >&2; exit 2; }
export PG_BIN
# The Twenty connector's model-conformance test drives the real connector through the design model's event sequences; the model
# is kept in tests/connectors/twenty/model and always runs. TWENTY_MODEL_DIR, when set, names the design kit's folder and the
# test proves the copy here matches it.
if [ -n "${TWENTY_MODEL_DIR:-}" ] && [ ! -f "$TWENTY_MODEL_DIR/twenty_erasure.py" ]; then
  echo "FAIL  TWENTY_MODEL_DIR names no folder holding twenty_erasure.py" >&2; exit 2
fi
[ -f tests/connectors/twenty/model/twenty_erasure.py ] || { echo "FAIL  the Twenty model is missing from tests/connectors/twenty/model" >&2; exit 2; }
export PATH="$HOME/.local/bin:$PATH"
logs=$(mktemp -d "${TMPDIR:-/tmp}/checkpoint.XXXXXX") || exit 2
results=()
failed=0

stage() {
  local name=$1; shift
  local log="$logs/$(echo "$name" | tr -c 'A-Za-z0-9' '_').log"
  if "$@" >"$log" 2>&1; then
    results+=("PASS  $name")
  else
    results+=("FAIL  $name  (log: $log)")
    failed=1
  fi
}

py() { uv run --extra dev python "$@"; }

secret_scan() {
  if command -v gitleaks >/dev/null 2>&1; then
    local cfg="$logs/gitleaks.toml"
    py - "$root/.gitleaks.toml" "$cfg" <<'PY' || return 1
import re, sys
src, dst = sys.argv[1:3]
text = open(src).read()
skip = ["\\.next/", "node_modules/", "\\.venv/", "(^|/)out/", "__pycache__/", "\\.git/"]
paths = "paths = [" + ", ".join("'''" + s + "'''" for s in skip) + "]\n"
text = re.sub(r"(\[allowlist\]\n)", lambda m: m.group(1) + paths, text, count=1)
open(dst, "w").write(text)
PY
    gitleaks dir --no-banner --redact -c "$cfg" "$root" || return 1
  else
    py scripts/secret_scan.py
  fi
}

dashboard_build() { (cd portal/app && npm run build); }
dashboard_unit()  { (cd portal/app && npm test); }
dashboard_e2e()   { (cd portal/app && npm run e2e); }

# the python suite writes every test's outcome to a run report; the traceability stage fails a mapped test that did not
# pass in it (skipped, deselected or failed) unless its requirement names a receipt or a covering test that passed
run_report="$logs/python_run.json"
stage "python suite"               env CONSENTVAULT_RUN_REPORT_OUT="$run_report" uv run --extra dev pytest -q
stage "edge tests"                 bash -c 'cd edge && npm test'
stage "dashboard build"            dashboard_build
stage "dashboard unit tests"       dashboard_unit
stage "dashboard browser run"      dashboard_e2e
stage "migrations up/down/up"      py tests/traceability/migration_roundtrip.py
stage "security manifest current"  py scripts/build_security_manifest.py --check
stage "copy check"                 py scripts/copy_check.py
stage "secret scan"                secret_scan
stage "traceability"               env CONSENTVAULT_RUN_REPORT_IN="$run_report" uv run --extra dev pytest -q tests/traceability/test_requirements_traceability.py
stage "security gate"              bash scripts/security_gate.sh

echo
for r in "${results[@]}"; do echo "$r"; done
echo
if [ "$failed" -ne 0 ]; then echo "CHECKPOINT: FAIL (logs in $logs)"; exit 1; fi
echo "CHECKPOINT: PASS"
