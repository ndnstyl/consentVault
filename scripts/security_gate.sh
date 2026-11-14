#!/usr/bin/env bash
# The security gate: static analysis, dependency audits, secret scan, infrastructure-code scan, container image scan,
# dynamic baseline. One PASS, FAIL or PARTIAL line per step, a dated evidence bundle, non-zero exit on any FAIL.
# PARTIAL means a step could not fully run and said why (for example no Docker daemon); CV_GATE_STRICT=1 makes it a FAIL.
#   scripts/security_gate.sh                          every step against this repository
#   SECURITY_GATE_STEPS=sast,secrets scripts/security_gate.sh
# Environment: SECURITY_GATE_ROOT (scan another folder; the tests use it), SECURITY_GATE_ALLOWLIST, SECURITY_GATE_EVIDENCE_DIR,
#   CV_SECURITY_TOOLS (tool folder, default ~/.local/share/cv-security-tools), CV_GATE_DAST_URL (run the ZAP baseline there).
set -uo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SECURITY_GATE_ROOT:-$SELF/..}" && pwd)"
LIB="$SELF/security/gate_lib.py"
RULES="$SELF/security/semgrep"
ALLOW="${SECURITY_GATE_ALLOWLIST:-$SELF/security/allowlist.json}"
TOOLS="${CV_SECURITY_TOOLS:-$HOME/.local/share/cv-security-tools}"
STEPS="${SECURITY_GATE_STEPS:-allowlist,suppressions,sast,npm-audit,pip-audit,secrets,iac,image,dast}"
STRICT="${CV_GATE_STRICT:-0}"
CALL_TIMEOUT="${CV_GATE_TIMEOUT:-900}"

# Pinned tool versions. Changing one is a reviewed edit, never a drift.
SEMGREP_V=1.183.0; BANDIT_V=1.9.4; PIPAUDIT_V=2.10.1; TRIVY_V=0.76.1; GITLEAKS_V=8.30.1; ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:2.17.0@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238"
STAMP="semgrep=$SEMGREP_V bandit=$BANDIT_V pip-audit=$PIPAUDIT_V trivy=$TRIVY_V gitleaks=$GITLEAKS_V"

LOGDIR="$(mktemp -d "${TMPDIR:-/tmp}/security-gate.XXXXXX")" || exit 2
RESULTS="$LOGDIR/results.jsonl"; : >"$RESULTS"
trap 'rm -rf "$LOGDIR"' EXIT
failed=0

# A hard deadline for every call (macOS has no timeout(1)); 142 is SIGALRM.
run_to() { perl -e 'alarm shift; exec @ARGV or die "exec failed: $!\n"' "$CALL_TIMEOUT" "$@"; }

record() { # name status detail counts-json
  local counts="${4:-}"; [ -n "$counts" ] || counts='{}'
  python3 - "$RESULTS" "$1" "$2" "$3" "$counts" <<'PY'
import json, sys
path, name, status, detail, counts = sys.argv[1:6]
try:
    c = json.loads(counts)
except ValueError:
    c = {}
open(path, "a").write(json.dumps({"name": name, "status": status, "detail": detail, "counts": c}) + "\n")
PY
  case "$2" in
    FAIL) failed=1 ;;
    PARTIAL) [ "$STRICT" = 1 ] && failed=1 ;;
  esac
  printf '%-8s %-14s %s\n' "$2" "$1" "$3"
}

# conclude NAME LOGFILE RC : turns an evaluate/lib exit code into the line
conclude() {
  local name=$1 log=$2 rc=$3 counts detail
  counts=$(sed -n 's/^COUNTS //p' "$log" | tail -1)
  detail=$(grep -v '^COUNTS ' "$log" | head -30)
  if [ "$rc" -eq 0 ]; then record "$name" PASS "${counts:-clean}" "${counts:-}"; else
    record "$name" FAIL "exit $rc ${counts:-}"; [ -n "$detail" ] && printf '%s\n' "$detail" | sed 's/^/           /'; fi
}

wants() { case ",$STEPS," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# ---- tool install (idempotent, user-local, no sudo) ----
install_tools() {
  mkdir -p "$TOOLS" || { echo "cannot create $TOOLS" >&2; return 1; }
  if [ "$(cat "$TOOLS/.stamp" 2>/dev/null)" = "$STAMP" ] && [ -x "$TOOLS/venv/bin/semgrep" ] && [ -x "$TOOLS/trivy" ] && [ -x "$TOOLS/gitleaks" ]; then return 0; fi
  local os arch tarch garch
  os=$(uname -s); arch=$(uname -m)
  case "$os-$arch" in
    Darwin-arm64) tarch=macOS-ARM64; garch=darwin_arm64
      T_SHA=11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5; G_SHA=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
    Linux-x86_64) tarch=Linux-64bit; garch=linux_x64
      T_SHA=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0; G_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
    Linux-aarch64|Linux-arm64) tarch=Linux-ARM64; garch=linux_arm64
      T_SHA=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f; G_SHA=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
    *) echo "no pinned trivy and gitleaks build for $os-$arch" >&2; return 1 ;;
  esac
  local dl; dl=$(mktemp -d "$TOOLS/dl.XXXXXX") || return 1
  fetch() { # url sha dest-member out
    curl -fsSL --max-time 300 -o "$dl/a.tgz" "$1" || { echo "download failed: $1" >&2; return 1; }
    local got; got=$( (shasum -a 256 "$dl/a.tgz" 2>/dev/null || sha256sum "$dl/a.tgz") | cut -d' ' -f1)
    [ "$got" = "$2" ] || { echo "checksum mismatch for $1 (got $got)" >&2; return 1; }
    tar xzf "$dl/a.tgz" -C "$dl" "$3" && mv "$dl/$3" "$4" && chmod 755 "$4"
  }
  fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_V/trivy_${TRIVY_V}_${tarch}.tar.gz" "$T_SHA" trivy "$TOOLS/trivy" || return 1
  fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_V/gitleaks_${GITLEAKS_V}_${garch}.tar.gz" "$G_SHA" gitleaks "$TOOLS/gitleaks" || return 1
  rm -rf "$dl"
  if command -v uv >/dev/null 2>&1; then
    uv venv --clear --python 3.12 -q "$TOOLS/venv" 2>/dev/null || uv venv --clear -q "$TOOLS/venv" || return 1
    uv pip install -q --python "$TOOLS/venv/bin/python" "semgrep==$SEMGREP_V" "bandit==$BANDIT_V" "pip-audit==$PIPAUDIT_V" || return 1
  else
    python3 -m venv "$TOOLS/venv" && "$TOOLS/venv/bin/pip" install -q "semgrep==$SEMGREP_V" "bandit==$BANDIT_V" "pip-audit==$PIPAUDIT_V" || return 1
  fi
  echo "$STAMP" >"$TOOLS/.stamp"
}

if ! install_tools >"$LOGDIR/install.log" 2>&1; then
  cat "$LOGDIR/install.log" >&2
  record tools FAIL "tool install failed; see above (a missing tool is a failure, never a skip)"
  printf 'SECURITY GATE: FAIL\n'; exit 1
fi
PY="$TOOLS/venv/bin/python"; export PATH="$TOOLS/venv/bin:$TOOLS:$PATH"
export TRIVY_CACHE_DIR="$TOOLS/trivy-cache" SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
TOOLS_JSON=$(printf '{"semgrep":"%s","bandit":"%s","pip-audit":"%s","trivy":"%s","gitleaks":"%s","node":"%s"}' \
  "$SEMGREP_V" "$BANDIT_V" "$PIPAUDIT_V" "$TRIVY_V" "$GITLEAKS_V" "$(node --version 2>/dev/null || echo none)")

EXCL=(--exclude node_modules --exclude .venv --exclude .terraform --exclude out --exclude .next --exclude __pycache__ --exclude tests --exclude test --exclude e2e)

has_files() { [ -n "$(find "$ROOT" \( -path '*/node_modules' -o -path '*/.venv' -o -path '*/.terraform' -o -path '*/.git' \) -prune -o -type f \( "$@" \) -print -quit 2>/dev/null)" ]; }

# ---- steps ----
step_allowlist() {
  local log="$LOGDIR/allowlist.log"
  "$PY" -I "$LIB" check-allowlist "$ALLOW" >"$log" 2>&1; local rc=$?
  if [ $rc -eq 0 ]; then record allowlist PASS "$(cat "$log")"; else record allowlist FAIL "$(head -c 600 "$log")"; fi
}

step_suppressions() {
  local log="$LOGDIR/supp.log"
  "$PY" -I "$LIB" suppressions "$ROOT" >"$log" 2>&1; conclude suppressions "$log" $?
}

step_sast() {
  local log="$LOGDIR/sast.log" rc any=0
  local sg="$LOGDIR/semgrep.json"
  local cfgs=(--config "$RULES/custom.yml")
  [ -f "$RULES/python.yml" ] && cfgs+=(--config "$RULES/python.yml")
  [ -f "$RULES/typescript.yml" ] && cfgs+=(--config "$RULES/typescript.yml")
  run_to semgrep scan "${cfgs[@]}" --metrics=off --disable-version-check --quiet --no-git-ignore "${EXCL[@]}" --json --output "$sg" "$ROOT" >"$LOGDIR/semgrep.err" 2>&1; rc=$?
  if [ $rc -ne 0 ] && [ ! -s "$sg" ]; then
    record sast-semgrep FAIL "semgrep could not run (exit $rc): $(tail -3 "$LOGDIR/semgrep.err" | tr '\n' ' ')"
  else
    "$PY" -I "$LIB" evaluate semgrep "$sg" --allowlist "$ALLOW" --root "$ROOT" >"$log" 2>&1; conclude sast-semgrep "$log" $?
  fi
  if has_files -name '*.py'; then
    local bj="$LOGDIR/bandit.json" bex="" d
    for d in node_modules .venv .terraform tests test out .next e2e; do bex="$bex,*/$d,*/$d/*"; done
    run_to bandit -r "$ROOT" -x "${bex#,}" -f json -o "$bj" -q >"$LOGDIR/bandit.err" 2>&1; rc=$?
    if [ ! -s "$bj" ]; then record sast-bandit FAIL "bandit produced no report (exit $rc): $(tail -3 "$LOGDIR/bandit.err" | tr '\n' ' ')"
    else "$PY" -I "$LIB" evaluate bandit "$bj" --allowlist "$ALLOW" --root "$ROOT" >"$log" 2>&1; conclude sast-bandit "$log" $?; fi
  else
    record sast-bandit PASS "no Python files in scope"
  fi
}

step_npm_audit() {
  local pkgs; pkgs=$(find "$ROOT" \( -name node_modules -o -name .git -o -name .next -o -name out \) -prune -o -name package.json -print 2>/dev/null | sort)
  [ -n "$pkgs" ] || { record npm-audit PASS "no package.json in scope"; return; }
  local p dir rel out log rc ok=1 audited=0 msgs=""
  for p in $pkgs; do
    dir=$(dirname "$p"); rel=${dir#"$ROOT"}; rel=${rel#/}; rel=${rel:-.}
    if ! "$PY" -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if (d.get("dependencies") or d.get("devDependencies") or d.get("optionalDependencies")) else 1)' "$p"; then
      msgs="$msgs [$rel: no dependencies declared]"; continue; fi
    if [ ! -f "$dir/package-lock.json" ] && [ ! -f "$dir/npm-shrinkwrap.json" ]; then
      record "npm-audit" FAIL "$rel declares dependencies but has no lock file, so nothing can be audited; commit its lock file"; ok=0; continue; fi
    out="$LOGDIR/npm_$(echo "$rel" | tr -c 'A-Za-z0-9' '_').json"; log="$LOGDIR/npm.log"
    (cd "$dir" && run_to npm audit --omit=dev --audit-level=high --json >"$out" 2>"$LOGDIR/npm.err"); rc=$?
    if [ ! -s "$out" ]; then record "npm-audit" FAIL "$rel: npm audit gave no report (exit $rc): $(tail -2 "$LOGDIR/npm.err" | tr '\n' ' ')"; ok=0; continue; fi
    audited=$((audited + 1))
    "$PY" -I "$LIB" evaluate npm "$out" --allowlist "$ALLOW" >"$log" 2>&1; rc=$?
    if [ $rc -ne 0 ]; then conclude "npm-audit:$rel" "$log" $rc; ok=0; else msgs="$msgs [$rel: $(sed -n 's/^COUNTS //p' "$log")]"; fi
  done
  [ $ok -eq 1 ] && record npm-audit PASS "run $(date +%F), $audited audited$msgs"
}

step_pip_audit() {
  local files; files=$(find "$ROOT" -maxdepth 2 \( -name node_modules -o -name .venv -o -name .git \) -prune -o -type f \( -name 'requirements*.lock' -o -name 'requirements*.txt' \) -print 2>/dev/null | sort)
  [ -n "$files" ] || { record pip-audit PASS "no Python requirement or lock files in scope, nothing to audit"; return; }
  local f ok=1 log="$LOGDIR/pipaudit.log" out rc n=0
  for f in $files; do
    out="$LOGDIR/pa_$n.json"; n=$((n + 1))
    run_to pip-audit -r "$f" --no-deps --disable-pip --strict --progress-spinner off --format json -o "$out" >"$LOGDIR/pa.err" 2>&1; rc=$?
    if [ ! -s "$out" ]; then record pip-audit FAIL "${f#"$ROOT"/}: no report (exit $rc): $(tail -3 "$LOGDIR/pa.err" | tr '\n' ' ')"; ok=0; continue; fi
    "$PY" -I "$LIB" evaluate pip-audit "$out" --allowlist "$ALLOW" >"$log" 2>&1; rc=$?
    if [ $rc -ne 0 ]; then conclude "pip-audit:${f#"$ROOT"/}" "$log" $rc; ok=0; fi
  done
  [ $ok -eq 1 ] && record pip-audit PASS "run $(date +%F), $n file(s) audited"
}

step_secrets() {
  local cfg="$LOGDIR/gitleaks.toml" rep="$LOGDIR/gitleaks.json" log="$LOGDIR/secrets.log" rc
  "$PY" -I "$LIB" gitleaks-config "$ROOT/.gitleaks.toml" "$cfg" || { record secrets FAIL "cannot build gitleaks config"; return; }
  # Scan what can be committed (tracked, staged, untracked-but-not-ignored), never git-ignored working files.
  local target="$ROOT" snap="$LOGDIR/commitable"
  if [ -d "$ROOT/.git" ]; then
    mkdir -p "$snap"
    git -C "$ROOT" ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' f; do
      [ -f "$ROOT/$f" ] || continue
      mkdir -p "$snap/$(dirname "$f")" && cp -p "$ROOT/$f" "$snap/$f" || { echo "snapshot copy failed: $f" >&2; exit 1; }
    done || { record secrets FAIL "could not snapshot the committable files"; return; }
    target="$snap"
  fi
  run_to gitleaks dir --no-banner --redact -c "$cfg" -f json -r "$rep" "$target" >"$LOGDIR/gl.err" 2>&1; rc=$?
  if [ $rc -gt 1 ] || [ ! -f "$rep" ]; then record secrets FAIL "gitleaks could not run (exit $rc): $(tail -2 "$LOGDIR/gl.err" | tr '\n' ' ')"; return; fi
  "$PY" -I "$LIB" evaluate gitleaks "$rep" >"$log" 2>&1; rc=$?
  if [ -d "$ROOT/.git" ]; then
    local hrep="$LOGDIR/gitleaks_hist.json" hlog="$LOGDIR/secrets_hist.log" hrc
    run_to gitleaks git --no-banner --redact -c "$cfg" -f json -r "$hrep" "$ROOT" >"$LOGDIR/glh.err" 2>&1; hrc=$?
    if [ $hrc -gt 1 ] || [ ! -f "$hrep" ]; then record secrets FAIL "gitleaks history scan could not run (exit $hrc)"; return; fi
    "$PY" -I "$LIB" evaluate gitleaks "$hrep" >"$hlog" 2>&1; hrc=$?
    if [ $hrc -ne 0 ]; then { echo "history scan:"; cat "$hlog"; } >>"$log"; rc=1; fi
  fi
  conclude secrets "$log" $rc
}

step_iac() {
  local targets=() t
  for t in tofu terraform deploy Dockerfile docker-compose.yml docker docker-compose.yaml cloudflare; do [ -e "$ROOT/$t" ] && targets+=("$ROOT/$t"); done
  [ ${#targets[@]} -gt 0 ] || { record iac PASS "no infrastructure code in scope"; return; }
  local out="$LOGDIR/trivy_cfg.json" log="$LOGDIR/iac.log" rc
  run_to trivy config --quiet --skip-version-check --disable-telemetry --severity HIGH,CRITICAL --skip-dirs '**/.terraform' --skip-dirs '**/node_modules' --skip-dirs '**/.venv' --skip-dirs '**/.next' --skip-dirs '**/out' --format json -o "$out" "$ROOT" >"$LOGDIR/trivy.err" 2>&1; rc=$?
  if [ ! -s "$out" ]; then record iac FAIL "trivy config produced no report (exit $rc): $(tail -3 "$LOGDIR/trivy.err" | tr '\n' ' ')"; return; fi
  "$PY" -I "$LIB" evaluate trivy "$out" --allowlist "$ALLOW" --root "$ROOT" >"$log" 2>&1; conclude iac "$log" $?
}

docker_up() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

step_image() {
  [ -f "$ROOT/Dockerfile" ] || { record image PASS "no Dockerfile in scope"; return; }
  if ! docker_up; then
    record image PARTIAL "Docker daemon unreachable: image not built or scanned; the Dockerfile configuration was scanned in the iac step only"; return; fi
  local tag="cv-gate-image:$$" log="$LOGDIR/image.log" out="$LOGDIR/trivy_img.json" rc sbom="$LOGDIR/sbom.cdx.json"
  run_to docker build -q -t "$tag" -f "$ROOT/Dockerfile" "$ROOT" >"$LOGDIR/build.log" 2>&1 || { record image FAIL "docker build failed: $(tail -3 "$LOGDIR/build.log" | tr '\n' ' ')"; return; }
  run_to trivy image --quiet --skip-version-check --disable-telemetry --severity HIGH,CRITICAL --ignore-unfixed --scanners vuln --format json -o "$out" "$tag" >"$LOGDIR/trivy_img.err" 2>&1; rc=$?
  run_to trivy image --quiet --skip-version-check --disable-telemetry --format cyclonedx -o "$sbom" "$tag" >/dev/null 2>&1
  docker rmi -f "$tag" >/dev/null 2>&1
  if [ ! -s "$out" ]; then record image FAIL "trivy image produced no report (exit $rc): $(tail -3 "$LOGDIR/trivy_img.err" | tr '\n' ' ')"; return; fi
  "$PY" -I "$LIB" evaluate trivy "$out" --allowlist "$ALLOW" --root "$ROOT" >"$log" 2>&1; rc=$?
  [ -s "$sbom" ] || { record image FAIL "no SBOM produced"; return; }
  conclude image "$log" $rc
}

step_dast() {
  if [ -z "${CV_GATE_DAST_URL:-}" ]; then
    record dast PARTIAL "not run: set CV_GATE_DAST_URL to a running local stack (needs Docker for ZAP)"; return; fi
  docker_up || { record dast PARTIAL "not run: Docker daemon unreachable"; return; }
  local wrk="$LOGDIR/zap"; mkdir -p "$wrk"; chmod 777 "$wrk"
  run_to docker run --rm -v "$wrk:/zap/wrk" "$ZAP_IMAGE" zap-baseline.py -t "$CV_GATE_DAST_URL" -J report.json -I >"$LOGDIR/zap.log" 2>&1
  [ -s "$wrk/report.json" ] || { record dast FAIL "ZAP produced no report: $(tail -3 "$LOGDIR/zap.log" | tr '\n' ' ')"; return; }
  "$PY" -I "$LIB" evaluate zap "$wrk/report.json" --allowlist "$ALLOW" >"$LOGDIR/dast.log" 2>&1; conclude dast "$LOGDIR/dast.log" $?
}

for s in allowlist suppressions sast npm-audit pip-audit secrets iac image dast; do
  wants "$s" || continue
  case "$s" in
    allowlist) step_allowlist ;; suppressions) step_suppressions ;; sast) step_sast ;; npm-audit) step_npm_audit ;;
    pip-audit) step_pip_audit ;; secrets) step_secrets ;; iac) step_iac ;; image) step_image ;; dast) step_dast ;;
  esac
done

# ---- evidence bundle ----
EV="${SECURITY_GATE_EVIDENCE_DIR:-}"
if [ -z "$EV" ]; then
  if [ -d "$ROOT/governance/evidence" ]; then EV="$ROOT/governance/evidence/C-47"
  elif [ -d "/Users/oxfloors/ConsentVault/operations/governance/evidence" ]; then EV="$(cd "/Users/oxfloors/ConsentVault/operations" && pwd)/governance/evidence/C-47"
  else EV="$ROOT/.security-evidence"; fi
fi
if bpath=$("$PY" -I "$LIB" bundle "$EV/$(basename "$ROOT")-$(date +%F).json" "$RESULTS" "$ROOT" "$TOOLS_JSON" 2>"$LOGDIR/bundle.err"); then
  echo "evidence: $bpath"
else
  echo "FAIL: could not write the evidence bundle: $(cat "$LOGDIR/bundle.err")"; failed=1
fi
if [ "$failed" -ne 0 ]; then echo "SECURITY GATE: FAIL"; exit 1; fi
echo "SECURITY GATE: PASS"
