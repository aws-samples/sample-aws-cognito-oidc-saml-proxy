#!/usr/bin/env bash
#
# security-scan.sh — run the security scanner suite locally, mirroring the
# jobs the Amazon Probe / Holmes pipeline runs against this repo so findings
# can be triaged BEFORE pushing.
#
# Scanners (each is skipped with a note if not installed):
#   - gitleaks     secrets (honors .gitleaksignore + .gitleaks.toml)
#   - semgrep      SAST (honors inline // nosemgrep and .semgrepignore)
#   - checkov      IaC / Terraform / Dockerfile (honors inline #checkov:skip)
#   - cfn_nag      CloudFormation
#   - bandit       Python
#   - grype        dependency / vulnerability
#   - govulncheck  Go call-graph vulnerabilities
#
# Results are written to scan-results/ (gitignored).
#
# Gating (default SEVERITY_GATE=error): fails only on the findings that block
# the Public Content Security Review — secrets (gitleaks) and High/Critical
# dependency vulnerabilities (grype, govulncheck). SAST/IaC (semgrep, checkov,
# cfn_nag, bandit) are advisory: reported for triage but non-gating, matching
# how the Probe/Holmes pipeline classifies them (WARNING/INFO).
#
# Strict mode (SEVERITY_GATE=warning): also gates on semgrep ERROR/WARNING and
# grype Medium.
#
# Usage:
#   scripts/security-scan.sh            # run all available scanners
#   SEVERITY_GATE=warning scripts/security-scan.sh
#   scripts/security-scan.sh gitleaks semgrep   # run a subset

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/scan-results"
SEVERITY_GATE="${SEVERITY_GATE:-error}"
mkdir -p "$OUT"
cd "$ROOT"

# Prefer pipx-installed tools in ~/.local/bin.
export PATH="$HOME/.local/bin:$PATH"

FAIL=0
RAN=()
SKIPPED=()

hr() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

want() { # want <name>: true if no args given, or name is in the arg list
  [ "$#" -eq 1 ] && [ "${#SELECT[@]}" -eq 0 ] && return 0
  local n="$1"; shift
  for s in "${SELECT[@]}"; do [ "$s" = "$n" ] && return 0; done
  return 1
}

SELECT=("$@")

run_gitleaks() {
  want gitleaks || return 0
  hr "gitleaks (secrets)"
  if ! have gitleaks; then SKIPPED+=("gitleaks: brew install gitleaks"); return; fi
  RAN+=("gitleaks")
  if gitleaks git -c .gitleaks.toml --report-format json \
       --report-path "$OUT/gitleaks.json" --redact 2>&1 | tail -n 3; then
    echo "gitleaks: no leaks"
  else
    echo "gitleaks: findings -> $OUT/gitleaks.json"
    FAIL=1
  fi
}

run_semgrep() {
  want semgrep || return 0
  hr "semgrep (SAST)"
  if ! have semgrep; then SKIPPED+=("semgrep: brew install semgrep"); return; fi
  RAN+=("semgrep")
  local sev="--severity ERROR"
  [ "$SEVERITY_GATE" = "warning" ] && sev="--severity ERROR --severity WARNING"
  semgrep scan --config auto $sev --sarif --output "$OUT/semgrep.sarif" . >/dev/null 2>&1
  local rc=$?
  semgrep scan --config auto $sev --quiet . 2>/dev/null | tail -n 20
  # SAST is advisory by default (aligns with Probe, which treats SAST as
  # WARNING/INFO). Only gate on it in strict mode.
  if [ "$SEVERITY_GATE" = "warning" ] && [ $rc -ne 0 ]; then FAIL=1; fi
}

run_checkov() {
  want checkov || return 0
  hr "checkov (IaC)"
  if ! have checkov; then SKIPPED+=("checkov: pipx install checkov"); return; fi
  RAN+=("checkov")
  # Soft-fail: checkov best-practice findings are advisory for this sample.
  checkov -d . --compact --quiet \
    --output json --output-file-path "$OUT/checkov.json" >/dev/null 2>&1 || true
  echo "checkov: report -> $OUT/checkov.json/results_json.json"
}

run_cfn_nag() {
  want cfn_nag || return 0
  hr "cfn_nag (CloudFormation)"
  local bin; bin="$(command -v cfn_nag_scan || echo "$(ruby -e 'print Gem.bindir' 2>/dev/null)/cfn_nag_scan")"
  if [ ! -x "$bin" ]; then SKIPPED+=("cfn_nag: gem install cfn-nag"); return; fi
  RAN+=("cfn_nag")
  "$bin" --input-path internal/iac/templates/testdata --output-format json \
    > "$OUT/cfn_nag.json" 2>"$OUT/cfn_nag.err" \
    && echo "cfn_nag: clean" \
    || { echo "cfn_nag: findings/err -> $OUT/cfn_nag.json ($(tail -n1 "$OUT/cfn_nag.err"))"; }
}

run_bandit() {
  want bandit || return 0
  hr "bandit (Python)"
  if ! have bandit; then SKIPPED+=("bandit: pipx install bandit"); return; fi
  RAN+=("bandit")
  bandit -r . -f json -o "$OUT/bandit.json" -q 2>/dev/null \
    && echo "bandit: no findings" \
    || echo "bandit: report -> $OUT/bandit.json"
}

run_grype() {
  want grype || return 0
  hr "grype (dependencies)"
  if ! have grype; then SKIPPED+=("grype: brew install grype"); return; fi
  RAN+=("grype")
  local fail="--fail-on high"
  [ "$SEVERITY_GATE" = "warning" ] && fail="--fail-on medium"
  if grype dir:. --output json --file "$OUT/grype.json" $fail >/dev/null 2>&1; then
    echo "grype: no findings at/above gate"
  else
    echo "grype: findings -> $OUT/grype.json"
    FAIL=1
  fi
}

run_govulncheck() {
  want govulncheck || return 0
  hr "govulncheck (Go)"
  if ! have govulncheck; then SKIPPED+=("govulncheck: go install golang.org/x/vuln/cmd/govulncheck@latest"); return; fi
  RAN+=("govulncheck")
  if GOPROXY="${GOPROXY:-off}" govulncheck ./... > "$OUT/govulncheck.txt" 2>&1; then
    echo "govulncheck: no vulnerabilities"
  else
    echo "govulncheck: findings -> $OUT/govulncheck.txt"
    FAIL=1
  fi
}

run_gitleaks
run_semgrep
run_checkov
run_cfn_nag
run_bandit
run_grype
run_govulncheck

hr "summary"
echo "gate: $SEVERITY_GATE   results: $OUT/"
[ "${#RAN[@]}" -gt 0 ]     && printf 'ran:     %s\n' "${RAN[*]}"
for s in "${SKIPPED[@]:-}"; do [ -n "$s" ] && echo "skipped: $s"; done
if [ "$FAIL" -ne 0 ]; then
  echo -e "\n\033[31mFAIL: findings at/above '$SEVERITY_GATE'. See $OUT/.\033[0m"
  exit 1
fi
echo -e "\n\033[32mOK: no findings at/above '$SEVERITY_GATE'.\033[0m"
