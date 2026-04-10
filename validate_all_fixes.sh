#!/usr/bin/env bash
set -euo pipefail

# validate_all_fixes.sh
# Usage: bash validate_all_fixes.sh
# Run from repo root.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

FAILURES=0
WARNINGS=0

pass() { echo "✅ $*"; }
fail() { echo "❌ $*"; FAILURES=$((FAILURES + 1)); }
warn() { echo "⚠️  $*"; WARNINGS=$((WARNINGS + 1)); }

run_cmd() {
  local desc="$1"; shift
  if "$@"; then
    pass "$desc"
  else
    fail "$desc"
  fi
}

echo "== Perfodia Full Fix Validation =="
echo

# -------------------------------------------------------------------
# 1) Static/code quality checks
# -------------------------------------------------------------------
run_cmd "ruff check ." ruff check .
run_cmd "mypy ." mypy .
run_cmd "pytest -q" pytest -q

# -------------------------------------------------------------------
# 2) CLI capability checks
# -------------------------------------------------------------------
HELP_OUT="$(python3 perfodia.py --help 2>&1 || true)"

for flag in \
  "--target-list" "--modules" "--config" "--session" "--resume" \
  "--nmap-extra" "--nmap-raw" "--nmap-scan-type" "--nmap-scripts" \
  "--report-format" "--check-tools" "--init"
do
  if grep -q -- "$flag" <<<"$HELP_OUT"; then
    pass "CLI exposes $flag"
  else
    fail "CLI missing $flag"
  fi
done

# Resume requires session
if python3 perfodia.py -t 127.0.0.1 -m recon --resume >/tmp/perfodia_resume_no_session.out 2>&1; then
  fail "--resume without --session should fail"
else
  if grep -q -- "--resume requires --session" /tmp/perfodia_resume_no_session.out; then
    pass "--resume requires --session enforced"
  else
    fail "--resume error message not found"
  fi
fi

# Target list support (dry-run)
TMP_TARGETS="$(mktemp)"
cat > "$TMP_TARGETS" <<EOF
127.0.0.1
localhost
EOF

if python3 perfodia.py -tL "$TMP_TARGETS" -m recon --dry-run -v >/tmp/perfodia_target_list.out 2>&1; then
  pass "target-list flow executes"
else
  fail "target-list flow failed"
fi
rm -f "$TMP_TARGETS"

# Nmap override validation path
if python3 perfodia.py -t 127.0.0.1 -m scan --dry-run --nmap-extra "-Pn --top-ports 1000" >/tmp/perfodia_nmap_extra.out 2>&1; then
  pass "nmap extra override accepted"
else
  fail "nmap extra override failed"
fi

# Report format integration path
if python3 perfodia.py -t 127.0.0.1 -m recon --dry-run --report-format json >/tmp/perfodia_report_fmt.out 2>&1; then
  pass "report-format flow executes"
else
  fail "report-format flow failed"
fi

# -------------------------------------------------------------------
# 3) Filesystem/content checks for hardening + docs alignment
# -------------------------------------------------------------------
# Dockerfile pinned refs required
for token in NETEXEC_REF SECLISTS_REF EXPLOITDB_REF ENUM4LINUX_REF; do
  if grep -q "ARG ${token}=" Dockerfile; then
    pass "Dockerfile defines ${token}"
  else
    fail "Dockerfile missing ${token}"
  fi
done

if grep -q "immutable commit SHAs" Dockerfile; then
  pass "Dockerfile enforces immutable SHA requirement message"
else
  fail "Dockerfile missing immutable SHA enforcement message"
fi

# install_deps verified skip tracking
if grep -q "SKIPPED_VERIFIED=0" install_deps.sh; then
  pass "install_deps initializes SKIPPED_VERIFIED"
else
  fail "install_deps missing SKIPPED_VERIFIED init"
fi

if grep -q "Verified remote installs skipped" install_deps.sh; then
  pass "install_deps summary warns on skipped verified installs"
else
  fail "install_deps missing skipped verified summary warning"
fi

# README/Docker Guide alignment statements
if grep -q -- "--resume --session" README.md; then
  pass "README documents resume/session requirement"
else
  fail "README missing resume/session guidance"
fi

if grep -q -- "--report-format" README.md; then
  pass "README documents report-format"
else
  fail "README missing report-format guidance"
fi

if grep -q -- "-tL" "Docker Guide.md"; then
  pass "Docker Guide includes target-list example"
else
  fail "Docker Guide missing target-list example"
fi

# mypy strictness profile
if grep -q "check_untyped_defs = True" mypy.ini; then
  pass "mypy strict untyped-def checking enabled"
else
  fail "mypy strict setting missing"
fi

if grep -q "\[mypy-tests\.\*\]" mypy.ini; then
  pass "mypy tests override present"
else
  fail "mypy tests override missing"
fi

echo
echo "== Validation Summary =="
echo "Failures: $FAILURES"
echo "Warnings: $WARNINGS"

if [[ "$FAILURES" -gt 0 ]]; then
  exit 1
fi

pass "All validation checks passed"
