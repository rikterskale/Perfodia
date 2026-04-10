#!/usr/bin/env bash
set -euo pipefail

FAIL=0
pass(){ echo "✅ $*"; }
fail(){ echo "❌ $*"; FAIL=$((FAIL+1)); }

echo "== Repo sanity =="
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Not a git repo"; exit 2; }
git status --short
echo "HEAD: $(git rev-parse --short HEAD)"
echo

echo "== Quality gates =="
ruff check . && pass "ruff check ." || fail "ruff check ."
mypy . && pass "mypy ." || fail "mypy ."
pytest -q && pass "pytest -q" || fail "pytest -q"

echo
echo "== CLI surface checks =="
HELP="$(python3 perfodia.py --help 2>&1 || true)"

for f in \
  "--target-list" "--modules" "--config" "--session" "--resume" \
  "--nmap-extra" "--nmap-raw" "--nmap-scan-type" "--nmap-scripts" \
  "--report-format" "--check-tools" "--init"
do
  if grep -q -- "$f" <<<"$HELP"; then
    pass "CLI exposes $f"
  else
    fail "CLI missing $f"
  fi
done

echo
echo "== Behavior checks =="

if python3 perfodia.py -t 127.0.0.1 -m recon --resume >/tmp/resume.err 2>&1; then
  fail "--resume without --session should fail"
else
  grep -q -- "--resume requires --session" /tmp/resume.err \
    && pass "--resume requires --session enforced" \
    || fail "Expected resume/session error message not found"
fi

TMP_TARGETS="$(mktemp)"
printf "127.0.0.1\nlocalhost\n" > "$TMP_TARGETS"
python3 perfodia.py -tL "$TMP_TARGETS" -m recon --dry-run -v >/tmp/targets.out 2>&1 \
  && pass "target-list flow executes" \
  || fail "target-list flow failed"
rm -f "$TMP_TARGETS"

python3 perfodia.py -t 127.0.0.1 -m scan --dry-run --nmap-extra "-Pn --top-ports 1000" >/tmp/nmap.out 2>&1 \
  && pass "nmap extra override accepted" \
  || fail "nmap extra override failed"

python3 perfodia.py -t 127.0.0.1 -m recon --dry-run --report-format json >/tmp/reportfmt.out 2>&1 \
  && pass "report-format flow executes" \
  || fail "report-format flow failed"

echo
echo "== File-content checks =="
for token in NETEXEC_REF SECLISTS_REF EXPLOITDB_REF ENUM4LINUX_REF; do
  grep -q "ARG ${token}=" Dockerfile \
    && pass "Dockerfile defines ${token}" \
    || fail "Dockerfile missing ${token}"
done

grep -q "immutable commit SHAs" Dockerfile \
  && pass "Dockerfile immutable SHA enforcement message present" \
  || fail "Dockerfile missing immutable SHA enforcement message"

grep -q "SKIPPED_VERIFIED=0" install_deps.sh \
  && pass "install_deps initializes SKIPPED_VERIFIED" \
  || fail "install_deps missing SKIPPED_VERIFIED init"

grep -q "Verified remote installs skipped" install_deps.sh \
  && pass "install_deps summary warning present" \
  || fail "install_deps missing skipped verified summary warning"

grep -q -- "--report-format" README.md \
  && pass "README documents report-format" \
  || fail "README missing report-format guidance"

grep -q -- "-tL" "Docker Guide.md" \
  && pass "Docker Guide includes target-list example" \
  || fail "Docker Guide missing target-list example"

grep -q "check_untyped_defs = True" mypy.ini \
  && pass "mypy strict untyped-def checking enabled" \
  || fail "mypy strict setting missing"

echo
echo "Failures: $FAIL"
[[ $FAIL -eq 0 ]]
