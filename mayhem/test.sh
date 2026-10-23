#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# RUN the unit-test runners that mayhem/build.sh produced (upstream's `make test` binaries, built with
# the project's normal flags). Each prints one "<test>: passed|failed" line per case; we parse those
# lines instead of trusting exit codes, and require at least the case count upstream has today, so a
# runner that is neutered (empty output) or silently skips cases fails loudly.
passed=0 failed=0
declare -A MIN=(
  [test-csv]=11 [test-load-options]=5 [test-mock-variables]=20 [test-mok-mirror]=32
  [test-pe-relocate]=1 [test-pe-util]=1 [test-sbat]=27 [test-str]=32
)
for t in "${!MIN[@]}"; do
  if [ ! -x "./$t" ]; then echo "MISSING runner ./$t (mayhem/build.sh must build it)" >&2; failed=$((failed + 1)); continue; fi
  out="$("./$t" 2>&1)"; rc=$?
  p=$(grep -c ': passed$' <<<"$out" || true)
  f=$(grep -c ': failed$' <<<"$out" || true)
  echo "$t: rc=$rc passed=$p failed=$f (need >= ${MIN[$t]})"
  if [ "$rc" -ne 0 ] || [ "$f" -gt 0 ] || [ "$p" -lt "${MIN[$t]}" ]; then
    printf '%s\n' "$out" | tail -20 >&2
    failed=$((failed + (f > 0 ? f : 1)))
  fi
  passed=$((passed + p))
done

# Known-answer probes for buildid (ELF build-id printer): fixed ELF in -> exact build-id out.
# The ELFs were linked with --build-id=<hex>, so the expected output is independent of the code under test.
BID="$SRC/build-mayhem/buildid-normal"
S="$SRC/mayhem/buildid/testsuite"
probe() { # <name> <expected stdout> <files...>
  local name="$1" want="$2"; shift 2
  local got; got="$("$BID" "$@" 2>/dev/null)"
  if [ "$got" = "$want" ]; then passed=$((passed + 1)); echo "probe $name: ok"
  else failed=$((failed + 1)); echo "probe $name: FAILED, got [$got] want [$want]" >&2; fi
}
probe buildid-20-byte "$S/elf-buildid-20 0123456789abcdef0123456789abcdef01234567" "$S/elf-buildid-20"
probe buildid-8-byte  "$S/elf-buildid-8 deadbeefcafef00d" "$S/elf-buildid-8"
probe buildid-none    "" "$S/elf-nobuildid"
probe buildid-several "$S/elf-buildid-8 deadbeefcafef00d
$S/elf-buildid-20 0123456789abcdef0123456789abcdef01234567" "$S/elf-buildid-8" "$S/elf-nobuildid" "$S/elf-buildid-20"

emit_ctrf "shim-unit+kat" "$passed" "$failed" 0
