#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

BDIR="$SRC/build-mayhem"          # gitignored by upstream's /build*/
mkdir -p "$BDIR"

# 3) The project's own unit tests, NORMAL flags (upstream `make test`: gcc, no sanitizers).
#    test.mk compiles each test-*.c and then runs it through $(VALGRIND); VALGRIND=true makes that a
#    no-op, so this only BUILDS the runners that mayhem/test.sh later executes.
make generated_sbat_var_defs.h
make test VALGRIND=true CFLAGS_GCOV="$COVERAGE_FLAGS"

# 1) The sanitized build. Upstream's fuzz.mk builds AND runs the fuzzers, so we compile ourselves, with
#    the arch flags taken from Make.defaults so arch handling stays upstream's.
cat > "$BDIR/vars.mk" <<'MK'
COMPILER = clang
TOPDIR := $(SRC)
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults
print-%: ; @echo '$($*)'
MK
mkvar() { make -s -f "$BDIR/vars.mk" SRC="$SRC" "print-$1"; }
ARCH_CFLAGS_V="$(mkvar ARCH_CFLAGS)"
EFI_INCLUDES_V="$(mkvar EFI_INCLUDES)"
ARCH_GNUEFI_V="$(mkvar ARCH_GNUEFI)"
ARCH_V="$(mkvar ARCH)"

# gnu-efi's libefi.a (upstream's fuzz.mk calls it libefi-test.a), built with clang.
make -C gnu-efi COMPILER=clang CC=clang ARCH="$ARCH_GNUEFI_V" TOPDIR="$SRC/gnu-efi" \
    -f "$SRC/gnu-efi/Makefile" clean lib
mv "gnu-efi/$ARCH_V/lib/libefi.a" "$BDIR/libefi-fuzz.a"
make -C gnu-efi COMPILER=clang ARCH="$ARCH_GNUEFI_V" TOPDIR="$SRC/gnu-efi" \
    -f "$SRC/gnu-efi/Makefile" clean

# Two UBSan checks are relaxed, the rest of UBSan and all of ASan stay halting:
#  - pointer-overflow: csv.c/include/str.h wrap a size_t `max` by design in strntoken()/parse_csv_line()
#    on a trivial "\n\n" input, which halted fuzz-sbat on its first execution;
#  - alignment: the PE and DHCPv6 parsers cast packed wire data to structs (pe-relocate.c:316, netboot.c:94),
#    harmless on x86-64 and found on the first seed of fuzz-pe-relocate and fuzz-tftpboot.
FUZZ_SAN="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow,alignment"

MULTIARCH="$(gcc -print-multiarch)"
# shellcheck disable=SC2086
SHIM_FLAGS="-std=gnu11 -O1 -w \
 -isystem $SRC/include/system $EFI_INCLUDES_V -Iinclude -iquote . \
 -isystem /usr/include \
 -isystem $($CC $ARCH_CFLAGS_V -print-file-name=include) \
 -isystem $($CC $ARCH_CFLAGS_V -print-file-name=include-fixed) \
 -isystem /usr/include/$MULTIARCH \
 $ARCH_CFLAGS_V -fshort-wchar -fno-builtin -rdynamic -fno-inline \
 -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI -DPAGE_SIZE=4096 -DSHIM_UNIT_TEST -DSHIM_ENABLE_LIBFUZZER \
 -DDEFAULT_DEBUG_PRINT_STATE=0"
SBAT_FLAGS="-DHAVE_GET_VARIABLE -DHAVE_GET_VARIABLE_ATTR -DHAVE_SHIM_LOCK_GUID"

# LeakSanitizer off at build time (leaks are not what this fleet fuzzes for).
$CXX $FUZZ_SAN $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$BDIR/lsan_off.o"

# name -> sources beyond test.c + the harness (upstream's fuzz-<t>_FILES plus the module under test)
declare -A FILES=(
  [fuzz-csv]="csv.c"
  [fuzz-pe-relocate]="pe-relocate.c globals.c"
  [fuzz-sbat]="sbat.c csv.c lib/variables.c lib/guid.c sbat_var.S mock-variables.c"
  [fuzz-tftpboot]="lib/string.c netboot.c"
)
declare -A EXTRA=( [fuzz-sbat]="$SBAT_FLAGS" )
# Upstream's fuzz-pe-relocate.c stops after read_header() (59 edges); the mayhem-owned harness follows
# handle_image() through relocate_coff(). Every other target uses upstream's harness.
declare -A HARNESS=( [fuzz-pe-relocate]="mayhem/fuzz-pe-relocate-deep.c" )

# 2) Each harness twice: the libFuzzer binary and a standalone run-once reproducer.
for t in fuzz-csv fuzz-pe-relocate fuzz-sbat fuzz-tftpboot; do
  srcs="test.c ${HARNESS[$t]:-$t.c} ${FILES[$t]}"
  # shellcheck disable=SC2086
  $CC $FUZZ_SAN $DEBUG_FLAGS $SHIM_FLAGS ${EXTRA[$t]:-} $LIB_FUZZING_ENGINE \
      $srcs "$BDIR/libefi-fuzz.a" "$BDIR/lsan_off.o" -lefivar -o "$SRC/$t"
  # shellcheck disable=SC2086
  $CC $FUZZ_SAN $DEBUG_FLAGS $SHIM_FLAGS ${EXTRA[$t]:-} \
      "$STANDALONE_FUZZ_MAIN" $srcs "$BDIR/libefi-fuzz.a" "$BDIR/lsan_off.o" -lefivar -o "$SRC/$t-standalone"
done

# buildid (legacy mayhemheroes target): upstream's ELF build-id printer, a file-input target.
# -fsanitize=fuzzer-no-link adds the SanCov instrumentation Mayhem needs without a fuzzer main.
# shellcheck disable=SC2086
$CC $FUZZ_SAN $DEBUG_FLAGS -fsanitize=fuzzer-no-link -I/usr/include -O1 -w \
    "$SRC/buildid.c" "$BDIR/lsan_off.o" -lelf -o "$BDIR/buildid"
# Same source, normal flags: the oracle's build.
$CC -I/usr/include -O1 -w "$SRC/buildid.c" -lelf -o "$BDIR/buildid-normal"
