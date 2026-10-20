#!/bin/bash
# The local gates CI runs, in one go, with a one-line summary per gate ("== <command> -> exit N").
# It keeps going after a failing gate and exits non-zero if any failed. Each gate's full output
# is in target/gates/<n>.out.
#
# Run it from anywhere in the repository: bash scripts/gates.sh
#
# Platform notes:
# - The GCC -Werror check compiles the C tests as CI's Ubuntu GCC does (clang accepts unused
#   macro values and POSIX functions under -std=c99 that GCC and glibc reject). On Linux it uses
#   the system gcc against glibc; on macOS, Homebrew's gcc, plus glibc's headers in Docker when
#   Docker is running.
# - Miri runs only if a nightly toolchain with Miri is installed
#   (rustup toolchain install nightly --component miri,rust-src); it splits rustyssl-capi's
#   tests into CI's shards and runs them in parallel. Its exit status is in the summary line:
#   "== miri <target>: N ok, M failed".
# - Don't run two copies at once: they share target/dist and target/gates.
set -u
export NO_COLOR=1 CARGO_TERM_COLOR=never
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT" || exit 1
OUT=$ROOT/target/gates
mkdir -p "$OUT"
FAILED=0
N=0
run() {
  N=$((N + 1))
  "$@" > "$OUT/$N.out" 2>&1
  local r=$?
  echo "== $* -> exit $r"
  [ $r -eq 0 ] || FAILED=1
  LAST=$OUT/$N.out
}

run cargo fmt --all --check
run cargo clippy --workspace --all-targets -- -D warnings
grep -E "^(error|warning)" -A5 "$LAST" | head -30
run cargo test --workspace
grep -E "FAILED|panicked" "$LAST" | head
run cargo xtask codegen
run cargo xtask coverage
git diff --stat -- 'crates/*/src/generated' libs docs/coverage.md | tail -3
run cargo xtask test-c
grep -E "FAIL|passed|failed" "$LAST" | tail -5

# The C tests' sources under GCC -Werror, against the current series' headers.
SERIES=$(grep -o 'OPENSSL_SERIES: &str = "[0-9.]*"' xtask/src/targets.rs | grep -o '[0-9]\.[0-9]*')
C_SOURCES="tests/c/*.c tests/c/modules/*.c libs/*/*.c tests/bogo/shim.c tests/timing/dudect.c"
gcc_check() { # $1: gcc; $2: the config directory for the target
  local bad=0 f
  for f in $C_SOURCES; do
    [ -f "$f" ] || continue
    if ! "$1" -std=c99 -Wall -Wextra -Werror -fsyntax-only -I "abi/openssl-$SERIES/config/$2" \
        -I "abi/openssl-$SERIES/include" -I tests/c "$f" > "$OUT/gcc.err" 2>&1; then
      echo "FAIL $f"; head -5 "$OUT/gcc.err"; bad=1
    fi
  done
  return $bad
}
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) run gcc_check gcc linux-x86_64 ;;
  Linux-aarch64) run gcc_check gcc linux-aarch64 ;;
  Darwin-*)
    HB_GCC=$(ls /opt/homebrew/bin/gcc-[0-9]* /usr/local/bin/gcc-[0-9]* 2>/dev/null | head -1)
    if [ -n "$HB_GCC" ]; then run gcc_check "$HB_GCC" darwin64-arm64; else echo "== gcc check skipped: no Homebrew gcc"; fi
    if docker info > /dev/null 2>&1; then
      run docker run --rm --platform linux/amd64 -v "$ROOT":/src:ro -w /src rust:1.99.0-slim-trixie \
        bash -c "for f in $C_SOURCES; do [ -f \"\$f\" ] || continue; gcc -std=c99 -Wall -Wextra -Werror -fsyntax-only -I abi/openssl-$SERIES/config/linux-x86_64 -I abi/openssl-$SERIES/include -I tests/c \"\$f\" || exit 1; done"
    else
      echo "== gcc check against glibc skipped: Docker isn't running"
    fi
    ;;
esac
grep FAIL -A5 "$LAST" | head -20

run cargo xtask test-apps
grep -E "FAIL|behave the same" "$LAST" | tail -5
run cargo xtask test-openssl-suite
grep -E "FAIL|pass on rustyssl" "$LAST" | tail -5
run cargo xtask test-wycheproof
grep -E "FAIL|Wycheproof tests agree" "$LAST" | tail -5
run cargo xtask test-differential --random 1000
grep -E "FAIL|Random|differ" "$LAST" | tail -5
run cargo xtask abi-check
grep -E "^(ok|FAIL)" "$LAST" | cut -c1-70
run cargo deny check
run cargo vet --locked

# Miri: CI's shards of rustyssl-capi's tests, in parallel; on macOS also the x86_64 Linux target.
if cargo +nightly miri --version > /dev/null 2>&1; then
  shards=("evp::sigver evp::ctrl" "evp::pkey" "evp::signature evp::kem evp::pmeth"
    "evp:: --skip evp::sigver --skip evp::ctrl --skip evp::pkey --skip evp::signature --skip evp::kem --skip evp::pmeth"
    "--skip evp::")
  targets=("")
  [ "$(uname -s)" = Darwin ] && targets+=("--target x86_64-unknown-linux-gnu")
  for tgt in "${targets[@]}"; do
    i=0
    for f in "${shards[@]}"; do
      i=$((i + 1))
      # shellcheck disable=SC2086
      CARGO_TARGET_DIR=$ROOT/target/gates/miri-$i cargo +nightly miri test -p rustyssl-capi $tgt -- $f \
        > "$OUT/miri$i.out" 2>&1 &
    done
    wait
    nf=$(cat "$OUT"/miri*.out | grep -c 'FAILED\|error:')
    [ "$nf" -eq 0 ] || FAILED=1
    echo "== miri ${tgt:-host}: $(cat "$OUT"/miri*.out | grep -c 'test result: ok') ok, $nf failed"
    grep -hE "^test .*FAILED|^error" "$OUT"/miri*.out | head -5
  done
else
  echo "== miri skipped: no nightly toolchain with Miri"
fi
exit $FAILED
