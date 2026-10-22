#!/bin/bash -eu
# Builds rustyssl's fuzz targets (fuzz/, TEST_PLAN.md layer L9) the way OSS-Fuzz and
# ClusterFuzzLite expect: every target's binary in $OUT, built with the sanitizer the
# infrastructure selects (cargo-fuzz reads $SANITIZER, $RUSTFLAGS and $CC from the base image).
#
# OSS-Fuzz: this file is projects/rustyssl/build.sh. ClusterFuzzLite: .clusterfuzzlite/Dockerfile
# copies it. Set FUZZ_TARGETS to a space-separated list to build only those (for a quick local
# check); by default every target in fuzz/Cargo.toml is built.

cd "$SRC/rustyssl/fuzz"

# rust-toolchain.toml pins stable 1.99; cargo-fuzz needs the base image's nightly.
export RUSTUP_TOOLCHAIN=nightly

targets=${FUZZ_TARGETS:-$(cargo fuzz list)}
build_dir=target/x86_64-unknown-linux-gnu/release

for target in $targets; do
  cargo fuzz build -O --debug-assertions "$target"
  cp "$build_dir/$target" "$OUT/"
done
