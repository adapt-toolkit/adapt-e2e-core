#!/usr/bin/env bash
# rv32 bare-metal build gate.
#
# Builds the crate as a `no_std` C-ABI **staticlib** for the TRUE no-atomics
# target `riscv32im-unknown-none-elf` (`atomic-cas: false`) — no OS, no std, no
# getrandom, no atomic-extension crutch — using nightly + `-Zbuild-std`
# (core/alloc built from source, since there is no precompiled std for
# `*-none-elf`). This mirrors the production artifact ADAPT links into its
# `-march=rv32im` eval_naked (baremetal/build-adapt-e2e-core-rv32.sh).
#
# Two design wins are exercised here:
#   * Injected entropy — every keygen consumes the caller's seed via ChaCha20
#     (no OS entropy), so the crate links no getrandom/OsRng on bare-metal.
#   * No-atomics rv32im — a transitive dep (bytes <- prost <- vodozemac) needs
#     compare-and-swap; bytes' upstream `extra-platforms` feature (enabled by our
#     `baremetal-rt` feature) routes its atomics through portable-atomic, whose
#     single-core CAS is opted into with `--cfg portable_atomic_unsafe_assume_single_core`.
#     Sound because the target is single-hart / non-preemptive (see PATCH.md).
#
# Requires: nightly toolchain + the `rust-src` component
#   rustup toolchain install nightly && rustup component add rust-src --toolchain nightly
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=riscv32im-unknown-none-elf

echo "Building no_std staticlib for ${TARGET} (build-std core,alloc, single-core atomics)..."
RUSTFLAGS="-Cpanic=abort --cfg portable_atomic_unsafe_assume_single_core" cargo +nightly rustc \
  --release \
  --no-default-features --features baremetal-rt \
  --lib --crate-type staticlib \
  --target "${TARGET}" \
  -Zbuild-std=core,alloc \
  --quiet

echo "PASS: adapt-e2e-core builds as a no_std staticlib for ${TARGET} (true rv32im, no atomics, no getrandom/OsRng)."
