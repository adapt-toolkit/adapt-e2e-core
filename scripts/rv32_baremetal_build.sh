#!/usr/bin/env bash
# rv32 bare-metal build gate (SPEC §6.3, §9).
#
# Builds the crate as a `no_std` rlib for `riscv32imac-unknown-none-elf` — no OS,
# no std, no getrandom — using nightly + `-Zbuild-std` (core/alloc built from
# source, since there is no precompiled std for `*-none-elf`). This is the design
# win of the injected-entropy architecture: because every keygen consumes the
# caller's seed via ChaCha20 (no OS entropy), the crate links no getrandom/OsRng
# and builds on bare-metal with no custom getrandom shim.
#
# Requires: nightly toolchain + the `rust-src` component
#   rustup toolchain install nightly && rustup component add rust-src --toolchain nightly
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=riscv32imac-unknown-none-elf

echo "Building no_std rlib for ${TARGET} (build-std core,alloc)..."
cargo +nightly rustc \
  --no-default-features \
  --lib --crate-type rlib \
  --target "${TARGET}" \
  -Zbuild-std=core,alloc \
  --quiet

echo "PASS: adapt-e2e-core builds as a no_std rlib for ${TARGET} (bare-metal, no getrandom/OsRng)."
