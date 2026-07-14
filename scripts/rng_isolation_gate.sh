#!/usr/bin/env bash
# RNG-isolation gate.
#
# The adapt path must be a pure function of its injected seed: the shipped
# library MUST NOT link the `getrandom` crate, `OsRng`, `thread_rng`, or the
# `rand` thread-local generator. This script builds the release staticlib
# (WITHOUT dev-dependencies, so `std-rng` is off) and fails if any forbidden
# symbol is present.
#
# Note: Rust std's own `std::sys::random` syscall wrapper (used for HashMap
# seeding) is NOT the getrandom crate and is expected while linking std; it
# disappears on the `no_std` / bare-metal targets. This gate looks only for the
# getrandom CRATE and the rand OS/thread generators.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building release staticlib (no dev-deps => std-rng off)..."
cargo build --release --quiet

LIB="target/release/libadapt_e2e_core.a"
[ -f "$LIB" ] || { echo "FAIL: $LIB not found"; exit 1; }

# Forbidden: the getrandom crate (backends/error/fill), OsRng, thread_rng, and
# the rand crate's ThreadRng / rngs module.
FORBIDDEN='9getrandom8backends|9getrandom5error|GETRANDOM_FN|OsRng|thread_rng|[0-9]rand.*ThreadRng|[0-9]rand7rngs'

HITS="$(nm "$LIB" 2>/dev/null | grep -E "$FORBIDDEN" || true)"

if [ -n "$HITS" ]; then
  echo "FAIL: forbidden RNG symbols linked into the adapt path:"
  echo "$HITS" | head -40
  exit 1
fi

# Belt and braces: the getrandom crate must not be in the non-dev dependency graph.
if cargo tree -e normal 2>/dev/null | grep -qiE '(^|[^_])getrandom v'; then
  echo "FAIL: the getrandom crate is present in the normal dependency graph:"
  cargo tree -e normal -i 'getrandom@0.4.3' 2>/dev/null | head -20 || true
  exit 1
fi

echo "PASS: no getrandom-crate / OsRng / thread_rng symbols; getrandom absent from the dep graph."
