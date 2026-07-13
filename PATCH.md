# PATCH.md — vendored vodozemac fork ledger

This file is the **re-audit ledger** for the vendored, pinned fork of vodozemac
under `vendor/vodozemac/`. Policy: **security-backport-only** — we do not chase
upstream feature releases; we cherry-pick security fixes and re-apply our delta.
Every change to `vendor/` MUST be recorded here.

## Re-audit baseline

| Field | Value |
|---|---|
| Upstream | `matrix-org/vodozemac` |
| Upstream version | 0.10.0 (edition 2024, MSRV 1.85) |
| Upstream fork point | `6b38b2c6d3167cdeb69c09887af8c249485409c3` (main, 2026-07-08) |
| Our fork | `adapt-toolkit/vodozemac`, branch `feature/with-rng-entropy-injection` |
| Vendored pin | `a64823efcae77b62d472c8b9cd8e6c71045440ee` |
| Upstream PR | matrix-org/vodozemac#379 (open) |
| Vendored via | `git subtree --squash` into `vendor/vodozemac` |

**Re-audit method:** `git diff` the vendored tree against pristine upstream 0.10.0.
The Least-Authority audit (2022) predates 0.10.0 by years; it covers neither
0.10.0's own drift nor our delta. This ledger scopes *our* delta only.

## Delta 1 — additive `*_with_rng` entropy-injection seam (UPSTREAMABLE)

**Status:** submitted upstream as PR #379 (open). If merged, switch the crate's
dependency to upstream vodozemac and drop this delta. If rejected, keep it here.

**Nature:** purely additive parallel `*_with_rng` methods on every Olm keygen
path; every existing method body is byte-identical to upstream (the only removed
lines augment two `use` statements). Threads a caller-supplied `impl CryptoRng`
from the public entry points down to the leaf secret-key constructors so the
engine can be driven by our injected 32-byte seed via a ChaCha20 CSPRNG.

Public additions: `Account::{new,generate_one_time_keys,generate_fallback_key,
create_outbound_session}_with_rng`, `Session::encrypt_with_rng`,
`Curve25519SecretKey::new_with_rng`, `Curve25519Keypair::new_with_rng`,
`Ed25519Keypair::new_with_rng`, `Ed25519SecretKey::new_with_rng`. Internal
threading via parallel `_with_rng` on `Ratchet`, `RemoteRootKey::advance`,
`DoubleRatchet`, `OneTimeKeys`, `FallbackKeys`. `decrypt` /
`create_inbound_session` are untouched (they mint no keys).

**Security review:** adversarially reviewed incl. a mutation test (patching the
ratchet mint to ignore the injected rng, confirmed caught by the reproducibility
test). Behaviour-preserving; the audited OsRng code paths are unchanged.

**Tests:** `vendor/vodozemac/tests/with_rng.rs`.

## Pending deltas (NOT upstreamable — our private fork only, tracked)

These are required for the crate's `no_std`/rv32 lane and the RNG-isolation gate
(SPEC §7.7, §9). They are NOT part of PR #379 (upstream wants OsRng-by-default):

- **D2 (M3, DONE):** `rand`, `getrandom`, and `chacha20poly1305` are optional
  Cargo deps bound to the default-on `std-rng` feature; `--no-default-features`
  builds the Olm path with the injected-entropy `*_with_rng` API only and links
  no `rand`/`getrandom`/`OsRng`. The ~25 OS-RNG default methods (leaf ctors,
  intermediate chain, `Account`/`Session` public defaults, dehydrated-device)
  are `#[cfg(feature = "std-rng")]`; `rand_core` (the `CryptoRng` trait) is a
  new non-optional dep. The `getrandom`-crate leak that entered transitively via
  `chacha20poly1305 -> aead -> crypto-common/getrandom` is severed by making
  `chacha20poly1305` optional (it is used only by gated dehydration/ECIES/PK
  paths). The crate depends on vodozemac with `default-features = false` for the
  shipped lib and re-enables `std-rng` via a dev-dependency for tests. The
  RNG-isolation gate (`scripts/rng_isolation_gate.sh`, SPEC §7.7) passes: 0
  forbidden symbols, `getrandom` absent from the normal dep graph. (Rust std's
  own `std::sys::random` remains while linking std; it goes away on `no_std`/M4.)
  ORIGINAL PLAN (retained for history):
- **D2-orig (superseded by the above):** make `rand` and `getrandom` *optional*
  bound to a new `std-rng` feature (default-on) so `--no-default-features` links
  no `getrandom`/`OsRng`. DONE so far: Cargo.toml (`rand`/`getrandom` optional;
  `std-rng = ["dep:rand","dep:getrandom"]`; `default` includes `std-rng`;
  `wasm_js` now `["dep:getrandom","getrandom/wasm_js"]`); added non-optional
  `rand_core` (the `CryptoRng` trait for `*_with_rng`, always needed);
  repointed `use rand::CryptoRng` → `use rand_core::CryptoRng` in 9 files;
  gated `use rand::rng` behind `std-rng` in curve25519/ed25519. Default build +
  all 40 crate tests stay green (behaviour-preserving).
  REMAINING: gate the OS-RNG default-method chain behind `#[cfg(feature =
  "std-rng")]` — the ~25 default (non-`_with_rng`) methods: leaves
  `Curve25519SecretKey::new`(+Default), `Curve25519Keypair::new`,
  `Ed25519Keypair::new`(+Default), `Ed25519SecretKey::new`, `RatchetKey::new`
  (+Default); intermediates `Ratchet::new`, `RemoteRootKey::advance`,
  `DoubleRatchet::{next_message_key,encrypt,encrypt_truncated_mac,active}`,
  `InactiveDoubleRatchet::activate`, `Session::{new,encrypt}`,
  `OneTimeKeys::{generate,generate_one_time_key}`, `FallbackKey::new`,
  `FallbackKeys::generate_fallback_key`, `Account::{new,generate_one_time_keys,
  generate_fallback_key,create_outbound_session}`; plus the dehydrated-device
  methods (`Nonce::generate` OS entropy). Compiler-guided via `cargo build
  --no-default-features` (lib only; tests stay under default `std-rng`). The
  `_with_rng` chain is self-contained and must remain so (never call a default).
  Currently `--no-default-features` does NOT yet compile (3 leaf `rng()` sites +
  their cascade) — expected mid-D2.
- **D3 (M3, DONE):** cfg-gated the non-Olm modules (`ecies`, `megolm`, `sas`,
  `pk_encryption`) behind `std-rng` in `lib.rs` to remove their OS-entropy draws
  from the adapt path.
- **D4 (planned, M4):** `#![no_std]` conversion of the vendored Olm path
  (std::io pickle plumbing, etc.).
- **After D2:** switch the crate's `vodozemac` dep to `default-features = false`
  (Olm-only, no `std-rng`) and add the RNG-isolation symbol gate (SPEC §7.7):
  grep the built object for `getrandom`/`OsRng`/`thread_rng`; fail if present.
