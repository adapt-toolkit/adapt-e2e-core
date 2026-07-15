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

## 2nd pinned fork — base64 0.22.1 (security-backport-only)

| Field | Value |
|---|---|
| Upstream | crates.io `base64` |
| Pinned version | 0.22.1 |
| Vendored at | `vendor/base64/`, applied via `[patch.crates-io]` in the crate Cargo.toml |
| Delta | make the `Error` impls (`DecodeError`, `DecodeSliceError`, `EncodeSliceError`, `ParseAlphabetError`) unconditional `core::error::Error` (was `#[cfg(any(feature="std",test))] impl std::error::Error`) so the types impl `Error` in no_std |
| Rationale | thiserror `#[from] base64::DecodeError` in vodozemac needs the source to impl `core::error::Error`; base64 0.22 only impls it under `std`. Required for the bare-metal build. |
| Behaviour | **exactly preserving**: since Rust 1.81 `std::error::Error` is a re-export of `core::error::Error` (same trait), so std users see zero change; only 3 files (alphabet/decode/encode) touched, no decode/encode/padding/alphabet logic altered, Cargo.toml byte-identical. Verified behaviour-preserving; all determinism golden vectors byte-identical. |
| Policy | security-backport-only, same as vodozemac; re-audit = `diff -ru` vs pristine base64 0.22.1. **base64ct was explicitly rejected** — its padding semantics differ from vodozemac's "indifferent" mode (crypto-sensitive), so it is NOT a drop-in. |

**Re-audit method:** `git diff` the vendored tree against pristine upstream 0.10.0.
The Least-Authority audit (2022) predates 0.10.0 by years; it covers neither
0.10.0's own drift nor our delta. This ledger scopes *our* delta only.

## Bare-metal atomics — `bytes` `extra-platforms` + single-core CAS cfg (NO fork)

| Field | Value |
|---|---|
| Crate | `bytes` (transitive: `bytes` ← `prost` ← vodozemac protobuf codec) |
| Fork? | **None.** `bytes` is used UNMODIFIED from crates.io. |
| What we enable | `bytes`'s own upstream `extra-platforms` feature (turned on by our `baremetal-rt` crate feature: `bytes/extra-platforms`). It routes bytes' atomics through `portable-atomic` instead of `core::sync::atomic`. |
| Why | The true no-atomics target `riscv32im-unknown-none-elf` is `atomic-cas: false`; `bytes` needs compare-and-swap for its `Bytes` refcount, so it will not compile there against `core::sync::atomic`. Enabling `extra-platforms` lets `portable-atomic` supply CAS — no vendored fork of `bytes`/`prost`. |
| Build cfg | `--cfg portable_atomic_unsafe_assume_single_core` (set in `scripts/rv32_baremetal_build.sh` and ADAPT's `baremetal/build-adapt-e2e-core-rv32.sh`). Selects portable-atomic's single-core CAS: emulate RMW by briefly disabling interrupts. |
| Soundness (the `unsafe` cfg) | Correct **iff** a single hardware thread with no concurrent atomic agent. Holds here: the rv32 bare-metal eval is single-hart, non-preemptive (no scheduler, no second core), and e2e is invoked synchronously from the one eval thread. No interrupt handler touches these atomics. Verified: the built staticlib emits **no `__atomic_*` libcalls** (CAS is inlined, no libatomic dependency). |
| Scope | Applies ONLY to the `baremetal-rt` (rv32 staticlib) build. Native/wasm builds do not enable `extra-platforms` and use native atomics. |
| Re-audit | On a `bytes`/`portable-atomic` version bump: re-confirm the built rv32im staticlib still has zero `__atomic_*` undefined symbols and that the single-core precondition (single-hart/non-preemptive) still holds for the deployment target. |

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

## Private deltas (NOT upstreamable — our fork only)

These are required for the crate's `no_std`/rv32 lane and the RNG-isolation
guarantee. They are NOT part of PR #379 (upstream keeps OsRng-by-default).

- **D2 — getrandom severance.** `rand`, `getrandom`, and `chacha20poly1305` are
  optional Cargo deps bound to the default-on `std-rng` feature. With
  `--no-default-features` the Olm path exposes only the injected-entropy
  `*_with_rng` API and links no `rand`/`getrandom`/`OsRng`: the OS-RNG default
  methods (leaf constructors, intermediate chain, `Account`/`Session` defaults,
  dehydrated-device) are `#[cfg(feature = "std-rng")]`, while `rand_core` (the
  `CryptoRng` trait) is a non-optional dep. The transitive `getrandom` leak via
  `chacha20poly1305 -> aead -> crypto-common` is severed by making
  `chacha20poly1305` optional (used only by gated dehydration/ECIES/PK paths). The
  shipped lib depends on vodozemac with `default-features = false`; tests re-enable
  `std-rng` via a dev-dependency. Verified by `scripts/rng_isolation_gate.sh`:
  zero forbidden symbols, `getrandom` absent from the normal dependency graph.

- **D3 — non-Olm engines gated.** `ecies`, `megolm`, `sas`, and `pk_encryption`
  are cfg-gated behind `std-rng` in `lib.rs`, removing their OS-entropy draws from
  the adapt path.

- **D4 — `#![no_std]` + `alloc`.** The vendored vodozemac (and the crate) build
  `#![no_std]` + `alloc`: `#![cfg_attr(not(feature = "std"), no_std)]` + `extern
  crate alloc`; a `std`/`alloc` feature split with all deps
  `default-features = false` (+ `block-padding` on cipher/cbc); per-file
  `alloc::{...}` imports on the Olm path; the libolm binary-pickle backend
  (`matrix_pickle`, which needs `std::io`) gated behind `libolm-compat`;
  `mod dehydrated_device` gated behind `std-rng`; and the runtime `HashMap` moved
  to `hashbrown` / `alloc::BTreeMap`. The base64 `core::error::Error` requirement
  is met by the 2nd pinned fork above. The crate then builds as a `no_std`
  staticlib for the true no-atomics `riscv32im-unknown-none-elf` (nightly
  `-Zbuild-std=core,alloc`, `baremetal-rt` feature, single-core CAS cfg — see the
  "Bare-metal atomics" ledger above) — bare-metal, no OS, no getrandom (see
  `scripts/rv32_baremetal_build.sh`). The
  `wasm32-unknown-emscripten` lane is not built here (it must be ABI-pinned to the
  consumer's emsdk/emcc); the no_std-clean crate builds consumer-side once emsdk
  is available.
