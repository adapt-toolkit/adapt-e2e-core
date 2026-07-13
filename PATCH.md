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

- **D2 (planned, M3):** make `rand` and `getrandom` *optional* Cargo deps bound
  to a `std-rng` feature so `--no-default-features` links no `getrandom`/`OsRng`.
- **D3 (planned, M3):** cfg-gate the non-Olm modules (`sas`, `ecies`, `megolm`,
  dehydrated-device) off the adapt path to remove their OS-entropy draws.
- **D4 (planned, M4):** `#![no_std]` conversion of the vendored Olm path
  (std::io pickle plumbing, etc.).
