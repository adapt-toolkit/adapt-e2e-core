# Testing adapt-e2e-core

The crate is only as trustworthy as its tests — the failure mode is "green CI,
silently insecure" (SPEC §7). This document is the map of what is tested and how
to run each gate. Everything below runs green today except where marked pending.

## Test suites

| Suite | File | What it proves |
|---|---|---|
| Unit — RNG | `src/seeded_rng.rs` | ChaCha20 seed expansion is deterministic. |
| Unit — pickle envelope | `src/mgmt/pickle.rs` | AE2C magic/version/kind validation; never panics on malformed bytes. |
| Unit — account/session/bundle | `src/mgmt/*` | keygen determinism, handshake round-trip, session-id agreement, wrong-pickle-key rejection, `matches_inbound` re-delivery detection. |
| C-ABI | `tests/ffi.rs` | full handshake through the raw `extern "C"` fns; two-call length convention; cross-ABI determinism; malformed/NULL → clean negative rc, never panic. |
| Adversarial | `tests/adversarial.rs` | determinism goldens (pre-key **and** DH-advance, byte-pinned); retry-vs-replay entropy guard; skipped-key out-of-order + 40-key bound + beyond-2000-gap rejection; tampered-ciphertext rejection; **negative forward secrecy** (evicted vs retained). |
| Interop oracle | `tests/interop.rs` | our seed-injected fork is wire-compatible with the **real upstream vodozemac 0.10.0** (crates.io), both handshake directions — the independent behaviour-preservation check. |
| Property fuzz | `tests/proptest_abi.rs` | arbitrary bytes to the C-ABI never panic (no `PANIC=-99`), always a clean error; `e2e_account_create` is total + deterministic over the whole input space. |
| Seam smoke | `tests/seam_smoke.rs` | the crate drives the vendored fork's `*_with_rng` seam deterministically. |

Run everything: `cargo test`. Lint gate: `cargo clippy --all-targets`.

## miri (UB / aliasing at the FFI marshalling)

The C-ABI does raw-pointer marshalling (`src/ffi.rs`: `in_slice`, `in_arr32`,
`write_out`). Validate it under miri.

**Requirement — Tree Borrows.** The RustCrypto `cbc`/`aes` pickle-encryption
path trips miri's default *Stacked Borrows* model (a known false positive in
those upstream crates, not our code). Run miri with the newer aliasing model:

```sh
MIRIFLAGS="-Zmiri-tree-borrows" cargo +nightly miri test
```

Under Tree Borrows the crate is miri-clean (pure marshalling passes under either
model; the crypto path passes under Tree Borrows). Stacked-Borrows on the
crypto path is tracked upstream in the `cbc`/`cipher` crates.

## Pending (tracked for later milestones)

- **cargo-fuzz** targets over the `#[no_mangle]` fns with ASan/UBSan + a committed
  corpus (SPEC §7.6) — proptest covers the property today; libFuzzer coverage is
  a CI addition (M5).
- **Committed KAT vectors** under `tests/vectors/` (SPEC §7.1) — behaviour
  preservation is currently proven by the live interop oracle; static Signal/Olm
  vectors are additive.
- **Coverage gate** ≥95% line on `ffi`/`mgmt`/`seeded_rng` (SPEC §7.10) — M5 CI.
- **Constant-time smoke** (`dudect`-style) on decrypt/MAC (SPEC §7.9) — posture
  guard; the constant-time ops are inherited from vodozemac/dalek.
- **`no_std` + wasm + rv32 test lanes** (SPEC §6.2, M4) — depends on the
  getrandom-severance + no_std conversion of the vendored fork (M3/M4).
