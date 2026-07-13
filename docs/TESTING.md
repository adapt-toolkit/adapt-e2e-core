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
| Golden vectors | `tests/golden_vectors.rs` | byte-pins every keygen seam (identity Curve25519 + Ed25519, one-time key, fallback key, session id) from fixed seeds — cross-build determinism regression guard. |
| libFuzzer | `fuzz/` (SPEC §7.6) | coverage-guided libFuzzer over the C-ABI (needs `cargo-fuzz`; CI runs a bounded budget). Same no-crash invariant as the proptest suite. See `fuzz/README.md`. |
| Seam smoke | `tests/seam_smoke.rs` | the crate drives the vendored fork's `*_with_rng` seam deterministically. |

Run everything: `cargo test`. Lint gate: `cargo clippy --all-targets`.

## RNG-isolation gate (SPEC §7.7)

`scripts/rng_isolation_gate.sh` builds the release staticlib **without**
dev-dependencies (so vodozemac's `std-rng` feature is off) and fails if the
object links the `getrandom` crate, `OsRng`, `thread_rng`, or the `rand`
thread-local generator, or if `getrandom` appears in the normal dependency
graph. This proves the adapt path is a pure function of its injected seed. (Rust
std's own `std::sys::random` is not the getrandom crate and is expected while
linking std; it disappears on the `no_std`/bare-metal targets.)

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

- **Coverage gate** ≥95% line on `ffi`/`mgmt`/`seeded_rng` (SPEC §7.10) — needs
  `cargo-llvm-cov` (not installed here); a CI addition.
- **Constant-time posture** (SPEC §7.9) — the constant-time scalar/compare ops are
  inherited from `curve25519-dalek`/`subtle` (decrypt MAC-compare, X25519). The
  management layer adds no data-dependent branches on secret material: `decrypt`
  returns every failure via the same `DecryptFailed` path (no early
  secret-dependent return), and pickle AEAD/MAC is vodozemac's. This is a posture
  statement + regression guard, not a formal CT proof; a `dudect`-style timing
  harness is a future CI addition.
- **wasm-emscripten lane** (SPEC §6.2) — DEFERRED (owner): needs the consumer's
  emsdk/emcc (ABI-pinned). The crate is no_std-clean, so it builds consumer-side
  once emsdk is available; `wasm32-unknown-unknown` can serve as a no_std proxy.

## no_std / rv32 bare-metal (SPEC §6.3, §9) — DONE

The crate and the vendored vodozemac fork are `#![no_std]` + `alloc` (the `std`
feature, default-on, is native convenience only). `scripts/rv32_baremetal_build.sh`
builds the crate as a `no_std` rlib for `riscv32imac-unknown-none-elf` with
nightly `-Zbuild-std=core,alloc` — no OS, no std, no getrandom. This is the
injected-entropy design win: because every keygen consumes the caller's seed via
ChaCha20, the crate needs no OS entropy and no `getrandom` shim on bare metal.

```sh
rustup toolchain install nightly && rustup component add rust-src --toolchain nightly
./scripts/rv32_baremetal_build.sh
```

Note: a no_std *library* defers the global allocator, `#[panic_handler]`, and
`panic = "abort"` to the consumer's firmware; the rlib build verifies the crate's
code is no_std-correct. base64's no_std `Error` support comes from the 2nd pinned
fork (`vendor/base64`, see PATCH.md).
