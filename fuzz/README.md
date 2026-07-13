# Fuzzing adapt-e2e-core (SPEC §7.6)

libFuzzer targets over the `#[no_mangle] extern "C"` boundary. Malformed input
must never crash, panic, or hit UB — always a clean `int32_t` rc.

```sh
cargo install cargo-fuzz          # one-time (nightly)
cargo +nightly fuzz run ffi_boundary          # run
cargo +nightly fuzz run ffi_boundary -- -runs=100000   # bounded (CI per-PR)
```

The in-tree `tests/proptest_abi.rs` provides the same invariant under
property-based testing (runs in `cargo test`, no extra tooling); these libFuzzer
targets add coverage-guided input + ASan/UBSan. A seed corpus lives under
`corpus/ffi_boundary/` (grown by CI); crash reproducers land in `artifacts/`.
