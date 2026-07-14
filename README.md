# adapt-e2e-core

A standalone, pure-Rust, Signal-class end-to-end encryption engine — an
X3DH-style handshake plus the Double Ratchet — exposed as a C-ABI library. It is
a vendored, pinned fork of [vodozemac](https://github.com/matrix-org/vodozemac)
(Matrix's Olm/Megolm implementation), focused on the Olm path, with a thin
management layer and a stable `extern "C"` surface. Apache-2.0.

## What makes it different

Two properties define the crate:

- **Stateless.** It holds no long-lived state. Every call takes an opaque,
  encrypted *pickle* blob in and returns the new pickle out — the caller owns and
  persists all state. The engine is a pure function
  `f(state, seed, msg) -> (state', out)`.
- **Deterministic via injected entropy.** Randomness is never sourced internally
  — no `getrandom`, no `OsRng`, no thread-local RNG. Every key-generating call
  takes a caller-supplied 32-byte **seed** and expands it with a ChaCha20 CSPRNG,
  so identical `(state, seed, message)` inputs produce byte-identical output.

Together these make the engine reproducible (useful for consensus / replayable
systems) and buildable with **no operating system**: it compiles to a `no_std`
`riscv32imac-unknown-none-elf` bare-metal rlib that links no OS entropy source.

## C-ABI surface

Ten `extern "C"` functions over opaque pickle blobs (`const uint8_t*` + length in;
caller-allocated `uint8_t*` + `size_t*` out, using a two-call length convention).
Every call returns an `int32_t` code (`enum e2e_rc`); no panic crosses the
boundary. The generated header is [`include/adapt_e2e_core.h`](include/adapt_e2e_core.h):

- `e2e_account_create`, `e2e_account_gen_otks`, `e2e_account_gen_fallback`,
  `e2e_account_bundle` — identity and prekey material
- `e2e_session_outbound`, `e2e_session_inbound`, `e2e_matches_inbound` —
  X3DH-style session establishment
- `e2e_encrypt`, `e2e_decrypt`, `e2e_session_id` — the Double-Ratchet channel

## Building

```sh
cargo build --release                  # native staticlib + cdylib + rlib
cargo build --features generate-header # regenerate include/adapt_e2e_core.h
cargo test                             # full test suite

# no_std / bare-metal (riscv32, nightly + rust-src):
./scripts/rv32_baremetal_build.sh
```

The default `std` feature is native convenience only; `--no-default-features`
builds the `no_std` + `alloc` library. See [`docs/PACKAGING.md`](docs/PACKAGING.md)
for the full target matrix and [`docs/TESTING.md`](docs/TESTING.md) for the test
and gate posture.

## Caller obligations (important)

Because the crate is stateless, three load-bearing security invariants — **seed
uniqueness**, **one-time-key one-time-ness**, and **pickle persistence +
integrity** — cannot be enforced by the crate and are the **caller's**
responsibility. Read [`docs/CALLER-CONTRACTS.md`](docs/CALLER-CONTRACTS.md) before
integrating; violating any of them breaks a cryptographic guarantee.

## Security status

The cryptographic core is inherited from vodozemac: the entropy-injection fork is
purely additive, and the audited default code paths are unchanged (see
[`PATCH.md`](PATCH.md), the vendored-fork ledger). The crate has been
**independently reviewed for hardening by an external security team**, whose
findings on test-completeness and caller-contract honesty are addressed in this
tree. It has **not** yet undergone a formal third-party cryptographic audit — do
not treat it as audited.

## License

Apache-2.0. Vendored dependencies under `vendor/` retain their own licenses; the
vodozemac and base64 forks and their deltas are documented in [`PATCH.md`](PATCH.md).
