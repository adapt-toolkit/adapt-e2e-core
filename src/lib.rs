//! # adapt-e2e-core
//!
//! A standalone, pure-Rust, MUFL/ADAPT-agnostic Signal-class end-to-end channel
//! (X3DH-class handshake + Double Ratchet) exposed as a C-ABI library. It is a
//! vendored, pinned fork of [vodozemac](https://github.com/matrix-org/vodozemac)
//! (the additive `*_with_rng` entropy-injection seam) plus a thin
//! management-primitive layer.
//!
//! Two contracts define the crate:
//!
//! * **Stateless** — no long-lived internal state; every call takes an opaque
//!   pickled-blob state in and returns the new pickled-blob state out.
//! * **Deterministic via injected entropy** — randomness is never sourced
//!   internally; each keygen-bearing call takes a 32-byte seed and produces
//!   byte-identical output for identical `(state, seed, message)`.
//!
//! Because the crate is **stateless**, three load-bearing security invariants —
//! seed uniqueness, one-time-key one-time-ness, and pickle persistence/integrity —
//! are the **caller's** responsibility, not the crate's. The crate cannot enforce
//! them without breaking determinism; they are documented (with reachable-break
//! boundary tests) in `docs/CALLER-CONTRACTS.md`.
//!
//! The crate is `#![no_std]` + `alloc` (the `std` feature, default-on, is only
//! for native convenience — a better panic guard at the FFI boundary). The
//! `--no-default-features` build targets bare-metal; it links no
//! `getrandom`/`OsRng`, sourcing all entropy from the injected seed.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod ffi;
pub mod mgmt;
pub mod seeded_rng;
