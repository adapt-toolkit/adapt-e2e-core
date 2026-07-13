//! # adapt-e2e-core
//!
//! A standalone, pure-Rust, MUFL/ADAPT-agnostic Signal-class end-to-end channel
//! (X3DH-class handshake + Double Ratchet) exposed as a C-ABI library. It is a
//! vendored, pinned fork of [vodozemac](https://github.com/matrix-org/vodozemac)
//! (the additive `*_with_rng` entropy-injection seam) plus a thin
//! management-primitive layer.
//!
//! Two contracts define the crate (see `docs/SPEC.md`):
//!
//! * **Stateless** — no long-lived internal state; every call takes an opaque
//!   pickled-blob state in and returns the new pickled-blob state out.
//! * **Deterministic via injected entropy** — randomness is never sourced
//!   internally; each keygen-bearing call takes a 32-byte seed and produces
//!   byte-identical output for identical `(state, seed, message)`.
//!
//! This is the milestone-M0 skeleton: it vendors the seed-injected vodozemac
//! fork and exposes the [`seeded_rng`] entropy source that drives it. The
//! management layer, C-ABI (`ffi`), pickle envelope, and adversarial test suite
//! land in subsequent milestones.

pub mod mgmt;
pub mod seeded_rng;
