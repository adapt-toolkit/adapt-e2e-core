//! The management-primitive layer over the vendored vodozemac fork.
//!
//! Each submodule provides the stateless `unpickle → op(SeededRng) → pickle`
//! orchestration behind the C-ABI (`crate::ffi`). Everything here works in Rust
//! terms (byte slices, `Vec<u8>`, [`error::Result`]); the FFI boundary and the
//! two-call length convention live in [`crate::ffi`].

pub mod account;
pub mod error;
pub mod pickle;
pub mod session;
