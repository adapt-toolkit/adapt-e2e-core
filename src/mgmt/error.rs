//! Stable C-ABI return codes and the internal management error type.

/// Stable C-ABI return code. **These values are frozen and MUST never be
/// renumbered** — they are part of the committed ABI (`enum e2e_rc`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eRc {
    /// Success.
    Ok = 0,
    /// A required pointer argument was NULL.
    NullArg = -1,
    /// The caller's output buffer was too small (see the two-call convention).
    ShortBuffer = -2,
    /// A pickled-blob input was malformed or could not be decrypted.
    BadPickle = -3,
    /// The pickle envelope had an unknown magic / format / engine version.
    Version = -4,
    /// Message decryption failed (bad MAC, missing/evicted key, etc.).
    DecryptFailed = -5,
    /// A supplied seed was the wrong length or otherwise invalid.
    BadSeed = -6,
    /// No one-time key was available to satisfy the request.
    OtkExhausted = -7,
    /// The operation did not match the supplied session/account.
    SessionMismatch = -8,
    /// An unexpected internal error occurred.
    Internal = -98,
    /// A panic was caught at the ABI boundary (defence in depth).
    Panic = -99,
}

/// Internal management-layer error. Maps to a stable [`E2eRc`] at the ABI edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A required pointer argument was NULL.
    NullArg,
    /// The caller's output buffer was too small.
    ShortBuffer,
    /// A pickled-blob input was malformed or could not be decrypted.
    BadPickle,
    /// The pickle envelope had an unknown magic / format / engine version.
    Version,
    /// Message decryption failed.
    DecryptFailed,
    /// A supplied seed was invalid.
    BadSeed,
    /// No one-time key was available.
    OtkExhausted,
    /// The operation did not match the supplied session/account.
    SessionMismatch,
    /// An unexpected internal error occurred.
    Internal,
}

impl Error {
    /// Map to the stable C-ABI return code.
    pub const fn rc(self) -> E2eRc {
        match self {
            Error::NullArg => E2eRc::NullArg,
            Error::ShortBuffer => E2eRc::ShortBuffer,
            Error::BadPickle => E2eRc::BadPickle,
            Error::Version => E2eRc::Version,
            Error::DecryptFailed => E2eRc::DecryptFailed,
            Error::BadSeed => E2eRc::BadSeed,
            Error::OtkExhausted => E2eRc::OtkExhausted,
            Error::SessionMismatch => E2eRc::SessionMismatch,
            Error::Internal => E2eRc::Internal,
        }
    }
}

/// Management-layer result alias.
pub type Result<T> = core::result::Result<T, Error>;
