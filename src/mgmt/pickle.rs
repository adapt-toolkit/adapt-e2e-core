//! The self-describing pickle envelope.
//!
//! Both blob kinds share an outer envelope wrapping a vodozemac *encrypted
//! pickle* (AES-256-CBC + truncated HMAC-SHA256 under the caller's `pickle_key`
//! — note: not an AEAD; the IV is HKDF-derived from the key, so the ciphertext
//! is deterministic given the same key and plaintext, which the crate's
//! byte-identical determinism guarantee relies on):
//!
//! ```text
//! pickle_blob = magic(4)="AE2C" || fmt_ver(u8) || engine_ver(u16 LE)
//!               || kind(u8: 1=acct, 2=sess) || vodozemac_pickle_string_bytes
//! ```

use crate::mgmt::error::{Error, Result};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const MAGIC: [u8; 4] = *b"AE2C";
const FMT_VER: u8 = 1;

/// Pins the vendored vodozemac serde pickle layout.
///
/// vodozemac's native pickle carries no format-version integer of its own, so
/// this is a **crate-assigned** constant meaning "the pickle serde shape shipped
/// with the vendored vodozemac revision". Bump it whenever a vendored-rev change
/// alters the pickle shape; the compat-matrix test guards it.
pub const ENGINE_VER: u16 = 1;

const HEADER_LEN: usize = 4 + 1 + 2 + 1;

/// Which kind of state a blob carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A serialized `Account` pickle.
    Account = 1,
    /// A serialized `Session` pickle.
    Session = 2,
}

/// Wrap a vodozemac encrypted-pickle string in the self-describing envelope.
pub fn wrap(kind: Kind, pickle: &str) -> Vec<u8> {
    let body = pickle.as_bytes();
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(FMT_VER);
    out.extend_from_slice(&ENGINE_VER.to_le_bytes());
    out.push(kind as u8);
    out.extend_from_slice(body);
    out
}

/// Parse and validate the envelope, returning the inner vodozemac pickle string.
///
/// Rejects an unknown magic / format / engine version with [`Error::Version`],
/// and a wrong `kind` or non-UTF-8 / too-short body with [`Error::BadPickle`].
/// Never panics on malformed input.
pub fn unwrap(blob: &[u8], expected: Kind) -> Result<&str> {
    if blob.len() < HEADER_LEN {
        return Err(Error::BadPickle);
    }
    if blob[0..4] != MAGIC {
        return Err(Error::Version);
    }
    if blob[4] != FMT_VER {
        return Err(Error::Version);
    }
    let engine = u16::from_le_bytes([blob[5], blob[6]]);
    if engine != ENGINE_VER {
        return Err(Error::Version);
    }
    if blob[7] != expected as u8 {
        return Err(Error::BadPickle);
    }
    core::str::from_utf8(&blob[HEADER_LEN..]).map_err(|_| Error::BadPickle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrips() {
        let blob = wrap(Kind::Account, "hello-pickle");
        assert_eq!(unwrap(&blob, Kind::Account).unwrap(), "hello-pickle");

        let blob = wrap(Kind::Session, "sess");
        assert_eq!(unwrap(&blob, Kind::Session).unwrap(), "sess");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = wrap(Kind::Account, "x");
        blob[0] = b'X';
        assert_eq!(unwrap(&blob, Kind::Account), Err(Error::Version));
    }

    #[test]
    fn rejects_bad_fmt_ver() {
        let mut blob = wrap(Kind::Account, "x");
        blob[4] = 99;
        assert_eq!(unwrap(&blob, Kind::Account), Err(Error::Version));
    }

    #[test]
    fn rejects_bad_engine_ver() {
        let mut blob = wrap(Kind::Account, "x");
        blob[5] = blob[5].wrapping_add(1);
        assert_eq!(unwrap(&blob, Kind::Account), Err(Error::Version));
    }

    #[test]
    fn rejects_wrong_kind() {
        let blob = wrap(Kind::Account, "x");
        assert_eq!(unwrap(&blob, Kind::Session), Err(Error::BadPickle));
    }

    #[test]
    fn rejects_short_blob() {
        assert_eq!(unwrap(b"AE2", Kind::Account), Err(Error::BadPickle));
        assert_eq!(unwrap(b"", Kind::Account), Err(Error::BadPickle));
    }
}
