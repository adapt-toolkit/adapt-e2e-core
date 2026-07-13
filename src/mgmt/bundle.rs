//! Prekey-bundle emission (SPEC fn 4). Pure read of an account's public
//! material; the *host* signs it and defines the wire format (SPEC §4.3). We
//! emit a concrete, self-describing, **deterministic** (key-id-sorted) body:
//!
//! ```text
//! bundle_body = ik_curve(32) || ik_ed(32)
//!   || fallback_count(u8)  || [ key_id(u32 LE) || key(32) ] * fallback_count
//!   || otk_count(u32 LE)   || [ key_id(u32 LE) || key(32) ] * otk_count
//! ```
//!
//! The `key_id` is informational for the host; the crate's inbound path
//! identifies the one-time key by its public key (carried in the pre-key
//! message), not by id.

use vodozemac::KeyId;

use crate::mgmt::account;
use crate::mgmt::error::Result;

/// Derive a 32-bit key id from vodozemac's opaque [`KeyId`] via its base64 form
/// (8 big-endian bytes = the underlying u64); the low 32 bits suffice for the
/// host-facing id.
fn key_id_u32(id: KeyId) -> u32 {
    let bytes = vodozemac::base64_decode(id.to_base64()).unwrap_or_default();
    let mut acc = 0u64;
    for b in bytes.iter().take(8) {
        acc = (acc << 8) | u64::from(*b);
    }
    acc as u32
}

/// SPEC fn 4 — emit the account's public prekey-bundle material.
pub fn bundle(acct_pickle: &[u8], pickle_key: &[u8; 32]) -> Result<Vec<u8>> {
    let account = account::load(acct_pickle, pickle_key)?;

    let mut out = Vec::new();
    out.extend_from_slice(account.curve25519_key().as_bytes());
    out.extend_from_slice(account.ed25519_key().as_bytes());

    // Fallback keys (0 or 1), sorted by id for determinism.
    let mut fallback: Vec<(u32, [u8; 32])> = account
        .fallback_key()
        .iter()
        .map(|(id, key)| (key_id_u32(*id), *key.as_bytes()))
        .collect();
    fallback.sort_by_key(|(id, _)| *id);
    out.push(fallback.len() as u8);
    for (id, key) in &fallback {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(key);
    }

    // Unpublished one-time keys, sorted by id for determinism.
    let mut otks: Vec<(u32, [u8; 32])> = account
        .one_time_keys()
        .iter()
        .map(|(id, key)| (key_id_u32(*id), *key.as_bytes()))
        .collect();
    otks.sort_by_key(|(id, _)| *id);
    out.extend_from_slice(&(otks.len() as u32).to_le_bytes());
    for (id, key) in &otks {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(key);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::account;

    const PK: [u8; 32] = [0x33; 32];

    #[test]
    fn bundle_is_deterministic_and_well_formed() {
        let acct = account::create(&[1u8; 32], &PK).unwrap();
        let acct = account::gen_otks(&acct, 3, &[2u8; 32], &PK).unwrap();
        let acct = account::gen_fallback(&acct, &[3u8; 32], &PK).unwrap();

        let a = bundle(&acct, &PK).unwrap();
        let b = bundle(&acct, &PK).unwrap();
        assert_eq!(a, b, "bundle must be deterministic (sorted)");

        // ik_curve(32) + ik_ed(32) + fb_count(1) + 1*(4+32) + otk_count(4) + 3*(4+32)
        assert_eq!(a.len(), 32 + 32 + 1 + 36 + 4 + 3 * 36);
        assert_eq!(a[64], 1, "one fallback key present");
        let otk_count = u32::from_le_bytes([a[101], a[102], a[103], a[104]]);
        assert_eq!(otk_count, 3);
    }
}
