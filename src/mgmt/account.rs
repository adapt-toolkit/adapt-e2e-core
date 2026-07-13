//! Account-side management primitives (SPEC fns 1–4): create identity, generate
//! one-time / fallback keys. Each orchestrates `unpickle → op(SeededRng) →
//! pickle`, taking the caller's 32-byte seed and `pickle_key` and returning the
//! new envelope-wrapped account pickle. The crate keeps no state.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use vodozemac::olm::{Account, AccountPickle};

use crate::mgmt::error::{Error, Result};
use crate::mgmt::pickle::{self, Kind};
use crate::seeded_rng::SeededRng;

/// Decrypt + unpickle an account from an envelope blob.
pub(crate) fn load(blob: &[u8], pickle_key: &[u8; 32]) -> Result<Account> {
    let inner = pickle::unwrap(blob, Kind::Account)?;
    let pickled = AccountPickle::from_encrypted(inner, pickle_key).map_err(|_| Error::BadPickle)?;
    Ok(Account::from_pickle(pickled))
}

/// Pickle + encrypt + envelope-wrap an account.
pub(crate) fn store(account: &Account, pickle_key: &[u8; 32]) -> Vec<u8> {
    pickle::wrap(Kind::Account, &account.pickle().encrypt(pickle_key))
}

/// SPEC fn 1 — create a new account with identity keys derived from `seed`.
pub fn create(seed: &[u8; 32], pickle_key: &[u8; 32]) -> Result<Vec<u8>> {
    let account = Account::new_with_rng(SeededRng::from_seed(*seed).rng());
    Ok(store(&account, pickle_key))
}

/// SPEC fn 2 — generate `n` one-time keys, all drawn from `seed`.
pub fn gen_otks(
    in_pickle: &[u8],
    n: u32,
    seed: &[u8; 32],
    pickle_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut account = load(in_pickle, pickle_key)?;
    account.generate_one_time_keys_with_rng(n as usize, SeededRng::from_seed(*seed).rng());
    Ok(store(&account, pickle_key))
}

/// SPEC fn 3 — generate a new fallback key from `seed`.
pub fn gen_fallback(in_pickle: &[u8], seed: &[u8; 32], pickle_key: &[u8; 32]) -> Result<Vec<u8>> {
    let mut account = load(in_pickle, pickle_key)?;
    account.generate_fallback_key_with_rng(SeededRng::from_seed(*seed).rng());
    Ok(store(&account, pickle_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: [u8; 32] = [0xAB; 32];

    #[test]
    fn create_is_deterministic_and_roundtrips() {
        let a = create(&[1u8; 32], &PK).unwrap();
        let b = create(&[1u8; 32], &PK).unwrap();
        assert_eq!(a, b, "same seed => byte-identical account pickle");

        let c = create(&[2u8; 32], &PK).unwrap();
        assert_ne!(a, c, "distinct seed => distinct pickle");

        // Load-back succeeds and yields a usable account.
        let acct = load(&a, &PK).unwrap();
        assert_eq!(
            acct.curve25519_key(),
            load(&b, &PK).unwrap().curve25519_key()
        );
    }

    #[test]
    fn gen_otks_is_deterministic() {
        let acct = create(&[3u8; 32], &PK).unwrap();
        let a = gen_otks(&acct, 5, &[4u8; 32], &PK).unwrap();
        let b = gen_otks(&acct, 5, &[4u8; 32], &PK).unwrap();
        assert_eq!(a, b);

        let c = gen_otks(&acct, 5, &[9u8; 32], &PK).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn gen_fallback_is_deterministic() {
        let acct = create(&[5u8; 32], &PK).unwrap();
        let a = gen_fallback(&acct, &[6u8; 32], &PK).unwrap();
        let b = gen_fallback(&acct, &[6u8; 32], &PK).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn wrong_pickle_key_is_rejected() {
        let acct = create(&[7u8; 32], &PK).unwrap();
        let wrong = [0x11; 32];
        assert_eq!(load(&acct, &wrong).map(|_| ()), Err(Error::BadPickle));
    }
}
