//! The crate's deterministic entropy source.
//!
//! `adapt-e2e-core` never draws from an OS RNG, a thread-local, or a global.
//! Every keygen-bearing operation expands a caller-supplied **32-byte seed**
//! into as many keystream bytes as it needs via a ChaCha20 CSPRNG. This is what
//! makes the engine a pure function `f(state, seed, msg) -> (state', out)`
//! and lets it link no `getrandom`/`OsRng` on any target.
//!
//! The seeded RNG is handed to the vendored vodozemac fork's additive
//! `*_with_rng` entry points, which thread it down to every secret-key mint.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroize;

/// A deterministic CSPRNG seeded by the caller's 32-byte entropy blob.
///
/// Wraps a [`ChaCha20Rng`]. Construct it with [`SeededRng::from_seed`] and hand
/// it to vodozemac's `*_with_rng` APIs via [`SeededRng::rng`]. Identical seeds
/// produce identical keystreams and therefore byte-identical keys and
/// ciphertext — the core determinism guarantee.
///
/// The 32-byte seed is wiped from the caller's copy on construction; the
/// expanded ChaCha20 state lives only as long as this value.
pub struct SeededRng {
    inner: ChaCha20Rng,
}

impl SeededRng {
    /// Expand a 32-byte seed into a deterministic ChaCha20 CSPRNG.
    ///
    /// The input `seed` is zeroized before returning.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let inner = ChaCha20Rng::from_seed(seed);
        seed.zeroize();

        Self { inner }
    }

    /// Borrow the underlying CSPRNG to pass to vodozemac's `*_with_rng` APIs,
    /// e.g. `account.new_with_rng(seeded.rng())`.
    pub fn rng(&mut self) -> &mut ChaCha20Rng {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::SeededRng;

    #[test]
    fn same_seed_yields_same_keystream() {
        use rand_core::Rng;

        let mut a = SeededRng::from_seed([7u8; 32]);
        let mut b = SeededRng::from_seed([7u8; 32]);

        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.rng().fill_bytes(&mut buf_a);
        b.rng().fill_bytes(&mut buf_b);

        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn distinct_seeds_yield_distinct_keystream() {
        use rand_core::Rng;

        let mut a = SeededRng::from_seed([1u8; 32]);
        let mut b = SeededRng::from_seed([2u8; 32]);

        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.rng().fill_bytes(&mut buf_a);
        b.rng().fill_bytes(&mut buf_b);

        assert_ne!(buf_a, buf_b);
    }
}
