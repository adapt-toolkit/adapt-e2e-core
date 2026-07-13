// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! Property-based fuzzing of the C-ABI boundary (SPEC §7.6). The load-bearing
//! invariant: arbitrary / malformed input bytes NEVER panic, crash, or hit UB —
//! they always yield a clean negative return code. `proptest` treats any panic
//! (including one caught by the FFI `catch_unwind` guard converting to
//! `E2E_RC_PANIC`) as a failing case, and shrinks to a minimal reproducer.

use adapt_e2e_core::ffi::*;
use proptest::prelude::*;

const PK: [u8; 32] = [0x5A; 32];

fn one_out(f: impl Fn(*mut u8, *mut usize) -> i32) -> i32 {
    let mut buf = vec![0u8; 16384];
    let mut len = buf.len();
    f(buf.as_mut_ptr(), &mut len)
}

fn blob() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..400)
}

proptest! {
    /// Arbitrary bytes fed as an account pickle: never panic; garbage is a clean
    /// negative rc (never accidentally OK, never PANIC=-99).
    #[test]
    fn gen_otks_arbitrary_pickle_is_clean(pickle in blob(), n in 0u32..8) {
        let rc = one_out(|p, l| unsafe {
            e2e_account_gen_otks(pickle.as_ptr(), pickle.len(), n, [0u8; 32].as_ptr(), PK.as_ptr(), p, l)
        });
        prop_assert!(rc < 0, "garbage pickle must be a clean error, got {rc}");
        prop_assert_ne!(rc, -99, "must not be a caught panic");
    }

    /// Arbitrary session + message + type to decrypt: never panic.
    #[test]
    fn decrypt_arbitrary_is_clean(sess in blob(), mt in 0u32..6, msg in blob()) {
        let rc = one_out(|p, l| {
            let mut s2 = vec![0u8; 16384];
            let mut s2l = s2.len();
            unsafe {
                e2e_decrypt(sess.as_ptr(), sess.len(), mt, msg.as_ptr(), msg.len(), PK.as_ptr(), p, l, s2.as_mut_ptr(), &mut s2l)
            }
        });
        prop_assert!(rc < 0);
        prop_assert_ne!(rc, -99);
    }

    /// Arbitrary account + identity key + pre-key message to session_inbound.
    #[test]
    fn session_inbound_arbitrary_is_clean(acct in blob(), ik in any::<[u8; 32]>(), msg in blob()) {
        let mut s = vec![0u8; 16384];
        let mut sl = s.len();
        let mut a = vec![0u8; 16384];
        let mut al = a.len();
        let mut pt = vec![0u8; 16384];
        let mut ptl = pt.len();
        let rc = unsafe {
            e2e_session_inbound(
                acct.as_ptr(), acct.len(), ik.as_ptr(), msg.as_ptr(), msg.len(), PK.as_ptr(),
                s.as_mut_ptr(), &mut sl, a.as_mut_ptr(), &mut al, pt.as_mut_ptr(), &mut ptl,
            )
        };
        prop_assert!(rc < 0);
        prop_assert_ne!(rc, -99);
    }

    /// Arbitrary session + pre-key message to matches_inbound: never panic;
    /// garbage is a clean error.
    #[test]
    fn matches_inbound_arbitrary_is_clean(sess in blob(), msg in blob()) {
        let mut out: u32 = 7;
        let rc = unsafe {
            e2e_matches_inbound(sess.as_ptr(), sess.len(), msg.as_ptr(), msg.len(), PK.as_ptr(), &mut out)
        };
        prop_assert!(rc < 0);
        prop_assert_ne!(rc, -99);
    }

    /// `e2e_account_create` is total: for ANY seed and pickle_key it succeeds and
    /// is deterministic (the crate's core property, over the whole input space).
    #[test]
    fn create_is_total_and_deterministic(seed in any::<[u8; 32]>(), key in any::<[u8; 32]>()) {
        let mut b1 = vec![0u8; 16384];
        let mut l1 = b1.len();
        let rc1 = unsafe { e2e_account_create(seed.as_ptr(), key.as_ptr(), b1.as_mut_ptr(), &mut l1) };
        let mut b2 = vec![0u8; 16384];
        let mut l2 = b2.len();
        let rc2 = unsafe { e2e_account_create(seed.as_ptr(), key.as_ptr(), b2.as_mut_ptr(), &mut l2) };
        prop_assert_eq!(rc1, 0);
        prop_assert_eq!(rc2, 0);
        prop_assert_eq!(&b1[..l1], &b2[..l2]);
    }
}
