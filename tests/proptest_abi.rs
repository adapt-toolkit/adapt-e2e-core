// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! Property-based fuzzing of the C-ABI boundary. The load-bearing
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

    // --- review F4: the previously-UNFUZZED 5 of 10 entry points ------------

    /// ★ e2e_encrypt — the sharpest: it deserializes an UNTRUSTED session pickle
    /// (same risk class as the already-fuzzed decrypt). Garbage session must be a
    /// clean negative rc, never a caught panic.
    #[test]
    fn encrypt_arbitrary_is_clean(sess in blob(), pt in blob()) {
        let mut msg = vec![0u8; 16384];
        let mut msgl = msg.len();
        let mut mt: u32 = 0;
        let mut s2 = vec![0u8; 16384];
        let mut s2l = s2.len();
        let rc = unsafe {
            e2e_encrypt(sess.as_ptr(), sess.len(), pt.as_ptr(), pt.len(), [0u8; 32].as_ptr(), PK.as_ptr(),
                msg.as_mut_ptr(), &mut msgl, &mut mt, s2.as_mut_ptr(), &mut s2l)
        };
        prop_assert!(rc < 0, "garbage session pickle must be a clean error, got {rc}");
        prop_assert_ne!(rc, -99, "must not be a caught panic");
    }

    /// e2e_account_bundle — arbitrary account pickle (pure read).
    #[test]
    fn bundle_arbitrary_is_clean(pickle in blob()) {
        let rc = one_out(|p, l| unsafe {
            e2e_account_bundle(pickle.as_ptr(), pickle.len(), PK.as_ptr(), p, l)
        });
        prop_assert!(rc < 0);
        prop_assert_ne!(rc, -99);
    }

    /// e2e_account_gen_fallback — arbitrary account pickle.
    #[test]
    fn gen_fallback_arbitrary_is_clean(pickle in blob()) {
        let rc = one_out(|p, l| unsafe {
            e2e_account_gen_fallback(pickle.as_ptr(), pickle.len(), [0u8; 32].as_ptr(), PK.as_ptr(), p, l)
        });
        prop_assert!(rc < 0);
        prop_assert_ne!(rc, -99);
    }

    /// e2e_session_outbound — arbitrary account pickle + arbitrary ik/otk bytes.
    #[test]
    fn outbound_arbitrary_is_clean(acct in blob(), ikb in any::<[u8; 32]>(), otkb in any::<[u8; 32]>()) {
        let mut s = vec![0u8; 16384];
        let mut sl = s.len();
        let mut a = vec![0u8; 16384];
        let mut al = a.len();
        let rc = unsafe {
            e2e_session_outbound(acct.as_ptr(), acct.len(), ikb.as_ptr(), otkb.as_ptr(), [0u8; 32].as_ptr(), PK.as_ptr(),
                s.as_mut_ptr(), &mut sl, a.as_mut_ptr(), &mut al)
        };
        prop_assert!(rc < 0);
        prop_assert_ne!(rc, -99);
    }

    /// e2e_session_id — arbitrary session pickle (fixed 32-byte out).
    #[test]
    fn session_id_arbitrary_is_clean(sess in blob()) {
        let mut id = [0u8; 32];
        let rc = unsafe { e2e_session_id(sess.as_ptr(), sess.len(), PK.as_ptr(), id.as_mut_ptr()) };
        prop_assert!(rc < 0);
        prop_assert_ne!(rc, -99);
    }

    /// Robustness fuzz: a REAL account pickle with ANY single envelope-metadata
    /// byte (fmt_ver / engine_ver / kind, offsets 4..8) corrupted must ALWAYS be
    /// cleanly rejected when fed to a session entry point — never a panic (-99),
    /// never a false load (rc == 0). NOTE this is a ROBUSTNESS envelope, not the
    /// type-confusion proof: most random corruptions trip the version/kind check,
    /// so only a tiny fraction actually reach inner deserialization. The
    /// deterministic acct↔sess type-confusion (kind flipped to the *valid* other
    /// value, so inner deser is the guard) is covered exhaustively AND both
    /// directions in `tests/boundary_invariants.rs::flipped_envelope_kind_*`; the
    /// kind byte's own enforcement is pinned by `mgmt::pickle::rejects_wrong_kind`.
    #[test]
    fn corrupted_envelope_meta_is_cleanly_rejected(seed in any::<[u8; 32]>(), pos in 4usize..8, xor in 1u8..=255) {
        let mut acct = vec![0u8; 16384];
        let mut al = acct.len();
        let rc = unsafe { e2e_account_create(seed.as_ptr(), PK.as_ptr(), acct.as_mut_ptr(), &mut al) };
        prop_assume!(rc == 0);
        acct.truncate(al);
        acct[pos] ^= xor;
        let mut id = [0u8; 32];
        let rc2 = unsafe { e2e_session_id(acct.as_ptr(), acct.len(), PK.as_ptr(), id.as_mut_ptr()) };
        prop_assert!(rc2 < 0, "corrupted-envelope account must not load as a session, got {rc2}");
        prop_assert_ne!(rc2, -99);
    }
}
