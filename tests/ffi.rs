// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! Exercises the C-ABI (`extern "C"`) surface directly: a full handshake through
//! the raw functions, the two-call length convention, determinism across the
//! boundary, and the load-bearing safety invariant — malformed / NULL input
//! yields a clean negative return code, never a panic or UB.

use std::ptr;

use adapt_e2e_core::ffi::*;

const PK: [u8; 32] = [0x5A; 32];
const RC_OK: i32 = 0;
const RC_SHORT: i32 = -2;
const RC_BAD_PICKLE: i32 = -3;
const RC_NULL: i32 = -1;

/// Call a single-out-buffer function with an oversized buffer; return (rc, bytes).
fn one_out(f: impl Fn(*mut u8, *mut usize) -> i32) -> (i32, Vec<u8>) {
    let mut buf = vec![0u8; 16384];
    let mut len = buf.len();
    let rc = f(buf.as_mut_ptr(), &mut len);
    buf.truncate(if rc == RC_OK { len } else { 0 });
    (rc, buf)
}

fn create(seed: [u8; 32]) -> Vec<u8> {
    let (rc, blob) =
        one_out(|p, l| unsafe { e2e_account_create(seed.as_ptr(), PK.as_ptr(), p, l) });
    assert_eq!(rc, RC_OK);
    blob
}

fn gen_otks(pickle: &[u8], n: u32, seed: [u8; 32]) -> Vec<u8> {
    let (rc, blob) = one_out(|p, l| unsafe {
        e2e_account_gen_otks(
            pickle.as_ptr(),
            pickle.len(),
            n,
            seed.as_ptr(),
            PK.as_ptr(),
            p,
            l,
        )
    });
    assert_eq!(rc, RC_OK);
    blob
}

fn bundle(pickle: &[u8]) -> Vec<u8> {
    let (rc, b) = one_out(|p, l| unsafe {
        e2e_account_bundle(pickle.as_ptr(), pickle.len(), PK.as_ptr(), p, l)
    });
    assert_eq!(rc, RC_OK);
    b
}

/// Read just the identity key from an account's bundle.
fn ik_of(account_pickle: &[u8]) -> [u8; 32] {
    let b = bundle(account_pickle);
    let mut ik = [0u8; 32];
    ik.copy_from_slice(&b[0..32]);
    ik
}

/// Read a peer's identity key and first published one-time key from its bundle
/// (the real C-ABI publication path).
fn ik_and_otk(account_pickle: &[u8]) -> ([u8; 32], [u8; 32]) {
    let b = bundle(account_pickle);
    let mut ik = [0u8; 32];
    ik.copy_from_slice(&b[0..32]);

    let fb_count = b[64] as usize;
    let mut off = 65 + fb_count * 36; // skip ik_ed(32) already, fallback block
    let otk_count = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize;
    off += 4;
    assert!(otk_count >= 1, "peer must have a published OTK");

    let mut otk = [0u8; 32];
    otk.copy_from_slice(&b[off + 4..off + 36]); // skip key_id(4), read key(32)
    (ik, otk)
}

#[test]
fn full_handshake_over_the_c_abi() {
    let alice = create([1u8; 32]);
    let bob = create([2u8; 32]);
    let bob = gen_otks(&bob, 3, [3u8; 32]);

    let (ik_b, otk_b) = ik_and_otk(&bob);
    let ik_a = ik_of(&alice);

    // Alice: outbound session (two out buffers).
    let mut sess = vec![0u8; 16384];
    let mut sess_len = sess.len();
    let mut acct = vec![0u8; 16384];
    let mut acct_len = acct.len();
    let rc = unsafe {
        e2e_session_outbound(
            alice.as_ptr(),
            alice.len(),
            ik_b.as_ptr(),
            otk_b.as_ptr(),
            [4u8; 32].as_ptr(),
            PK.as_ptr(),
            sess.as_mut_ptr(),
            &mut sess_len,
            acct.as_mut_ptr(),
            &mut acct_len,
        )
    };
    assert_eq!(rc, RC_OK);
    sess.truncate(sess_len);
    let alice_sess = sess;

    // Alice: encrypt (message + type + session).
    let mut msg = vec![0u8; 16384];
    let mut msg_len = msg.len();
    let mut msg_type: u32 = 99;
    let mut asess = vec![0u8; 16384];
    let mut asess_len = asess.len();
    let rc = unsafe {
        e2e_encrypt(
            alice_sess.as_ptr(),
            alice_sess.len(),
            b"hello bob".as_ptr(),
            9,
            [5u8; 32].as_ptr(),
            PK.as_ptr(),
            msg.as_mut_ptr(),
            &mut msg_len,
            &mut msg_type,
            asess.as_mut_ptr(),
            &mut asess_len,
        )
    };
    assert_eq!(rc, RC_OK);
    assert_eq!(msg_type, 0, "first message is a pre-key message");
    msg.truncate(msg_len);

    // Bob: inbound (session + account + plaintext).
    let mut bsess = vec![0u8; 16384];
    let mut bsess_len = bsess.len();
    let mut bacct = vec![0u8; 16384];
    let mut bacct_len = bacct.len();
    let mut pt = vec![0u8; 16384];
    let mut pt_len = pt.len();
    let rc = unsafe {
        e2e_session_inbound(
            bob.as_ptr(),
            bob.len(),
            ik_a.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            PK.as_ptr(),
            bsess.as_mut_ptr(),
            &mut bsess_len,
            bacct.as_mut_ptr(),
            &mut bacct_len,
            pt.as_mut_ptr(),
            &mut pt_len,
        )
    };
    assert_eq!(rc, RC_OK);
    pt.truncate(pt_len);
    bsess.truncate(bsess_len);
    assert_eq!(pt, b"hello bob");

    // Session ids agree.
    let mut id_a = [0u8; 32];
    let mut id_b = [0u8; 32];
    assert_eq!(
        unsafe {
            e2e_session_id(
                alice_sess.as_ptr(),
                alice_sess.len(),
                PK.as_ptr(),
                id_a.as_mut_ptr(),
            )
        },
        RC_OK
    );
    assert_eq!(
        unsafe { e2e_session_id(bsess.as_ptr(), bsess.len(), PK.as_ptr(), id_b.as_mut_ptr()) },
        RC_OK
    );
    assert_eq!(id_a, id_b);

    // Bob replies; Alice decrypts.
    let mut rmsg = vec![0u8; 16384];
    let mut rmsg_len = rmsg.len();
    let mut rtype: u32 = 99;
    let mut rsess = vec![0u8; 16384];
    let mut rsess_len = rsess.len();
    let rc = unsafe {
        e2e_encrypt(
            bsess.as_ptr(),
            bsess.len(),
            b"hey back".as_ptr(),
            8,
            [6u8; 32].as_ptr(),
            PK.as_ptr(),
            rmsg.as_mut_ptr(),
            &mut rmsg_len,
            &mut rtype,
            rsess.as_mut_ptr(),
            &mut rsess_len,
        )
    };
    assert_eq!(rc, RC_OK);
    rmsg.truncate(rmsg_len);

    let mut dpt = vec![0u8; 16384];
    let mut dpt_len = dpt.len();
    let mut dsess = vec![0u8; 16384];
    let mut dsess_len = dsess.len();
    let rc = unsafe {
        e2e_decrypt(
            alice_sess.as_ptr(),
            alice_sess.len(),
            rtype,
            rmsg.as_ptr(),
            rmsg.len(),
            PK.as_ptr(),
            dpt.as_mut_ptr(),
            &mut dpt_len,
            dsess.as_mut_ptr(),
            &mut dsess_len,
        )
    };
    assert_eq!(rc, RC_OK);
    dpt.truncate(dpt_len);
    assert_eq!(dpt, b"hey back");
}

#[test]
fn two_call_length_convention() {
    let seed = [7u8; 32];
    // Probe with a NULL out pointer: reports required length, returns ShortBuffer.
    let mut len: usize = 0;
    let rc = unsafe { e2e_account_create(seed.as_ptr(), PK.as_ptr(), ptr::null_mut(), &mut len) };
    assert_eq!(rc, RC_SHORT);
    assert!(len > 0);

    // Second call with the exact buffer: Ok, same length.
    let mut buf = vec![0u8; len];
    let mut len2 = buf.len();
    let rc = unsafe { e2e_account_create(seed.as_ptr(), PK.as_ptr(), buf.as_mut_ptr(), &mut len2) };
    assert_eq!(rc, RC_OK);
    assert_eq!(len2, len);

    // A too-small buffer also returns ShortBuffer and reports the true length.
    let mut tiny = [0u8; 4];
    let mut tiny_len = tiny.len();
    let rc =
        unsafe { e2e_account_create(seed.as_ptr(), PK.as_ptr(), tiny.as_mut_ptr(), &mut tiny_len) };
    assert_eq!(rc, RC_SHORT);
    assert_eq!(tiny_len, len);
}

#[test]
fn create_is_deterministic_over_the_abi() {
    assert_eq!(create([42u8; 32]), create([42u8; 32]));
    assert_ne!(create([42u8; 32]), create([43u8; 32]));
}

#[test]
fn malformed_and_null_inputs_never_panic() {
    // Garbage account pickle -> clean negative rc (Version/BadPickle), no panic.
    let garbage = [0xFFu8; 200];
    let (rc, _) = one_out(|p, l| unsafe {
        e2e_account_gen_otks(
            garbage.as_ptr(),
            garbage.len(),
            1,
            [0u8; 32].as_ptr(),
            PK.as_ptr(),
            p,
            l,
        )
    });
    assert!(rc < 0, "garbage pickle must fail cleanly, got {rc}");

    // Valid-looking envelope but garbage inner pickle -> BadPickle.
    let acct = create([1u8; 32]);
    let mut corrupt = acct.clone();
    let n = corrupt.len();
    corrupt[n - 1] ^= 0xFF; // flip a byte in the encrypted pickle body
    let (rc, _) = one_out(|p, l| unsafe {
        e2e_account_gen_fallback(
            corrupt.as_ptr(),
            corrupt.len(),
            [0u8; 32].as_ptr(),
            PK.as_ptr(),
            p,
            l,
        )
    });
    assert_eq!(rc, RC_BAD_PICKLE);

    // NULL seed -> NullArg.
    let mut len = 0usize;
    let rc = unsafe { e2e_account_create(ptr::null(), PK.as_ptr(), ptr::null_mut(), &mut len) };
    assert_eq!(rc, RC_NULL);

    // Random bytes as a "message" to decrypt against a real session -> DecryptFailed,
    // never a panic.
    let bob = gen_otks(&create([2u8; 32]), 1, [3u8; 32]);
    let (ik_b, otk_b) = ik_and_otk(&bob);
    let alice = create([1u8; 32]);
    let mut sess = vec![0u8; 16384];
    let mut sl = sess.len();
    let mut acct = vec![0u8; 16384];
    let mut al = acct.len();
    let rc = unsafe {
        e2e_session_outbound(
            alice.as_ptr(),
            alice.len(),
            ik_b.as_ptr(),
            otk_b.as_ptr(),
            [4u8; 32].as_ptr(),
            PK.as_ptr(),
            sess.as_mut_ptr(),
            &mut sl,
            acct.as_mut_ptr(),
            &mut al,
        )
    };
    assert_eq!(rc, RC_OK);
    sess.truncate(sl);

    let junk = [0x41u8; 120];
    let (rc, _) = one_out(|p, l| {
        let mut s2 = vec![0u8; 16384];
        let mut s2l = s2.len();
        unsafe {
            e2e_decrypt(
                sess.as_ptr(),
                sess.len(),
                1,
                junk.as_ptr(),
                junk.len(),
                PK.as_ptr(),
                p,
                l,
                s2.as_mut_ptr(),
                &mut s2l,
            )
        }
    });
    assert!(rc < 0, "decrypting junk must fail cleanly, got {rc}");
}
