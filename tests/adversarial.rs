// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! The adversarial suite (SPEC §7) — the tests that matter, driven through the
//! management layer:
//!
//! * determinism-under-replay golden (byte-pinned);
//! * retry-vs-replay entropy guard (replay-safe; two genuinely-new DH steps
//!   diverge under fresh seeds and *provably* collapse under a reused seed);
//! * skipped-message-key out-of-order decryption within the window;
//! * the **negative forward-secrecy** keystone: a ratchet-evicted key MUST fail
//!   to decrypt a superseded message, even from a compromised current state.

use adapt_e2e_core::mgmt::{account, bundle, session};

const PK: [u8; 32] = [0x5A; 32];

fn acct(seed: u8) -> Vec<u8> {
    account::create(&[seed; 32], &PK).unwrap()
}
fn with_otks(pickle: &[u8], n: u32, seed: u8) -> Vec<u8> {
    account::gen_otks(pickle, n, &[seed; 32], &PK).unwrap()
}

/// Identity key = first 32 bytes of the bundle.
fn ik(pickle: &[u8]) -> [u8; 32] {
    let b = bundle::bundle(pickle, &PK).unwrap();
    b[0..32].try_into().unwrap()
}
/// First published one-time key from the bundle body.
fn first_otk(pickle: &[u8]) -> [u8; 32] {
    let b = bundle::bundle(pickle, &PK).unwrap();
    let fb_count = b[64] as usize;
    let off = 65 + fb_count * 36 + 4; // skip ik_ed, fallback block, otk_count
    b[off + 4..off + 36].try_into().unwrap()
}

/// Establish Alice→Bob and return `(alice_session, bob_session)` both advanced
/// past the initial pre-key message. Fully deterministic.
fn established() -> (Vec<u8>, Vec<u8>) {
    let alice = acct(1);
    let bob = with_otks(&acct(2), 2, 3);
    let (alice_sess, _) = session::outbound(&alice, &ik(&bob), &first_otk(&bob), &[4; 32], &PK).unwrap();
    let e0 = session::encrypt(&alice_sess, b"establish", &[5; 32], &PK).unwrap();
    let inb = session::inbound(&bob, &ik(&alice), &e0.message, &PK).unwrap();
    assert_eq!(inb.plaintext, b"establish");
    (e0.session, inb.session)
}

// --- SPEC §7.3 determinism-under-replay golden -----------------------------

#[test]
fn determinism_golden_is_stable() {
    // A fixed (seed, pickle_key) must always yield this exact account pickle and
    // this exact first-message ciphertext. Pins RNG plumbing byte-for-byte so a
    // silent regression is caught even across builds.
    let a = acct(1);
    let b = acct(1);
    assert_eq!(a, b);

    let bob = with_otks(&acct(2), 1, 3);
    let (s, _) = session::outbound(&a, &ik(&bob), &first_otk(&bob), &[4; 32], &PK).unwrap();
    let e = session::encrypt(&s, b"golden", &[5; 32], &PK).unwrap();

    // The message body is deterministic; pin its hex. (Regenerated intentionally
    // whenever the vendored engine's pickle/format changes — see PATCH.md.)
    let hex: String = e.message.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, GOLDEN_FIRST_MESSAGE_HEX, "determinism golden drifted");
}

const GOLDEN_FIRST_MESSAGE_HEX: &str = "030a20403e5376b7e466f103572da5ac47cab01c7226109925ffb2b20e12c3f3476a561220325420fcc13cc3a0f84d673c85f59c6c2764afa49e256068c04025fb1855ef171a20091e876575795f5fced43ff7ce5ae652db21e3453c6b1ec5d3bd23b1ec410655223f030a205dfe8900bee4c0ff707a530cc7bbce1dbe2d649d9228b4852e746550b9189e7410002210175ac90997409da4ccfaee3a1649f35be5d5c36907081bc4";

// --- SPEC §7.4 retry-vs-replay entropy guard -------------------------------

#[test]
fn replay_same_seed_same_session_is_byte_identical() {
    let (alice_sess, _bob) = established();
    let a = session::encrypt(&alice_sess, b"x", &[9; 32], &PK).unwrap();
    let b = session::encrypt(&alice_sess, b"x", &[9; 32], &PK).unwrap();
    assert_eq!(a.message, b.message, "replay: identical (state,seed,pt) => identical ciphertext");
    assert_eq!(a.session, b.session);
}

/// Drive a genuine DH-ratchet advance: Bob replies, Alice decrypts (her sending
/// ratchet goes inactive), so Alice's next encrypt mints a fresh ratchet key
/// from the supplied seed. Returns the advancing message for a given seed.
fn alice_advancing_message(adv_seed: u8) -> Vec<u8> {
    let (alice_sess, bob_sess) = established();
    let reply = session::encrypt(&bob_sess, b"reply", &[7; 32], &PK).unwrap();
    let (_pt, alice_after) = session::decrypt(&alice_sess, reply.msg_type, &reply.message, &PK).unwrap();
    // This encrypt advances the DH ratchet and consumes adv_seed.
    session::encrypt(&alice_after, b"advance", &[adv_seed; 32], &PK).unwrap().message
}

#[test]
fn retry_two_new_dh_steps_diverge_under_fresh_seeds() {
    let m_fresh_a = alice_advancing_message(40);
    let m_fresh_b = alice_advancing_message(41);
    assert_ne!(m_fresh_a, m_fresh_b, "distinct seeds => distinct ephemeral ratchet key");

    // Reusing the SAME seed across two distinct advancing steps collapses to the
    // identical ephemeral — the failure mode is REACHABLE, proving the host's
    // fresh-seed-per-new-DH-step obligation is necessary (SPEC §5.3).
    let m_reuse_a = alice_advancing_message(40);
    assert_eq!(m_fresh_a, m_reuse_a, "same seed on a new DH step => reused ephemeral (detectable)");
}

// --- SPEC §7 skipped-message-key store -------------------------------------

#[test]
fn skipped_keys_decrypt_out_of_order_within_window() {
    let (alice_sess, bob_sess) = established();

    // Alice sends three normal messages in one chain.
    let e1 = session::encrypt(&alice_sess, b"one", &[10; 32], &PK).unwrap();
    let e2 = session::encrypt(&e1.session, b"two", &[11; 32], &PK).unwrap();
    let e3 = session::encrypt(&e2.session, b"three", &[12; 32], &PK).unwrap();

    // Bob receives 1, then 3 (skipping 2 -> its key is stored), then 2.
    let (p1, bob1) = session::decrypt(&bob_sess, e1.msg_type, &e1.message, &PK).unwrap();
    assert_eq!(p1, b"one");
    let (p3, bob3) = session::decrypt(&bob1, e3.msg_type, &e3.message, &PK).unwrap();
    assert_eq!(p3, b"three");
    let (p2, _bob2) = session::decrypt(&bob3, e2.msg_type, &e2.message, &PK).unwrap();
    assert_eq!(p2, b"two", "the skipped key decrypts out of order");
}

// --- SPEC §7.8 NEGATIVE forward secrecy (the keystone) ---------------------

#[test]
fn negative_forward_secrecy_evicted_key_cannot_decrypt() {
    let (alice_sess, bob_sess) = established();

    // Alice sends two normal messages in order.
    let e_a = session::encrypt(&alice_sess, b"superseded", &[20; 32], &PK).unwrap();
    let e_b = session::encrypt(&e_a.session, b"latest", &[21; 32], &PK).unwrap();

    // Bob decrypts both IN ORDER. Decrypting e_a consumes and *discards* its
    // message key (in-order, so it never enters the skip store); decrypting e_b
    // advances the chain further.
    let (pa, bob_a) = session::decrypt(&bob_sess, e_a.msg_type, &e_a.message, &PK).unwrap();
    assert_eq!(pa, b"superseded");
    let (pb, bob_b) = session::decrypt(&bob_a, e_b.msg_type, &e_b.message, &PK).unwrap();
    assert_eq!(pb, b"latest");

    // Simulate a COMPROMISE of Bob's current (advanced) state `bob_b` and attempt
    // to recover the superseded message. The evicted key is gone from the current
    // pickle: decryption MUST fail. This is the crate's forward-secrecy guarantee
    // for what it controls (the host must also destroy the old pickle bytes).
    let recovered = session::decrypt(&bob_b, e_a.msg_type, &e_a.message, &PK);
    assert!(
        recovered.is_err(),
        "forward secrecy breach: compromised current state decrypted a superseded message"
    );
}
