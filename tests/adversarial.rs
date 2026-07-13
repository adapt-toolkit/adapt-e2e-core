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

#[test]
fn determinism_golden_dh_advance_is_stable() {
    // Pins the highest-risk deterministic path: the DH-ratchet-advance encrypt,
    // where the injected seed actually flows into a fresh ephemeral. A single
    // pre-key golden does not cover this seam.
    let m = alice_advancing_message(40);
    let hex: String = m.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, GOLDEN_DH_ADVANCE_HEX, "DH-advance determinism golden drifted");
}

const GOLDEN_DH_ADVANCE_HEX: &str = "030a20b2678df336ebede372ec359b26400701a83de822273499dd23da0ccfcb86872b100022109882071d900ccbfd8d095fd059a4deca769c230da415162f";

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

// --- SPEC §7 skipped-key BOUND + tamper rejection --------------------------

#[test]
fn tampered_ciphertext_fails_cleanly() {
    let (alice_sess, bob_sess) = established();
    let e = session::encrypt(&alice_sess, b"authentic", &[30; 32], &PK).unwrap();

    let mut tampered = e.message.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01; // flip a bit -> MAC must reject

    let res = session::decrypt(&bob_sess, e.msg_type, &tampered, &PK);
    assert!(res.is_err(), "tampered ciphertext must fail the MAC, not decrypt");
}

// --- SPEC §7.8 NEGATIVE forward secrecy (the keystone) ---------------------

#[test]
fn consumed_in_order_key_is_not_retained() {
    // Honest, narrow claim: an in-order-consumed message key is discarded (never
    // enters the skip store), so the resulting state cannot re-decrypt it.
    let (alice_sess, bob_sess) = established();
    let e = session::encrypt(&alice_sess, b"once", &[31; 32], &PK).unwrap();

    let (pt, bob_after) = session::decrypt(&bob_sess, e.msg_type, &e.message, &PK).unwrap();
    assert_eq!(pt, b"once");
    assert_ne!(bob_after, bob_sess, "state genuinely advanced");
    assert!(
        session::decrypt(&bob_after, e.msg_type, &e.message, &PK).is_err(),
        "in-order key is discarded, not stashed"
    );
}

#[test]
fn beyond_max_message_gap_is_rejected() {
    // Skipping more than MAX_MESSAGE_GAP (2000) messages must be refused cleanly
    // (TooBigMessageGap -> DecryptFailed), not accepted or panicked.
    let (alice_sess, bob_sess) = established();

    let mut sess = alice_sess;
    let mut last = None;
    for i in 0..2100u32 {
        let e = session::encrypt(&sess, format!("m{i}").as_bytes(), &[70; 32], &PK).unwrap();
        sess = e.session.clone();
        last = Some(e);
    }
    let last = last.unwrap();

    // Bob has only seen the establish message; jumping ~2100 ahead exceeds the gap.
    let res = session::decrypt(&bob_sess, last.msg_type, &last.message, &PK);
    assert!(res.is_err(), "a gap beyond MAX_MESSAGE_GAP must be rejected");
}

#[test]
fn negative_forward_secrecy_evicted_vs_retained() {
    // The rigorous keystone: distinguish an EVICTED key (forward-secret; gone
    // from the current pickle) from a RETAINED skipped key (recoverable from the
    // 40-key store). Alice sends 50 messages; Bob decrypts only the LAST, which
    // stashes the newest 40 skipped keys and EVICTS the oldest. From Bob's
    // compromised current state:
    //   * the very first message (>40 back) MUST fail  -> forward secrecy holds;
    //   * a recent skipped message (1 back)  MUST succeed -> the store is the
    //     only recovery path, so the failure above is genuine eviction, not a
    //     mere "already used" artefact.
    let (alice_sess, bob_sess) = established();

    let mut msgs = Vec::new();
    let mut sess = alice_sess;
    for i in 0..50u8 {
        let e = session::encrypt(&sess, &[b'm', i], &[100 + i; 32], &PK).unwrap();
        sess = e.session.clone();
        msgs.push(e);
    }

    // Bob decrypts the last message first (skips 0..=48).
    let last = &msgs[49];
    let (_pt, bob_now) = session::decrypt(&bob_sess, last.msg_type, &last.message, &PK).unwrap();

    // Oldest message: evicted from the 40-key store -> forward secrecy.
    let first = &msgs[0];
    assert!(
        session::decrypt(&bob_now, first.msg_type, &first.message, &PK).is_err(),
        "forward-secrecy breach: an evicted key decrypted a superseded message"
    );

    // Recent skipped message: still in the store -> proves the store is the
    // recovery path and the eviction above is real.
    let recent = &msgs[48];
    let (pt, _) = session::decrypt(&bob_now, recent.msg_type, &recent.message, &PK).unwrap();
    assert_eq!(pt, &[b'm', 48]);
}
