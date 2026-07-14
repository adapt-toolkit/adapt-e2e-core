// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! Cross-session isolation (external security review, finding F1). Every OTHER test in the
//! crate drives a single Alice→Bob session; a Double-Ratchet library with no
//! multi-session coverage has a real gap. These tests run two concurrent sessions
//! from one Alice identity — Alice↔Bob and Alice↔Carol — and assert they are
//! cryptographically isolated:
//!
//!   * distinct session ids per conversation;
//!   * a ciphertext from session AB does NOT decrypt on session AC;
//!   * a skipped-message-key stored in one session cannot be used by the other.

use adapt_e2e_core::mgmt::{account, bundle, session};

const PK: [u8; 32] = [0x5A; 32];

fn acct(seed: u8) -> Vec<u8> {
    account::create(&[seed; 32], &PK).unwrap()
}
fn with_otks(pickle: &[u8], n: u32, seed: u8) -> Vec<u8> {
    account::gen_otks(pickle, n, &[seed; 32], &PK).unwrap()
}
fn ik(pickle: &[u8]) -> [u8; 32] {
    bundle::bundle(pickle, &PK).unwrap()[0..32]
        .try_into()
        .unwrap()
}
fn first_otk(pickle: &[u8]) -> [u8; 32] {
    let b = bundle::bundle(pickle, &PK).unwrap();
    let off = 65 + (b[64] as usize) * 36 + 4;
    b[off + 4..off + 36].try_into().unwrap()
}

/// Fully establish a bidirectional session between `alice` and `peer` using the
/// given seeds; return `(alice_session, peer_session)` both advanced past the
/// initial handshake AND one reply (so Alice's sending chain yields normal
/// messages, not further pre-key messages).
fn establish(alice: &[u8], peer: &[u8], s_out: u8, s_est: u8, s_reply: u8) -> (Vec<u8>, Vec<u8>) {
    let (a0, _) = session::outbound(alice, &ik(peer), &first_otk(peer), &[s_out; 32], &PK).unwrap();
    let est = session::encrypt(&a0, b"establish", &[s_est; 32], &PK).unwrap();
    let inb = session::inbound(peer, &ik(alice), &est.message, &PK).unwrap();
    // Peer replies; Alice decrypts so both chains are live and bidirectional.
    let reply = session::encrypt(&inb.session, b"reply", &[s_reply; 32], &PK).unwrap();
    let (_pt, a1) = session::decrypt(&est.session, reply.msg_type, &reply.message, &PK).unwrap();
    (a1, reply.session)
}

#[test]
fn two_sessions_have_distinct_ids_and_do_not_cross_decrypt() {
    let alice = acct(1);
    let bob = with_otks(&acct(2), 2, 3);
    let carol = with_otks(&acct(20), 2, 21);

    let (alice_bob, bob_sess) = establish(&alice, &bob, 4, 5, 6);
    let (alice_carol, carol_sess) = establish(&alice, &carol, 7, 8, 9);

    // 1. Distinct conversations ⇒ distinct session ids; endpoints of one agree.
    let id_ab = session::session_id(&alice_bob, &PK).unwrap();
    let id_ba = session::session_id(&bob_sess, &PK).unwrap();
    let id_ac = session::session_id(&alice_carol, &PK).unwrap();
    let id_ca = session::session_id(&carol_sess, &PK).unwrap();
    assert_eq!(id_ab, id_ba, "AB endpoints share a session id");
    assert_eq!(id_ac, id_ca, "AC endpoints share a session id");
    assert_ne!(
        id_ab, id_ac,
        "distinct conversations have distinct session ids"
    );

    // 2. A message Alice encrypts to Bob decrypts on Bob's session ONLY.
    let m = session::encrypt(&alice_bob, b"secret for bob", &[30; 32], &PK).unwrap();
    let (pt, _) = session::decrypt(&bob_sess, m.msg_type, &m.message, &PK).unwrap();
    assert_eq!(pt, b"secret for bob");
    assert!(
        session::decrypt(&carol_sess, m.msg_type, &m.message, &PK).is_err(),
        "a ciphertext from session AB must NOT decrypt on session AC"
    );
}

#[test]
fn skipped_key_store_is_session_local() {
    let alice = acct(1);
    let bob = with_otks(&acct(2), 2, 3);
    let carol = with_otks(&acct(20), 2, 21);

    let (alice_bob, bob_sess) = establish(&alice, &bob, 4, 5, 6);
    let (_alice_carol, carol_sess) = establish(&alice, &carol, 7, 8, 9);

    // Alice sends three messages to Bob on one chain.
    let m1 = session::encrypt(&alice_bob, b"one", &[10; 32], &PK).unwrap();
    let m2 = session::encrypt(&m1.session, b"two", &[11; 32], &PK).unwrap();
    let m3 = session::encrypt(&m2.session, b"three", &[12; 32], &PK).unwrap();

    // Bob receives 1 then 3 — skipping 2, so Bob stores m2's message key.
    let (p1, bob1) = session::decrypt(&bob_sess, m1.msg_type, &m1.message, &PK).unwrap();
    assert_eq!(p1, b"one");
    let (p3, bob3) = session::decrypt(&bob1, m3.msg_type, &m3.message, &PK).unwrap();
    assert_eq!(p3, b"three");

    // ★ Carol's session — with its own skip capacity — cannot decrypt AB's
    // skipped m2. The skip store does not cross session boundaries.
    assert!(
        session::decrypt(&carol_sess, m2.msg_type, &m2.message, &PK).is_err(),
        "session AB's skipped message must not decrypt on session AC"
    );

    // And Bob's OWN store still resolves the skipped m2 (positive control — the
    // negative above is a real isolation boundary, not a broken message).
    let (p2, _) = session::decrypt(&bob3, m2.msg_type, &m2.message, &PK).unwrap();
    assert_eq!(
        p2, b"two",
        "Bob's session-local skip store decrypts m2 out of order"
    );
}
