// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! Cross-implementation interop (SPEC §7.2) — the independent oracle. Our
//! seed-injected fork must be wire-compatible with the REAL upstream vodozemac
//! from crates.io (`vodozemac_upstream`). Because every other test in the crate
//! checks the fork against *itself*, this is the only defence against a
//! behaviour-changing regression in the `*_with_rng` patch: a subtle key-
//! derivation bug would keep the self-referential tests green while producing
//! ciphertext no real Olm client can read.
//!
//! The two crates never share Rust types (they are distinct crate instances);
//! they exchange only wire bytes (public keys and message bodies).

use adapt_e2e_core::mgmt::{account, bundle, session};
use vodozemac_upstream::Curve25519PublicKey as UpCurve;
use vodozemac_upstream::olm::{
    Account as UpAccount, PreKeyMessage as UpPreKey, SessionConfig as UpConfig,
};

const PK: [u8; 32] = [0x5A; 32];

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

#[test]
fn our_fork_outbound_is_read_by_upstream() {
    // Upstream (OsRng) Bob publishes an identity + one-time key.
    let mut bob = UpAccount::new();
    let bob_otk = *bob.generate_one_time_keys(1).created.first().expect("otk");
    let bob_ik = bob.curve25519_key();

    // Our seed-injected Alice opens an outbound session to upstream Bob.
    let alice = account::create(&[1u8; 32], &PK).unwrap();
    let (alice_sess, _) = session::outbound(
        &alice,
        bob_ik.as_bytes(),
        bob_otk.as_bytes(),
        &[4u8; 32],
        &PK,
    )
    .unwrap();
    let alice_ik = ik(&alice);
    let e = session::encrypt(&alice_sess, b"hello upstream", &[5u8; 32], &PK).unwrap();
    assert_eq!(e.msg_type, 0, "first message is a pre-key message");

    // Upstream Bob decrypts our fork's pre-key message.
    let prekey = UpPreKey::from_bytes(&e.message).expect("parse prekey");
    let result = bob
        .create_inbound_session(
            UpConfig::version_1(),
            UpCurve::from_bytes(alice_ik),
            &prekey,
        )
        .expect("upstream inbound");
    assert_eq!(
        result.plaintext, b"hello upstream",
        "upstream must read our fork's ciphertext"
    );

    // And the reply direction: upstream Bob replies, our fork Alice decrypts.
    let mut bob_sess = result.session;
    let reply = bob_sess
        .encrypt("hi from upstream")
        .expect("upstream encrypt");
    let (rtype, rbody) = reply.to_parts();
    let (pt, _) = session::decrypt(&alice_sess, rtype as u32, &rbody, &PK).unwrap();
    assert_eq!(
        pt, b"hi from upstream",
        "our fork must read upstream's ciphertext"
    );
}

#[test]
fn upstream_outbound_is_read_by_our_fork() {
    // Our seed-injected Bob publishes keys.
    let bob = account::gen_otks(
        &account::create(&[2u8; 32], &PK).unwrap(),
        1,
        &[3u8; 32],
        &PK,
    )
    .unwrap();
    let bob_ik = ik(&bob);
    let bob_otk = first_otk(&bob);

    // Upstream (OsRng) Alice opens an outbound session to our Bob.
    let alice = UpAccount::new();
    let alice_ik = alice.curve25519_key();
    let mut alice_sess = alice
        .create_outbound_session(
            UpConfig::version_1(),
            UpCurve::from_bytes(bob_ik),
            UpCurve::from_bytes(bob_otk),
        )
        .expect("upstream outbound");
    let msg = alice_sess.encrypt("hello fork").expect("upstream encrypt");
    let (_mtype, body) = msg.to_parts();

    // Our fork Bob establishes the inbound session and recovers the plaintext.
    let inb = session::inbound(&bob, alice_ik.as_bytes(), &body, &PK).unwrap();
    assert_eq!(
        inb.plaintext, b"hello fork",
        "our fork must read upstream's pre-key message"
    );

    // Reply: our fork Bob replies, upstream Alice decrypts.
    let reply = session::encrypt(&inb.session, b"reply from fork", &[7u8; 32], &PK).unwrap();
    let up_msg =
        vodozemac_upstream::olm::OlmMessage::from_parts(reply.msg_type as usize, &reply.message)
            .expect("parse our message upstream");
    let pt = alice_sess.decrypt(&up_msg).expect("upstream decrypt");
    assert_eq!(pt, b"reply from fork");
}
