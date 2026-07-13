// Copyright 2026 adapt-toolkit
//
// Licensed under the Apache License, Version 2.0.

//! M0 smoke test: prove the crate can drive the vendored vodozemac
//! entropy-injection seam deterministically through [`SeededRng`]. This is the
//! foundation the full determinism/KAT/interop suite (SPEC §7) builds on.

use adapt_e2e_core::seeded_rng::SeededRng;
use vodozemac::olm::{Account, OlmMessage, SessionConfig};

#[test]
fn account_creation_is_deterministic_via_seeded_rng() {
    let a = Account::new_with_rng(SeededRng::from_seed([42u8; 32]).rng());
    let b = Account::new_with_rng(SeededRng::from_seed([42u8; 32]).rng());

    assert_eq!(a.curve25519_key(), b.curve25519_key());
    assert_eq!(a.ed25519_key(), b.ed25519_key());

    let c = Account::new_with_rng(SeededRng::from_seed([43u8; 32]).rng());
    assert_ne!(a.curve25519_key(), c.curve25519_key());
}

#[test]
fn full_outbound_flow_is_byte_identical_under_the_same_seeds() {
    // Run the whole "create Bob, mint an OTK, open an outbound session, encrypt"
    // flow twice with identical seeds and assert byte-identical ciphertext —
    // the crate-level statement of SPEC §5.2 determinism, driven end to end
    // through the vendored fork's `*_with_rng` seam.
    let run = || -> (String, (usize, Vec<u8>)) {
        let mut bob = Account::new_with_rng(SeededRng::from_seed([1u8; 32]).rng());
        let bob_otk = *bob
            .generate_one_time_keys_with_rng(1, SeededRng::from_seed([2u8; 32]).rng())
            .created
            .first()
            .expect("one OTK");

        let alice = Account::new_with_rng(SeededRng::from_seed([3u8; 32]).rng());
        let mut session = alice
            .create_outbound_session_with_rng(
                SessionConfig::version_1(),
                bob.curve25519_key(),
                bob_otk,
                SeededRng::from_seed([4u8; 32]).rng(),
            )
            .expect("outbound session");

        let msg = session
            .encrypt_with_rng("deterministic", SeededRng::from_seed([5u8; 32]).rng())
            .expect("encrypt");
        (session.session_id(), msg.to_parts())
    };

    let (id1, ct1) = run();
    let (id2, ct2) = run();

    assert_eq!(id1, id2, "session id must be reproducible");
    assert_eq!(ct1, ct2, "ciphertext must be byte-identical for identical seeds");
}

#[test]
fn seeded_session_interoperates_with_a_default_peer() {
    // A seed-driven Alice must be decryptable by an OsRng-built Bob: the seam is
    // behaviour-preserving, not a separate protocol.
    let mut bob = Account::new();
    let bob_otk = *bob.generate_one_time_keys(1).created.first().expect("one OTK");

    let alice = Account::new_with_rng(SeededRng::from_seed([9u8; 32]).rng());
    let mut alice_session = alice
        .create_outbound_session_with_rng(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            bob_otk,
            SeededRng::from_seed([10u8; 32]).rng(),
        )
        .expect("outbound session");

    let msg = alice_session
        .encrypt_with_rng("hello", SeededRng::from_seed([11u8; 32]).rng())
        .expect("encrypt");
    let OlmMessage::PreKey(prekey) = msg else { panic!("expected pre-key message") };

    let result = bob
        .create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &prekey)
        .expect("inbound session");
    assert_eq!(result.plaintext, b"hello");
}
