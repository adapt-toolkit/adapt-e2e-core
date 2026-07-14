// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! Boundary tests for the THREE external invariants (from an external security
//! review). The crate is deliberately a pure `f(state, seed, msg)` — it holds
//! no state — so three catastrophic-if-violated invariants live ENTIRELY in the
//! caller (the ADAPT engine), not in the crate:
//!
//!   1. **seed uniqueness** — a distinct entropy window per entropy-bearing op;
//!      violation ⇒ ephemeral/nonce reuse ⇒ key recovery.
//!   2. **OTK one-time-ness** — atomically persist the consumed-OTK account;
//!      violation ⇒ a one-time key serves two sessions ⇒ X3DH forward-secrecy loss.
//!   3. **pickle persistence + integrity** — persist the *returned* state and
//!      feed back only untampered pickles; violation ⇒ stale-state replay.
//!
//! Each test below is NON-VACUOUS: it drives the crate to the *reachable break*
//! (actually reuses the seed / the pre-consumption pickle / a stale session) and
//! asserts the break happens — proving the invariant is real, reachable, and
//! external. A positive-only "distinct inputs ⇒ distinct outputs" check would not
//! prove reachability; these carry the succeeding-reuse witness (defense-in-depth).
//!
//! These are CALLER CONTRACTS, documented in docs/CALLER-CONTRACTS.md. The crate
//! cannot enforce them without breaking determinism (`f(state,seed,msg)` purity).

use adapt_e2e_core::mgmt::{account, bundle, session};

const PK: [u8; 32] = [0x5A; 32];

fn acct(seed: u8) -> Vec<u8> {
    account::create(&[seed; 32], &PK).unwrap()
}
fn with_otks(pickle: &[u8], n: u32, seed: u8) -> Vec<u8> {
    account::gen_otks(pickle, n, &[seed; 32], &PK).unwrap()
}
/// Identity Curve25519 key = first 32 bytes of the bundle.
fn ik(pickle: &[u8]) -> [u8; 32] {
    bundle::bundle(pickle, &PK).unwrap()[0..32].try_into().unwrap()
}
/// First published one-time key from the bundle body.
fn first_otk(pickle: &[u8]) -> [u8; 32] {
    let b = bundle::bundle(pickle, &PK).unwrap();
    let off = 65 + (b[64] as usize) * 36 + 4;
    b[off + 4..off + 36].try_into().unwrap()
}

/// Establish Alice→Bob, both advanced past the initial pre-key message.
fn established() -> (Vec<u8>, Vec<u8>) {
    let alice = acct(1);
    let bob = with_otks(&acct(2), 2, 3);
    let (alice_sess, _) =
        session::outbound(&alice, &ik(&bob), &first_otk(&bob), &[4; 32], &PK).unwrap();
    let e0 = session::encrypt(&alice_sess, b"establish", &[5; 32], &PK).unwrap();
    let inb = session::inbound(&bob, &ik(&alice), &e0.message, &PK).unwrap();
    assert_eq!(inb.plaintext, b"establish");
    (e0.session, inb.session)
}

/// Drive a genuine DH-ratchet advance and return the advancing message for a
/// given seed: Bob replies, Alice decrypts (her sending ratchet goes inactive),
/// so Alice's next encrypt mints a fresh ratchet key from `adv_seed`.
fn alice_advancing_message(adv_seed: u8) -> Vec<u8> {
    let (alice_sess, bob_sess) = established();
    let reply = session::encrypt(&bob_sess, b"reply", &[7; 32], &PK).unwrap();
    let (_pt, alice_after) =
        session::decrypt(&alice_sess, reply.msg_type, &reply.message, &PK).unwrap();
    session::encrypt(&alice_after, b"advance", &[adv_seed; 32], &PK)
        .unwrap()
        .message
}

// === Invariant 1 — SEED UNIQUENESS (caller contract) =======================

#[test]
fn seed_reuse_across_distinct_dh_steps_is_a_reachable_break() {
    // Distinct seeds on two new DH steps ⇒ distinct ephemeral (healthy case).
    let fresh_a = alice_advancing_message(40);
    let fresh_b = alice_advancing_message(41);
    assert_ne!(
        fresh_a, fresh_b,
        "distinct seeds must mint distinct ephemeral ratchet keys"
    );

    // ★ WITNESS: the SAME seed on two DISTINCT DH-advancing encrypts reproduces a
    // byte-identical ephemeral. The crate has ZERO in-crate defence — it expands
    // whatever seed it is handed. So seed-reuse ⇒ ephemeral/nonce reuse IS
    // reachable; the ADAPT engine MUST supply a distinct entropy window per
    // DH-advancing op (CALLER CONTRACT #1).
    let reuse = alice_advancing_message(40);
    assert_eq!(
        fresh_a, reuse,
        "seed reuse on a new DH step reproduces the ephemeral — reachable break, no crate-side guard"
    );
}

#[test]
fn replay_same_state_and_seed_is_byte_identical_by_design() {
    // The flip side of the contract: identical (state, seed, plaintext) MUST give
    // byte-identical ciphertext — this is the required determinism a consensus
    // replay depends on (SPEC §5.3). Distinctness is the caller's job, not the
    // crate's; the crate's job is exact reproduction.
    let (alice_sess, _bob) = established();
    let a = session::encrypt(&alice_sess, b"x", &[9; 32], &PK).unwrap();
    let b = session::encrypt(&alice_sess, b"x", &[9; 32], &PK).unwrap();
    assert_eq!(a.message, b.message);
    assert_eq!(a.session, b.session);
}

// === Invariant 2 — OTK ONE-TIME-NESS / F5 (caller contract) ================

#[test]
fn otk_reuse_via_preconsumption_pickle_is_a_reachable_break() {
    // Bob publishes ONE one-time key. Two DIFFERENT senders both open a session
    // to Bob's SAME published (ik, otk) — both pre-key messages consume that OTK.
    let bob = with_otks(&acct(2), 1, 3);
    let bob_ik = ik(&bob);
    let bob_otk = first_otk(&bob);

    let alice1 = acct(1);
    let (a1_sess, _) = session::outbound(&alice1, &bob_ik, &bob_otk, &[4; 32], &PK).unwrap();
    let e1 = session::encrypt(&a1_sess, b"from alice1", &[5; 32], &PK).unwrap();

    let alice2 = acct(7);
    let (a2_sess, _) = session::outbound(&alice2, &bob_ik, &bob_otk, &[8; 32], &PK).unwrap();
    let e2 = session::encrypt(&a2_sess, b"from alice2", &[9; 32], &PK).unwrap();

    // Bob establishes the first inbound session; the RETURNED account has the OTK
    // removed (`inbound` re-emits a mutated account pickle).
    let inb1 = session::inbound(&bob, &ik(&alice1), &e1.message, &PK).unwrap();
    assert_eq!(inb1.plaintext, b"from alice1");

    // ★ WITNESS: re-submitting the PRE-consumption Bob pickle for alice2's pre-key
    // SUCCEEDS — the same one-time key serves a SECOND session. The crate is
    // stateless and cannot detect it; one-time-ness lives in the CALLER, which
    // MUST atomically persist the consumed-OTK account and never reuse the prior
    // one (CALLER CONTRACT #2). This is the X3DH-FS-weakening reuse, made reachable.
    let reuse = session::inbound(&bob, &ik(&alice2), &e2.message, &PK);
    assert!(
        reuse.is_ok(),
        "OTK reuse via a stale pre-consumption pickle is REACHABLE (undefended in-crate)"
    );

    // The CORRECT caller persists the returned account; feeding THAT to the second
    // inbound refuses the already-consumed OTK — the invariant holds exactly when
    // the caller keeps its half of the contract.
    let correct = session::inbound(&inb1.account, &ik(&alice2), &e2.message, &PK);
    assert!(
        correct.is_err(),
        "with the persisted post-consumption account the consumed OTK is gone — second inbound refused"
    );
}

// === Invariant 3 — PICKLE PERSISTENCE + INTEGRITY (caller contract) =========

#[test]
fn tampered_pickle_body_is_rejected_by_the_pickle_mac() {
    // The inner vodozemac pickle is AES-CBC + truncated HMAC under pickle_key.
    // Flipping any body byte must fail the MAC on load — no silent corruption.
    let a = acct(1);
    assert!(bundle::bundle(&a, &PK).is_ok(), "untampered account loads (non-vacuous baseline)");
    let mut bad = a.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    // Load the account AS an account (bundle reads it) so the pickle MAC — not the
    // envelope kind-check — is what rejects the flipped body.
    assert!(
        bundle::bundle(&bad, &PK).is_err(),
        "tampered account pickle body must fail the pickle MAC"
    );

    // A session pickle tampered in the body likewise fails.
    let (sess, _) = established();
    let mut bad_sess = sess.clone();
    let mid = bad_sess.len() - 2;
    bad_sess[mid] ^= 0x01;
    assert!(
        session::decrypt(&bad_sess, 1, b"whatever", &PK).is_err(),
        "tampered session pickle must not load"
    );
}

#[test]
fn flipped_envelope_kind_does_not_type_confuse() {
    // The outer envelope's `kind` byte (offset 7: 1=acct, 2=sess) is plaintext,
    // NOT AEAD-authenticated. But flipping it cannot cause acct↔sess type
    // confusion: either the envelope kind-check rejects it, or the inner pickle
    // deserialization (wrong serde shape) fails — never a usable wrong-type object.
    let a = acct(1);
    let mut a_as_sess = a.clone();
    a_as_sess[7] = 2; // claim Session
    assert!(
        session::session_id(&a_as_sess, &PK).is_err(),
        "an account blob relabelled Session must be rejected, not loaded as a session"
    );

    let (sess, _) = established();
    let mut sess_as_acct = sess.clone();
    sess_as_acct[7] = 1; // claim Account
    assert!(
        bundle::bundle(&sess_as_acct, &PK).is_err(),
        "a session blob relabelled Account must be rejected, not loaded as an account"
    );
}

#[test]
fn flipped_envelope_version_is_rejected() {
    // Envelope format/engine version bytes gate deserialization; a bumped version
    // is refused (no attempt to parse an unknown pickle shape).
    let a = acct(1);
    let mut bad_fmt = a.clone();
    bad_fmt[4] = bad_fmt[4].wrapping_add(1); // fmt_ver
    assert!(session::session_id(&bad_fmt, &PK).is_err() && bundle::bundle(&bad_fmt, &PK).is_err());

    let mut bad_engine = a.clone();
    bad_engine[5] = bad_engine[5].wrapping_add(1); // engine_ver low byte
    assert!(bundle::bundle(&bad_engine, &PK).is_err());
}

#[test]
fn stale_session_reuse_is_a_reachable_break() {
    // Encrypting advances the session S → S'. Re-using the STALE pre-encrypt S
    // with the same seed reproduces byte-identical ciphertext — i.e. the same
    // chain material is consumed twice. The caller MUST persist S' and discard S
    // (CALLER CONTRACT #3); the crate, being stateless, cannot force it.
    let (alice_sess, _bob) = established();
    let e1 = session::encrypt(&alice_sess, b"m1", &[9; 32], &PK).unwrap();
    let e1_stale = session::encrypt(&alice_sess, b"m1", &[9; 32], &PK).unwrap();
    assert_eq!(
        e1.message, e1_stale.message,
        "reusing the stale pre-encrypt session reproduces ciphertext — stale-state replay is reachable"
    );
    // (When the caller persists correctly, it would encrypt from e1.session next,
    //  advancing the chain — no reuse.)
}
