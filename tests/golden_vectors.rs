// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.

//! Committed golden vectors pinning the deterministic output
//! of EVERY keygen seam byte-for-byte, from fixed `(seed, pickle_key)` inputs.
//! Where the M1 ciphertext goldens (`tests/adversarial.rs`) pin the encrypt
//! path, these pin the account-side seams (identity, one-time key, fallback) and
//! the derived session id — so an RNG-plumbing regression in ANY seam is caught
//! across builds, not just the encrypt seam.

use adapt_e2e_core::mgmt::{account, bundle, session};

const PK: [u8; 32] = [0x5A; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Identity Curve25519 key = first 32 bytes of the bundle.
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
fn golden_identity_curve25519_key() {
    let acct = account::create(&[1u8; 32], &PK).unwrap();
    assert_eq!(hex(&ik(&acct)), GOLDEN_IK_CURVE);
}

#[test]
fn golden_identity_ed25519_key() {
    let acct = account::create(&[1u8; 32], &PK).unwrap();
    let ed: [u8; 32] = bundle::bundle(&acct, &PK).unwrap()[32..64]
        .try_into()
        .unwrap();
    assert_eq!(hex(&ed), GOLDEN_IK_ED);
}

#[test]
fn golden_one_time_key() {
    let acct = account::gen_otks(
        &account::create(&[2u8; 32], &PK).unwrap(),
        1,
        &[3u8; 32],
        &PK,
    )
    .unwrap();
    assert_eq!(hex(&first_otk(&acct)), GOLDEN_OTK);
}

#[test]
fn golden_fallback_key() {
    let acct =
        account::gen_fallback(&account::create(&[4u8; 32], &PK).unwrap(), &[5u8; 32], &PK).unwrap();
    // fallback block sits right after ik_curve(32)+ik_ed(32)+fb_count(1); read its key.
    let b = bundle::bundle(&acct, &PK).unwrap();
    assert_eq!(b[64], 1, "one fallback key");
    let fb_key: [u8; 32] = b[65 + 4..65 + 36].try_into().unwrap();
    assert_eq!(hex(&fb_key), GOLDEN_FALLBACK);
}

#[test]
fn golden_session_id() {
    // The session id transitively pins account identity, the outbound ephemeral
    // base key, and the peer OTK — a broad determinism anchor.
    let alice = account::create(&[1u8; 32], &PK).unwrap();
    let bob = account::gen_otks(
        &account::create(&[2u8; 32], &PK).unwrap(),
        1,
        &[3u8; 32],
        &PK,
    )
    .unwrap();
    let (sess, _) =
        session::outbound(&alice, &ik(&bob), &first_otk(&bob), &[4u8; 32], &PK).unwrap();
    assert_eq!(
        hex(&session::session_id(&sess, &PK).unwrap()),
        GOLDEN_SESSION_ID
    );
}

// --- committed golden values (regenerate only on an intentional engine change,
//     documented in PATCH.md) ---
const GOLDEN_IK_CURVE: &str = "091e876575795f5fced43ff7ce5ae652db21e3453c6b1ec5d3bd23b1ec410655";
const GOLDEN_IK_ED: &str = "4d4b18062f8502598de045ca7b69f067f59f93b16e3af8733a988adc2341f5c8";
const GOLDEN_OTK: &str = "403e5376b7e466f103572da5ac47cab01c7226109925ffb2b20e12c3f3476a56";
const GOLDEN_FALLBACK: &str = "e2f7ef50c811d6e64b901eed154ec2436e5a2a1eb9a2f82a40ccd1ea11ea1144";
const GOLDEN_SESSION_ID: &str = "2f852eb8ab5475f1da0549e3324fc167a6808bf69b6544b1cbe0273257147f89";
