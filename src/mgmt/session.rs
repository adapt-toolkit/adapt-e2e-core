//! Session-side management primitives (SPEC fns 5–9): establish outbound /
//! inbound sessions, encrypt, decrypt, read the session id. Each takes the
//! caller's `pickle_key` (and a `seed` on the keygen-bearing calls) and returns
//! new envelope-wrapped pickles. The crate keeps no state.
//!
//! **Deviation from the abbreviated SPEC §2 signature:** [`inbound`] also returns
//! the plaintext of the pre-key message. vodozemac's `create_inbound_session`
//! consumes and decrypts that first message while establishing the session, so
//! the plaintext would otherwise be irrecoverably lost. Flagged for review.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{
    MessageType, OlmMessage, PreKeyMessage, Session, SessionConfig, SessionPickle,
};

use crate::mgmt::account;
use crate::mgmt::error::{Error, Result};
use crate::mgmt::pickle::{self, Kind};
use crate::seeded_rng::SeededRng;

fn load_session(blob: &[u8], pickle_key: &[u8; 32]) -> Result<Session> {
    let inner = pickle::unwrap(blob, Kind::Session)?;
    let pickled = SessionPickle::from_encrypted(inner, pickle_key).map_err(|_| Error::BadPickle)?;
    Ok(Session::from_pickle(pickled))
}

fn store_session(session: &Session, pickle_key: &[u8; 32]) -> Vec<u8> {
    pickle::wrap(Kind::Session, &session.pickle().encrypt(pickle_key))
}

/// The outputs of establishing an inbound session (SPEC fn 6).
pub struct InboundResult {
    /// The new session pickle.
    pub session: Vec<u8>,
    /// The account pickle (mutated: the used one-time key is removed).
    pub account: Vec<u8>,
    /// The decrypted plaintext of the pre-key message.
    pub plaintext: Vec<u8>,
}

/// The outputs of an encrypt call (SPEC fn 7).
pub struct EncryptResult {
    /// 0 = pre-key message, 1 = normal message (matches [`MessageType`]).
    pub msg_type: u32,
    /// The serialized Olm message body.
    pub message: Vec<u8>,
    /// The advanced session pickle.
    pub session: Vec<u8>,
}

/// SPEC fn 5 — create an outbound session to a peer's identity + one-time key.
/// Returns `(session_pickle, account_pickle)`. The account is unchanged (an
/// outbound session mints its own ephemeral) but re-emitted for API uniformity.
pub fn outbound(
    acct_pickle: &[u8],
    ik_b: &[u8; 32],
    otk_b: &[u8; 32],
    seed: &[u8; 32],
    pickle_key: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let account = account::load(acct_pickle, pickle_key)?;
    let ik = Curve25519PublicKey::from_bytes(*ik_b);
    let otk = Curve25519PublicKey::from_bytes(*otk_b);

    let session = account
        .create_outbound_session_with_rng(
            SessionConfig::version_1(),
            ik,
            otk,
            SeededRng::from_seed(*seed).rng(),
        )
        .map_err(|_| Error::SessionMismatch)?;

    Ok((store_session(&session, pickle_key), account::store(&account, pickle_key)))
}

/// SPEC fn 6 — establish an inbound session from a peer's pre-key message,
/// consuming the matching one-time key. Returns the session, the mutated
/// account, and the decrypted first-message plaintext (see module note).
pub fn inbound(
    acct_pickle: &[u8],
    ik_a: &[u8; 32],
    prekey_msg: &[u8],
    pickle_key: &[u8; 32],
) -> Result<InboundResult> {
    let mut account = account::load(acct_pickle, pickle_key)?;
    let ik = Curve25519PublicKey::from_bytes(*ik_a);
    let prekey = PreKeyMessage::from_bytes(prekey_msg).map_err(|_| Error::BadPickle)?;

    let created = account
        .create_inbound_session(SessionConfig::version_1(), ik, &prekey)
        .map_err(|_| Error::SessionMismatch)?;

    Ok(InboundResult {
        session: store_session(&created.session, pickle_key),
        account: account::store(&account, pickle_key),
        plaintext: created.plaintext,
    })
}

/// SPEC fn 7 — encrypt `plaintext`, drawing `seed` only if the message triggers
/// a Diffie-Hellman ratchet advance. Returns the message + advanced session.
pub fn encrypt(
    sess_pickle: &[u8],
    plaintext: &[u8],
    seed: &[u8; 32],
    pickle_key: &[u8; 32],
) -> Result<EncryptResult> {
    let mut session = load_session(sess_pickle, pickle_key)?;
    let message = session
        .encrypt_with_rng(plaintext, SeededRng::from_seed(*seed).rng())
        .map_err(|_| Error::SessionMismatch)?;
    let (msg_type, body) = message.to_parts();

    Ok(EncryptResult {
        msg_type: msg_type as u32,
        message: body,
        session: store_session(&session, pickle_key),
    })
}

/// SPEC fn 8 — decrypt a message into plaintext + the advanced session. Draws no
/// entropy. `msg_type` is 0 (pre-key) or 1 (normal), per [`MessageType`].
pub fn decrypt(
    sess_pickle: &[u8],
    msg_type: u32,
    message: &[u8],
    pickle_key: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Reject an out-of-range message type before touching the ciphertext.
    let _ = MessageType::try_from(msg_type as usize).map_err(|_| Error::DecryptFailed)?;
    let mut session = load_session(sess_pickle, pickle_key)?;
    let olm = OlmMessage::from_parts(msg_type as usize, message).map_err(|_| Error::DecryptFailed)?;
    let plaintext = session.decrypt(&olm).map_err(|_| Error::DecryptFailed)?;

    Ok((plaintext, store_session(&session, pickle_key)))
}

/// SPEC fn 9a — the session's globally-unique 32-byte id.
pub fn session_id(sess_pickle: &[u8], pickle_key: &[u8; 32]) -> Result<[u8; 32]> {
    let session = load_session(sess_pickle, pickle_key)?;
    let id_b64 = session.session_id();
    let raw = vodozemac::base64_decode(id_b64).map_err(|_| Error::Internal)?;
    raw.as_slice().try_into().map_err(|_| Error::Internal)
}

/// SPEC fn 9b — does `sess_pickle` correspond to the session that `prekey_msg`
/// would establish? Used for idempotent PRE_KEY re-delivery detection: a
/// re-delivered pre-key message shares the session id of the session it created,
/// so the consumer can skip creating a duplicate inbound session.
pub fn matches_inbound(
    sess_pickle: &[u8],
    prekey_msg: &[u8],
    pickle_key: &[u8; 32],
) -> Result<bool> {
    let session = load_session(sess_pickle, pickle_key)?;
    let prekey = PreKeyMessage::from_bytes(prekey_msg).map_err(|_| Error::BadPickle)?;
    Ok(session.session_id() == prekey.session_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::account;

    const PK: [u8; 32] = [0x5A; 32];

    /// Build a deterministic (alice_account, bob_account, bob_otk_bytes) triple.
    fn parties() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let alice = account::create(&[1u8; 32], &PK).unwrap();
        let bob = account::create(&[2u8; 32], &PK).unwrap();
        let bob = account::gen_otks(&bob, 1, &[3u8; 32], &PK).unwrap();
        let bob_acct = account::load(&bob, &PK).unwrap();
        let otk = *bob_acct.one_time_keys().values().next().expect("one otk").as_bytes();
        (alice, bob, otk)
    }

    fn ik_of(acct_pickle: &[u8]) -> [u8; 32] {
        *account::load(acct_pickle, &PK).unwrap().curve25519_key().as_bytes()
    }

    #[test]
    fn outbound_is_deterministic() {
        let (alice, bob, otk) = parties();
        let ik_b = ik_of(&bob);
        let (s1, _) = outbound(&alice, &ik_b, &otk, &[4u8; 32], &PK).unwrap();
        let (s2, _) = outbound(&alice, &ik_b, &otk, &[4u8; 32], &PK).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn full_handshake_roundtrips_and_is_deterministic() {
        let (alice, bob, otk) = parties();
        let ik_b = ik_of(&bob);
        let ik_a = ik_of(&alice);

        let run = || {
            let (alice_sess, _alice_acct) =
                outbound(&alice, &ik_b, &otk, &[4u8; 32], &PK).unwrap();
            let enc = encrypt(&alice_sess, b"hello bob", &[5u8; 32], &PK).unwrap();

            let inb = inbound(&bob, &ik_a, &enc.message, &PK).unwrap();
            assert_eq!(inb.plaintext, b"hello bob");
            (enc.message.clone(), enc.msg_type, inb.plaintext.clone())
        };

        let (m1, t1, _) = run();
        let (m2, t2, _) = run();
        assert_eq!(t1, MessageType::PreKey as u32);
        assert_eq!((m1, t1), (m2, t2), "byte-identical prekey message for identical seeds");
    }

    #[test]
    fn reply_direction_and_session_id_agree() {
        let (alice, bob, otk) = parties();
        let ik_b = ik_of(&bob);
        let ik_a = ik_of(&alice);

        let (alice_sess, _) = outbound(&alice, &ik_b, &otk, &[4u8; 32], &PK).unwrap();
        let enc = encrypt(&alice_sess, b"hi", &[5u8; 32], &PK).unwrap();
        let inb = inbound(&bob, &ik_a, &enc.message, &PK).unwrap();

        // Bob replies; Alice decrypts.
        let reply = encrypt(&inb.session, b"hey back", &[6u8; 32], &PK).unwrap();
        let (pt, _alice_sess2) =
            decrypt(&alice_sess, reply.msg_type, &reply.message, &PK).unwrap();
        assert_eq!(pt, b"hey back");

        // Both ends agree on the session id.
        assert_eq!(session_id(&alice_sess, &PK).unwrap(), session_id(&inb.session, &PK).unwrap());
    }

    #[test]
    fn matches_inbound_detects_redelivery() {
        let (alice, bob, otk) = parties();
        let ik_b = ik_of(&bob);
        let ik_a = ik_of(&alice);

        let (alice_sess, _) = outbound(&alice, &ik_b, &otk, &[4u8; 32], &PK).unwrap();
        let enc = encrypt(&alice_sess, b"hi", &[5u8; 32], &PK).unwrap();
        let inb = inbound(&bob, &ik_a, &enc.message, &PK).unwrap();

        // Bob's session matches the pre-key message that created it.
        assert!(matches_inbound(&inb.session, &enc.message, &PK).unwrap());

        // A pre-key message for a different session does not match.
        let (alice2, bob2, otk2) = parties_with(&[8u8; 32], &[9u8; 32], &[10u8; 32]);
        let _ = (bob2,);
        let (alice2_sess, _) = outbound(&alice2, &ik_b, &otk2, &[11u8; 32], &PK).unwrap();
        let enc2 = encrypt(&alice2_sess, b"other", &[12u8; 32], &PK).unwrap();
        assert!(!matches_inbound(&inb.session, &enc2.message, &PK).unwrap());
    }

    fn parties_with(a_seed: &[u8; 32], b_seed: &[u8; 32], otk_seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let alice = account::create(a_seed, &PK).unwrap();
        let bob = account::create(b_seed, &PK).unwrap();
        let bob = account::gen_otks(&bob, 1, otk_seed, &PK).unwrap();
        let bob_acct = account::load(&bob, &PK).unwrap();
        let otk = *bob_acct.one_time_keys().values().next().expect("one otk").as_bytes();
        (alice, bob, otk)
    }
}
