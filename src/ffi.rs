//! The C-ABI surface (SPEC §2): thin `extern "C"` wrappers over the management
//! layer. Conventions:
//!
//! * **Opaque pickled blobs** cross the boundary as `*const u8` + `size_t`; new
//!   state is returned via caller-allocated `*mut u8` + `*mut size_t`.
//! * **Two-call length convention:** call with a NULL out pointer (or a buffer
//!   smaller than required) to learn the required length via `*out_len`; the
//!   call returns [`E2eRc::ShortBuffer`] and writes every `*out_len`. Call again
//!   with adequately-sized buffers to receive [`E2eRc::Ok`] and the bytes.
//!   Because the engine is deterministic, re-running the operation to size then
//!   fill buffers is a safe replay (SPEC §5.3), not a key-reusing rewind.
//! * **Seed** is a `const uint8_t seed[32]` present only on keygen-bearing calls.
//!   The crate's internal copy of the seed is held in [`Zeroizing`] and wiped when
//!   the call returns, so no seed material lingers on the crate's stack (the
//!   `SeededRng` expansion copy is likewise zeroized). The caller still owns and
//!   must wipe its OWN seed buffer.
//! * Every call returns `int32_t rc` ([`E2eRc`]); no panic crosses the boundary.

use crate::mgmt::error::{E2eRc, Error, Result};
use crate::mgmt::{account, session};
use zeroize::Zeroizing;

// ---- input helpers -------------------------------------------------------

/// Build a `&[u8]` from a caller pointer+len. A NULL pointer with non-zero len
/// is [`Error::NullArg`]; a NULL pointer with zero len is an empty slice.
///
/// # Safety
/// `ptr` must be valid for reads of `len` bytes (or NULL).
unsafe fn in_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8]> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err(Error::NullArg);
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Read a fixed 32-byte array argument (`const uint8_t x[32]`).
///
/// # Safety
/// `ptr` must be valid for reads of 32 bytes (or NULL).
unsafe fn in_arr32(ptr: *const u8) -> Result<[u8; 32]> {
    if ptr.is_null() {
        return Err(Error::NullArg);
    }
    let mut out = [0u8; 32];
    unsafe { core::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), 32) };
    Ok(out)
}

// ---- output helpers ------------------------------------------------------

#[derive(PartialEq, Eq)]
enum OutStatus {
    Copied,
    NeedsSpace,
}

/// Write `data` into a caller out-buffer per the two-call convention. Always
/// sets `*out_len` to the required length. Copies only if `out_ptr` is non-NULL
/// and the caller-provided capacity (the incoming `*out_len`) is large enough.
///
/// # Safety
/// `out_len` must be a valid `*mut usize` (or NULL); if `out_ptr` is non-NULL it
/// must be valid for writes of `*out_len` (capacity) bytes.
unsafe fn write_out(data: &[u8], out_ptr: *mut u8, out_len: *mut usize) -> Result<OutStatus> {
    if out_len.is_null() {
        return Err(Error::NullArg);
    }
    let cap = unsafe { *out_len };
    unsafe { *out_len = data.len() };

    if out_ptr.is_null() || cap < data.len() {
        return Ok(OutStatus::NeedsSpace);
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), out_ptr, data.len()) };
    Ok(OutStatus::Copied)
}

/// Fold a set of [`write_out`] results into the aggregate return: `Ok` iff every
/// buffer was copied; otherwise `ShortBuffer` (every `*out_len` is already set).
fn finish(statuses: &[OutStatus]) -> Result<()> {
    if statuses.iter().all(|s| *s == OutStatus::Copied) {
        Ok(())
    } else {
        Err(Error::ShortBuffer)
    }
}

/// Run an FFI body, catching panics (defence in depth) and mapping the result to
/// a stable `int32_t` return code. No panic ever crosses the ABI.
#[cfg(feature = "std")]
fn guard<F: FnOnce() -> Result<()>>(f: F) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => E2eRc::Ok as i32,
        Ok(Err(e)) => e.rc() as i32,
        Err(_) => E2eRc::Panic as i32,
    }
}

/// no_std variant: the crate is built with `panic = "abort"`, so a panic aborts
/// the process (abort-isolation) rather than unwinding across the boundary.
#[cfg(not(feature = "std"))]
fn guard<F: FnOnce() -> Result<()>>(f: F) -> i32 {
    match f() {
        Ok(()) => E2eRc::Ok as i32,
        Err(e) => e.rc() as i32,
    }
}

// ---- the ~9 C-ABI functions ---------------------------------------------

/// SPEC fn 1 — create a new account from `seed`.
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_account_create(
    seed: *const u8,
    pickle_key: *const u8,
    out_pickle: *mut u8,
    out_pickle_len: *mut usize,
) -> i32 {
    guard(|| {
        let seed = Zeroizing::new(unsafe { in_arr32(seed) }?);
        let pk = unsafe { in_arr32(pickle_key) }?;
        let blob = account::create(&seed, &pk)?;
        let s = unsafe { write_out(&blob, out_pickle, out_pickle_len) }?;
        finish(&[s])
    })
}

/// SPEC fn 2 — generate `n` one-time keys from `seed`.
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_account_gen_otks(
    in_pickle: *const u8,
    in_pickle_len: usize,
    n: u32,
    seed: *const u8,
    pickle_key: *const u8,
    out_pickle: *mut u8,
    out_pickle_len: *mut usize,
) -> i32 {
    guard(|| {
        let in_pickle = unsafe { in_slice(in_pickle, in_pickle_len) }?;
        let seed = Zeroizing::new(unsafe { in_arr32(seed) }?);
        let pk = unsafe { in_arr32(pickle_key) }?;
        let blob = account::gen_otks(in_pickle, n, &seed, &pk)?;
        let s = unsafe { write_out(&blob, out_pickle, out_pickle_len) }?;
        finish(&[s])
    })
}

/// SPEC fn 3 — generate a fallback key from `seed`.
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_account_gen_fallback(
    in_pickle: *const u8,
    in_pickle_len: usize,
    seed: *const u8,
    pickle_key: *const u8,
    out_pickle: *mut u8,
    out_pickle_len: *mut usize,
) -> i32 {
    guard(|| {
        let in_pickle = unsafe { in_slice(in_pickle, in_pickle_len) }?;
        let seed = Zeroizing::new(unsafe { in_arr32(seed) }?);
        let pk = unsafe { in_arr32(pickle_key) }?;
        let blob = account::gen_fallback(in_pickle, &seed, &pk)?;
        let s = unsafe { write_out(&blob, out_pickle, out_pickle_len) }?;
        finish(&[s])
    })
}

/// SPEC fn 4 — emit the account's public prekey-bundle material. Pure read.
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_account_bundle(
    in_pickle: *const u8,
    in_pickle_len: usize,
    pickle_key: *const u8,
    out_bundle: *mut u8,
    out_bundle_len: *mut usize,
) -> i32 {
    guard(|| {
        let in_pickle = unsafe { in_slice(in_pickle, in_pickle_len) }?;
        let pk = unsafe { in_arr32(pickle_key) }?;
        let blob = crate::mgmt::bundle::bundle(in_pickle, &pk)?;
        let s = unsafe { write_out(&blob, out_bundle, out_bundle_len) }?;
        finish(&[s])
    })
}

/// SPEC fn 5 — create an outbound session. Emits `out_session` and (unchanged)
/// `out_pickle` (account). Both follow the two-call convention.
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_session_outbound(
    in_pickle: *const u8,
    in_pickle_len: usize,
    ik_b: *const u8,
    otk_b: *const u8,
    seed: *const u8,
    pickle_key: *const u8,
    out_session: *mut u8,
    out_session_len: *mut usize,
    out_pickle: *mut u8,
    out_pickle_len: *mut usize,
) -> i32 {
    guard(|| {
        let in_pickle = unsafe { in_slice(in_pickle, in_pickle_len) }?;
        let ik = unsafe { in_arr32(ik_b) }?;
        let otk = unsafe { in_arr32(otk_b) }?;
        let seed = Zeroizing::new(unsafe { in_arr32(seed) }?);
        let pk = unsafe { in_arr32(pickle_key) }?;
        let (sess, acct) = session::outbound(in_pickle, &ik, &otk, &seed, &pk)?;
        let s1 = unsafe { write_out(&sess, out_session, out_session_len) }?;
        let s2 = unsafe { write_out(&acct, out_pickle, out_pickle_len) }?;
        finish(&[s1, s2])
    })
}

/// SPEC fn 6 — establish an inbound session from a pre-key message. Emits
/// `out_session`, the mutated `out_pickle` (account, OTK removed), and the
/// decrypted first-message `out_pt`. All follow the two-call convention.
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_session_inbound(
    in_pickle: *const u8,
    in_pickle_len: usize,
    ik_a: *const u8,
    prekey_msg: *const u8,
    prekey_msg_len: usize,
    pickle_key: *const u8,
    out_session: *mut u8,
    out_session_len: *mut usize,
    out_pickle: *mut u8,
    out_pickle_len: *mut usize,
    out_pt: *mut u8,
    out_pt_len: *mut usize,
) -> i32 {
    guard(|| {
        let in_pickle = unsafe { in_slice(in_pickle, in_pickle_len) }?;
        let ik = unsafe { in_arr32(ik_a) }?;
        let msg = unsafe { in_slice(prekey_msg, prekey_msg_len) }?;
        let pk = unsafe { in_arr32(pickle_key) }?;
        let r = session::inbound(in_pickle, &ik, msg, &pk)?;
        let s1 = unsafe { write_out(&r.session, out_session, out_session_len) }?;
        let s2 = unsafe { write_out(&r.account, out_pickle, out_pickle_len) }?;
        let s3 = unsafe { write_out(&r.plaintext, out_pt, out_pt_len) }?;
        finish(&[s1, s2, s3])
    })
}

/// SPEC fn 7 — encrypt `pt`. Draws `seed` only on a DH-ratchet advance. Emits the
/// message body (`out_msg`), its type (`out_msg_type`: 0=pre-key, 1=normal), and
/// the advanced session (`out_session`).
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_encrypt(
    in_session: *const u8,
    in_session_len: usize,
    pt: *const u8,
    pt_len: usize,
    seed: *const u8,
    pickle_key: *const u8,
    out_msg: *mut u8,
    out_msg_len: *mut usize,
    out_msg_type: *mut u32,
    out_session: *mut u8,
    out_session_len: *mut usize,
) -> i32 {
    guard(|| {
        let in_session = unsafe { in_slice(in_session, in_session_len) }?;
        let pt = unsafe { in_slice(pt, pt_len) }?;
        let seed = Zeroizing::new(unsafe { in_arr32(seed) }?);
        let pk = unsafe { in_arr32(pickle_key) }?;
        let r = session::encrypt(in_session, pt, &seed, &pk)?;
        if out_msg_type.is_null() {
            return Err(Error::NullArg);
        }
        unsafe { *out_msg_type = r.msg_type };
        let s1 = unsafe { write_out(&r.message, out_msg, out_msg_len) }?;
        let s2 = unsafe { write_out(&r.session, out_session, out_session_len) }?;
        finish(&[s1, s2])
    })
}

/// SPEC fn 8 — decrypt a message. Draws no entropy. Emits plaintext + advanced
/// session.
///
/// # Safety
/// All non-NULL pointers must be valid per the two-call convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_decrypt(
    in_session: *const u8,
    in_session_len: usize,
    msg_type: u32,
    msg: *const u8,
    msg_len: usize,
    pickle_key: *const u8,
    out_pt: *mut u8,
    out_pt_len: *mut usize,
    out_session: *mut u8,
    out_session_len: *mut usize,
) -> i32 {
    guard(|| {
        let in_session = unsafe { in_slice(in_session, in_session_len) }?;
        let msg = unsafe { in_slice(msg, msg_len) }?;
        let pk = unsafe { in_arr32(pickle_key) }?;
        let (plaintext, sess) = session::decrypt(in_session, msg_type, msg, &pk)?;
        let s1 = unsafe { write_out(&plaintext, out_pt, out_pt_len) }?;
        let s2 = unsafe { write_out(&sess, out_session, out_session_len) }?;
        finish(&[s1, s2])
    })
}

/// SPEC fn 9a — write the session's 32-byte id into `out_id[32]`.
///
/// # Safety
/// `out_id` must be valid for writes of 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_session_id(
    in_session: *const u8,
    in_session_len: usize,
    pickle_key: *const u8,
    out_id: *mut u8,
) -> i32 {
    guard(|| {
        let in_session = unsafe { in_slice(in_session, in_session_len) }?;
        let pk = unsafe { in_arr32(pickle_key) }?;
        if out_id.is_null() {
            return Err(Error::NullArg);
        }
        let id = session::session_id(in_session, &pk)?;
        unsafe { core::ptr::copy_nonoverlapping(id.as_ptr(), out_id, 32) };
        Ok(())
    })
}

/// SPEC fn 9b — write 1 into `*out_bool` if the session pickle corresponds to the
/// session the pre-key message would establish (idempotent re-delivery
/// detection), else 0.
///
/// # Safety
/// All non-NULL pointers must be valid; `out_bool` must be a valid `*mut u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e2e_matches_inbound(
    in_pickle: *const u8,
    in_pickle_len: usize,
    prekey_msg: *const u8,
    prekey_msg_len: usize,
    pickle_key: *const u8,
    out_bool: *mut u32,
) -> i32 {
    guard(|| {
        let in_pickle = unsafe { in_slice(in_pickle, in_pickle_len) }?;
        let msg = unsafe { in_slice(prekey_msg, prekey_msg_len) }?;
        let pk = unsafe { in_arr32(pickle_key) }?;
        if out_bool.is_null() {
            return Err(Error::NullArg);
        }
        let matches = session::matches_inbound(in_pickle, msg, &pk)?;
        unsafe { *out_bool = u32::from(matches) };
        Ok(())
    })
}
