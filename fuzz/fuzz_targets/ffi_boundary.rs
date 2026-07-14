// Copyright 2026 adapt-toolkit. Licensed under Apache-2.0.
//
// libFuzzer harness over the `#[no_mangle] extern "C"` boundary (SPEC §7.6).
// Invariant: arbitrary / malformed input bytes NEVER crash, panic, or hit UB —
// every call returns a clean `int32_t` rc. libFuzzer + ASan/UBSan catch any
// crash; the catch_unwind guard maps a caught panic to E2E_RC_PANIC (-99), which
// the fuzzer surfaces as a distinct signal. This complements the in-tree
// `tests/proptest_abi.rs` property tests with coverage-guided libFuzzer input.
#![no_main]

use adapt_e2e_core::ffi::*;
use libfuzzer_sys::fuzz_target;

const PK: [u8; 32] = [0x5A; 32];

fuzz_target!(|data: &[u8]| {
    let mut a = vec![0u8; 16384];
    let mut al = a.len();
    let mut b = vec![0u8; 16384];
    let mut bl = b.len();
    let mut c = vec![0u8; 16384];
    let mut cl = c.len();

    // Split the input so distinct fields get distinct arbitrary bytes.
    let (lhs, rhs) = data.split_at(data.len() / 2);

    // 1. gen_otks: arbitrary account pickle.
    unsafe {
        e2e_account_gen_otks(
            data.as_ptr(), data.len(), 1, [0u8; 32].as_ptr(), PK.as_ptr(),
            a.as_mut_ptr(), &mut al,
        );
    }
    al = a.len();

    // 2. account bundle: arbitrary pickle.
    unsafe {
        e2e_account_bundle(data.as_ptr(), data.len(), PK.as_ptr(), a.as_mut_ptr(), &mut al);
    }
    al = a.len();

    // 3. decrypt: arbitrary session + message (msg_type from a byte).
    let mt = data.first().copied().unwrap_or(0) as u32;
    unsafe {
        e2e_decrypt(
            lhs.as_ptr(), lhs.len(), mt, rhs.as_ptr(), rhs.len(), PK.as_ptr(),
            a.as_mut_ptr(), &mut al, b.as_mut_ptr(), &mut bl,
        );
    }
    al = a.len();
    bl = b.len();

    // 4. session_inbound: arbitrary account + identity key + pre-key message.
    unsafe {
        e2e_session_inbound(
            lhs.as_ptr(), lhs.len(), [0u8; 32].as_ptr(), rhs.as_ptr(), rhs.len(), PK.as_ptr(),
            a.as_mut_ptr(), &mut al, b.as_mut_ptr(), &mut bl, c.as_mut_ptr(), &mut cl,
        );
    }
    al = a.len();

    // 5. matches_inbound: arbitrary session + pre-key message.
    let mut out_bool: u32 = 0;
    unsafe {
        e2e_matches_inbound(
            lhs.as_ptr(), lhs.len(), rhs.as_ptr(), rhs.len(), PK.as_ptr(), &mut out_bool,
        );
    }

    // 6. ★ encrypt: arbitrary session pickle + plaintext (deserializes an
    //    untrusted session — the sharpest of the write paths).
    let mut mt: u32 = 0;
    unsafe {
        e2e_encrypt(
            lhs.as_ptr(), lhs.len(), rhs.as_ptr(), rhs.len(), [0u8; 32].as_ptr(), PK.as_ptr(),
            a.as_mut_ptr(), &mut al, &mut mt, b.as_mut_ptr(), &mut bl,
        );
    }
    al = a.len();
    bl = b.len();

    // 7. gen_fallback: arbitrary account pickle.
    unsafe {
        e2e_account_gen_fallback(data.as_ptr(), data.len(), [0u8; 32].as_ptr(), PK.as_ptr(), a.as_mut_ptr(), &mut al);
    }
    al = a.len();

    // 8. session_outbound: arbitrary account pickle + ik/otk from the split.
    unsafe {
        e2e_session_outbound(
            data.as_ptr(), data.len(), [0u8; 32].as_ptr(), [0u8; 32].as_ptr(), [0u8; 32].as_ptr(), PK.as_ptr(),
            a.as_mut_ptr(), &mut al, b.as_mut_ptr(), &mut bl,
        );
    }

    // 9. session_id: arbitrary session pickle (fixed 32-byte out).
    let mut id = [0u8; 32];
    unsafe {
        e2e_session_id(data.as_ptr(), data.len(), PK.as_ptr(), id.as_mut_ptr());
    }
});
