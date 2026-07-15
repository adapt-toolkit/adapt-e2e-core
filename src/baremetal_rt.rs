//! Bare-metal runtime shims for the `no_std` **staticlib** build.
//!
//! A `no_std` crate compiled to an `rlib` inherits the global allocator and
//! panic handler from whatever final binary links it. A `no_std` crate compiled
//! to a **`staticlib`** (our C-ABI archive) is itself the final Rust artifact,
//! so Rust requires it to carry exactly one `#[global_allocator]` and one
//! `#[panic_handler]`. This module supplies both, wired to the host newlib the
//! bare-metal ELF already links (`memalign`/`free`/`abort`). It is gated behind
//! the `baremetal-rt` feature so it is compiled ONLY for the rv32 staticlib
//! build — never for the `std` build (which uses std's own runtime) and never
//! for the plain `rlib` compile gate (`scripts/rv32_baremetal_build.sh`, whose
//! downstream binary would provide its own).
//!
//! ── TARGET: true rv32im (no atomics) ──────────────────────────────────────
//! This staticlib is built for `riscv32im-unknown-none-elf` — a GENUINE
//! no-atomics target (`atomic-cas: false`), matching ADAPT's `-march=rv32im`
//! ELF exactly and running on real rv32im silicon / the risc0 zkVM, not just
//! qemu. A transitive dependency (`bytes` ← `prost` ← vodozemac, the protobuf
//! codec) needs compare-and-swap, which the bare ISA lacks. Rather than fork
//! `bytes`, we enable its upstream `extra-platforms` feature (see the crate
//! Cargo.toml `baremetal-rt` feature), which routes bytes' atomics through
//! `portable-atomic`. On a single-hart, non-preemptive target the missing CAS
//! is supplied by `portable-atomic`'s single-core path, opted into with the
//! build flag `--cfg portable_atomic_unsafe_assume_single_core`.
//!
//! SOUNDNESS of the single-core cfg: `portable-atomic` emulates CAS by briefly
//! disabling interrupts around the read-modify-write. That is correct iff the
//! target is a single hardware thread with no other agent performing atomics
//! concurrently — which holds here: the rv32 bare-metal eval runs single-hart
//! with no preemptive scheduler and no second core, and e2e is called
//! synchronously from the single eval thread. See PATCH.md for the ledgered
//! rationale. (The verified build emits no `__atomic_*` libcalls — the CAS is
//! inlined, so no libatomic is required.)

use core::alloc::{GlobalAlloc, Layout};

// newlib symbols resolved from the final bare-metal ELF's libc.
unsafe extern "C" {
    fn memalign(alignment: usize, size: usize) -> *mut core::ffi::c_void;
    fn free(ptr: *mut core::ffi::c_void);
    fn abort() -> !;
}

/// Global allocator backed by newlib `memalign`/`free`.
///
/// `memalign` honours the requested (power-of-two) alignment directly, so a
/// single call satisfies every `Layout` without the store-the-base-pointer
/// bookkeeping a plain `malloc` would need. `dealloc` maps straight to `free`
/// (newlib's `free` accepts `memalign`-returned pointers). Only `alloc`/`dealloc`
/// are provided; `GlobalAlloc`'s default `realloc`/`alloc_zeroed` (alloc + copy /
/// alloc + zero) are correct on top of them.
struct NewlibAlloc;

unsafe impl GlobalAlloc for NewlibAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // newlib requires the alignment to be at least the word size; clamp up
        // (Layout::align() is always a power of two, so the max stays one).
        let align = layout.align().max(core::mem::size_of::<usize>());
        unsafe { memalign(align, layout.size()) as *mut u8 }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { free(ptr as *mut core::ffi::c_void) };
    }
}

#[global_allocator]
static ALLOCATOR: NewlibAlloc = NewlibAlloc;

/// Bare-metal panic handler: abort the module. The crate is built `-Cpanic=abort`
/// (no unwinding across the C ABI), and every FFI entry point already returns a
/// stable error code rather than propagating a panic, so reaching here is a
/// last-resort defence-in-depth stop, matching the FFI boundary's abort posture.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { abort() }
}
