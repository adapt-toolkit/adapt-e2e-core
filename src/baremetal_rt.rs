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
//! ── ARCHITECTURE CAVEAT (imac vs rv32im) ──────────────────────────────────
//! This staticlib is built for `riscv32imac-unknown-none-elf` (the **A**tomic
//! extension), NOT bare `rv32im`. That is deliberate and load-bearing: a
//! transitive dependency (`bytes` ← `prost` ← vodozemac, the protobuf message
//! codec) uses `core::sync::atomic` compare-and-swap directly, which does not
//! exist on an `atomic-cas: false` target such as `riscv32im-unknown-none-elf`,
//! and cannot be redirected by a `portable-atomic` shim (that only helps crates
//! that opt into `portable_atomic`, which `bytes` does not). Building for `imac`
//! gives real atomics and lets the whole dependency graph compile.
//!
//! The resulting archive is linked into ADAPT's `rv32im` (`-march=rv32im`)
//! newlib ELF. Under **qemu-riscv32 user-mode** (the CI simulator) the A-extension
//! instructions execute fine — qemu emulates the full ISA. On **real A-less
//! rv32im silicon or the risc0 zkVM** those instructions would trap. Enabling
//! e2e on a genuinely atomic-free rv32im target is a separate, larger effort
//! (forking `bytes`/`prost` off core atomics); this file's approach is scoped to
//! "e2e green on the rv32:func CI leg (qemu)", which is the current requirement.

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
