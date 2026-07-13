---
title: "adapt-e2e-core — a standalone deterministic Double-Ratchet library (pure Rust, C-ABI)"
subtitle: "Implementation-grade specification. Forked vodozemac engine + Rust management primitives for X3DH/Double-Ratchet/prekey lifecycle. MUFL/ADAPT-agnostic, stateless, seed-injected. Apache-2.0."
author: "Cryptographic-engineering lead"
date: 2026-07-13
geometry: margin=2cm
fontsize: 10pt
colorlinks: true
---

# 0. What this document specifies

A **new, standalone, open-source repository**: `adapt-e2e-core` — a **pure Rust crate** under **Apache-2.0** that provides a Signal-class end-to-end channel (X3DH-class asynchronous handshake + Double Ratchet + skipped-key store + prekey lifecycle) as a **C-ABI library** for embedding into any host.

The crate is **completely MUFL/ADAPT-agnostic**. It knows nothing about MUFL packets, Merkle seals, brokers, or transactions. It is two things stacked:

1. a **vendored, pinned fork of [vodozemac](https://github.com/matrix-org/vodozemac)** (Rust, Apache-2.0, Least-Authority-audited 2022) — the full Olm protocol engine — with **exactly one behavioural fork: a `from_seed` reroll** (§3);
2. a thin Rust **management-primitive layer** over vodozemac's `Account`/`Session` types, exposing **~9 `#[no_mangle] extern "C"` functions** (§2). Headers are generated with **cbindgen**. Build artefacts are `staticlib` + `cdylib`.

**Everything cryptographic is Rust.** The only non-Rust surface is the generated C header and the FFI boundary. There is no C++ in this repository. The ADAPT/MUFL side later writes a thin **binding (обвязка)** *against* this C-ABI; that binding is out of scope here and appears only as the short closing §8.

**Two contracts define the crate:**

- **Stateless.** The library holds NO long-lived internal state — no statics, no singletons, no thread-locals, no internal RNG. Every C-ABI call takes an **opaque pickled-blob state in** and returns the **new pickled-blob state out**. The *consumer* owns and persists state. Keys and session state cross the ABI only as opaque bytes.
- **Deterministic via injected entropy.** Randomness is never sourced internally. Each keygen-bearing call takes a **32-byte seed blob** and produces byte-identical output for identical `(state-in, seed, message)`. This is the property that makes the engine a pure function `f(state, seed, msg) → (state', out)` — replayable, embeddable in a deterministic host, and (the §9 win) buildable on bare-metal with **no `getrandom`/`OsRng`**.

`||` = concatenation. `H` = BLAKE2b unless noted. vodozemac symbols are `crate::olm::{Account, Session}` unless qualified.

## 0.1 Non-goals

- **Not** a MUFL/ADAPT component. No packet-state, no Merkle, no broker code, no transaction wire format lives here.
- **Not** a C++ library. It is a Rust crate that *exposes* a C ABI.
- **Not** a general RNG-agnostic re-architecture of vodozemac — the fork is minimal, additive, and confined to keygen call sites.
- **Not** responsible for transport, prekey publication/fetch, anti-downgrade policy, or forward-secrecy *history destruction* — those are host obligations (noted, not implemented). The crate provides the mechanism (deterministic keygen, `zeroize`-on-drop, programmable session removal); the host provides the policy and the physical erasure of old state.
- **No** persistence, filesystem, network, or clock dependencies.

---

# 1. Crate layout and dependency posture

```
adapt-e2e-core/                     # the new standalone repo
├── Cargo.toml                      # [lib] crate-type = ["staticlib","cdylib","rlib"]
├── cbindgen.toml                   # C header generation config
├── build.rs                        # invokes cbindgen -> include/adapt_e2e_core.h
├── include/adapt_e2e_core.h        # GENERATED, committed for consumers
├── src/
│   ├── lib.rs                      # crate root; #![no_std] + alloc; feature-gated std
│   ├── ffi.rs                      # the ~9 #[no_mangle] extern "C" fns (§2)
│   ├── seeded_rng.rs               # SeededRng over ChaCha20Rng (§3)
│   ├── mgmt/                       # management-primitive layer over vodozemac
│   │   ├── account.rs  session.rs  bundle.rs  pickle.rs  error.rs
│   └── panic.rs                    # catch_unwind guard; no_std panic=abort variant
├── vendor/vodozemac/               # PINNED FORK (git subtree/submodule), from_seed patch (§3)
├── tests/                          # KATs, interop, determinism, negatives (§7)
├── fuzz/                           # cargo-fuzz targets over the C-ABI (§7)
└── cbindgen / xtask                # header + xcframework + cargo-ndk packaging
```

**Dependencies (kept tiny and `no_std`-capable — §9 depends on this):**

| Crate | Role | `no_std` | Notes |
|---|---|---|---|
| `vodozemac` (vendored fork) | Olm engine | yes (feature-gated) | the ONE fork; §3 |
| `rand_core` | `RngCore`/`CryptoRng`/`SeedableRng` traits | yes | trait glue only |
| `rand_chacha` | `ChaCha20Rng` deterministic CSPRNG | yes | the seeded DRBG |
| `zeroize` | secret wiping on drop | yes | §4.4 |
| `subtle` (transitively via vodozemac) | constant-time ops | yes | §7.9 |

**No `getrandom`, no `std`-required deps on the crypto path.** `std` is feature-gated (`default = ["std"]`) purely for host convenience (better panic messages on native); the `no_std` build (`--no-default-features`) is a first-class, CI-gated target (§9).

---

# 2. The C-ABI surface (~9 functions)

A thin `extern "C"` layer (`src/ffi.rs`) over vodozemac `Account`/`Session`. **Conventions:**

- **State in/out are opaque pickled blobs** (`*const u8` + `size_t len` in; caller-allocated `*mut u8` + `*mut size_t` out). No Rust type crosses the boundary.
- **Two-call length convention.** Call with `out_ptr = NULL` to learn required length via `*out_len`; call again with a buffer of that size. Every out-buffer follows this.
- **Seed** is a `const uint8_t seed[32]` argument, present ONLY on the four keygen-bearing calls (create, gen_otks/gen_fallback, session_outbound, encrypt).
- **All fallible ops return `int32_t rc`** (`0 = OK`; negative = a stable error enum, §4.5). No value is returned by pointer on error.
- **No panic crosses the boundary.** Every entry is wrapped in `catch_unwind` (std build) / `panic=abort` isolation (no_std build); a caught panic maps to `E2E_RC_PANIC` (defence-in-depth — the fuzz gate §7.6 asserts panics never occur on malformed input).
- **cbindgen** generates `include/adapt_e2e_core.h` from these signatures (`enum e2e_rc`, `#pragma once`, C99, `extern "C"` guard for C++ consumers).

Representative generated signatures (abbreviated; every blob is `const uint8_t*, size_t`):

```c
// include/adapt_e2e_core.h  (generated by cbindgen)
int32_t e2e_account_create(const uint8_t seed[32],
                           uint8_t* out_pickle, size_t* out_pickle_len);

int32_t e2e_account_gen_otks(const uint8_t* in_pickle, size_t in_pickle_len,
                             uint32_t n, const uint8_t seed[32],
                             uint8_t* out_pickle, size_t* out_pickle_len);

int32_t e2e_account_gen_fallback(const uint8_t* in_pickle, size_t in_pickle_len,
                                 const uint8_t seed[32],
                                 uint8_t* out_pickle, size_t* out_pickle_len);

int32_t e2e_account_bundle(const uint8_t* in_pickle, size_t in_pickle_len,
                           uint8_t* out_bundle, size_t* out_bundle_len);   // no seed: pure read

int32_t e2e_session_outbound(const uint8_t* in_pickle, size_t in_pickle_len,
                             const uint8_t ik_b[32], const uint8_t otk_b[32],
                             const uint8_t seed[32],
                             uint8_t* out_session, size_t* out_session_len,
                             uint8_t* out_pickle,  size_t* out_pickle_len);  // account may rotate

int32_t e2e_session_inbound(const uint8_t* in_pickle, size_t in_pickle_len,
                            const uint8_t ik_a[32],
                            const uint8_t* prekey_msg, size_t prekey_msg_len,
                            uint8_t* out_session, size_t* out_session_len,
                            uint8_t* out_pickle,  size_t* out_pickle_len);   // no seed; removes OTK

int32_t e2e_encrypt(const uint8_t* in_session, size_t in_session_len,
                    const uint8_t* pt, size_t pt_len, const uint8_t seed[32],
                    uint8_t* out_msg, size_t* out_msg_len, uint32_t* out_msg_type,
                    uint8_t* out_session, size_t* out_session_len);          // seed used only on DH step

int32_t e2e_decrypt(const uint8_t* in_session, size_t in_session_len,
                    uint32_t msg_type, const uint8_t* msg, size_t msg_len,
                    uint8_t* out_pt, size_t* out_pt_len,
                    uint8_t* out_session, size_t* out_session_len);          // no seed

int32_t e2e_session_id(const uint8_t* in_session, size_t in_session_len, uint8_t out_id[32]);
int32_t e2e_matches_inbound(const uint8_t* in_pickle, size_t in_pickle_len,
                            const uint8_t* prekey_msg, size_t prekey_msg_len,
                            uint32_t* out_bool);
```

## 2.1 Function → vodozemac mapping

| # | C-ABI symbol | vodozemac API | seed? | `from_seed` site |
|---|---|---|---|---|
| 1 | `e2e_account_create` | `Account::new()` → `.pickle().encrypt(k)` | YES | **A** — `Curve25519SecretKey::new(rng)` (IK) + `Ed25519SecretKey::new(rng)` (IK_ed) |
| 2 | `e2e_account_gen_otks` | `Account::generate_one_time_keys(n)` | YES | **B** — each OTK `Curve25519SecretKey::new(rng)` (loop draws from one seeded DRBG) |
| 3 | `e2e_account_gen_fallback` | `Account::generate_fallback_key()` | YES | **B** — one `Curve25519SecretKey::new(rng)` |
| 4 | `e2e_account_bundle` | `curve25519_key()`/`ed25519_key()`/`one_time_keys()`/`fallback_key()` + `sign()` | — | pure read; emits §4.3 bundle body |
| 5 | `e2e_session_outbound` | `Account::create_outbound_session(cfg, ik_B, otk_B)` | YES | **C** — ephemeral base key `E_A = Curve25519SecretKey::new(rng)` (the security-critical one) |
| 6 | `e2e_session_inbound` | `Account::create_inbound_session(ik_A, &PreKeyMessage)` | — | peer supplies ephemerals; also `remove_one_time_key` |
| 7 | `e2e_encrypt` | `Session::encrypt(pt)` | YES *on DH step only* | **D** — lazy DH-ratchet advance mints `Curve25519SecretKey::new(rng)`; pure symmetric advance draws nothing (§5.3) |
| 8 | `e2e_decrypt` | `Session::decrypt(&OlmMessage)` | — | deterministic; skipped-key store internal |
| 9a | `e2e_session_id` | `Session::session_id()` | — | 32-byte id |
| 9b | `e2e_matches_inbound` | `Account::create_inbound_session` dry-match / `Session::session_keys` compare | — | idempotent PRE_KEY re-delivery detection |

**Pickle wrapping.** vodozemac's `PickledAccount`/`PickledSession` serialize; `.pickle().encrypt(pickle_key)` yields a versioned AEAD blob (§4). The `pickle_key` is supplied by the caller (32 bytes, derived host-side from the host's root key) so the blob is bound to an identity — but the crate never persists it; it goes straight back out to the consumer.

**Honesty.** Functions 4, 6, 8, 9 are pure wrappers — zero crypto-fork risk. Functions 1, 2, 3, 5, 7 each touch a keygen call site and are where the fork lives; treat as §9-risk.

---

# 3. The `from_seed` vodozemac fork (the one behavioural change)

**What consumes randomness in vodozemac.** Keygen bottoms out in `Curve25519SecretKey::new(rng)` and `Ed25519SecretKey::new(rng)`, where `rng: impl CryptoRng + RngCore` is threaded down from `Account::new`, `Account::generate_one_time_keys`, `Account::generate_fallback_key`, `Account::create_outbound_session`, and the lazy DH-ratchet advance inside `Session::encrypt`. Upstream calls these with `OsRng`/`thread_rng()` — the exact injection seam we need but lack.

**Patch pattern — thread a seed, do NOT rewrite the math.** vodozemac already parametrizes on `impl CryptoRng`, so the reroll supplies a **deterministic CSPRNG seeded by our 32 bytes** instead of `OsRng`, at the same call sites. The entire crypto delta is one module plus additive `*_with_rng` entry points:

```rust
// src/seeded_rng.rs — the ENTIRE new-crate crypto delta (no_std)
use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;              // audited, deterministic, CryptoRng, no_std

pub struct SeededRng(ChaCha20Rng);
impl SeededRng {
    pub fn from_seed(seed: [u8; 32]) -> Self { Self(ChaCha20Rng::from_seed(seed)) }
}
impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 { self.0.next_u32() }
    fn next_u64(&mut self) -> u64 { self.0.next_u64() }
    fn fill_bytes(&mut self, d: &mut [u8]) { self.0.fill_bytes(d) }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> { self.0.try_fill_bytes(d) }
}
impl CryptoRng for SeededRng {}            // ChaCha20 is a CSPRNG
```

```rust
// vendor/vodozemac fork: ADDITIVE *_with_rng entry points (upstream OsRng versions retained)
impl Account {
    pub fn new_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Account { /* same body, rng param */ }
    pub fn generate_one_time_keys_with_rng<R: RngCore + CryptoRng>(
        &mut self, n: usize, rng: &mut R) -> OneTimeKeyGenerationResult { /* ... */ }
    pub fn generate_fallback_key_with_rng<R: RngCore + CryptoRng>(
        &mut self, rng: &mut R) -> Option<Curve25519PublicKey> { /* ... */ }
    pub fn create_outbound_session_with_rng<R: RngCore + CryptoRng>(
        &self, cfg: SessionConfig, ik: Curve25519PublicKey,
        otk: Curve25519PublicKey, rng: &mut R) -> Session { /* ... */ }
}
impl Session {
    pub fn encrypt_with_rng<R: RngCore + CryptoRng>(&mut self, pt: &[u8], rng: &mut R) -> OlmMessage
    { /* DH-ratchet advance uses rng; symmetric-chain advance ignores it */ }
}
```

The C-ABI (§2) constructs `SeededRng::from_seed(seed32)` from the injected seed and calls the `*_with_rng` variants. Sites A/B/C always draw from the seed. **Site D (`encrypt_with_rng`) is created on every call but only *consumes* seed bytes when vodozemac actually rotates the DH key** (direction change); on a pure symmetric-chain message the fresh `SeededRng` is unused. This is fine for determinism (same input → same output) and is exactly why the consumer must supply a seed on every `e2e_encrypt` yet the retry-vs-replay invariant (§5) is keyed on *whether a DH step happened*.

**Fork discipline.**

- **(a) Additive only.** Upstream `OsRng` functions stay intact; the diff reads as "N new `_with_rng` fns + one `seeded_rng.rs`", reviewable in isolation. This keeps the audited code paths for non-ADAPT users byte-unchanged and makes the security review of the fork tractable.
- **(b) RNG-isolation CI gate.** A `#![deny]`-style symbol grep asserts the release object on the ADAPT/`no_std` path never links `OsRng`/`thread_rng`/`getrandom` (§7.7). The `_with_rng` API is the *only* keygen entry the C-ABI ever calls.
- **(c) Minimal added deps.** `rand_chacha` + `rand_core` only, both audited and `no_std`-capable (this is load-bearing for §9).
- **(d) Vendoring + pinned fork.** vodozemac is vendored as a git submodule/subtree pinned to an exact upstream rev + our patch. Policy: **security-backport-only** — we do NOT chase upstream feature releases; we cherry-pick only security fixes and re-apply the (small, additive) patch. A `PATCH.md` documents every touched line for re-audit.

**Honest framing.** This is a *small but real* edit to audited Rust keygen. It voids the audit for the touched functions. It is the crate's dominant risk (§9) precisely because a subtle error here is "passes tests, silently insecure."

---

# 4. Pickled-blob state model

## 4.1 The stateless in/out contract

The crate is a pure function of its inputs. There are exactly two blob kinds crossing the ABI:

- **Account pickle** — a serialized `PickledAccount`: identity keypair (IK Curve25519 + IK_ed Ed25519), the one-time-key set, the fallback key(s), and vodozemac's max-OTK counter. Produced by fns 1/2/3; consumed by 2/3/4/5/6; mutated whenever OTKs change (gen, or removal on inbound-session creation).
- **Session pickle** — a serialized `PickledSession`: the Double-Ratchet state (root key, sending/receiving chains, DH ratchet keypair, message counters, and the **skipped-message-key store** with its bound). Produced by 5/6/7; consumed by 7/8/9.

Every mutating call takes `in_pickle` and returns a **new** `out_pickle`; the consumer decides whether to keep, discard, or `delete` the old one. The crate keeps nothing.

## 4.2 Envelope & versioning

Both blob kinds share a self-describing outer envelope emitted by `src/mgmt/pickle.rs`:

```
pickle_blob = magic(4)="AE2C" || fmt_ver(u8) || engine_ver(u16) || kind(u8: 1=acct,2=sess)
              || vodozemac_pickle_ciphertext(AEAD, pickle_key)      // versioned inner pickle
```

- `fmt_ver` is our envelope version (bumped on any layout change); `engine_ver` pins the vodozemac pickle format. Decode **rejects** unknown `magic`/`fmt_ver` with `E2E_RC_VERSION`. A **forward/back compat matrix test** (§7.5) covers every shipped `(fmt_ver, engine_ver)` pair.
- vodozemac's `Account::from_libolm_pickle` is exposed as an **import-only** path (`e2e_import_libolm_*`, not in the core 9) for cross-stack migration, gated behind a `libolm-compat` feature.

## 4.3 Bundle body (fn 4 output — engine-agnostic, host-signed)

`e2e_account_bundle` emits the raw public material for a prekey bundle; the *host* signs it (root→IK binding is host policy, not crate crypto):

```
bundle_body = ik_curve(32) || ik_ed(32) || fallback{key_id(4),key(32)} || otks:[{key_id(4),key(32)}]
```

The crate provides `ik_ed`-signatures over each OTK/fallback via vodozemac's `Account::sign`; the root→IK delegation signature and address binding are the consumer's job (§8). The crate does not define a wire bundle format — that is a host concern.

## 4.4 Zeroization

- Every secret-bearing Rust type (`SecretKey`, unpickled `Account`/`Session`, the `SeededRng`, decrypted-plaintext scratch, the derived `pickle_key`) is `#[derive(Zeroize)]` / wrapped in `Zeroizing<_>` and wiped on drop via the `zeroize` crate (compiler-fence-backed, non-elidable).
- On **ratchet advance**, superseded chain/DH key material inside `Session` is zeroized before the new pickle is emitted (upstream vodozemac already zeroizes on drop; the fork preserves this and the §7.9 test asserts it).
- The crate does **not** and cannot erase the *old pickle bytes the consumer still holds* — that historical-destruction obligation is the host's (§8, and the negative-FS test §7.8 exists to keep the crate honest about what it can prove).

## 4.5 Error enum (stable ABI)

`enum e2e_rc { OK=0, NULL_ARG=-1, SHORT_BUFFER=-2, BAD_PICKLE=-3, VERSION=-4, DECRYPT_FAILED=-5, BAD_SEED=-6, OTK_EXHAUSTED=-7, SESSION_MISMATCH=-8, INTERNAL=-98, PANIC=-99 }` — cbindgen-exported, never renumbered.

---

# 5. Entropy-injection API + retry-vs-replay invariant

## 5.1 The seed contract

Entropy is injected as a **32-byte seed per keygen-bearing call** (fns 1,2,3,5,7). The crate never draws from an OS RNG, a thread-local, or a global. `ChaCha20Rng::from_seed(seed)` expands the 32 bytes into as many keystream bytes as the operation needs (one seed suffices for `n` OTKs — the DRBG is expanded in-loop). The seed is `Zeroizing` inside the crate and wiped after the call.

## 5.2 The core property: determinism under replay

> For fns 1–9, identical `(state-in, seed, message)` produce **byte-identical** `(state-out, output)`.

This is the crate's single most important guarantee and the top of the test plan (§7.3). It makes the engine embeddable in a deterministic/replayable host: a re-executed operation re-derives the *identical* pickle and ciphertext, so "restore-then-replay" is byte-identical reproduction, **not** a key-reusing rewind.

## 5.3 The invariant the consumer MUST honour

The crate cannot see the consumer's notion of "same operation" vs "new operation" — so it defines the invariant the consumer must satisfy:

- **REPLAY** (re-executing a recorded operation): re-supply the **same recorded seed**. Same `(session pickle, seed, plaintext)` → byte-identical output. Safe: no new key is minted on a symmetric-chain message, and a re-run DH step re-derives the identical ephemeral. This is what makes deterministic hosting sound.
- **RETRY of a genuinely-new DH step** (a real, advancing ratchet turn that was not previously executed): the consumer MUST draw a **fresh** seed. Reusing a seed across two *distinct advancing* DH steps means two real ephemerals (`E_A` / ratchet key) collapse to one value → **catastrophic ephemeral-DH reuse → forward-secrecy / post-compromise-security break.**

The sharp edge, stated precisely: because site D (§3) creates a `SeededRng` on every `encrypt` but only *consumes* bytes on a DH rotation, the consumer's obligation is exactly **"identical seed ⇒ identical (session, plaintext, and operation identity)"**. Any other case (same seed, different advancing operation) is a fatal misuse. The crate cannot enforce this alone (it has no operation-identity concept); it documents it loudly, and the interop/adversarial tests (§7.4) drive two genuinely-new steps and assert distinct ephemeral keys. The host binds the seed to operation identity and draws fresh OS entropy for new operations (§8).

---

# 6. Functional requirements, incl. build targets

## 6.1 Functional

- **F1** — Full Olm: X3DH-class 3DH handshake over parked one-time keys (+ fallback for OTK exhaustion), Double Ratchet with header-independent Olm framing, skipped-message-key store with a configurable bound, PRE_KEY vs MESSAGE typing.
- **F2** — Stateless C-ABI (§2); pickled blob in/out; no statics/RNG/IO.
- **F3** — Seed-injected determinism (§5); the four keygen ops take a seed.
- **F4** — cbindgen header committed; `staticlib` + `cdylib` + `rlib` artefacts.
- **F5** — `no_std` throughout, `std` feature-gated and default-on for native convenience; the whole crate **and the vodozemac fork** compile under `--no-default-features`.
- **F6** — No panic crosses the ABI; malformed input → error rc, never UB.
- **F7** — Skipped-key bound enforced; decrypt is deterministic and side-effect-confined to the returned session pickle.

## 6.2 Build targets (the honest cost of a Rust engine)

The crate must build and link as a static library for the full ADAPT target matrix. The consumer's build (e.g. `mixin_common.cmake` in the ADAPT repo, which already carries `wasm`, `riscv32`, `ios`, `android`, native branches with per-platform `install/<plat>/libsodium` include+link blocks) links `libadapt_e2e_core.a` exactly where it links `sodium`. Per target:

| Target | Rust lane | Difficulty |
|---|---|---|
| **native x86_64** (linux/macos/windows) | stable `cargo build --release`; link staticlib; cbindgen header | **easy** |
| **ARM iOS** | `aarch64-apple-ios` (+ sim `aarch64-apple-ios-sim`, `x86_64-apple-ios`); `xtask` packages an **xcframework** of per-arch `staticlib`s | **routine** |
| **ARM Android** | `aarch64-linux-android` (+ armv7/x86_64) via **cargo-ndk** using the consumer's NDK; static archive per ABI | **routine** |
| **ARM servers** | `aarch64-unknown-linux-gnu`; stable, same as native | **easy** |
| **WASM** | `wasm32-unknown-emscripten` — **ABI-pinned to the consumer's `emcc`.** Rust std (or `no_std`) + our staticlib must link against the *same* emscripten sysroot/ABI as the ADAPT wasm build. Feasible but fiddly; CI lane breaks on emscripten bumps | **hard** |
| **RISC-V linux** | `riscv64gc-unknown-linux-gnu` / `riscv32-*-linux`; stable-ish, std present | **moderate** |
| **RISC-V bare-metal rv32** | `riscv32imac-unknown-none-elf` (no-OS/newlib) — see §6.3 | **hard / costliest** |

## 6.3 rv32 bare-metal — the main build risk, and the design win

Bare-metal rv32 (no OS, no std) requires:

- **nightly** toolchain + `-Zbuild-std=core,alloc` (build `core`/`alloc` from source; there is no precompiled std for `*-none-elf`);
- **`panic = "abort"`** (no unwinder) — the ABI panic guard degrades to abort-isolation (§2);
- **float-ABI match** with the consumer's newlib/link (`imac` soft-float vs `imafc`); mismatched float ABI is a silent link/codegen hazard — pin it in the target JSON;
- **`#![no_std]` throughout** the crate *and* the vodozemac fork (feature-gate every `std` use; vodozemac is largely `no_std`-friendly, but the fork must keep it so).

**The crucial win:** upstream vodozemac needs `getrandom`/`OsRng`, which has **no backend on bare-metal rv32** — the standard blocker that makes bare-metal-Rust crypto hard (you normally must write and fail-closed a custom `getrandom` shim, and hope nothing else pulls std). **Our injected-entropy design removes that dependency entirely:** because every keygen consumes the caller's seed via `SeededRng`/`ChaCha20Rng` (pure `no_std`, no OS entropy), the crate links **no `getrandom` and no `OsRng`** on any target. The RNG problem that normally sinks bare-metal Rust crypto is solved *by design*, not by a shim.

**Honest bottom line.** native/iOS/Android/ARM-server are routine; RISC-V-linux moderate; **wasm and rv32-bare-metal are the schedule risk**, and rv32-bare-metal is the single costliest lane (nightly + build-std + float-ABI + full `no_std` audit of the fork). One-line callout: the *only* way to avoid Rust-on-bare-metal is to drop the Rust engine for a non-Rust one (libolm — **archived Feb 2026, CVE-2024-45191/2 WONTFIX**) or a hand-rolled C ratchet (~3–4 kLoC of audited crypto we refuse to own). Both are **rejected**; we pay the rv32 Rust cost.

---

# 7. Test plan (tests must be incredible)

The crate is worthless if the fork is subtly wrong, and the failure mode is "green CI, silently insecure." The test plan is therefore adversarial, not just confirmatory. All tests run under `cargo test` (native + `--no-default-features` no_std harness), `cargo fuzz`, and `cargo miri`; CI gates on all of them.

## 7.1 Published KATs (Signal / Olm / vodozemac)
Import the upstream Olm/vodozemac known-answer vectors: 3DH shared-secret KATs, Double-Ratchet chain-derivation vectors, HKDF/HMAC-SHA256 test vectors, Curve25519/Ed25519 RFC vectors. Assert our `*_with_rng` path with the vector's fixed inputs reproduces the published outputs. **Any divergence = the fork changed engine behaviour and fails hard.**

## 7.2 Cross-implementation interop
Round-trip against **real upstream vodozemac and libolm** (as dev-deps / a harness binary): our outbound → their inbound and vice-versa; our pickle read by upstream vodozemac (and libolm-pickle import). Interop is the strongest evidence the fork is behaviour-preserving. Vectors committed under `tests/vectors/interop/`.

## 7.3 Determinism-under-replay (THE core property)
Property test: for random `(state, seed, msg)`, `f(state,seed,msg)` twice ⇒ **byte-identical** `(state', out)` for all 9 fns. Fixed golden vectors pin exact bytes so a regression is caught even if the RNG plumbing subtly changes. This is the gate everything else depends on.

## 7.4 Retry-vs-replay entropy guard (adversarial)
- **Replay-safe:** same seed + same session + same plaintext ⇒ identical ciphertext & session' (asserts §5.2).
- **Retry-must-differ:** drive **two genuinely-new advancing DH steps**; assert the two ephemeral/ratchet public keys are **distinct** when fed distinct seeds, and assert that feeding the *same* seed to two distinct advancing steps yields the (detectably) reused ephemeral — a test that exists to *prove the failure mode is reachable* so the host guard is demonstrably necessary. Documented as the crate's headline misuse.

## 7.5 Pickle round-trip + version compat
Round-trip every blob kind (account/session incl. populated skipped-key store) through pickle→unpickle and assert equality. A **compat matrix** loads every shipped `(fmt_ver, engine_ver)` fixture and asserts either successful decode or a clean `E2E_RC_VERSION` (never a crash or silent misparse). libolm-pickle import covered.

## 7.6 Property-based + fuzz of the C-ABI boundary itself
- `proptest`: structured random inputs to every fn; invariants (no panic, rc-correctness, out-len honesty, idempotent `matches_inbound`).
- **`cargo fuzz`** targets **directly over the `#[no_mangle] extern "C"` functions** — feed arbitrary/malformed pickle & message bytes to `e2e_decrypt`/`e2e_session_inbound`/`e2e_account_gen_otks`/etc. **Requirement: malformed blobs NEVER crash, panic, or hit UB — always a clean error rc.** ASan/UBSan under the fuzz harness. Corpus committed; CI runs a bounded fuzz budget per PR + a long nightly.

## 7.7 RNG-isolation gate
CI symbol-greps the release `staticlib` (and the `no_std` object) for `getrandom`/`OsRng`/`thread_rng`; **fails the build if present** on the ADAPT path. Asserts the crate is a pure function of its seed — the precondition for both determinism and bare-metal.

## 7.8 NEGATIVE forward-secrecy test (must FAIL to decrypt)
The keystone. Establish a session, advance the ratchet past a message, then **`delete` (drop + zeroize) the session state that held the superseded key** and simulate a state compromise of the *current* pickle. Attempt to decrypt the earlier, superseded/deleted-key message. **The test MUST FAIL to decrypt.** This proves forward secrecy is real for what the crate controls (that superseded key material genuinely cannot recover old plaintext once removed) — not merely that the happy path works. It also documents the boundary: the crate proves the *deleted key* can't decrypt; the *host* must prove it physically destroyed the old pickle bytes.

## 7.9 Constant-time / side-channel posture
Assert reliance on `subtle`/`curve25519-dalek` constant-time scalar ops (inherited from vodozemac); `dudect`-style timing harness on decrypt/MAC-compare as a smoke check; document that we add no data-dependent branches on secret material in the management layer. Not a formal CT proof — a posture + regression guard.

## 7.10 miri + coverage + CI gating
`cargo miri test` over the pure-Rust logic (UB/aliasing/uninit at the FFI marshalling). **Coverage targets:** ≥95% line / ≥90% branch on `src/ffi.rs`, `src/mgmt/*`, `src/seeded_rng.rs`; the fork's `*_with_rng` fns ≥95%. CI matrix runs native + `no_std` + wasm + rv32 build, `cargo test`, `cargo fuzz` (bounded), `miri`, coverage gate, RNG-isolation gate, and the KAT/interop/negative-FS suites; **all must be green to merge**, and the negative-FS + retry-guard tests are marked non-skippable.

---

# 8. MUFL обвязка / integration (out of scope; short)

*This section is informative only — the binding is NOT part of this repo.* The ADAPT/MUFL side later writes a thin binding against the C-ABI above. In brief:

- **Thin MUFL primitives** (a `domain_e2e.cpp/.h` mirroring the `_crypto_*` thin-primitive pattern at `domain_crypto.cpp:345` `REGISTER_COLLECTION(DOMAIN_CRYPTO,…)` — `popBinaryArgument → scheme->method → Create`) each: pop args → read the pickled blob from packet-state → fetch a secret seed → call the exported `e2e_*` function → write the returned pickle back. No key material crosses the MUFL boundary except opaque blobs.
- **Pickled blobs live in MUFL packet-state** as module state mirroring `key_storage.mm`: `m_e2e_account` / `m_e2e_peers` alongside `m_key_storage IS t_key_storage` (`key_storage.mm:35`), with the same atomic add (`m_key_storage key_id -> keypair_info.` :54), read (:167), and **programmable `delete`** (`delete m_key_storage key_id.` :219) — the latter is how forward-secrecy key removal is met: `delete` the superseded session pickle in the same transaction, Merkle-sealed, atomic per tx.
- **Entropy** is passed in as the 32-byte seed drawn from the packet's *secret* entropy band (single-use, fresh-per-new-DH-step, replay-reused per §5.3).
- **Scheme-2 wire carrier** for the ciphertext, following the `CryptoElementDerivedVariable` pattern (`crypto_element.h`; scheme seam `CryptoSchemeBase` at :111) and registered in `CE_Selector`, with the outer Ed25519 em-signature retained.

Real seam citations for the binding (informative): `crypto_element.h:111 CryptoSchemeBase`, `domain_crypto.cpp:345` thin-primitive pattern, `key_storage.mm:35/54/167/219` state+delete, `src/cmake/mixin_common.cmake` target list. **All of that is the consumer's work, not this crate's.**

---

# 9. Per-component eng-days + biggest risk

Estimates are for the **standalone crate only** (a competent Rust cryptography engineer). The MUFL binding (§8) is separate and not counted here.

| Component | Eng-days |
|---|---|
| **vodozemac `from_seed` fork (`seeded_rng.rs` + additive `*_with_rng` at 4 sites) + re-audit prep (CRITICAL PATH)** | **10** |
| C-ABI layer (`ffi.rs`: 9 fns, two-call buffer convention, error enum, catch_unwind) | 6 |
| Management layer (`mgmt/`: account/session/bundle/pickle wrappers) | 4 |
| Pickle envelope + versioning + zeroize wiring | 3 |
| cbindgen header + `xtask` packaging (xcframework, cargo-ndk) | 3 |
| Build lanes: native/iOS/Android/ARM-server (routine) | 3 |
| Build lanes: **wasm (emscripten ABI-pin) + rv32-bare-metal (nightly/build-std/float-ABI/no_std audit of fork)** | 8 |
| **Test suite** — KATs, interop-vs-real-olm/vodozemac, determinism-golden, retry-guard adversarial, skipped-key bounds, out-of-order/replay/dup, pickle compat matrix, `proptest` + `cargo fuzz` over the C-ABI, miri, constant-time smoke, **negative-FS** | 14 |
| CI matrix (native/no_std/wasm/rv32 × test/fuzz/miri/coverage/RNG-isolation gates) | 3 |
| Docs (`PATCH.md` fork ledger, header docs, seed/retry-replay contract) | 2 |
| **CRATE TOTAL** | **~56 eng-days** (~2.5–3 months, 1 eng, with re-audit review of the fork) |

## 9.1 Single biggest risk

**The `from_seed` fork of audited Rust keygen, coupled to the retry-vs-replay seed contract.** Replacing `OsRng` with a seeded CSPRNG at every keygen site edits security-critical paths of an audited library, voiding the audit for the touched code. Both failure modes are **"passes tests, silently insecure":**

1. **A missed keygen site still reaching `OsRng`/`getrandom`** → non-determinism → (loud) divergence on replay — catchable; OR the inverse, a determinism shim leaking into a path that must stay unpredictable → (silent) predictable keys.
2. **A seed reused across two genuinely-new DH steps** (the §5.3 misuse the crate can't self-enforce) → ephemeral-DH reuse → forward-secrecy / PCS **silently broken** while headless determinism tests stay green.

**Mitigation = adversarial verification, not green CI:** (a) the RNG-isolation symbol gate (§7.7); (b) two-new-steps distinct-ephemeral test (§7.4); (c) the **negative-FS test** (§7.8) that compromises current state and MUST fail to decrypt a superseded/deleted-key message; (d) interop against real olm/vodozemac (§7.2) as behaviour-preservation evidence; (e) a documented `PATCH.md` fork ledger for line-by-line re-audit. **Secondary risk:** the **rv32-bare-metal / no_std lane** — keeping the whole crate *and* the vodozemac fork `no_std`, nightly + `-Zbuild-std`, and float-ABI-matched is the costliest, most brittle build work; the injected-entropy design removes the `getrandom` blocker (the one genuine design win here) but the toolchain fragility remains real.
