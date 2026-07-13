# adapt-e2e-core — Implementation Design (grounded)

**Status:** draft for critic review
**Author:** Developer-9
**Date:** 2026-07-13
**Authoritative requirements:** `docs/SPEC.md` (implementation-grade spec). This document does
NOT restate the spec; it records the *grounded engineering decisions*, corrections where the
spec's assumptions diverge from the real vodozemac 0.10.0 code, the milestone/TDD sequence, and
the open risks a critic must scrutinize.

---

## 0. Grounding: what the real vodozemac 0.10.0 code looks like

Source read: `/home/fleet/work/_research/vodozemac` (v0.10.0, edition 2024, MSRV 1.85), read-only
reference clone. Findings below are cited to `path:line` and drive every decision in §2–§6.

**The spec's central fork assumption is FALSE for 0.10.0.** The spec (§3) assumes "vodozemac
already parametrizes keygen on `impl CryptoRng` threaded from `Account::new`, so the fork is just
N additive `_with_rng` fns." Reality: every keygen calls `rand::rng()` (rand 0.10 thread-local,
std+getrandom) **directly inside the leaf secret-key constructors**. There is zero rng threading
today. So the fork must add an rng parameter at the leaves **and** at every intermediate frame.
It is still *additive* (upstream fns retained) and *confined to keygen paths*, but it touches more
frames than the spec implied. This does not change the crate's contracts — only the fork's size.

### 0.1 The five keygen seams (choke points)

Every Curve25519 keygen on the Olm path flows through **one** leaf: `Curve25519SecretKey::new`
(`types/curve25519.rs:34`). Ed25519 (identity only) flows through `Ed25519Keypair::new`
(`types/ed25519.rs:129`). Both already have deterministic siblings (`from_slice`,
`random_from_rng`, `SigningKey::generate(rng)`), so the `_with_rng` addition is a clean
pass-through, not a math rewrite.

| # | Seam (public trigger) | Entry fn | Intermediate frames to thread rng | Leaf mint |
|---|---|---|---|---|
| A | Account create (IK Curve + IK_ed Ed) | `Account::new` `account/mod.rs:144` | — | `Curve25519Keypair::new` + `Ed25519Keypair::new` |
| B | One-time keys | `Account::generate_one_time_keys` `account/mod.rs:338` | `OneTimeKeys::generate`→`generate_one_time_key` `one_time_keys.rs:130/115` | `Curve25519SecretKey::new` `:117` |
| B'| Fallback key | `Account::generate_fallback_key` `account/mod.rs:372` | `FallbackKeys::generate_fallback_key`→`FallbackKey::new` `fallback_keys.rs:75/30` | `Curve25519SecretKey::new` `:31` |
| C | Outbound session ephemeral | `Account::create_outbound_session` `account/mod.rs:193` | base key `mod.rs:199`; `Session::new`→`DoubleRatchet::active`→`Ratchet::new`→`RatchetKey::new` `session/mod.rs:324`,`double_ratchet.rs:80`,`ratchet.rs:126/62` | `Curve25519SecretKey::new` (×2: base + first ratchet) |
| D | Encrypt DH-ratchet advance | `Session::encrypt` `session/mod.rs:387` | `encrypt(_truncated_mac)`→`next_message_key`→`InactiveDoubleRatchet::activate`→`RemoteRootKey::advance` `double_ratchet.rs:71/52/242`,`root_key.rs:73` | `RatchetKey::new` `root_key.rs:77` (only on direction change; else no draw) |

`create_inbound_session` and `decrypt` need **no** rng (DH mint deferred to next encrypt). Confirmed.

### 0.2 Other grounded facts (corrections to the spec)

1. **Pickle is not AEAD/ChaCha20Poly1305.** `AccountPickle::encrypt`/`SessionPickle::encrypt`
   use `cipher::Cipher::new_pickle` = **AES-256-CBC (PKCS7) + truncated 8-byte HMAC-SHA256**,
   32-byte key, HKDF-expanded (info `"Pickle"`) → AES key ‖ MAC key ‖ IV (`utilities/mod.rs:60`,
   `cipher/mod.rs:141`). ChaCha20Poly1305 appears **only** in the dehydrated-device path (out of
   scope). Our envelope (§4) wraps the vodozemac pickle *string* output verbatim; we do not
   re-encrypt.
2. **Skipped-key bound is a compile-time `const`, not runtime-configurable.**
   `MAX_MESSAGE_KEYS=40`, `MAX_MESSAGE_GAP=2000` (`receiver_chain.rs:50/31`),
   `MAX_RECEIVING_CHAINS=5` (`session/mod.rs:55`). Decision in §5.
3. **no_std is a separate, larger effort than getrandom-severance.** Crate is *not* `#![no_std]`
   (std `fmt`/`HashMap`/`io`/`serde_json`/`thiserror`, `base64ct` `std` feature). `getrandom
   0.4.3` is an **unconditional** dep. **Severing getrandom** only requires removing every
   `rand::rng()` call (5 Olm seams + sas/ecies/megolm/dehydration). **no_std** additionally
   requires replacing `std::io` pickle plumbing, `HashMap`, etc. We sequence these (§3).
4. **DETERMINISM HAZARD (critical):** `AccountPickle.one_time_keys` is backed by a std `HashMap`
   (`account/mod.rs:18`, `one_time_keys.rs`). If its pickle serializes in hash order, identical
   `(state,seed)` could yield **byte-different** account pickles across runs — violating the
   crate's #1 guarantee (spec §5.2). Must verify in M1; likely resolved by forking the OTK store
   (and receiver-chain maps) to `BTreeMap`/ordered storage — which *also* advances no_std. See §7 R1.
5. **Lints the fork must uphold:** `missing_docs=deny` (every new `pub` fn needs `///`),
   clippy `panic/unwrap/expect/unwrap_used=deny` in non-test code.

---

## 1. Vendoring & fork discipline

- **Vendor a pinned copy** of vodozemac at a specific released version (**0.10.0**) into
  `vendor/vodozemac/`, committed in-tree (git subtree, not submodule). Rationale: we *edit* it
  (additive `_with_rng`, feature-gating, later no_std), so an in-tree copy with a diffable
  baseline beats a submodule+patch dance; it also keeps the private repo self-contained and
  offline-reproducible. Cargo dep: `vodozemac = { path = "vendor/vodozemac" }`.
- **Re-audit baseline.** Record the exact upstream source hash for 0.10.0 in `PATCH.md`. Every
  change to `vendor/` is logged there (file, hunk, why, security-relevance). Re-audit = `git diff`
  of `vendor/` against pristine 0.10.0. **Honesty:** the Least-Authority audit (2022) predates
  0.10.0 by years; it covers neither 0.10.0's own drift nor our fork. `PATCH.md` tracks *our*
  delta only; upstream drift-since-audit is a separate, documented caveat.
- **Policy: security-backport-only.** We do not chase upstream features; we cherry-pick security
  fixes and re-apply the additive patch.
- **Additive discipline:** upstream `rand::rng()` constructors are retained but **feature-gated**
  behind `std-rng` (default) so the `--no-default-features` adapt path compiles them out and links
  no getrandom (enables the §7.7 RNG-isolation gate to pass). The `_with_rng` variants are always
  present. Non-Olm modules (megolm, sas, ecies, pk_encryption, dehydrated-device) are
  **cfg-gated off** on the adapt path (minimal textual change, backport-friendly) to shrink the
  audit surface and remove their OS-entropy draws.

---

## 2. Crate architecture (per spec §1, unchanged)

`lib.rs` (`#![no_std]`+alloc, std feature-gated) · `ffi.rs` (9 `extern "C"` fns) · `seeded_rng.rs`
(`SeededRng(ChaCha20Rng)`) · `mgmt/{account,session,bundle,pickle,error}.rs` · `panic.rs`
(catch_unwind / abort) · `vendor/vodozemac/` · `tests/` · `fuzz/`. cbindgen → `include/adapt_e2e_core.h`.
Crate-type `["staticlib","cdylib","rlib"]`.

**Boundary contracts (from spec, load-bearing):** stateless (opaque pickled blob in/out, caller
owns state, no statics/RNG/IO); deterministic (`f(state,seed,msg)→(state',out)` byte-identical);
no panic crosses the ABI; two-call length convention on every out-buffer; `int32_t rc` error enum.

---

## 3. Milestone / TDD sequence (risk-ordered)

Sequenced so cryptographic correctness is proven before the costly no_std/rv32 slog, matching the
spec's risk ranking (§9). Each milestone is test-first where feasible; each ends green on its gates.

- **M0 — Skeleton + baseline.** Repo layout, `Cargo.toml`, vendor 0.10.0, `PATCH.md` seeded, CI
  bootstrap. **Gate:** vendored vodozemac builds unchanged and its own upstream test suite passes
  (proves a clean baseline before we touch it).
- **M1 — The fork (CRITICAL PATH).** `seeded_rng.rs`; additive `_with_rng` threaded through all 5
  seams (§0.1); resolve the determinism hazard (§7 R1, likely BTreeMap). **Tests first:**
  determinism-under-replay golden (spec §7.3), Signal/Olm KATs (§7.1), interop vs real upstream
  vodozemac 0.10.0 as dev-dep (§7.2), retry-vs-replay distinct-ephemeral (§7.4). **Critic reviews
  this diff** (security-critical) before M2 builds on it.
- **M2 — C-ABI + mgmt + pickle envelope.** `ffi.rs` (9 fns, two-call convention, error enum,
  catch_unwind), `mgmt/*`, envelope+versioning, zeroize wiring. **Tests:** pickle round-trip +
  version-compat matrix (§7.5), proptest + cargo-fuzz over the `extern "C"` boundary (§7.6), miri
  (§7.10), skipped-key bounds (§7 / §5 here), **negative-FS** (§7.8), constant-time smoke (§7.9).
- **M3 — getrandom severance + RNG-isolation gate.** Feature-gate all `rand::rng()` sites; build
  `--no-default-features`; symbol-grep the release object for `getrandom`/`OsRng`/`thread_rng`;
  **fail build if present** (§7.7).
- **M4 — no_std + build matrix.** Convert crate + vendored Olm path to `#![no_std]`+alloc
  (std::io pickle → byte cursors, HashMap → BTreeMap already done in M1, fmt); wasm
  (emscripten ABI-pin) + rv32 bare-metal (nightly `-Zbuild-std`, `panic=abort`, float-ABI pin).
- **M5 — Packaging + CI matrix + docs.** cbindgen header committed; `xtask` (xcframework,
  cargo-ndk); full CI (native/no_std/wasm/rv32 × test/fuzz/miri/coverage/RNG-gate); coverage gates
  (≥95% line on ffi/mgmt/seeded_rng and the `_with_rng` fns); `PATCH.md` + header/contract docs.

---

## 4. Pickle envelope (spec §4.2, grounded)

```
pickle_blob = magic(4)="AE2C" || fmt_ver(u8) || engine_ver(u16, LE) || kind(u8:1=acct,2=sess)
              || vodozemac_pickle_string_bytes    // AES-256-CBC+HMAC-SHA256, key = caller pickle_key
```
Decode rejects unknown `magic`/`fmt_ver` → `E2E_RC_VERSION`; a `(fmt_ver,engine_ver)` compat
matrix test asserts clean decode-or-`VERSION` (never crash/misparse). `pickle_key` (32 B) is
caller-supplied and never persisted. `libolm-compat` import stays an opt-in feature, not one of
the core 9. Error enum values are frozen per spec §4.5.

---

## 5. Skipped-key bound decision

Accept vodozemac's compile-time bounds (`MAX_MESSAGE_KEYS=40`, `MAX_MESSAGE_GAP=2000`,
`MAX_RECEIVING_CHAINS=5`). The spec's "configurable bound" is **descoped** to "enforced bound":
forking the `ArrayVec` const-generics to a runtime value is outside the minimal-keygen-fork
discipline and adds audit surface for no functional need the crate owns. The §7 skipped-key test
asserts *enforcement* (out-of-order within the window decrypts; a message beyond gap/window fails
cleanly with `DECRYPT_FAILED`, no crash). Documented in the header and `PATCH.md`. **Flagged for
critic:** confirm descoping is acceptable vs the spec wording.

---

## 6. Test & interop strategy (spec §7 is the point)

- **Interop dev-deps** (test-only, may use std/getrandom): real `vodozemac = "0.10.0"` from
  crates.io + `olm-rs`/`libolm` if buildable. our-outbound→their-inbound and vice-versa; our
  pickle read by upstream. **Risk:** libolm is archived (Feb 2026, CVE WONTFIX) and may not build;
  fallback = vodozemac-only interop + committed static Olm KAT vectors under
  `tests/vectors/`. Never depend on libolm at runtime.
- **Determinism golden vectors** pin exact bytes so RNG-plumbing regressions are caught even if a
  property test passes.
- **Non-skippable gates:** determinism-golden, retry-vs-replay, negative-FS, RNG-isolation.
- **Fuzz** targets call the `#[no_mangle] extern "C"` fns directly with arbitrary bytes; invariant:
  malformed input → clean error rc, never panic/UB (ASan/UBSan).

---

## 7. Open risks the critic must attack

- **R1 (determinism vs HashMap ordering) — HIGH.** Does 0.10.0's account pickle serialize OTKs in
  a nondeterministic order? If yes, the crate's #1 guarantee is broken until we fork the store to
  ordered (BTreeMap). Must be *proven* in M1 with a byte-identical golden across process restarts,
  not just within one process. Resolution likely: BTreeMap (also aids no_std). Confirm no *other*
  HashMap/iteration-order sneaks into pickle bytes (receiver chains, skipped-key store).
- **R2 (fork correctness — the dominant spec risk).** `_with_rng` must be a pure pass-through
  producing byte-identical crypto to upstream `rand::rng()` given the same drawn bytes. Prove via
  KATs + interop, not just internal determinism. A missed seam still reaching `rand::rng()` →
  caught loud by RNG-isolation gate + determinism; the inverse (a deterministic shim on a path
  that must stay unpredictable) is the silent killer — the negative-FS + two-new-steps tests exist
  to force it into the open.
- **R3 (seed→ephemeral reuse, §5.3).** The crate cannot self-enforce "fresh seed per genuinely-new
  DH step." Test §7.4 must *prove the failure mode is reachable* (same seed on two distinct
  advancing steps → detectably reused ephemeral) so the host guard is demonstrably necessary.
- **R4 (no_std/rv32 — costliest lane).** Vendored Olm path must lose std::io + HashMap; float-ABI
  pin; `-Zbuild-std`. Schedule risk, low correctness risk. Sequenced last (M4).
- **R5 (interop availability).** libolm archived; may block §7.2. Fallback documented above.
- **R6 (audit staleness).** 0.10.0 ≫ 2022 audit. `PATCH.md` scopes our delta; upstream drift is a
  disclosed caveat, not something we can close.

---

## 8. Explicitly out of scope

MUFL/ADAPT binding (обвязка, spec §8); transport; prekey publication/fetch; anti-downgrade;
physical destruction of old pickle bytes (host obligation — the negative-FS test proves only that
the *deleted key* cannot decrypt). No persistence/network/clock/filesystem.
