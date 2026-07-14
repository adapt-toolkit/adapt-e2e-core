# Caller contracts — load-bearing security obligations

`adapt-e2e-core` is a **pure, stateless** engine: every operation is a function
`f(state, seed, msg) → (state', out)`. That purity is what makes it deterministic
and bare-metal-capable (no_std, no OS entropy) — but it also means three security
invariants that a *stateful* E2E library would enforce internally **cannot** be
enforced by this crate. They are the **caller's** responsibility (the host engine
/ integration layer).

Each is load-bearing: violating it breaks a cryptographic guarantee. None of
these is a crate-provided safety — the crate cannot provide them without holding
mutable state and breaking determinism. Each has a boundary test in
`tests/boundary_invariants.rs` that drives the crate to the **reachable break**,
proving the obligation is real and external.

## 1. Seed uniqueness — a distinct entropy window per entropy-bearing call

The crate expands whatever 32-byte seed it is handed and has **no reuse
detection**.

- **Obligation:** supply a fresh, unpredictable, distinct seed to every
  entropy-bearing call — account / one-time-key / fallback keygen, `outbound`, and
  every DH-ratchet-advancing `encrypt`. Never feed the same seed to two *distinct*
  such operations.
- **Violation:** ephemeral / nonce reuse ⇒ key recovery.
- **Safe by contrast:** re-supplying the *same* seed to reproduce the *same*
  committed message (a deterministic replay) is REQUIRED and safe — the hazard is
  one seed feeding two *different* messages.
- **Witness:** `seed_reuse_across_distinct_dh_steps_is_a_reachable_break`.

## 2. One-time-key one-time-ness — atomically persist the consumed account

`session::inbound` returns a **new** account pickle with the used one-time key
removed. The crate cannot stop a caller from re-submitting the *pre-consumption*
pickle, which would reuse the one-time key.

- **Obligation:** after a successful `inbound`, atomically persist the RETURNED
  account pickle and use only it thereafter; never reuse a pre-consumption pickle.
- **Violation:** one one-time key serves two sessions ⇒ X3DH forward-secrecy loss.
- **Witness:** `otk_reuse_via_preconsumption_pickle_is_a_reachable_break` (the
  reuse succeeds; the persisted post-consumption account correctly refuses it).

## 3. Pickle persistence + integrity — persist the returned state, feed back untampered

Every state-advancing call returns a new pickle. Reusing a stale pre-call pickle,
or feeding back a tampered / foreign blob, is the caller's hazard.

- **Obligation:** after each call, persist the returned pickle and discard the
  prior one (atomic, no rollback); keep pickles under integrity protection and
  feed back only untampered blobs produced by this crate.
- **What the crate DOES defend:** the pickle body is AES-CBC + HMAC — tampering is
  rejected on load; the envelope `kind` is checked — no account↔session
  type-confusion. **What it CANNOT defend:** a *stale-yet-valid* pickle (correct
  MAC, old state) is indistinguishable from the current one — only the caller's
  persistence discipline prevents stale-state / chain-key replay.
- **Witnesses:** `stale_session_reuse_is_a_reachable_break`,
  `tampered_pickle_body_is_rejected_by_the_pickle_mac`,
  `flipped_envelope_kind_does_not_type_confuse`.

## Why the crate cannot enforce these

Enforcing reuse-rejection, one-time-ness, or persistence would require mutable,
durable state inside the crate — breaking the `f(state, seed, msg)` purity that
the determinism (byte-identical replay) and bare-metal (no_std, no OS) guarantees
depend on. The crate is deliberately honest about this boundary: it makes no
claim to provide these three properties, and the boundary tests above keep that
honesty verifiable.
