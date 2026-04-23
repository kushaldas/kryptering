# ADR 0001 — Choice of CSPRNG for signing paths

**Status:** Accepted
**Date:** 2026-04-23
**Deciders:** Kushal Das (crate author)
**Related:** `DRR02.md` findings L-01 / L-02

---

## Context

`kryptering` contains two randomized signing paths:

1. ML-DSA (`src/software/sign.rs::pq_ml_dsa_sign`) — calls
   `ml_dsa::ExpandedSigningKey::sign_randomized(rng: &mut impl TryCryptoRng)`
   from `ml-dsa 0.1.0-rc.8`, which is built on **`rand_core 0.10`**.

2. RSA-PSS (`src/software/sign.rs::rsa_pss_sign`) — calls
   `rsa::pss::SigningKey::sign_with_rng(rng: &mut impl CryptoRngCore)` from
   `signature 2.2.0` (transitively via `rsa 0.9`), which is built on
   **`rand_core 0.6`**.

Additional randomness is required in test-only key generation paths (Ed25519,
ML-DSA generation), but those have no production impact.

Three CSPRNGs are readily available in the dependency graph:

| RNG | Crate | rand_core version | Nature |
|---|---|---|---|
| `getrandom::SysRng` | `getrandom 0.4` (w/ `sys_rng`) | 0.10 (fallible `TryCryptoRng`) | zero-sized syscall wrapper |
| `rand::rngs::OsRng` | `rand 0.8` | 0.6 (infallible `CryptoRngCore`) | zero-sized syscall wrapper |
| `rand::thread_rng()` | `rand 0.8` | 0.6 (infallible `CryptoRngCore`) | ChaCha12 reseeded from OsRng, thread-local state |

`SysRng` and `OsRng` are **semantically identical** — both issue one OS entropy
syscall (`getrandom(2)` on Linux, `getentropy(2)` on *BSD, `BCryptGenRandom` on
Windows, `SecRandomCopyBytes` on macOS) per randomness draw, hold zero user-space
state, and are fork-safe by construction. They differ only in which `rand_core`
major version's traits they implement.

`thread_rng()` is a userspace ChaCha12 stream reseeded periodically from
`OsRng`. It is faster (no per-call syscall) at the cost of holding a keyed RNG
state in process memory.

---

## Decision

**Prefer `getrandom::SysRng` for all new code. Where an upstream API
requires `rand_core 0.6` traits that `SysRng` does not satisfy, use
`rand::rngs::OsRng` as the equivalent-semantics substitute. Never use
`rand::thread_rng()` for cryptographic signing paths.**

Concretely in this crate:

| Call site | RNG | Reason |
|---|---|---|
| `pq_ml_dsa_sign` | `&mut getrandom::SysRng` | `sign_randomized` takes `TryCryptoRng` (rand_core 0.10) — direct fit |
| `rsa_pss_sign` | `let mut rng = rand::rngs::OsRng; &mut rng` | `sign_with_rng` requires `CryptoRngCore` (rand_core 0.6); `SysRng` does not implement that trait |
| tests (key generation) | `rand::rngs::OsRng` | test-only; uniformity with RSA-PSS path |

Tests-only call sites are explicitly out of scope of this ADR but follow the
same preference for readability.

---

## Rationale

Kryptering is a cryptographic library: it runs inside other people's processes,
in unknown threading / forking / sandboxing regimes, and is touched at modest
call rates (one signature per API call, not per TLS record). The ranking of
what we care about, highest to lowest:

1. **Correctness under fork.** `thread_rng()` holds keyed ChaCha state in TLS.
   Post-`fork(2)`, both parent and child share that state until the next
   reseed; this is a historically recurring footgun
   ([OpenSSL CVE-2010-4252](https://nvd.nist.gov/vuln/detail/CVE-2010-4252),
   [Wireguard-Go wg-fork bug](https://www.zx2c4.com/projects/wireguard-go/)).
   `SysRng` / `OsRng` hold no state, so forking cannot produce correlated
   output.

2. **Failure visibility.** `SysRng` implements the fallible
   `TryCryptoRng`; OS RNG exhaustion (e.g. seccomp filter blocking
   `getrandom(2)`, chroot without `/dev/urandom`) propagates as a `Result`
   and is converted to `Error::Crypto` by the existing error path. The
   previously-used `UnwrapErr(SysRng)` collapsed the same failure into a
   panic (see DRR02 finding L-01), which is surprising to callers running
   under `catch_unwind`, async runtimes, or structured logging. Direct
   `SysRng` is clean.

   `rand_core 0.6`'s `CryptoRngCore` is infallible — `OsRng` panics on OS
   RNG failure. This is accepted on the RSA-PSS path because we cannot
   bridge traits without adapters, and fail-closed-by-panic is still the
   correct answer in the cryptographic-signing context (better than signing
   with predictable output).

3. **Memory hygiene.** `SysRng` and `OsRng` are unit structs — they carry no
   secret material that could leak via core dump, swap, `ptrace(2)`, or
   `/proc/<pid>/mem`. `thread_rng()` holds a live ChaCha key whose exposure
   is bounded only by reseed frequency; that keyed state is not wrapped in
   `Zeroize`.

4. **Dependency minimality.** `SysRng` lives in `getrandom`, already present
   in the graph transitively. `OsRng` requires `rand 0.8`, also already
   present. No new crates are pulled for either choice.

5. **Performance.** The per-sign syscall cost (~μs) is negligible next to
   the ML-DSA / RSA-PSS arithmetic (~ms). The speed advantage of
   `thread_rng()` is irrelevant on signing paths — it only matters in hot
   loops drawing thousands of random values per second (e.g. TLS record
   masking, randomized blinding in tight loops), none of which exist in
   this crate.

---

## Why the split across two RNG types is acceptable

A reader will note that, after this ADR, two different concrete RNG types
appear in the signing module: `getrandom::SysRng` (ML-DSA) and
`rand::rngs::OsRng` (RSA-PSS). This is a pragmatic response to the current
state of the RustCrypto trait ecosystem:

- `signature 2.2.0` (used by `rsa 0.9`, `dsa 0.6`, `ed25519-dalek 2.x`, etc.)
  defines `RandomizedSigner::sign_with_rng<R: CryptoRngCore>` where
  `CryptoRngCore` comes from `rand_core 0.6`.
- `ml-dsa 0.1.0-rc.8` was published against the newer
  `rand_core 0.10 TryCryptoRng`.
- There is no automatic trait bridge between the two `rand_core` major
  versions.

We considered writing a small shim implementing `rand_core 0.6`'s `RngCore`
on top of `getrandom` directly; we rejected that option because (a) it
duplicates code that already exists in `rand::rngs::OsRng`, (b) it requires
us to maintain a trait adapter, and (c) `OsRng`'s behaviour is
bit-for-bit equivalent to what the shim would implement.

When `signature` and downstream crates migrate to `rand_core 0.10` (tracked
upstream — see [RustCrypto/traits#1596](https://github.com/RustCrypto/traits/issues/1596)),
this ADR should be revisited and the RSA-PSS path should be moved to
`SysRng` for uniformity.

---

## Consequences

**Positive**
- OS RNG failures in ML-DSA surface as `Error::Crypto("ML-DSA sign failed: ...")`
  — no panic — allowing callers to handle RNG exhaustion programmatically.
- Both signing paths now share the "syscall-per-draw, no user-space state"
  property; fork-safety is no longer hash-rate-dependent on reseeding.
- No new crates; the `Cargo.lock` delta is zero.
- `thread_rng()`'s internal ChaCha state is gone from the signing module,
  reducing the surface area that would need `Zeroize` coverage to be airtight.

**Negative**
- Per-sign latency on RSA-PSS grows by one `getrandom(2)` syscall relative
  to the old `thread_rng()` path. For a signing API, this is submicrosecond
  vs. millisecond arithmetic — practically unmeasurable.
- Two concrete RNG types live in the same module until upstream trait
  alignment catches up. Comments at both call sites point back to this ADR.

**Neutral**
- Tests continue to use `rand::rngs::OsRng` directly; test semantics
  unchanged.

---

## Alternatives considered

### A. Keep `rand::thread_rng()` everywhere
Rejected: user-space RNG state introduces a fork-safety class of bug we
do not need to carry, and the speed advantage does not apply to signing.

### B. Write a `rand_core 0.6` adapter over `getrandom` directly
Rejected: code duplication of `OsRng`; no functional benefit.

### C. Use `rand_chacha::ChaCha20Rng::from_entropy()` per call
Rejected: creates ChaCha state whose zeroization story is upstream, not
under our control; no advantage over `OsRng` for a single 32-byte draw.

### D. Accept `impl RngCore` in a public API so callers choose
Rejected: pushes the RNG-choice footgun to every caller. The crate is
opinionated about cryptographic primitives elsewhere (e.g., rejecting
SHA-1 MGF1 in OAEP); RNG choice fits the same pattern.

---

## References

- FIPS 204 §3.4 ML-DSA signing (hedged vs deterministic rationale)
- `getrandom 0.4` documentation, `SysRng`
- `rand_core 0.10` `TryCryptoRng`, `UnwrapErr`
- `rand_core 0.6` `CryptoRngCore`
- DRR02 findings L-01, L-02
- RustCrypto migration tracking: <https://github.com/RustCrypto/traits/issues/1596>
