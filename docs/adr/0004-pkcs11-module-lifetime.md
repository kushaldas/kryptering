# ADR 0004 - Retain initialized PKCS#11 modules independently of sessions

**Status:** Accepted
**Date:** 2026-10-07
**Related:** [ADR 0003](0003-cryptographic-input-and-token-validation.md),
[performance evidence](../performance/pkcs11-20261007.md)

## Context

Repeated provider construction calls the dynamic loader, resolves the PKCS#11
interface, and calls C_Initialize, even when the same module was used earlier.
pyFF already retains providers for a given module and selector, but direct
library callers and different token selectors can still repeat initialization.
Local SoftHSM profiling confirmed repeated module loads and millisecond costs;
it did not reproduce the reported approximately 20-second Luna delay.

Module ownership and authentication are different lifetimes. Avoiding repeated
initialization must not retain credentials or bypass the existing login checks.

## Decision

Retain a cloned cryptoki context in a static registry keyed by canonical module
file path. All provider constructors use this registry. A mutex covers lookup,
initialization, and insertion, ensuring concurrent constructors perform one
successful load/initialization per path. Only successful initialization is stored;
errors remain retryable. Token-selection failure does not discard an initialized
module, and token selection runs again on each provider construction.

`Pkcs11Provider::preload` explicitly warms this registry without selecting a token
or opening a session. Loading on import or automatically selecting an HSM is not
appropriate because configuration belongs to the application.

Token-label selection reads each present slot's information once and filters
initialized tokens itself, retaining label/serial uniqueness checks. Sessions,
PINs, private-key handles, and cryptographic results are not cached. Existing
RSA modulus checks and already-logged-in rejection remain unchanged.

## Ownership and process boundaries

Successful contexts stay loaded until process exit, even when all providers are
dropped. The registry does not finalize or unload them, and has no reset API.
Applications needing fresh module configuration must restart. External PKCS#11
clients may have initialized the module first; CKR_CRYPTOKI_ALREADY_INITIALIZED
remains accepted. Those clients must not finalize the module while kryptering
uses it. There is no safe automatic recovery from external finalization.

The guarantee is per canonical path per linked kryptering instance, not across
separate shared objects that statically link their own copy. Symlinks converge;
hard links do not. Paths must exist and resolve through filesystem
canonicalization. Platform-loader-only search names are intentionally unsupported.
Replacing a module file during a process lifetime does not replace its cached
context. Dynamic module hot replacement is unsupported.

An atomic process identifier is checked before either registry initialization or
mutex access. Children that inherit a used registry are rejected rather than
waiting on a possibly inherited locked mutex or reusing vendor state. Opening a
session through an inherited provider also performs this check. This does not
make sessions or operation objects fork-safe: callers must not use or drop those
inherited objects in the child. Start workers before initialization, or exec in
the child before using PKCS#11. No atfork handlers or unsafe reset logic are added.

## Tradeoffs and alternatives

The single mutex serializes even unrelated first module loads. This is acceptable
for a small configured set of modules and avoids a more complicated per-entry
initialization state machine. Vendor initialization must not reenter this registry.
The process retains module memory/resources until exit; automatic weak-reference
caching would reintroduce loads after the last provider was dropped.

Provider-level caching alone misses other callers and multiple token selectors.
Session caching could reduce login costs but changes authenticated lifetime and
is outside this decision. Preloading moves cold cost to startup; it does not
remove that cost from a fresh CLI invocation.

## Verification

Unit tests cover concurrent initialization, shared ownership after all callers
drop handles, retries after errors, symlink aliases, and inherited-cache rejection
before locking. The latter simulates a changed PID with the cache mutex held; it
is not a claim that arbitrary post-fork vendor operations are supported.

The real SoftHSM integration test additionally exercises explicit preload and
concurrent providers alongside existing token-selection, wrong-PIN, shared-login,
key-policy, PIN-change and crypto-interoperability coverage. A release benchmark
recreates providers, opens sessions, signs and verifies with an existing dedicated
test key. Before/after timings and loader counts are recorded separately.

Luna hardware was unavailable. Module-call elapsed timing on that deployment is
still needed to attribute its fixed delay; local improvements are not a claim
that this change resolves it.
