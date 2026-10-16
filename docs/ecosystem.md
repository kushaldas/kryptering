# Dependency ecosystem status

**Last reviewed:** 2026-10-16
**Tool:** `cargo outdated --depth 1` against the top-level `Cargo.toml`
**Scope:** kryptering's direct RustCrypto / randomness deps only
(transitive deps are not evaluated here; `cargo audit` handles those)

This document records which direct-dep major bumps are currently
*ecosystem-blocked* — i.e. the upstream crate has shipped a new major,
but other direct deps we still need haven't caught up to the new
trait version, so taking the bump unilaterally produces trait-bound
errors at compile time. It exists so that future `cargo outdated`
runs don't re-litigate the same investigation: the blockers and the
upstream gating versions are listed up front.

## Status at a glance

**All three RustCrypto trait waves are taken.** Every direct dependency sits
on a single trait line: `digest 0.11`, `signature 3`, `rand_core 0.10`,
`elliptic-curve 0.14` (hybrid-array), `pkcs8 0.11` / `spki 0.8` / `der 0.8`,
`crypto-bigint 0.7`, `cipher 0.5`. `cargo tree -d` reports no duplicated
crypto crate (only `syn` 2/3, a proc-macro dependency).

| Crate | Pinned at | Why not "latest" |
|---|---|---|
| `rsa` | `=0.10.0-rc.19` | no 0.10 final yet; exact pin (see below) |
| `sha3` | `0.11` (latest 0.12) | sha3 0.12 has no `EagerHash` impl (needed by hmac 0.13 / hkdf 0.13 / dsa 0.7) and moved `Shake256` to the `shake` crate; ml-kem and slh-dsa pin 0.11 too |
| `aes` | `0.9.2` in Cargo.lock (latest 0.9.3) | aes 0.9.3 raised `rust-version` to 1.89; kryptering's MSRV is 1.88. Held with `cargo update aes@0.9.3 --precise 0.9.2` |
| `ed448-goldilocks` | `=0.14.0-pre.15` | pre-release; see "Composite-signature Ed448 dependency" |
| `slh-dsa` | `0.2.0-rc.5` | no final yet |
| `x448` | `=0.14.0-pre.12` | pre-release; depends on exactly `ed448-goldilocks ^0.14.0-pre.15`, so both pins move together |
| `k256`, `bp256`, `bp384` | `0.14` | current line (elliptic-curve 0.14 / ecdsa 0.17); no `bp512` crate exists |

Deliberately removed: `rand` (replaced by `getrandom::SysRng` everywhere),
`generic-array` (gone with digest 0.10), the unused provider-neutral
`pkcs8 0.10` dependency, and the `pkcs8-pq` alias (now plain `pkcs8 0.11`).

---

## Wave taken — digest 0.11 / signature 3 / rand_core 0.10 / elliptic-curve 0.14 (2026-10-16)

The last blocker was `rsa`: every other crate in Waves 1 and 3 had shipped
a final, but `rsa 0.10` exists only as release candidates. The decision was
to pin `rsa = "=0.10.0-rc.19"` (same precedent as `slh-dsa` and
`ed448-goldilocks`) and take the whole wave in one commit.

### Why take an rsa release candidate

- It is the only way to get Brainpool curves (`bp256`/`bp384 0.14` need
  `elliptic-curve 0.14`), and to unify the trait lines the post-quantum
  crates already pulled in.
- rc.19 drops `num-bigint-dig` (and with it `rand 0.8`), closing the
  RUSTSEC-2026-0097 exposure.
- rc.19's `PaddingScheme` / `RandomizedSigner` APIs take a *fallible*
  `TryCryptoRng` and run every private operation with RSA blinding when an
  RNG is supplied. Kryptering supplies `getrandom::SysRng` on all of them.
- **It does not fix the Marvin attack.** RUSTSEC-2023-0071 lists no patched
  version and names rc.18 as still affected. The audit ignore stays, with
  rewritten rationale, in `.cargo/audit.toml`.

Revisit: when `rsa 0.10.0` final ships, move to a caret `0.10` and re-read
this section.

### Direct-dep bumps taken

```
digest         0.10 -> 0.11
sha1, sha2     0.10 -> 0.11
sha3           0.10 -> 0.11   (NOT 0.12, see status table)
md-5           0.10 -> 0.11
ripemd         0.1  -> 0.2
hmac, hkdf, pbkdf2   0.12 -> 0.13
rsa            0.9  -> =0.10.0-rc.19
ecdsa          0.16 -> 0.17
dsa            0.6  -> 0.7    (+ `hazmat` feature: SigningKey is gated)
p256/p384/p521 0.13 -> 0.14
ed25519-dalek  2.1  -> 3.0    (+ `alloc` feature: pkcs8 encode impls need it)
x25519-dalek   2.0  -> 3.0
signature      2    -> 3      (features rand_core, digest)
pkcs8-pq       ->  pkcs8 0.11 (alias removed)
rand           removed
generic-array  removed
pkcs8 0.10     removed (was unused)
dev-deps: rand 0.8 -> getrandom 0.4 + rand_core 0.10 (`UnwrapErr(SysRng)`)
```

### Source fallout (all in kryptering's own code)

- **rsa rc.19**: `BigUint` -> `rsa::BoxedUint`; `n().bits()` is now `u32`
  (`src/key.rs`, `src/software/sign.rs`); PKCS#1 v1.5 and PSS signing use
  `RandomizedSigner::try_sign_with_rng(&mut getrandom::SysRng, ..)`
  (blinding, RNG failure -> `Error::Crypto`); OAEP / PKCS#1 v1.5 transport
  go through `rsa::traits::PaddingScheme::{encrypt, decrypt(Some(rng), ..)}`;
  `Oaep::<D, MGD>::new_with_mgf_hash()` and `label: Option<Box<[u8]>>`, so
  the old UTF-8-only label restriction is gone (RFC 8017 octet strings are
  passed through byte-for-byte). `RsaPrivateKey::new` refuses < 1024 bits,
  so the PSS salt-capacity unit tests build synthetic public moduli.
- **ecdsa 0.17 / elliptic-curve 0.14**: `VerifyingKey::from_encoded_point`
  gone (`p521::ecdsa::VerifyingKey::from(&PublicKey)`), `sec1::ToEncodedPoint`
  deprecated (`ToSec1Point::to_sec1_point`), `EncodedPoint` alias gone
  (`PublicKey::from_sec1_bytes` parses and validates in one step),
  `SecretKey::random` / `SigningKey::random` deprecated (`Generate`).
- **dsa 0.7**: `DigestSigner`/`DigestVerifier` take a closure that updates
  the digest; `Signature::from_components -> Option`; `r()/s()` are
  `NonZero<BoxedUint>` (`to_be_bytes_trimmed_vartime`).
- **hmac 0.13**: `new_from_slice` moved to `KeyInit`.
- **RNG**: `src/backend.rs` `fill_random` uses `getrandom::fill`. No
  `rand_core 0.6` trait remains, so ADR 0001's split is retired.
- No changes were needed in `src/kdf.rs`, `src/pkcs12.rs`, `src/hazmat/`,
  the PKCS#11 provider, or the AWS-LC provider.

### Verification

- clippy `--all-targets -D warnings` clean for default,
  `rustcrypto,legacy,post-quantum` and `aws-lc,legacy`
- lib tests: 146 (default), 150 (rustcrypto complete), 19 (aws-lc,legacy);
  provider_baseline / provider_parity / tls_provider pass on both providers;
  FIPS known answers pass; SoftHSM2 integration test passes
- `cargo +1.88.0 check --locked` passes (after the `aes 0.9.2` hold)
- `cargo audit --deny warnings` exits 0 (148 deps scanned, down from 179)
- AWS-LC feature tree contains no RustCrypto primitive crate and no longer
  carries `pkcs8 0.10` / `spki 0.7` / `der 0.7`

---

## Recently unblocked — post-quantum pre-release wave (2026-06-01)

The post-quantum crates were previously pinned to exact pre-releases
because their APIs were still churning. Finals (or newer RCs) have now
shipped and were taken together in this update:

| Crate | Was | Now | Pin style |
|---|---|---|---|
| `ml-dsa` | `=0.1.0-rc.8` | `0.1.0` | caret (final) |
| `pkcs8-pq` (`pkcs8`) | `=0.11.0-rc.11` | `0.11.0` | caret (final) |
| `slh-dsa` | `0.2.0-rc.4` | `0.2.0-rc.5` | pre-release caret (still RC) |

`ml-dsa 0.1.0`, `pkcs8 0.11.0` final, and `slh-dsa 0.2.0-rc.5` resolve
together cleanly — they agree on the same `pkcs8 0.11`, `signature 3`,
and `digest 0.11` lines. New transitive deps pulled: `shake 0.1.0`,
`sponge-cursor 0.1.0` (both clean under `cargo audit`).

**Source fallout:** `ml-dsa 0.1.0` removed the `KeyGen` trait (in rc.8 it
was a blanket `impl<P> KeyGen for P` used only as a bound). Key generation
now lives on `SigningKey::<P>::generate()` via the new `Generate` trait.
kryptering never called `key_gen` — it generates keys via
`ExpandedSigningKey::<P>::from_seed` — so the fix was simply dropping the
now-nonexistent `+ ml_dsa::KeyGen` bound from the four
`P: ml_dsa::MlDsaParams + ml_dsa::KeyGen` sites in `src/software/sign.rs`.
No behavioural change; 96 lib tests still pass.

`slh-dsa` remains a release candidate (`0.2.0-rc.5`); it has no final yet.
Keep the pre-release caret pin until `slh-dsa 0.2.0` final ships.

---

## Recently unblocked — cipher 0.5 wave (2026-07-01)

The two blockers Wave 2 was waiting on both shipped finals since the
last review, so the whole wave was taken together in one migration:

| Blocker | Was | Now |
|---|---|---|
| `aes-gcm` | 0.10 (internal `aes 0.8`) | **0.11.0** (internal `aes 0.9`) |
| `pkcs5` (transitive, PBES2) | 0.7 (`des 0.8`) | **0.8.1** (`des 0.9`) |

Direct-dep bumps taken:

```
aes      0.8 -> 0.9
aes-gcm  0.10 -> 0.11
aes-kw   0.2 -> 0.3
cbc      0.1 -> 0.2
des      0.8 -> 0.9   (legacy feature)
```

`cipher` moved 0.4 -> 0.5 in the lockfile as a result. No half-wave:
every direct block-cipher dep moved at once.

**Source fallout** (all in kryptering's own code — verified against the
registry sources for each new major):

- **cbc 0.2 (`cipher 0.5`)**: the block-mode traits were renamed
  `BlockEncryptMut`/`BlockDecryptMut` -> `BlockModeEncrypt`/`BlockModeDecrypt`,
  and the padded helpers lost their `_mut` suffix
  (`encrypt_padded_mut`/`decrypt_padded_mut` -> `encrypt_padded`/`decrypt_padded`).
  `KeyIvInit::new_from_slices` and the `block_padding::NoPadding` path are
  unchanged. Touched `src/hazmat/aes_cbc.rs`, `src/software/cipher.rs`
  (3DES-CBC), `src/software/keywrap.rs` (3DES-CBC). The 3DES sites also
  moved from `new(key.into(), iv.into())` to `new_from_slices(key, iv)?`
  because `&Array: From<&[u8]>` was removed from hybrid-array.
- **aes-kw 0.3**: `Kek<C>` was replaced by `AesKw<C>`; construction is now
  via `KeyInit::new_from_slice` (returns `Result`, no longer panics on bad
  length); `wrap`/`unwrap` were renamed `wrap_key`/`unwrap_key`. Touched
  `src/software/keywrap.rs`. The RFC 3394 / NIST SP 800-38F known-answer
  vectors still pass byte-for-byte, confirming the wrap output is identical.
- **aes-gcm 0.11**: no trait/method changes, but `Nonce::from_slice` is now
  deprecated in favour of `TryFrom` (hybrid-array). Replaced with
  `Nonce::from([u8; 12])` on the encrypt path and a checked `try_into` +
  `Nonce::from` on the decrypt path. Touched `src/software/cipher.rs`.

96 -> 107 lib tests passed under the then-current complete RustCrypto feature
set; clippy with all targets was clean and `cargo audit --deny warnings`
exited 0. Provider builds now use the explicit matrix documented in
`docs/providers.md`.

---

## Wave 2 — `cipher 0.5` / block-cipher majors — ✅ DONE (2026-07-01)

This wave is complete. `aes-gcm 0.11` and `pkcs5 0.8` shipped finals,
which were the two blockers (the former moved its internal `aes` to
0.9, the latter its `des` to 0.9), so `aes`, `aes-kw`, `cbc`, and `des`
were all bumped together on 2026-07-01. See "Recently unblocked —
cipher 0.5 wave" above for the blocker table and source fallout.

## Composite-signature Ed448 dependency (2026-07-23)

`draft-ietf-jose-pq-composite-sigs-03` requires Ed448 for its
ML-DSA-87-Ed448 combination. Kryptering pins
`ed448-goldilocks =0.14.0-pre.15`, because that is still a pre-release and
draft-vector behavior must not change through an implicit update. Only its
`alloc` and `signing` features are enabled.

The crate uses `signature 3`, `rand_core 0.10` and `elliptic-curve 0.14`,
which since the 2026-10-16 wave is the single trait line of the whole crate.
Revisit the exact pin, upstream audit status, and API calls when a final
`ed448-goldilocks 0.14` is released.

Since 0.7.0 the crate also backs standalone Ed448 keys (with its `pkcs8`
feature for RFC 8410 envelopes) and, through `x448 =0.14.0-pre.12`, X448
agreement. `x448` pins `ed448-goldilocks ^0.14.0-pre.15` exactly, so the
two must be bumped in the same change.

## Curve crates added for 0.7.0 (2026-10-16)

| Crate | Version | Features | Used for |
|---|---|---|---|
| `k256` | 0.14 | `arithmetic, ecdsa, ecdh, pkcs8, std` (no `schnorr`) | secp256k1 / ES256K |
| `bp256`, `bp384` | 0.14 | `arithmetic, ecdsa, pkcs8, sha256/sha384, std` | brainpoolP256r1 / P384r1 (`sha*` provides the RFC 6979 nonce digest) |
| `ecdsa` | 0.17 | `algorithm, pkcs8, der, std` | generic `SigningKey<C>` for the Brainpool curves |
| `elliptic-curve` | 0.14 | `ecdh, pkcs8, std` | `ecdh::diffie_hellman` for Brainpool |
| `x448` | `=0.14.0-pre.12` | `static_secrets` | X448 |

`bp256`/`bp384` 0.6.x (the old elliptic-curve 0.13 line) only shipped
`wip-arithmetic-do-not-use`, which is why Brainpool required the wave.

---

## What was actually pulled on 2026-10-16

`cargo update` compat-range patches (no Cargo.toml changes required),
notably clearing **four rustls advisories** (RUSTSEC-2026-0346, -0347,
-0348, -0349, all fixed in 0.23.46):

```
rustls        0.23.45 -> 0.23.46
aes           0.9.1   -> 0.9.3
aes-gcm       0.11.0  -> 0.11.1
aws-lc-rs     1.18.1  -> 1.18.2   (aws-lc-sys 0.45 -> 0.46, aws-lc-fips-sys 0.14.2 -> 0.14.3)
rand          0.8.7   -> 0.8.8
thiserror     2.0.18  -> 2.0.21
zeroize       1.9.0   -> 1.9.1
sha2          0.11.0  -> 0.11.1   (transitive, PQ line)
spki          0.8.0   -> 0.8.1
der           0.8.1   -> 0.8.2
hybrid-array  0.4.13  -> 0.4.15
cc            1.2.67  -> 1.8.0
bindgen       0.72.1  -> 0.73.2
libc, log, serde, syn, zerocopy, smallvec, ... (45 packages in total)
```

Pin held back deliberately (lockfile only):

```
aes  0.9.3 -> 0.9.2   (0.9.3 requires rustc 1.89; MSRV is 1.88)
```

After the update:
- clippy (`--all-targets -D warnings`) clean for default,
  `rustcrypto,legacy,post-quantum` and `aws-lc,legacy`
- lib tests: 146 (default), 150 (rustcrypto complete), 19 (aws-lc,legacy)
- provider_baseline / provider_parity / tls_provider pass on both providers
- `cargo audit --deny warnings` exits 0 (179 deps scanned)

## What was actually pulled on 2026-07-01

Direct-dep major bumps (the `cipher 0.5` wave — see "Recently unblocked
— cipher 0.5 wave" above for the source migration):

```
aes      0.8 -> 0.9
aes-gcm  0.10 -> 0.11
aes-kw   0.2 -> 0.3
cbc      0.1 -> 0.2
des      0.8 -> 0.9   (legacy)
# cipher 0.4 -> 0.5 followed transitively
```

`cargo update` compat-range patches (no Cargo.toml changes required),
notably clearing a **yanked** advisory:

```
crypto-bigint  0.7.3 -> 0.7.5   (0.7.3 was YANKED — cargo audit warning, now gone)
zeroize        1.8.2 -> 1.9.0
ml-dsa         0.1.0 -> 0.1.1
getrandom      0.4.2 -> 0.4.3
block-buffer   0.12.0 -> 0.12.1
hybrid-array   0.4.12 -> 0.4.13
log            0.4.30 -> 0.4.33
quote          1.0.45 -> 1.0.46
smallvec       1.15.1 -> 1.15.2
syn            2.0.117 -> 2.0.118
zerocopy(+derive) 0.8.50 -> 0.8.52
zeroize_derive 1.4.3 -> 1.5.0
```

Pin held back deliberately (dropped on 2026-10-16 together with digest 0.10):

```
generic-array  0.14.9 -> 0.14.7 (pinned)
```

`generic-array 0.14.9` added a `#[deprecated(note = "please upgrade to
generic-array 1.x")]` attribute to `from_slice`, which fires 12 times in
`src/digest.rs` (via `p256::FieldBytes::from_slice`) and breaks
`clippy -- -D warnings`. `from_slice` cannot be dropped without moving to
`generic-array 1.x`, which is gated behind the `digest 0.11` wave (Wave 1,
still blocked on `rsa 0.10`). Pinning to `0.14.7` — the last 0.14 release
without the deprecation attribute — keeps clippy clean without touching the
digest-0.10-era code. Drop this pin when Wave 1 is taken.

After the update (before selectable providers were introduced):
- the complete RustCrypto feature set built cleanly
- the complete RustCrypto library suite passed 107 tests
- clippy with all targets was clean
- `cargo audit --deny warnings` exits 0 (127 deps scanned, no yanked crates)

## What was actually pulled on 2026-06-01

Direct-dep major bumps (post-quantum pre-release wave — see "Recently
unblocked" above):

```
ml-dsa    0.1.0-rc.8   -> 0.1.0    (KeyGen bound dropped in src/software/sign.rs)
pkcs8-pq  0.11.0-rc.11 -> 0.11.0
slh-dsa   0.2.0-rc.4   -> 0.2.0-rc.5
```

`cargo update` compat-range patches (no Cargo.toml changes required):

```
autocfg        1.5.0   -> 1.5.1
cmov           0.5.3   -> 0.5.4
cpubits        0.1.0   -> 0.1.1
crypto-common  0.2.1   -> 0.2.2
digest         0.11.2  -> 0.11.3   (transitive, PQ line)
hashbrown      0.17.0  -> 0.17.1
hybrid-array   0.4.10  -> 0.4.12
libc           0.2.185 -> 0.2.186
log            0.4.29  -> 0.4.30
memchr         2.8.0   -> 2.8.1
module-lattice 0.2.1   -> 0.2.3
serde_json     1.0.149 -> 1.0.150
serdect        0.4.2   -> 0.4.3
signature      3.0.0-rc.10 -> 3.0.0  (transitive, PQ line)
typenum        1.20.0  -> 1.20.1
zerocopy       0.8.48  -> 0.8.50
```

New transitive deps added: `shake 0.1.0`, `sponge-cursor 0.1.0`.

After the update (before selectable providers were introduced):
- the complete RustCrypto feature set and its individual combinations built
- the complete RustCrypto library suite passed 96 tests
- clippy with all targets was clean
- `cargo audit --deny warnings` exits 0 (155 deps scanned)

## What was actually pulled on 2026-04-23

`cargo update` picked up these compat-range patches (no Cargo.toml
changes required):

```
cmov      0.5.2  -> 0.5.3
ctutils   0.4.0  -> 0.4.2
libc      0.2.184 -> 0.2.185
rand      0.8.5  -> 0.8.6
rand_core 0.10.0 -> 0.10.1
semver    1.0.27 -> 1.0.28
sha3      0.10.8 -> 0.10.9
spki      0.8.0-rc.4 -> 0.8.0
typenum   1.19.0 -> 1.20.0
```

After the update (before selectable providers were introduced):
- the complete RustCrypto feature set built cleanly
- the complete RustCrypto library suite passed 93 tests
- clippy with all targets was clean
- `cargo audit --deny warnings` exits 0

## How to re-evaluate

```bash
cargo outdated --depth 1
```

Expected "behind" rows and why (as of 2026-10-16): `sha3 0.12` (EagerHash,
see status table), `aes 0.9.3` (MSRV), `rsa` once a `0.10.0` final exists
(then drop the exact pin). Anything else that appears as a new major is a
new wave: read the crate's registry `Cargo.toml` for the trait crate it
pins, probe with a one-line `Cargo.toml` edit if unclear, and take the
whole wave in one commit as was done above.
