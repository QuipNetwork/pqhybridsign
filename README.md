# pqhybridsign

Hybrid post-quantum signatures in Rust. Each suite pairs a classical signature
with a post-quantum signature and AND-composes them. A composite signature
verifies only when both halves verify, so the composite stays unforgeable while
either component survives a break.

This crate is a standalone reference implementation. It does not depend on
Substrate.

**Status: pre-release.** The wire format is not frozen, and no
cross-implementation test vectors exist yet. See [Limitations](#limitations).

## Features

- **Unforgeable while either half survives.** The security goal is EUF-CMA if
  at least one component scheme is secure. A break of the classical half or the
  post-quantum half alone does not forge a composite signature. For the
  stateful suites the post-quantum guarantee is conditional on state discipline
  (see [Stateful signing](#stateful-signing)).
- **Constant-time composite verify.** Verification combines the two component
  results with a bitwise `Choice` conjunction, never a short-circuiting `&&`.
  Neither the result nor the running time reveals which half failed.
- **Canonical and hedged signing.** `sign` hedges with fresh randomness by
  default. `sign_deterministic` produces a reproducible signature for uses that
  need verifiers to agree byte for byte, such as finality votes and light-client
  justifications.
- **Single master seed.** One 32-byte seed derives both the classical and the
  post-quantum half through HKDF-SHA256, so one backup covers the whole suite.
- **Noise-style suite names.** Each suite name is a generated label such as
  `hybrid-ed25519-mldsa44-v1`. The name doubles as the domain-separation label,
  and the crate checks it against a registry literal at compile time, so a
  signature made for one suite cannot verify under another.
- **Two families, one composition layer.** Stateless lattice suites and
  stateful hash-based suites share one generic composite layer. Only names and
  sizes vary between them.
- **Compile only what you use.** The stateful hash-based suites sit behind the
  `stateful` feature, on by default. Turn it off and the SHRINCS code and the
  `hashsigs-rs` dependency are neither compiled nor downloaded.
- **`no_std` and no-allocator capable.** The library builds for a target with
  no `std` prelude, both with and without an allocator. The pure-Rust crate
  sets `#![forbid(unsafe_code)]`.
- **Four language bindings.** Rust, C, Python, and WebAssembly, each shipped
  from its own registry.
- **Stateful misuse resistance built into the types.** The stateful secret key
  is not `Clone`. Signing commits the spent leaf through a journal before it
  returns a signature. The stateless budget is a required parameter. Rotation
  needs both components. See [Stateful signing](#stateful-signing).

## Suites

Suites follow the Noise Protocol Framework style: a suite combines a classical
component with a post-quantum component, and that combination is its name. The
name is also the domain-separation label. The crate checks it against a registry
literal when it compiles. Every name follows one grammar:

```
label = "hybrid-" classical "-" pq [ "-rotate" ] "-v1" NUL
```

The label carries a trailing null byte. A signature made for one suite cannot
verify under another.

**Stateless lattice suites.** Four variations, always built.

| Variation | Classical | Post-quantum |
|---|---|---|
| `hybrid-ed25519-mldsa44-v1` | ed25519 | ML-DSA-44 |
| `hybrid-sr25519-mldsa44-v1` | sr25519 | ML-DSA-44 |
| `hybrid-ed25519-falcon512-v1` | ed25519 | Falcon-512 |
| `hybrid-sr25519-falcon512-v1` | sr25519 | Falcon-512 |

**Stateful hash-based suites.** Eight variations: each classical key crossed
with each of the four SHRINCS profiles. The profile is part of the name.

| Variation | Classical | Profile |
|---|---|---|
| `hybrid-ed25519-shrincs-256s-v1` | ed25519 | 256s |
| `hybrid-ed25519-shrincs-256s-sha2-v1` | ed25519 | 256s-sha2 |
| `hybrid-ed25519-shrincs-128s-q18-v1` | ed25519 | 128s-q18 |
| `hybrid-ed25519-shrincs-128s-q20-v1` | ed25519 | 128s-q20 |
| `hybrid-sr25519-shrincs-256s-v1` | sr25519 | 256s |
| `hybrid-sr25519-shrincs-256s-sha2-v1` | sr25519 | 256s-sha2 |
| `hybrid-sr25519-shrincs-128s-q18-v1` | sr25519 | 128s-q18 |
| `hybrid-sr25519-shrincs-128s-q20-v1` | sr25519 | 128s-q20 |

Each stateful suite also carries a companion `...-rotate-v1` label for key
rotation, so the wire cannot confuse a rotation co-signature with an ordinary
one.

The Falcon-512 suites ship against the `fn-dsa` crate rather than waiting for a
final FIPS 206. Read the caveat under [Limitations](#limitations) before you
use them.

### Selecting a suite in the code

The Rust API names each lattice suite with a short type (`H1` through `H4`), and
the C, Python, and WebAssembly bindings take the same identifiers as strings.
The two SHRINCS types are `H5` (ed25519) and `H6` (sr25519). The profile is a
compile-time build feature, not a runtime argument, so one binary carries one
profile.

| Type / string handle | Variation |
|---|---|
| `H1` | `hybrid-ed25519-mldsa44-v1` |
| `H2` | `hybrid-ed25519-falcon512-v1` |
| `H3` | `hybrid-sr25519-mldsa44-v1` |
| `H4` | `hybrid-sr25519-falcon512-v1` |
| `H5` under the active profile | `hybrid-ed25519-shrincs-<profile>-v1` |
| `H6` under the active profile | `hybrid-sr25519-shrincs-<profile>-v1` |

## Sizes

Component primitives, in bytes:

| Primitive | Public key | Secret key | Signature |
|---|---|---|---|
| ed25519 | 32 | 64 | 64 |
| sr25519 | 32 | 64 | 64 |
| ML-DSA-44 (FIPS 204) | 1,312 | 2,560 | 2,420 |
| Falcon-512 (`fn-dsa` 0.4.0) | 897 | 1,345 | 666 |
| SHRINCS | 32 commitment / 164 bundle | 264 | variable |

Composite suites, in bytes. The classical choice does not change the size.
Each lattice row covers its ed25519 and sr25519 variation, and each SHRINCS row
covers both classical variations at that profile.

| Variation | Public key | Secret key | Signature |
|---|---|---|---|
| `hybrid-*-mldsa44-v1` | 1,344 | 2,624 | 2,484 (fixed) |
| `hybrid-*-falcon512-v1` | 929 | 1,409 | 731 (see note) |
| `hybrid-*-shrincs-256s-v1` | 64 stored / 196 verify | 328 | stateful 2,185 at leaf 1 / stateless 29,157 |
| `hybrid-*-shrincs-256s-sha2-v1` | 64 stored / 196 verify | 328 | stateful 2,185 at leaf 1 / stateless 29,157 |
| `hybrid-*-shrincs-128s-q18-v1` | 64 stored / 196 verify | 328 | stateful 1,161 at leaf 1 / stateless 5,769 |
| `hybrid-*-shrincs-128s-q20-v1` | 64 stored / 196 verify | 328 | stateful 1,161 at leaf 1 / stateless 5,769 |

- **The Falcon-512 secret key is 1,409 B**: 64 B classical plus the 1,345 B
  signing key that `fn-dsa` 0.4.0 emits. That signing key is larger than the
  1,281 B FN-DSA nominal value.
- **The Falcon-512 signature is 731 B today.** `fn-dsa` 0.4.0 emits a fixed
  666 B signature, so the composite is `64 + 1 delta byte + 666`. The wire
  format carries a length field and admits a shorter signature, down to 476 B,
  if a future component emits one.
- **The SHRINCS suites store 64 B but verify against 196 B.** Storage keeps the
  32 B classical key and a 32 B commitment. Verification needs the 164 B SHRINCS
  bundle the signature travels with, so its input is 32 + 164.
- **The SHRINCS signature is variable-length.** A stateful signature grows 32 B per
  leaf, from 2,185 B at leaf 1 to 133,225 B at leaf 4,096 under the 256s
  profiles. A stateless signature is fixed per profile.

## Performance

Measured on one machine in release mode. Reproduce the lattice figures with a
timing loop over `pqhybridsign::composite` and `pqhybridsign::composite_delta`,
and the SHRINCS figures with `crates/pqhybridsign/tests/profile_timing.rs`.

### Lattice suites

Wall-clock cost of one operation, averaged. These suites allocate nothing, and
their cost does not depend on any stored state.

| Variation | keygen | sign | verify |
|---|---|---|---|
| `hybrid-ed25519-mldsa44-v1` | 160 µs | 380 µs | 121 µs |
| `hybrid-sr25519-mldsa44-v1` | 159 µs | 385 µs | 120 µs |
| `hybrid-ed25519-falcon512-v1` | 1,634 µs | 221 µs | 43 µs |
| `hybrid-sr25519-falcon512-v1` | 1,546 µs | 221 µs | 45 µs |

Falcon-512 key generation is the slow operation. Falcon verification is faster
than ML-DSA verification, so the Falcon suites verify faster than the ML-DSA
suites.

### Hash-based suites

Timings depend on the SHRINCS profile, not on the classical half. Each row
covers two variations: `hybrid-ed25519-shrincs-<profile>-v1` and
`hybrid-sr25519-shrincs-<profile>-v1`. The figures below come from the ed25519
variant. The sr25519 classical half moves them by tens of microseconds, below
the resolution here. Each row reports one key at the 4,096-leaf capacity
limit (`maxSignatures = 4096`).

| Profile | keygen | sign (stateful) | verify | sign (stateless) |
|---|---|---|---|---|
| 256s | 1.46 s | 1.37 s | 0.19 ms | 1.15 s |
| 256s-sha2 | 0.39 s | 0.37 s | 0.08 ms | 0.32 s |
| 128s-q18 | ~47 s | ~0.7 s | 0.12 ms | 176.6 s |
| 128s-q20 | ~47 s | ~0.7 s | 0.12 ms | 166.5 s |

Four properties drive these numbers.

- **Key generation and stateful signing scale with the tree size.** The
  reference signer rebuilds the authentication path on each signature, so both
  cost about one hash per leaf of the chosen `maxSignatures`. The measured
  per-leaf rate is 0.33 ms under 256s, 0.089 ms under 256s-sha2, and 0.168 ms
  under 128s. A small tree costs proportionally less: a 4-leaf key generates in
  about 0.09 s and signs in about 1.4 ms under 256s. `DESIGN.md` reports the
  same operations at `maxSignatures = 4`, which isolates each profile's fixed
  cost.
- **Verification does not scale with the tree.** It checks the supplied
  authentication path and stays near a fifth of a millisecond at every profile.
- **The 128s key generation is dominated by the stateless hypertree.** It
  builds all 262,144 leaves of a single-layer height-18 tree, so `maxSignatures`
  barely changes it. The gain is a stateless signature five times smaller.
- **Stateless signing is the rotation and recovery path.** It is fixed per
  profile and reaches about three minutes under 128s, so a 128s recovery
  runbook must budget minutes, not milliseconds.

**The bindings re-import the stateful key on every signature.** A C or Python
SHRINCS signer under a 128s profile pays the key-generation cost, about 47
seconds, on every signature. The in-process Rust API does not. The table
measures the Rust API. Tracked as `pqhs-bf1`.

On-chain verification cost is a property of a downstream verifier, not of this
chain-agnostic library. The SHRINCS component has a Solidity verifier with
measured EVM gas and a Solana verify program, both in
[`hashsigs-rs`](https://gitlab.com/quip.network/hashsigs-rs). The lattice suites
have no on-chain verifier in this project.

## Crate

One crate, `pqhybridsign`, holds every suite. The lattice suites (over
`ed25519-zebra`, `schnorrkel`, `fips204`, and `fn-dsa`) are always built. The
SHRINCS suites (over `hashsigs-rs`) live behind the `stateful` feature, which
is on by default.

Turn the `stateful` feature off and the SHRINCS code and the `hashsigs-rs`
dependency are neither compiled nor downloaded, so a lattice-only consumer never
links them. The SHRINCS suites reuse the lattice classical components rather
than reimplementing them.

## Relationship to Substrate

This crate is Substrate-independent. It provides the composite signature layer:
the suites, canonical and hedged signing, key rotation, single-master-seed
derivation, the stateful safety machinery, and the hybrid VRF.

The Polkadot-SDK integration is a separate codebase: the QuipNetwork
`polkadot-sdk` fork and `quip-protocol-rs`. It implements the same hybrid
constructions and adds the pieces that need Substrate: the `Pair`, `Public`, and
`Signature` types, keystore and host functions, 32-byte account-ID derivation,
session keys, SCALE envelopes, and the BABE and GRANDPA wiring. That code does
not live here.

### Hybrid VRF

A verifiable random function (VRF) for every suite, behind the non-default
`vrf` feature. The classical component supplies the output: schnorrkel's own
VRF on the sr25519 suites, and an RFC 9381 `ECVRF-EDWARDS25519-SHA512-TAI` on
the ed25519 suites. A post-quantum binding signature over the same input proves
post-quantum key possession.

Every consensus-decisive byte derives from the classical pre-output alone. That
pre-output is unique per key and input. A verifier checks the binding but never
feeds it into that derivation. Post-quantum signatures are not unique for a
fixed message, so a signer able to read one into the output could grind it.

The ed25519 half passes the RFC's own Appendix B.3 test vectors. Its
pre-output followed by its proof is exactly the RFC's 80-byte `pi_string`.
Key validation is always on, so the verifier rejects a public key of small
order.

`hybrid-ed25519-shrincs-*-v1` and `hybrid-sr25519-shrincs-*-v1` bind through
the SHRINCS stateless path, spending one unit of the few-time budget rather
than a one-time leaf. That suits a low-frequency VRF such as epoch randomness,
not per-slot leader election.

### Mnemonic and junction derivation

Behind the non-default `mnemonic` feature, `master_seed_from_mnemonic` turns an
English BIP39 phrase into the 32-byte master seed. It reproduces Substrate's
derivation, which runs PBKDF2-HMAC-SHA512 over the mnemonic's entropy bytes
rather than over the phrase text. The same phrase therefore yields the same key
here and on chain. Golden vectors taken from the chain's own code hold that.

`derive_hard_junction` derives a child master seed from a parent seed and a
32-byte chain code, and both components are then re-derived from the child.
Hard derivation only: a soft junction produces a child public key and no child
secret, so no derived master seed exists for one. Parsing junction strings such
as `//alice` into chain codes stays in the Substrate integration.

A hard-derived child of a SHRINCS suite is a fresh tree starting at leaf 1.
Derive such a child once, persist it, and restore it through the validating
import path. Deriving the same child again on a second host produces a second
tree at leaf 1 and reissues every leaf the first one spends.

## Install

Each binding ships from its own registry.

### Rust

```toml
[dependencies]
# Every suite, stateful (SHRINCS) on by default.
pqhybridsign = "0.0.0-rc5"

# Lattice suites only, no hashsigs-rs:
# pqhybridsign = { version = "0.0.0-rc5", default-features = false, features = ["std"] }
```

`pqhybridsign-abi` is the type-erased layer that the C, Python, and
WebAssembly bindings share. A Rust consumer does not need it, and it is not
published to crates.io.

### JavaScript and TypeScript

The package is prerelease, so install the `next` tag.

```sh
npm install @quip.network/pqhybridsign@next
```

The module loads a WebAssembly binary before it can sign or verify. Every
function is async. The loader caches one load per process. Only the first
call pays that cost.

```typescript
import { keygenFromSeed, sign, verify } from "@quip.network/pqhybridsign";

// "H1" is the handle for hybrid-ed25519-mldsa44-v1.
const seed = new Uint8Array(32).fill(7);
const msg = new TextEncoder().encode("message");
const ctx = new TextEncoder().encode("context");

const { publicKey, secretKey } = await keygenFromSeed("H1", seed);
const sig = await sign("H1", secretKey, msg, ctx);
const valid = await verify("H1", publicKey, msg, ctx, sig);
```

The SHRINCS suites cannot sign in JavaScript. Verification and the length
accessors work for every suite.

### Python

```sh
pip install --pre pqhybridsign
```

PEP 440 spells the prerelease version `0.0.0rc5`, not `0.0.0-rc5`. Without
`--pre`, pip does not find it.

### C and C++

Download `pqhybridsign-clib-<tag>-linux-amd64.tar.gz` and its `.sha256` file
from the release page on GitLab. The archive holds
`libpqhybridsign_cffi.so`, `libpqhybridsign_cffi.a`, `include/pqhybridsign.h`,
and `LICENSE`.

## Stateless signing

The lattice suites need no stored state. This example signs under
`hybrid-ed25519-mldsa44-v1`, whose Rust type is `H1`.

```rust
use pqhybridsign::composite::{keypair_from_seed, sign, verify};
use pqhybridsign::error::Error;
use pqhybridsign::suite::Suite;
use pqhybridsign::H1;

fn demo() -> Result<(), Error> {
    let mut sk = [0u8; <H1 as Suite>::SECRET_KEY_LEN];
    let mut pk = [0u8; <H1 as Suite>::PUBLIC_KEY_LEN];
    keypair_from_seed::<H1>(&[7u8; 32], &mut sk, &mut pk)?;

    let mut sig = [0u8; <H1 as Suite>::SIGNATURE_LEN];
    sign::<H1>(&sk, b"message", b"context", &mut rand_core::OsRng, &mut sig)?;

    assert!(verify::<H1>(&pk, b"message", b"context", &sig));
    Ok(())
}
```

`sign` needs a `CryptoRngCore`. `rand_core::OsRng` above requires the
`getrandom` feature on `rand_core`.

`verify` returns `bool`, not `Result`. It combines the two component results
with a bitwise `&`, so it evaluates both halves whatever the first one decides.

The Falcon-512 suites use a delta-length wire format, so they call
`pqhybridsign::composite_delta` rather than `pqhybridsign::composite`. Their
`sign` returns the encoded length, because a Falcon signature is variable in
the format even where `fn-dsa` 0.4.0 emits a fixed size.

`sign_deterministic` takes a nonce, but not every component uses it. ed25519
and ML-DSA-44 are deterministic by their own specifications and ignore it.
sr25519 binds it. FN-DSA-512 does not sign deterministically by specification,
so the Falcon suites always vary their post-quantum half with the nonce. The
function documentation states the consequence for each suite.

## Stateful signing

Read this section before you use a SHRINCS suite.

**Use a SHRINCS suite only in a transactional system** that already keeps
durable, ordered, per-key state. Every signature consumes a one-time leaf, and a
key has at most 4,096 of them. Signing the same leaf twice destroys the security
of the post-quantum half. A signer restored from a seed backup
restarts at leaf 1 and reissues spent leaves. Any deployment that restores from
seed, replicates the signer, or runs it statelessly must use a lattice suite
instead.

Two rules follow, and the API enforces both:

- The secret key does not implement `Clone`. A clone forks the leaf counter.
- `sign_stateful` takes a `&mut impl LeafJournal` and commits the advanced
  leaf index through it before it returns a signature. A caller cannot hold a
  signature whose leaf is not already durable.

Every signing call spends its leaf, including a call the component refuses. A
signing path that can return without advancing the counter is a reuse hazard.
Reuse is total security failure. A spent leaf costs availability alone.
Authenticate and rate-limit requests before they reach the signer.

### Profiles

The `stateful` feature selects one SHRINCS parameter set at compile time.
Exactly one profile feature may be active. `stateful` selects `profile-256s`.
To pick another, turn off default features and name it.

| Feature | Default | Stateful signature at leaf 1 | Stateless signature |
|---|---|---|---|
| `profile-256s` | yes | 2,185 B | 29,157 B |
| `profile-256s-sha2` | no | 2,185 B | 29,157 B |
| `profile-128s-q18` | no | 1,161 B | 5,769 B |
| `profile-128s-q20` | no | 1,161 B | 5,769 B |

The `q18` and `q20` profiles are identical except for the stateless budget
(2^18 against 2^20). The SHRINCS parameter-set overview records that the
`q20` budget wants profile security analysis before production use. That
caveat travels with this crate, which exposes both.

The profile name goes into the suite label, so a SHRINCS suite under
`profile-256s` signs under `hybrid-ed25519-shrincs-256s-v1` or
`hybrid-sr25519-shrincs-256s-v1` and never collides with the same classical
key under another parameter set.

## Platforms

`pqhybridsign` must build for a target that provides no `std`, both with and
without the `alloc` feature. Treat a failure there as a defect. `DESIGN.md`
states it in full, with the rule it puts on authors: core has no `std`
prelude, so every `alloc` type needs an import by its full path.

Continuous integration builds core for `thumbv7em-none-eabi`, which has no
`std` to link against, and for `wasm32-unknown-unknown`, which the workspace
ships to. The SHRINCS suites need `std`.

The minimum supported Rust version is 1.95, set by `hashsigs-rs`.

## Testing

```bash
cargo test --workspace                    # default profile
cargo test -p pqhybridsign --no-default-features
cargo test -p pqhybridsign --no-default-features --features alloc
cargo test -p pqhybridsign --no-default-features --features profile-128s-q20
cargo test -p pqhybridsign --no-default-features --features profile-128s-q18
```

Tests read per-profile fixtures from `crates/pqhybridsign/tests/vectors/`
instead of generating keys and signatures. Regenerate a fixture with the
command in `generate_fixtures.rs`.

One real 128s key generation runs per commit, in `smoke_128s.rs`. It carries
`#[ignore]`, so run it explicitly:

```bash
cargo test -p pqhybridsign --release --no-default-features \
    --features profile-128s-q18 --test smoke_128s -- --ignored
```

That ignored smoke takes about 46 seconds in release. Debug builds run about
67 times slower than release for this code, so measure in release.

## Limitations

Stated plainly, because a release candidate should not imply more than it
delivers.

- **The golden vectors pin this implementation against itself.** They catch
  wire-format drift. They cannot catch an error that was present when they were
  generated, and this crate shares no vectors with another conforming
  implementation.
- **No external known-answer tests exist for the composition layer.** The
  component crates carry their own tests for the underlying primitives.
- **The Falcon-512 suites predate the standard.** FIPS 206 is not final. A
  signature made under a Falcon-512 suite today may not verify against a later,
  conforming implementation. Use them where you control both sides, or use an
  ML-DSA-44 suite.
- **The Falcon-512 length field is wider than it needs to be.** `fn-dsa` 0.4.0
  emits a fixed 666-byte signature, so the one-byte delta always carries the
  same value. The field stays because the format specifies it.
- **The WebAssembly binding signs under the lattice suites only.** JavaScript
  can structured-clone an object holding a stateful secret key, which forks
  the leaf counter. SHRINCS verification is available through
  `verifyWithStoredPublicKey`. To sign under a SHRINCS suite, use the C ABI or
  the Python binding.
- **The Python binding accepts `bytes` and `bytearray`, not arbitrary buffer
  objects.** The `abi3-py39` stable ABI cannot reach the buffer-protocol C API
  below CPython 3.11.
- **About 1 stateless signature in 9 million fails at 128s.** The FORS-C
  counter search gives up at 2^28 attempts and returns an error. The outcome is
  deterministic for one key, message, and context, so retrying the same message
  does not help. Changing the message does. The failure is loud and carries no
  security consequence.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
