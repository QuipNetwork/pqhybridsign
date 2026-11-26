# QPA-02: sr25519 identity-key rejection

The library rejects an sr25519 public key unless it decodes to a non-identity
Ristretto point. The identity is 32 zero bytes. Under that key, a publicly
constructible signature verifies for any message and signing label, removing
the classical protection even when the PQ signature is valid.

## Implementation

The shared parser in [sr25519.rs](../crates/pqhybridsign/src/classical/sr25519.rs)
decodes with schnorrkel and rejects `public.as_point().is_identity()`. Ristretto
decoding already rejects non-canonical encodings; identity is the only
low-order point. Checking the signature's R alone would be insufficient:
both `R = identity, s = 0` and `R = B, s = 1` satisfy the equation under an
identity public key, with schnorrkel's signature format marker set.

| Entry point | Identity or malformed sr25519 public key |
|---|---|
| `Sr25519::public_key_is_valid` | Returns `false` |
| `Sr25519::verify` | Returns a zero `Choice` |
| SrMl44, SrFn512 and both SrSh signature paths | Reject, including with a valid PQ signature |
| Stateful `PublicKey::from_bytes` and `from_stored_commitment_and_bundle` | Return `Error::ComponentFailure`; wrong composite length remains `Error::BadLength` |
| `rotation::verify_rotation` | Returns `None` for an identity current key or replacement classical key |
| `Sr25519::vrf_verify` | Returns a zero `Choice` |
| `Sr25519::vrf_make_bytes` | Returns `Error::ComponentFailure` |

Key derivation, signing, suite labels, signature-R acceptance and wire formats
are unchanged. Both hybrid signature components continue to be checked and
combined with bitwise `Choice` conjunction. Rotation signing does not validate
the target: installation must use the result of `verify_rotation`.

External registries can apply the same allocation-free policy without `std`
or the `vrf` feature:

```rust
use pqhybridsign::{classical::Sr25519, component::ClassicalScheme};

fn classical_key_is_admissible(classical_public_key: &[u8]) -> bool {
    Sr25519::public_key_is_valid(classical_public_key)
}
```

For a composite key, validate its complete suite-specific length before
passing the leading 32 bytes to this helper. Keep PQ key validation,
authorization and proof of possession as well. This helper checks key
suitability, not ownership.

## SDK admission review

Reviewed the local `polkadot-sdk` checkout at
`3dc723bb9518549479cd46f46fc23dddef3487f3` on 2026-11-26.

- H3 and H4 already reject identity keys through
  `crypto-core/src/suite/classical_key.rs::sr25519_public_is_valid`.
  Both suite public-key parsers call that helper. The new
  [SDK import tests](../../polkadot-sdk/quip/primitives/crypto-core/tests/sr25519_key_validation.rs)
  preserve a valid PQ key and assert identity/malformed classical rejection.
- Ordinary `pallet_session::set_keys` checks
  `OpaqueKeys::ownership_proof_is_valid` before storing keys. The generated
  opaque-key implementation calls each authority's proof-of-possession
  verifier. For H4, the chain is `RuntimePublic` → `Pair` → signature
  verification → `to_suite_public` → the checked H4 parser. Existing SDK
  weak-key tests exercise `Pair::verify`, `RuntimePublic::verify` and proof
  of possession; all reject the identity forgery with a valid PQ half.
- The wrapper's SCALE decoding and byte conversion alone check representation,
  not key suitability. Genesis configuration, `SessionInterface::set_keys`
  and storage migrations are trusted paths and can bypass ownership proof.
  Validate H4 keys with the suite parser before supplying them to those paths.
  The Asset Hub relay setter explicitly trusts validation on its source chain;
  that source must enforce the same admission rule.

The SDK currently pins a different pqhybridsign branch at
`0c8eaa81d439fd7b36c13218241634e79e2c9b9f` for its `quip-hd` API. SDK test
results establish its existing admission defenses under that pin; they do
not establish that the SDK consumes this working-tree library patch. Carry
this fix into the selected integration revision and pin it before deployment.
A full runtime session test and live chain inventory were not performed.

## Validation on 2026-11-26

Local validation used Rust 1.97.1, Node.js 24.22.3 and wasm-pack 0.13.1
(matching the existing CI installer). No dependencies or lockfiles changed.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Pass |
| Workspace clippy and separate `--features vrf` clippy, warnings denied | Pass |
| `cargo test --locked --workspace` | Pass |
| `cargo test --locked -p pqhybridsign --features vrf` | Pass |
| Workspace rustdoc, warnings denied | Pass |
| Audit feature set `--no-default-features --features alloc,std,vrf` | All six identity regression tests pass |
| Identity regressions with no default features, alloc, and VRF separately | Pass |
| QPA-02 SrSh and rotation tests under all four SHRINCS profiles | Pass |
| `thumbv7em-none-eabi` and `wasm32-unknown-unknown`, no default features, with no allocator, alloc, and VRF separately | Pass |
| Rebuilt C library and C integration executable | Pass |
| Rebuilt Python extension and Python suite | 227 tests pass |
| Rebuilt browser/Node npm package and npm suite | 74 tests pass |
| Regenerated browser/Node TypeScript declarations versus checked-in types | Pass |
| SDK crypto-core suite including H3/H4 import regressions | 27 tests pass |
| SDK wrapper weak-key regressions | Four tests pass, including H3/H4 verification and proof of possession |
| SDK H4 wrapper test module | Pass, including identity rejection on BABE VRF verification and output surfaces |

The regression suite includes the audit forgery and `R = B, s = 1`, positive
upstream acceptance controls, honest signatures, malformed keys, VRF entry
points, ABI dispatch and the npm Promise API. The SrSh tests retain valid PQ
signatures and deliberately bypass constructors to test verification of a
legacy identity key. Rotation tests sign the exact identity replacement with
an honest current key, so rejection depends on target admission.

Sensitivity was checked in a disposable source copy: removing only the
identity guard made `identity_forgeries_are_rejected_for_every_message_and_label`
fail on the forgery. The working source retained the guard.

Reproduce the focused library checks from the repository root:

```sh
cargo test --locked -p pqhybridsign --features vrf --test sr25519_identity
cargo test --locked -p pqhybridsign-abi --test roundtrip qpa02
for profile in profile-256s profile-256s-sha2 profile-128s-q18 profile-128s-q20; do
    cargo test --locked -p pqhybridsign --no-default-features --features "$profile" --lib qpa02
done
```

Run the full gates in [AGENTS.md](../AGENTS.md) and rebuild npm before running
its tests. From the SDK root:

```sh
cargo test --locked -p quip-crypto-primitives-core
cargo test --locked -p quip-crypto-primitives --lib substrate::weak_key_tests
cargo test --locked -p quip-crypto-primitives --lib substrate::sr25519_fndsa512::tests
```

## Existing consensus deployments

This changes signature acceptance. Local tests establish the library fix;
network activation requires deployment evidence:

1. Pin the fixed library/integration revision for native verification,
   runtime Wasm, BABE, proof consumers and registration services.
2. At a recorded finalized block, inventory active authorities, queued
   authorities and registered future session keys. Validate every H4 key,
   including its classical prefix; check genesis and privileged import data.
3. Replace any identity keys through authorized registration and wait for
   the session transition. Recheck active and queued sets before activation.
4. Coordinate an activation block or protocol/runtime version. Preserve
   historical verification where required by the chain's rules; a local
   build option must not determine consensus acceptance.
5. Record the artifact revisions, block hash, inventory results and activation
   evidence in the deployment's audit record.

Publication, live authority replacement and consensus activation have not
been performed by this remediation. The original report's Pending status is
historical; auditor acceptance and deployment status require their own record.
