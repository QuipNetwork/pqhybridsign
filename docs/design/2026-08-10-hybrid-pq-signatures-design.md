# Design: Rust hybrid post-quantum signature crates

**Status:** Approved for planning
**Date:** 2026-08-10
**Source specification:** Hybrid Post-Quantum Signature Constructions, version 2.0, 2026-07-18
**Tracker:** beads prefix `pqhs`

## Summary

This repository holds a standalone Rust version of the composite layer of the
hybrid signature specification, covering four constructions. H1 and H3 pair a
classical scheme with ML-DSA-44, while H5 and H6 pair one with SHRINCS. None of
the crates depends on the Polkadot SDK, so Substrate wiring stays in
`quip-crypto-primitives` inside the QuipNetwork Polkadot SDK fork.

Suites are defined by combination, in the style of the Noise Protocol
Framework. One generic composite layer takes a classical component and a
post-quantum component. The suite name doubles as the domain separation label.

Work runs over four cycles. Each cycle has its own epic and its own plan.

## Decisions

| # | Decision | Reason |
|---|----------|--------|
| 1 | Standalone crates, no Substrate dependency | Keeps the composite layer testable and reusable from WASM, Python and TypeScript bindings |
| 2 | Three crates: `pqhybridsign-core`, `pqhybridsign`, `pqhybridsign-shrincs` | Isolates the AGPL git dependency on `hashsigs-rs` and keeps each crate small |
| 3 | AGPL-3.0-or-later for every crate | Matches the `hashsigs-rs` license and the wider Quip repositories |
| 4 | Generic composition over component traits | Section 7 of the specification is a matrix of classical times post-quantum. Only names and sizes vary |
| 5 | Noise-style combinatorial suite naming | The label registry regenerates exactly from a name grammar. See Finding 1 |
| 6 | No H2 or H4 code this cycle | Sections 3, 4 and 22 gate both on final FIPS 206 and a stable `fn-dsa` release |

## Architecture

### Crates

| Crate | Contents | Dependencies |
|-------|----------|--------------|
| `pqhybridsign-core` | Component traits, suite macro, `M'` builder, encodings, HKDF derivation, error types, `LeafJournal` port | `subtle`, `zeroize`, `hkdf`, `sha2` |
| `pqhybridsign` | H1 and H3 | core, `ed25519-zebra`, `schnorrkel`, `fips204` |
| `pqhybridsign-shrincs` | H5 and H6 | core, `hashsigs-rs` pinned by revision |

Every library crate sets `#![forbid(unsafe_code)]`. The core and lattice
crates build for `wasm32-unknown-unknown` without an allocator. The SHRINCS
crate needs `std`, because the reference signer needs `std` today.

### Component traits

The core crate defines three abstractions. They map onto the Noise Protocol
Framework as follows.

| Noise Protocol Framework | This design | Provides |
|--------------------------|-------------|----------|
| DH functions, `DHLEN` | `ClassicalScheme` | `NAME`, key and signature sizes, `from_seed`, `sign`, `sign_deterministic`, `verify` returning `Choice` |
| Cipher functions | `PqScheme` | `NAME`, sizes, `SEED_LEN`, `from_seed`, `sign`, `verify` returning `Choice`, `IS_DETERMINISTIC` |
| Cipher functions, stateful variant | `PqStatefulScheme` | The same, plus `LEAF_CAPACITY_LIMIT`, `keygen_from_seed`, `leaf_capacity`, `next_leaf`, `precheck`, `max_stateful_sig_len`, and separate `sign_stateful` / `sign_stateless` and `verify_stateful` / `verify_stateless` entry points |
| Hash functions, `HASHLEN` | Fixed by the specification | SHA-256 for HKDF, keccak-256 for the SHRINCS commitment |
| Handshake pattern and modifiers | `Suite` and its `rotate` modifier | Label selection for signing and for rotation |
| `protocol_name` mixed into `h` | `Suite::LABEL` prepended into `M'` | Domain separation |

A suite is `Hybrid<C: ClassicalScheme, P: PqScheme, S: Suite>`. The `Suite`
type carries the label bytes and the registry byte count. The composite logic
exists once and stays generic over all three parameters.

`PqStatefulScheme` is a sibling of `PqScheme`, not a subtype of it. A stateful
component cannot implement `PqScheme`: signing takes `&mut sk`, it spends a
one-time leaf, and the stateful signature length varies with the leaf index,
so the fixed `SIGNATURE_LEN` and immutable secret key that `PqScheme` declares
do not hold. `StatefulSuite` pairs a `ClassicalScheme` with a
`PqStatefulScheme` and carries the same label bytes and registry byte count.

### Suite declaration

One macro declares each instance:

```rust
hybrid_suite! {
    /// H3 - sr25519 + ML-DSA-44
    H3 = "sr25519" + "mldsa44" -> "hybrid-sr25519-mldsa44-v1", 26 bytes;
    public_key = 32 + 1312;
    secret_key = 64 + 2560;
    signature  = 64 + 2420;
}
```

The macro joins the label parts and adds the null byte. It then emits constant
assertions, and the build fails when any of these drift apart:

- the composed label and the registry literal
- the label length and the registry byte count
- a name token and the matching `ClassicalScheme::NAME` or `PqScheme::NAME`
- a declared size and the sum of the component trait constants

The macro also emits the concrete array types for keys and signatures. Stable
Rust cannot express `[u8; C::PK_LEN + P::PK_LEN]`, so the arithmetic moves to
the instantiation site. H1 and H3 then allocate nothing.

A second macro, `hybrid_stateful_suite!`, declares H5 and H6 against
`StatefulSuite`. It applies the same compile-time label checks. It does not
emit fixed signature array types, because a stateful signature length depends
on the leaf index and is only bounded at run time by
`max_stateful_sig_len(max_signatures)`.

## Message binding

Both components bind the same application message through `M'`:

```
M' = Prefix(0x01) || Label || len(ctx) || ctx || M
```

`Label` means the full null-terminated registry value. The same definition
applies inside the HKDF `info` string. See Finding 2.

For H5 and H6 the classical component signs `M'`. The SHRINCS component signs
a canonical action hash built from `M'`, where `payload_hash = keccak256(M')`.
Section 7.1 of the specification defines that mapping.

## Encodings

Three encoding shapes exist. Each shape gets its own module and its own
decoder.

| Shape | Constructions | Layout |
|-------|---------------|--------|
| Fixed | H1, H3 | `classical_sig(64) \|\| pq_sig(2420)` |
| Delta length | H2, H4 | `classical_sig(64) \|\| delta(1) \|\| falcon_sig` |
| Path selected | H5, H6 | `classical_sig(64) \|\| selector(1) \|\| body` |

Decoding follows parse-do-not-validate. A composite value exists only after
every check in section 6 passes.

For H5 and H6 the decoder runs these steps in order:

1. Recompute the commitment from the supplied bundle. Reject a mismatch.
   Reject an all-zero commitment.
2. Read `maxSignatures` from the checked bundle.
3. Reject any `PathSelector` other than `0x01` or `0x02`.
4. Reject `LeafCount` below 1 or above `maxSignatures`, before any allocation
   of the authentication path.
5. Reject trailing bytes beyond the implied length.

Step 4 runs before allocation. Otherwise a large declared authentication path
becomes a denial of service.

## Stateful constructions

### Where the stateful suites apply

Use a stateful hash-based suite only in a system that already keeps durable,
ordered state for each signing key. The one-time leaf budget, the
persist-before-release ordering, and the counter that cannot be restored all
assume such a system.

A signer rebuilt from a seed backup starts again at the first leaf and
reissues leaves it already spent. Leaf reuse is total loss of security for
that key, so seed restore is not a recovery path. Every other kind of caller
must use the stateless path or a lattice suite:

| Caller | Path |
|---|---|
| Transactional system with a durable ordered journal per key | Stateful path, H5 or H6 |
| Stateless service, replicated signer, or any signer restored from a seed backup | Stateless path, or H1 or H3 |

The library cannot check this property, so it is stated here and in the crate
documentation. `docs/design` is the normative statement.

### Layers

H5 and H6 are built in three layers.

1. `PqStatefulScheme` describes one stateful post-quantum component and carries
   both signing modes. `ShrincsScheme` implements it against `hashsigs-rs`.
2. `StatefulSuite` and `hybrid_stateful_suite!` bind a classical component to a
   stateful post-quantum component under one label.
3. A generic composite over `StatefulSuite` holds `keygen`, `sign_stateful`,
   `sign_stateless` and `verify`, and supplies
   `StatefulHybridSignatureScheme` through a blanket implementation. The
   composite logic exists once, as it does for the stateless suites.

The stateless and stateful traits stay separate because the borrow shapes
differ. Stateless signing takes `&sk`. Stateful signing takes `&mut sk`.
Section 11.x of the specification turns on that difference.

Three rules become structural instead of documentary:

1. **The secret key does not implement `Clone`.** A clone forks the state, and
   a forked state reuses a leaf. A `trybuild` compile-fail test asserts the
   missing implementation.
2. **The function signature encodes persist-before-release.** `sign_stateful`
   takes a `&mut impl LeafJournal`. It commits the advanced leaf index through
   that port before it builds the returned signature. A caller cannot hold a
   signature whose leaf is not already durable.
3. **A rejected message costs no leaf.** `precheck` is a trait obligation on
   the component, not a check inside its signing function. The generic
   composite calls it before it commits anything, so a message the component
   would refuse never reaches the journal. Placing the check inside the
   signing function would be too late: the leaf is already committed by then.
   Upstream `sign_stateful_action` does not validate its `ActionContext` and
   spends a leaf on one that can never verify, so the obligation sits at this
   layer. Tracked upstream as `pqhs-bz1.10`.

The composite also cross-checks the journal against the component counter
before it spends a leaf, which catches a journal that has drifted out of step
with the key.

The core crate defines the `LeafJournal` port only. The crypto crates do no
input or output.

Verification combines the two component results with a bitwise `&` on
`subtle::Choice` and returns `bool`. The short-circuiting `&&` is wrong here:
skipping the post-quantum half once the classical half fails reveals which
component rejected, which is the leak the hybrid construction exists to
prevent.

Stateful signing returns a typed error: `LeavesExhausted`, `GrindAbort` or
`SigningFailed`. The documentation and the tests treat `GrindAbort` as
non-retryable, because the reference randomizer is a deterministic function of
the key and the message.

## Seed derivation

```
prk            = HKDF-Extract(salt = "hybrid-sig", ikm = master_seed)
classical_seed = HKDF-Expand(prk, info = "classical/" || Label, L = 32)
pq_seed        = HKDF-Expand(prk, info = "pq/"        || Label, L = P::SEED_LEN)
```

The `info` string binds the suite label, as section 9 requires. Zeroize every
intermediate seed after use.

Junction derivation is hard only and applies to the whole suite. A junction
derives a new master seed, and both components derive again from it. Soft
junctions return a typed rejection.

For H5 and H6 a reproducible key is a function of the master seed, the suite,
the profile and `maxSignatures`. `maxSignatures` is not seed derived, so all
four values need a record. Never restore a signer by generating the key again
from the seed. That resets the leaf counter to 1.

## Error handling

Errors split by what they may reveal.

Decode and key handling errors stay specific, because they act on public data.
Examples: `BadPathSelector`, `LeafCountOutOfRange`, `TrailingBytes`,
`CommitmentMismatch`, `SoftJunctionRejected`.

Verification never reports which component failed. It combines the component
results with a non-short-circuiting `Choice` conjunction and returns one
`bool` at the API boundary. A per-component error would leak through the error
channel exactly what the constant-time combination prevents.

Library code holds no `unwrap` or `expect` outside tests.

## Testing

Write the tests before the code they cover.

- Section 17 tests 1 to 14, applied per construction as annotated there. Tests
  15 to 32 apply to H5 and H6.
- Golden vectors as checked-in JSON. Each vector records the suite label and
  the exact `info` construction. H5 and H6 vectors also record the leaf index
  and `maxSignatures`, because the same message at two leaves gives two
  different signatures by design.
- Property tests over encode and decode round trips, and over negative
  decoding. An arbitrary byte string must never decode into a valid composite
  signature.
- Run constant-time sensitive tests in release mode. The `subtle` crate uses
  `debug_assert` with secret-dependent branches.
- Run `cargo-mutants` over the encoding and domain separation modules, where a
  skipped check is the dangerous failure.
- Add `trybuild` compile-fail tests for the negative guarantees: no `Clone` on
  secret keys, and no `PartialEq` on secret types.

## Findings from the specification review

### Finding 1: The label registry is a name grammar

Every row of the section 7 registry regenerates from this grammar:

```
label = "hybrid-" classical "-" pq [ "-rotate" ] "-v1" NUL
```

All 16 rows match their stated byte counts under this grammar, including the
four rotation rows. The registry is a generated name, not a hand-written
string table. This design generates the label and checks it against the
registry value at compile time.

### Finding 2: The label includes a null byte

Section 7 states that labels are null terminated. The stated byte counts
confirm it. `hybrid-ed25519-mldsa44-v1` holds 25 characters, and the registry
lists 26 bytes. Every row is characters plus one.

Section 9 does not say whether that null byte belongs inside the HKDF `info`
string. The two readings give different keys from one master seed, and no
layer raises an error. This design pins one reading: `Label` means the full
null-terminated registry value, in `M'` and in `info` alike. A golden vector
covers the choice, and the crate documentation states it.

Recommendation: state the rule in section 9 of the specification.

### Finding 3: Derived keys differ from the deployed code

Section 9 requires suite-separated HKDF. Section 22 records that the shipped
`quip-crypto-primitives` uses a fixed `info` value of `pq` for every suite,
tracked as QuipNetwork/quip-protocol-rs#9. A conforming crate gives different
component keys from the same master seed than the deployed H1 and H3 code.

Both sides are self-consistent. This is a recorded incompatibility, not a
defect. The golden vectors state which derivation they cover.

### Finding 4: No stated value for `MIN_FALCON512_SIG_LEN`

Section 6 requires a `MIN_FALCON512_SIG_LEN` constant from the Falcon-512
specification, but never gives the value. The delta length encoding stays
untrustworthy until someone derives the constant and pins it with a test. This
blocks all H2 and H4 encoding work.

## Delivery plan

Beads epic `pqhs-8ep` covers Cycle 1, `pqhs-bz1` Cycle 2, `pqhs-qy5` Cycle 3,
and `pqhs-efg` Cycle 4.

### Done

Cycle 1: the workspace, `pqhybridsign-core`, and H1 and H3. Covers the
component traits, the suite macro, `M'`, the fixed encoding, HKDF derivation,
hard junctions, golden vectors, and specification tests 1 to 10.

Cycle 2: `pqhybridsign-shrincs` with H5 and H6. Covers `PqStatefulScheme`,
`StatefulSuite`, the generic stateful composite, the `LeafJournal` port, the
path-selected encoding, commitment verification, leaf-indexed golden vectors,
and specification tests 15 to 32.

### Next

Cycle 3: rotation payloads and the two-path acceptance policy, from sections
19 and 20.

Three decisions that Cycle 2 raised and did not settle: whether the composite
stateful secret key gets a validating import and export path
(`pqhs-utz`), whether the library ships the `MonotonicIndex` verifier the
specification names (`pqhs-rg3`), and whether continuous integration gains a
cross-profile job (`pqhs-yn0`).

### Later

Cycle 4: H2 and H4. Gated on final FIPS 206 and a stable `fn-dsa` release, and
blocked by Finding 4.

## Out of scope

- Substrate integration: `sp_core::Pair`, the keystore extension, the
  commitment registry pallet, and account identifier derivation.
- The hybrid VRF from section 15.
- Language bindings for WASM, Python and TypeScript.
- A Go version and cross-language vectors.

## Open questions

The three questions Cycle 1 opened are closed. The sr25519 signing context is
the per-suite label (`pqhs-8ep.9`). The `fips204` deterministic call is
confirmed (`pqhs-8ep.10`). The dependency graph resolves to one `rand_core`
major version, and continuous integration asserts it (`pqhs-8ep.11`).

Two remain, both about documents rather than code:

1. Specification section 8 writes the deterministic nonce as
   `k = H(sk || nonce || msg)`. The ed25519 component cannot implement it,
   because `ed25519-zebra` derives its nonce internally from the expanded
   secret key and accepts no external `k`. The implementable reading shipped.
   Tracked as `pqhs-8ep.19`.
2. Upstream `sign_stateful_action` spends a leaf on an `ActionContext` it
   never validates. The `precheck` obligation defends against it here, and the
   fix belongs upstream. Tracked as `pqhs-bz1.10`.
