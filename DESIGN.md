# Design: Rust hybrid post-quantum signature crates

**Status:** Implemented through Cycle 5
**Date:** 2026-08-10, revised 2026-08-16
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
| `pqhybridsign` | H1 through H4 | core, `ed25519-zebra`, `schnorrkel`, `fips204`, `fn-dsa` |
| `pqhybridsign-shrincs` | H5 and H6 | core, `pqhybridsign`, `hashsigs-rs` pinned by revision |
| `pqhybridsign-abi` | Type-erased API over a runtime suite enum. Every binding sits on it, because no C header, JavaScript function or Python module can name a type parameter | core, `pqhybridsign`, `pqhybridsign-shrincs` |
| `pqhybridsign-cffi` | C ABI, with a checked-in header | abi |
| `pqhybridsign-wasm` | WebAssembly and npm package. Signing is H1 through H4 only. H5 and H6 are verify-side only | abi |
| `pqhybridsign-py` | Python wheel on the `abi3-py39` stable ABI | abi |

H5 and H6 reuse the lattice crate classical components. They do not write
those schemes again. Those components come from `ed25519-zebra` and
`schnorrkel` through `pqhybridsign`. A license or dependency audit that
reads only this table misses those crates.

The workspace denies `unsafe_code` for every crate through
`[workspace.lints.rust]`. The five pure-Rust crates also set
`#![forbid(unsafe_code)]`, which no downstream attribute can relax. The two
binding crates cannot: `pqhybridsign-cffi` is the raw-pointer boundary, and
`pqhybridsign-py` links the `unsafe` that pyo3's macros generate. Each of the
two carries a crate-root allow naming its reason. The core and lattice
crates build for `wasm32-unknown-unknown` without an allocator. The SHRINCS
crate needs `std`, because the reference signer needs `std` today.

### ed25519 verification: ZIP-215 acceptance is stated, not mandated

The ed25519 component verifies under ZIP-215, through `ed25519-zebra`. It
accepts non-canonical encodings of the public key and of the signature's `R`
value, and it checks the cofactored group equation `[8][s]B = [8]R + [8][k]A`
rather than the cofactorless `[s]B = R + [k]A`.

RFC 8032 section 5.1.7 permits both equations, so checking the cofactored one
is not by itself a departure from RFC 8032. The divergence is confined to
section 5.1.3, which requires rejecting non-canonical encodings of `A` and `R`
where ZIP-215 requires accepting them. This design states that property of this
implementation. It does not require a second implementation to reproduce it.
Reproducing it is RECOMMENDED, not mandatory.

A second implementation that verifies with a stricter and more commonly
deployed verifier stays conformant. Go's `crypto/ed25519`, the `verify_strict`
path of `ed25519-dalek`, and the common Solidity ed25519 ports all qualify.
Such an implementation can still disagree with this one about whether a
specific attacker-supplied signature is valid. The attacker needs no secret
key: an ed25519 public key with no prime-order component, of order 2, 4 or 8,
makes a fixed forgery accept under ZIP-215 for almost any message, with `R`
and `s` as fixed public constants. Rejecting such a key is a `verify_strict`
convention. Neither RFC 8032 nor ZIP-215 requires it, so an implementation
that omits the check stays conformant to both while still disagreeing with
this one.

This is a difference in the accepted set, not a signature-malleability
finding. Malleability is closed under ZIP-215 and under strict verification
alike: `s` must be canonical, and the encoded bytes of `R` are hashed into the
challenge `k`, so an attacker cannot derive a second valid signature over one
message from a first.

The outputs of this library are unaffected. `derive` and `sign_deterministic`
always produce output that is valid under ZIP-215 and under strict
verification, so the disadvantage falls on a second implementation that takes
the stricter path, never on a signature this library produces. The test suite
splits along that line. The tests that pin our own outputs as strict-valid
fail the build, because this library controls those bytes. The tests that
probe the divergence in the accepted set print a warning and pass, because the
accepted set of a third-party verifier is not ours to bind, and a dependency
upgrade that narrows or widens the gap is not a defect in this library. See
the rustdoc on `pqhybridsign::classical::Ed25519` and
`crates/pqhybridsign/tests/ed25519_strict.rs` for the pinned vectors and the
demonstration at the H1 composite level.

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
documentation. This file is the normative statement.

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
3. **Every signing attempt burns a leaf.** `sign_stateful` commits the
   advanced leaf index before it attempts the component signature, and it
   validates nothing beforehand. An attempt the component then refuses still
   spends its leaf. The rule holds because a signing path that can return
   without advancing the counter is a leaf-reuse hazard, and reuse is total
   security failure for the key, while a burned leaf is only availability
   loss. Upstream `sign_stateful_action` behaves the same way, which is
   correct rather than a defect.

   The cost is real. A caller who can hand arbitrary messages to a stateful
   signer can exhaust its leaf budget. That is accepted, and it is another
   reason the stateful suites suit only the transactional systems described
   below: such a system authenticates and rate-limits a request before the
   signer ever sees it.

   Validation still runs, but after the signature exists rather than before.
   The component signs, which spends the leaf and advances both counters,
   and then checks the message. A message that fails becomes an explicit
   error instead of a signature that could never verify. The leaf stays
   spent. Placing the same check earlier would recreate the hazard, because
   the call would then return with the counter unmoved.

   `precheck` remains on the component trait, but it guards the stateless
   path, where no leaf exists, and `verify`, where a message no honest
   signer could have produced is refused before any cryptography runs.

The composite also cross-checks the journal against the component counter
before it spends a leaf, which catches a journal that has drifted out of step
with the key.

The core crate defines two ports and no input or output of its own.
`LeafJournal` is the signer side. `LeafIndexStore`, with
`accept_monotonic_leaf`, is the verifier side: it refuses a leaf index that
is not above every index already accepted, before any cryptography runs.

Both are needed. A signer journal stops one signer from reissuing a leaf. It
cannot stop a copied key, or a signer restored from a seed backup, from
reissuing the first leaf with a signature that is cryptographically valid.
Only a verifier that remembers rejects that. Acceptance requires strictly
increasing indices rather than merely unseen ones, because a set of seen
indices grows without bound and a verifier that must remember every index
forever eventually forgets.

### Persistence

`SecretKey::export` and `SecretKey::import` are the only correct way to
restore a stateful signer. The blob is

```text
ClassicalSK || PqSecretKey || nextLeaf(4, big-endian) || PqVerifyKey
```

Import validates in two layers. The component validates its own half, which
for SHRINCS means upstream re-derives the root from the private seeds and so
rejects a tampered root, a spliced field, and an out-of-range counter. The
composite then cross-checks its counter field against the counter the
imported component key holds, so the parts cannot be restored out of step.
`SecretKey::next_leaf` lets an integrator reconcile against the journal at
restore time rather than discovering drift at signing time.

The blob is plaintext secret material. An export followed by two imports is a
forked leaf budget, so treat it as a single-holder token. The journal binding
described below detects that fork rather than relying on the caller to avoid
it, but the blob still deserves single-holder handling: the binding stops a
second holder from signing, not from possessing the secret.

Verification combines the two component results with a bitwise `&` on
`subtle::Choice` and returns `bool`. The short-circuiting `&&` is wrong here:
skipping the post-quantum half once the classical half fails reveals which
component rejected, which is the leak the hybrid construction exists to
prevent.

Stateful signing returns a typed error: `LeavesExhausted`, `GrindAbort`,
`JournalFailed`, `CountersDiverged`, `JournalKeyMismatch` or `SigningFailed`.
The remedies differ, which is why the variants stay separate instead of
collapsing into `SigningFailed`. The documentation and the tests treat
`GrindAbort` as non-retryable, because the reference randomizer is a
deterministic function of the key and the message. `JournalFailed` means the
durable commit did not land and nothing was spent, so a retry is correct.

### The leaf journal records two facts

A stateful suite spends one single-use leaf per signature. Reissuing a leaf
discloses one-time key material and permits forgery, so leaf consumption must
be durable before a signature exists. The `LeafJournal` port is how the
integrator supplies that durability. The library performs no I/O of its own.

A journal records two facts, and both must be durable:

1. **How far the key has spent**, through `next_leaf` and `commit`.
2. **Which key it is spending for**, through `bound_key` and `bind_key`.

The second fact exists because the first cannot express it. Hand one exported
key blob to two journals that have each recorded nothing, and both report that
leaf `0` is next. Each answer is honest: for a journal that has never seen this
key, `0` is correct, and it is identical to what one correctly reopened journal
reports for a key that has spent nothing. No comparison of counters separates
those two situations. Signing on that agreement spends leaf `0` twice, under
two different messages, and both signatures verify against the same public key.

#### Key identity comes from public material

A journal names its key with a `KeyIdentity`: a fixed 32-byte value derived by
hashing a versioned domain separator together with the suite label and the
post-quantum verify key, each length-prefixed.

The derivation uses public material only. Journals are persisted to files and
database rows that are not held to secret-key handling standards, so an
identity computed over secret key bytes would push secret material into storage
that is not built to protect it. The verify key is material a verifier already
holds and a signature already travels with, so the identity discloses nothing
new. It may be logged, stored in the clear, and compared with an ordinary
equality test: there is no secret for a timing difference to leak.

An identity is not a capability. Holding one lets a caller name a key, not sign
for it. The public key and the secret key blob for one key derive the same
identity, so either side can compute it.

The domain separator is versioned. Changing the derivation orphans every
journal record already written under the old one.

#### Adoption is explicit

A journal that has never seen a key cannot refuse one: it has nothing to
compare against. Binding is therefore an explicit, durable step the integrator
writes once, when the key's durable journal is created:

```text
identity = key_identity(suite, public_key)
adopt_key(journal, identity)
```

`adopt_key` has three outcomes. A journal that has never been bound records the
identity durably and returns success. A journal already bound to the same key
writes nothing and returns success, so an idempotent provisioning step is safe
to re-run. A journal bound to a different key writes nothing and fails with
`JournalKeyMismatch`. A journal belongs to one key for its whole life, because
the leaf numbers in it mean nothing under another key.

Call it once per key, at provisioning time. Calling it on a fresh journal at
every process restart reinstates the defect it closes: each restart would mint
a new binding, and each new journal would start the leaf budget over.

Every signing path checks the binding first, ahead of the budget read and ahead
of any commit. A journal that does not belong to the key holds counters that
mean nothing for it and must not be read as a budget.

The refusal lands earlier than that, at load. `load_stateful_secret_key`
rejects a journal that does not belong to the key, so a mispaired journal
fails when the key is constructed rather than at the first signature. This is
deliberate and stronger than deferring the check, because it fails before the
caller holds a signer it believes is usable. It is called out here because an
integrator reading only the signing documentation would not expect it.

#### `JournalKeyMismatch` against `CountersDiverged`

These are different failures and call for different recovery.

`CountersDiverged` means two counters that were once in step no longer are. The
key is finished. Rotate it. Do not repair the counters by hand: whichever
counter is behind names a leaf the other may already have spent.

`JournalKeyMismatch` means the journal is not this key's journal. It has never
been bound, or it is bound to a different key. It fires even when the counters
agree perfectly, and that agreement is exactly what makes the case dangerous.
The key is intact and the pairing is wrong. Recover by reopening the durable
journal that belongs to this key. It is not a reason to rotate.

Only if no such journal exists, for a new store whose spending history is known
by other means, call `adopt_key`. Understand that doing so for a key that has
signed before, against a journal that does not know it, reissues every leaf
that key has already spent.

#### Implementing the journal

Implementations must persist the identity in the same durable storage the
counter lives in, and it must survive a restart. A journal that forgets which
key it belongs to accepts any key, which is the whole of the hazard.

`bound_key` returning "not bound" must mean *never bound*, never *could not
read*. That answer is what `adopt_key` treats as an invitation to write, and
binding over a record that already exists forks the leaf budget. An
implementation that cannot read its storage must fail at construction, before a
journal value exists.

An implementation that can enforce write-once in its storage, through a
`UNIQUE` column or an `O_EXCL` create, should do so. That enforcement survives
a caller who reaches past this library.

#### Upgrading an existing integration

`LeafJournal` gains two required methods, so this is a breaking change for
every integrator that implements it. The break is deliberate. A silent upgrade
would leave existing journals unbound and the hazard open.

Rust implementations stop compiling until `bound_key` and `bind_key` are added,
which is the outcome to want: the compiler names every site that needs durable
storage for the 32-byte identity alongside the counter.

Python implementations do not get that. A journal class written against the old
contract raises `AttributeError: 'Journal' object has no attribute 'bound_key'`
on the first call, not `JournalKeyMismatchError`. The behaviour is correct and
fails closed, but the message names the missing method rather than the reason it
now exists, and it is the first thing a Python integrator meets on upgrade. Say
so in the changelog in those words, so the error is recognisable before anyone
has to debug it.

### The stateless budget is enforced by types, not by documentation

The stateless path carries a hard security bound of its own: `2^20` signatures,
`2^18` under the `profile-128s-q18` profile. The bound is shared across every
stateless signature, every rotation authorization, and every recovery a key
ever performs. Exceeding it degrades the security assumption of the underlying
few-time signature scheme, so it is not a quota a deployment may enforce
loosely.

`StatefulHybridSignatureScheme::sign_stateless` and `rotation::sign_rotation`
each take a required `&mut impl StatelessBudgetStore`, so neither can be called
without a durable store to charge. This is the discipline the leaf journal
follows, for the same reason: an obligation a caller can forget is not an
obligation.

The spend is made durable before the signature is built. A crash between the
two wastes one unit of budget, which is acceptable. Releasing a signature whose
spend is not yet durable is not, because a restart would hand the same unit out
again.

#### How the stateless budget differs from the leaf journal

Both are durable-state ports the integrator implements. Three things separate
them.

The budget is **keyed to the stateless key material**, `pkSeed ||
hypertreeRoot`, hashed to a 32-byte `BudgetKey`. A leaf journal instead holds a
bare counter and a separately recorded `KeyIdentity`, because a counter alone
cannot say whose leaves it counts. The budget needs no such record: identity is
inside the lookup key. Two keys sharing stateless material always resolve to
the same `BudgetKey`, and two keys with different stateless material never do.

It follows that the budget needs **no adoption step**. `adopt_key` exists
because a fresh journal and a correctly reopened one both report leaf `0`, and
only an explicit binding separates them. A budget store that has never seen a
given material reports nothing for that material alone, and cannot be mistaken
for a store holding another key's count. There is nothing for an adoption
ceremony to protect.

The budget is **shared**, not per key. One store serves every key a process
holds, and it is drawn on by ordinary stateless signing, by rotation
authorization, and by recovery. Ordinary application signing never touches it:
leaves and the stateless budget are separate bounds, with separate exhaustion
errors and separate remedies.

#### What a rotation does and does not reset

`sign_rotation` charges the pre-rotation material, which the function derives
itself from the key's own cached verify key. No caller can aim the charge at
the material a rotation is about to install.

A rotation therefore resets the budget only when the stateless material
actually changes. A stateful-only graft leaves the material untouched and
continues the same count. A rotation labelled `FullSwap` whose stateless half
happens to be identical also continues the same count, even though its
commitment and its next classical key both change on install: the `BudgetKey`
is a function of the material and of nothing else. Only a rotation that
genuinely changes `pkSeed || hypertreeRoot` starts a fresh count, and the old
material's count is left exactly where it was.

### Rotation

Rotation assigns future signing authority, so it is the one operation where a
single surviving component is not enough. Section 19.2 requires an AND gate:
both the classical co-signature and a stateless SHRINCS signature, never
either alone. A single-component rotation path would let one compromised
component redirect all future authority, which drops the composite below its
own guarantee at the worst possible moment.

Each suite carries a second compile-time label, `ROTATE_LABEL`, composed as
`"hybrid-" classical "-" pq "-rotate-v1"` plus the null byte and checked
against the registry the same way the ordinary label is. An ordinary signature
cannot be spliced in as a rotation co-signature, because the message differs.

`RotationKind` is its own type. It shares the values `0x01` and `0x02` with
the wire format's `PathSelector`, and the specification forbids merging them.
No conversion exists between the two, in either direction.

`verify_rotation` returns the next stored public key rather than a boolean.
Section 19.3 requires the classical key and the new commitment to install
together, atomically. A boolean forces a second install
step that a caller can invoke on its own. That is the non-atomicity the
section forbids, so the type carries the result instead.

**`NextClassicalPK` is bound twice, by independent mechanisms.** It sits
inside the rotation payload, so `M'_rotation` covers it, and it is folded into
the stateless signature's rotation domain separator,
`keccak256("hybrid-rotate-ds" || NextClassicalPK || RotationKind)`. Each
binding alone defeats the front-running attack section 19.2 describes.
Removing one binding and watching the attack still fail confirmed this, from
both sides.
The specification only requires the domain separator, because it assumes the
stateless signature covers the commitments alone. Signing over `M'_rotation`
makes the message binding a second, redundant defence rather than a
replacement.

### SHRINCS profile geometry, and why 128s keygen costs 47 seconds

Recorded here because it was reconstructed twice from timings and should not
have to be reconstructed a third time.

Measured in release, one H5 key with four leaves, by
`crates/pqhybridsign-shrincs/tests/profile_timing.rs`:

| Profile | keygen | sign_stateful | sign_stateless | Stateless signature |
|---|---|---|---|---|
| `profile-256s` | 0.09 s | under 0.01 s | 1.16 s | 29,157 B |
| `profile-256s-sha2` | 0.03 s | under 0.01 s | 0.33 s | 29,157 B |
| `profile-128s-q18` | 46.85 s | under 0.01 s | 176.60 s | 5,769 B |
| `profile-128s-q20` | 47.47 s | under 0.01 s | 166.51 s | 5,769 B |

Debug builds run about 70 times slower. Never quote a debug figure as a
performance characteristic.

Key generation costs hypertree geometry. Stateless signing costs FORS
geometry. Grinding is a small part of each, which the next subsection
measures. The parameter sets, from the SHRINCS Implementations overview,
which is the authority shared by the Solidity and Rust implementations:

| Parameter | `256s`, `256s-sha2` | `128s-q18`, `128s-q20` |
|---|---|---|
| Hypertree | `h = 64`, `d = 8` layers | `h = 18`, `d = 1` (single layer) |
| FORS-C | `k = 22` trees, height `a = 14` | `k = 6`, `a = 24` |
| WOTS-C chains | 64, target sum 480 | 32, target sum 240 |
| Hash length | 32 B | 16 B (truncated, high-aligned) |

`d` is the standard SPHINCS+ knob trading signature size against key
generation and signing time, and the two profiles sit at opposite ends of it.
Key generation builds the top subtree, whose height is `h / d`. At `d = 8`
that is 2^8 = 256 leaves. At `d = 1` it is the whole tree, 2^18 = 262,144
leaves: a 1024-fold difference in leaf count against a measured 520-fold
difference in time, the remainder being the cheaper 16-byte hash.

What the single layer buys is signature size. A stateless signature carries
one WOTS-C signature plus one authentication path per layer, so eight layers
of height 8 cost far more than one layer of height 18. The arithmetic matches
the measurements: at 256s the hypertree part is 8 × 2048 B of WOTS-C plus 64
nodes, about 18.4 kB, against 1 × 1024 B plus 18 nodes, about 1.6 kB, at
128s. Add the FORS-C part (21 revealed trees of height 14, against 5 of
height 24) and the totals land on the 29,157 B and 5,769 B actually measured.

#### Where a 128s stateless signature spends its time

Measured 2026-08-16, and recorded for the same reason as the rest of this
section: so that nobody derives it a fourth time.

The FORS-C grind rate comes from the upstream
`measure_128_fors_signature_success_rate` test. That test uses a placeholder
hypertree root, so it times the grind alone: 74,983,923 counter attempts in
50.63 seconds, which is 1,481,018 attempts per second, or 675 nanoseconds
each.

| Component | Cost | Why |
|---|---|---|
| FORS tree construction | about 117 s | 5 signed trees of 2^24 leaves |
| Hypertree subtree | about 47 s | 2^18 leaves in one layer |
| FORS-C counter grind | 11.3 s | mean 2^24 attempts |
| WOTS-C target-sum grind | under 0.1 s | mean 65.7 attempts |

**Grinding is about 6 percent of the cost, not the bulk of it.** The WOTS-C
target sum is not a rare event either: `WOTS_TARGET_SUM` is 240, the exact
mean of the sum of 32 base-16 digits, so each attempt succeeds with
probability 0.0152. Both source papers choose the target sum that way on
purpose, to minimise the search.

The `a = 24` FORS tree height drives everything above. It sets the grind
exponent, the 2^24-leaf trees, and the memory the upstream crate had to fix
with a streaming treehash. It is also **taller than any FORS tree in either
source paper**: SPHINCS+C tops out at a removed-tree height of 19, and
Kudinov and Nick use `a` between 14 and 16 across every parameter set,
including the ones for 2^20 signatures. The 256s profiles, at `a = 14`, sit
inside that range and sign in about a second.

**The internal documents record the parameter values, not the reason for
them.** `hashsigs-rs` states only that its constants mirror the Solidity
`SHRINCSParams` libraries. The reading above follows from the structure of
SPHINCS+ and is confirmed by the size arithmetic, but no document says "we
chose `d = 1` to shrink the signature". Treat it as a well-supported
inference. On-chain, where signature bytes are calldata gas paid on every
verification and key generation happens once off-chain, the trade is a
sensible one.

Two consequences for this crate:

- A recovery runbook for a 128s deployment must budget about three minutes
  for a stateless rotation or recovery signature. The Solidity measurements
  go further and call in-process stateless signing "compute-infeasible at
  128s" for their test harness.
- The overview flags that the `q20` profile's 2^20 stateless budget "wants
  profile security-analysis backing before production use". `q18` and `q20`
  are otherwise identical. This crate exposes both, so that caveat travels
  with it.

References: the constructions come from Kudinov, Hülsing, Ronen and Yogev,
*SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost*, ePrint 2022/778,
and from Kudinov and Nick, *Hash-based Signature Schemes for Bitcoin*,
ePrint 2025/2203.

Checked on 2026-08-16: **neither paper uses the name SHRINCS or the name
UXMSS.** Both supply the theory that SHRINCS instantiates. Neither supplies
its names. An earlier revision of this section cited 2025/2203 as the
definition of SHRINCS, with UXMSS in its appendix B.3. That citation does
not hold, and no public document defines SHRINCS by name.

### Verifier-side acceptance policy

Section 20 puts path acceptance in verifier state, not in the cryptographic
layer. The layer verifies what it is given and holds no policy.

The policy machine tracks leaf consumption under exactly one active policy per
key epoch: `MonotonicIndex`, `LeafBitmap`, or `RecoveryRotation`. It is total
and fails closed, and the type system carries that rather than a runtime
check: each variant holds only the sub-state its policy has, so an armed
`MonotonicIndex` or a frozen `RecoveryRotation` has no representable value.
The freeze and arming flags are two-variant enums rather than booleans, for
the same reason.

Accept and mark-consumed are one step, in the order `accept_monotonic_leaf`
already established: record first, and refuse if recording fails. Once a leaf
is consumed in an epoch the choice between the two consuming policies freezes,
because switching or reconciling two representations re-opens consumed leaves.
The owner-authorized move to `RecoveryRotation` stays available even when
frozen, or a key that had signed once could never be rotated.

`LeafBitmap` is a fixed 512-byte array, 4096 bits, matching the leaf capacity
limit. It is not an allocation, so the module works where core has no
allocator.

## Seed derivation

```
prk            = HKDF-Extract(salt = "hybrid-sig", ikm = master_seed)
classical_seed = HKDF-Expand(prk, info = "classical/" || Label, L = 32)
pq_seed        = HKDF-Expand(prk, info = "pq/"        || Label, L = P::SEED_LEN)
```

The `info` string binds the suite label, as section 9 requires.

The derivation zeroizes the PRK and every intermediate seed after use, with
one residual that the code cannot remove. `Hkdf` holds the same key as an
`hmac` 0.12 `HmacCore`, whose primed ipad and opad states expand exactly what
the PRK expands. That type implements neither `Drop` nor `Zeroize` and exposes
no field to reach, so neither `derive_component_seeds` nor any caller can wipe
it. The fix in `derive.rs` removes one of the two copies, not both.

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

Durable-state failures stay separate from each other and from
`SigningFailed`, because their remedies differ and a caller that cannot tell
them apart handles all of them wrongly.

| Error | Meaning | Remedy |
|-------|---------|--------|
| `JournalFailed` | The leaf commit did not land. Nothing was spent. | Transient. Repair the storage fault and retry. |
| `CountersDiverged` | The key counter and the journal no longer agree. | Permanent. Rotate. Never repair the counters by hand. |
| `JournalKeyMismatch` (ABI 18) | The journal is not this key's journal, whatever its counters say. | Reopen the journal that belongs to this key. Not a reason to rotate. |
| `StatelessBudgetExhausted` (ABI 19) | The few-time bound for this key's stateless material is spent. Nothing was spent on the refused attempt. | Permanent for this material. Rotate to material that actually differs. Do not raise the bound. |
| `BudgetStoreFailed` (ABI 20) | The budget store could not durably record the spend. Nothing was recorded. | Transient. Repair the storage fault; the same unit is still available. |

Library code holds no `unwrap` or `expect` outside tests.

`pqhybridsign-core` and `pqhybridsign-abi` write `fmt::Display` and
`Error` by hand. They do not depend on `thiserror`. Core builds with no
`std` and no allocator, and decision 2 keeps the dependency surface small.
Do not add the proc-macro crate to "fix" this.

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

### Test suite runtime

The suite runs under a fixed budget: 30 seconds per test as a target and 120
seconds as an absolute ceiling, with 4 minutes for the whole suite and 2
minutes preferred. Five choices hold it there.

**Dependencies build optimised, workspace crates do not.** The workspace
`Cargo.toml` sets `opt-level = 3` for `profile.dev.package."*"`. Hash-heavy
code runs about 67 times slower when its dependencies compile unoptimised,
which is what made one test binary take 184.80 seconds. Cargo still passes
`-C debug-assertions=on`, so the `subtle` assertions that the debug job
exists to exercise still run.

**Per-profile fixtures replace live signing.** Each profile has a fixture in
`crates/pqhybridsign-shrincs/tests/vectors/` holding the exported secret key,
the public key, and one signature of each kind. Tests verify stored
signatures instead of producing them, and verification costs under 0.01
seconds at every profile. `tests/generate_fixtures.rs` regenerates them and
carries `#[ignore]`. A missing fixture is a compile error and a mismatched
one panics with the regenerate command. Neither falls back to key
generation, because a fallback restores the cost silently.

**`SecretKey::import` is not a shortcut at 128s.** Upstream `Keys::import`
re-derives the hypertree root to validate the blob, so it costs about what
`keygen` costs. A test that needs a live secret key at 128s calls `keygen`
instead: the price is the same and the coverage is better. The stored blob
serves the 256s profiles and the scheduled job.

**Tests tier by whether they depend on the profile.** Tests of the
composition layer, covering leaf budgets, journals, the rotation gate and
tamper rejection, behave identically under every parameter set. They gate to
the default profile with `#![cfg(feature = "profile-256s")]` and run once.
Running them under four profiles tests `hashsigs-rs` four times rather than
this crate. Profile-dependent assertions live in
`tests/profile_conformance.rs` and run everywhere.

**One real 128s operation survives per commit.** `tests/smoke_128s.rs`
generates a key under `profile-128s-q18` and compares the public key against
pinned fixture bytes, which covers the whole 2^18 hypertree root derivation.
It carries `#[ignore]`, and a dedicated job runs it. Adding `q20` buys no
coverage, because the two profiles differ only in the stateless budget.

Measured cost per commit: 16.5 seconds for the workspace, 8.2 seconds for
the four-profile matrix, and 46.3 seconds for the smoke test. About 71
seconds in total.

What this gives up: no per-commit run produces a 128s stateless signature, so
the FORS-C grind, the WOTS-C grind and hypertree signing wait for the
scheduled `regenerate-fixtures` job. That job is also the only detector of
fixture staleness on the signing paths.

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
specification, but never gives the value.

**Resolved on 2026-08-10, and the premise turned out to be stale.** Section 6
describes Falcon-512 signatures as variable-length, up to 666 bytes. The
`fn-dsa` crate at version 0.4.0 produces a **fixed** 666-byte signature, with
a 897-byte verifying key and a 1345-byte signing key. Those three numbers come
from building the crate and running it, not from its documentation. FN-DSA
pads to a constant size where the earlier compressed Falcon format did not.

The maintainer chose to keep `FalconLen` as a real length field rather than
drop it or freeze it at zero, so the encoder computes it from the actual
length and the decoder honours whatever it reads.
`MIN_FALCON512_SIG_LEN` is pinned at **411**: the field is one byte
and spans 256 values, the largest signature the component emits is 666, so
the smallest representable length is `666 - 255`. Pinning the minimum at 666
would leave the field able to encode only lengths at or above the maximum,
which points the wrong way.

Specification section 6 still describes the variable-length shape. That text
needs an update, tracked separately, and this section records the measured
values in the meantime.

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

Cycle 3: rotation and the two-path acceptance policy, from sections 19 and
20. Covers the 97-byte rotation payload, the per-suite rotate labels, the
AND-gated rotation verification, the leaf-tracking policy machine, and the
stateless budget accounting.

The three decisions Cycle 2 raised are settled and built: the composite
stateful secret key has a validating export and import path (`pqhs-utz`), the
`MonotonicIndex` verifier ships in core beside `LeafJournal` (`pqhs-rg3`), and
continuous integration runs a cross-profile job that compares commitments
rather than labels (`pqhs-yn0`).

Cycle 4: H2 and H4, over `fn-dsa` 0.4.0. The maintainer decided on 2026-08-10
to ship these now rather than wait for a final FIPS 206, having been told that
the standard may change the wire format and that signatures made before then
could stop verifying. The dependency set the workspace Rust floor to 1.82.
The pinned `hashsigs-rs` revision later raised that floor to 1.89.

Cycle 5: the language bindings, all on `pqhybridsign-abi`. The C ABI with a
checked-in header, the WebAssembly and npm package, and the Python wheel.

The WebAssembly binding signs under H1 through H4 only. A JavaScript object
holding a stateful secret key can be structured-cloned, and a clone forks the
leaf counter. No H5 or H6 key generation or signing operation reaches
JavaScript. Verification does. `storedPublicKeyLen` reports the on-storage
public key size for any suite, and `verifyWithStoredPublicKey` checks an H5 or
H6 signature against that stored form. Neither function touches a secret key.
To sign under H5 or H6, use the C ABI or the Python binding.

`verify_with_stored_public_key` closes a real gap in the C ABI and the Python
binding. `pqhs_verify` and `phs.verify` take an H5 or H6 verify key with no
commitment to check it against, so the caller must establish that key's
provenance itself. The WebAssembly binding never had that gap, because its
`verify` already refused H5 and H6. There the function adds a capability
rather than closing a gap.

Rotation and the policy machine stay out of the binding surface for the first
release candidate. Both need registry state that lives in the integrator's
system, and exposing half a state machine across a C boundary invites the
misuse the state machine exists to prevent.

### Next

Cycle 5 shipped the C, Python, and WebAssembly bindings. They are no
longer next work. Rotation and the policy machine stay out of the first
release-candidate binding surface. The Cycle 5 paragraph records that
limit.

Two defects block a first crates.io release. Both are tracked, and the
upstream merge request this crate pins resolves neither.

- `pqhs-eig`: no crate that resolves a dependency from a git source can be
  published. crates.io serves `hashsigs-rs` 0.0.1 and 0.0.2, which predate
  SHRINCS and declare no features at all.
- `pqhs-4kc`: the 128s FORS-C grind cap. See the open question below.

### Later

Both items above wait on upstream `hashsigs-rs`. Nothing else is gated on an
external event.

## Out of scope

- Substrate integration: `sp_core::Pair`, the keystore extension, the
  commitment registry pallet, and account identifier derivation.
- The hybrid VRF from section 15.
- A Go version and cross-language vectors.

## Open questions

The three questions Cycle 1 opened are closed. The sr25519 signing context is
the per-suite label (`pqhs-8ep.9`). The `fips204` deterministic call is
confirmed (`pqhs-8ep.10`). The dependency graph resolves to one `rand_core`
major version, and continuous integration asserts it (`pqhs-8ep.11`).

Two more were raised against Cycle 2 and resolved on 2026-08-10. Neither was
a defect. Both readings are recorded here because the implementation depends
on them.

1. Specification section 8 writes the deterministic nonce as
   `k = H(sk || nonce || msg)`. The requirement is secure determinism, not an
   externally injected `k`. ed25519 already meets it: RFC 8032 derives the
   nonce from the expanded secret key and the message, so
   `Ed25519::sign_deterministic` ignores its `nonce` argument and remains
   compliant. sr25519 offers no native equivalent, so `classical/sr25519.rs`
   implements section 8 literally, seeding a deterministic RNG from
   `H(sk || nonce || msg)` and denying `schnorrkel` any access to the
   operating-system RNG. Closed as `pqhs-8ep.19`.
2. Upstream `sign_stateful_action` spends a leaf on an `ActionContext` it
   never validates. This is the intended behaviour, for the reason given in
   the third structural rule above, and the composite now matches it. Closed
   as `pqhs-bz1.10`.

### The 128s FORS-C grind cap, open as `pqhs-4kc`

`FORS_C_MAX_GRIND_COUNTER` is 2^28 at both 128s profiles. The FORS-C search
succeeds with probability 2^-24 per attempt, so the cap gives up on a
fraction `exp(-16)` of messages, about 1 in 9 million. That failure is
deterministic for one key and message, because the randomizer is a pure
function of both, so a retry of the same message cannot succeed. It is loud,
returning `Error::ComponentFailure`, and it carries no security consequence.
The cost is availability on the rotation and recovery path.

Both source papers bound the search, and both put the bound above the value
in use:

| Source | Convention | Required cap at `a = 24` |
|---|---|---|
| SPHINCS+C, section 6.2 | worked example at `p = 2^-32` | 2^28.47 |
| Kudinov and Nick, tables 1 and 2 | tabulated at `p = 2^-30` | 2^28.38 |

2^29 is the smallest power of two that satisfies both conventions, and it
puts the failure rate at 2^-46. Raising the cap does not change the expected
signing time, which stays at 2^24 attempts either way. It doubles the worst
case, and the worst case is reached only on a message that fails today.

**The position as of 2026-08-16 is to accept the limitation and not act.**
The evidence is recorded so that the choice stays deliberate rather than
inherited. Note that neither paper specifies a cap at all: the bound is an
addition by `hashsigs-rs`, and section 6.2 of SPHINCS+C is the formula for
setting one.
