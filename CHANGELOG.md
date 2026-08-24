# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.0.0-rc6

rc6 adds one type-level guarantee and one accessor to the public surface, and
otherwise closes gaps in how this project verifies itself. The signature suites
and the wire format do not change. The only breaking change is the
`sign_stateless` signature, which is behind the non-default `vrf` feature.

### Added

- `CommittedVerifyKey::compute_committed_key`, the inverse of
  `verify_committed_key`, and `PublicKey::stored_form`, which builds the small
  on-storage form of a stateful public key from a verify-form key. Callers who
  held a verify-form key had to slice the classical prefix and the commitment
  at a hard-coded component offset, which put component layout into
  application code. `bundle::commitment` is factored out of `verify_bundle`,
  so the side that computes a commitment and the side that checks one share
  one implementation and cannot drift apart.
- `vrf::DedicatedVrfKey` and `DedicatedVrfKey::adopt_unchecked` (behind the
  `vrf` feature). The type does not prove disjointness, and no type could:
  disjointness is a property of where key material came from, not of its
  shape. It makes the claim explicit and greppable.
- `StatefulKeyHandle` in `pqhybridsign-abi`, with `pqhs_stateful_key_open` in
  C, `StatefulSecretKey` holding the handle in Python, and `openStatefulKey`
  in the npm package. Importing a stateful key re-derives the hypertree root,
  which costs about 47 seconds at the `128s` profiles. A handle pays that once
  instead of once per signature.
- VRF, BIP39 mnemonic and hard-junction derivation in all four bindings. A C,
  Python or JavaScript caller can now evaluate a VRF, turn a recovery phrase
  into a master seed, and derive a child key. The stateful suites prove
  through a dedicated stateless key that the bindings derive under a label
  disjoint from the identity key. The bindings expose derivation only:
  `adopt_unchecked`, which rests on a caller's unverifiable assertion, stays
  inside the Rust ABI.
- `PqHybridSignPanic` in the npm package. A WebAssembly trap now reaches a
  JavaScript caller as a distinct error class rather than trapping the
  instance silently. The cached instance is discarded, and the package's own
  test suite exercises the reload under Node. In a browser the reload depends
  on a cache-busting re-import that the suite does not run, so treat a retry
  there as best-effort.
- A stateful key handle poisons itself after a trap. Once any call on a
  handle throws `PqHybridSignPanic`, every later call on that handle throws
  the same error instead of reaching the dead instance, including `free`.

### Changed

- **Breaking, behind the `vrf` feature.** `vrf::sign_stateless` takes a
  `DedicatedVrfKey` rather than a `SecretKey`. Nothing previously stopped a
  caller passing one key to both `rotation::sign_rotation` and the VRF, which
  spends on ordinary VRF evaluation the stateless reserve that rotation and
  recovery depend on. Documentation and one isolation test were the only
  things standing between a caller and that. `derive_stateless_key` now
  returns a `DedicatedVrfKey`, so the derived path needs no change at the call
  site. Key material of any other provenance enters through
  `adopt_unchecked`, whose name puts the claim in front of a reviewer.
- `DESIGN.md` records why rotation is offered for the stateful suites only.
  This is an exception to the principle that every algorithm should support
  every mechanism, and it is recorded as one rather than left to look like an
  unfilled gap. `RotationKind::StatefulGraft` grafts a fresh stateful tree
  onto the unchanged stateless-verify half, and a suite with no tree has no
  target for it. `RotationKind::FullSwap` replaces the stateless material that
  `PqStatefulScheme::stateless_key_material` exposes, and a lattice suite's
  post-quantum type never implements that trait.
- The WebAssembly crate documents that a panic traps the instance.
  `wasm32-unknown-unknown` builds its standard library with `panic = "abort"`,
  so `catch_unwind` cannot contain a panic there and the C ABI's
  per-entry-point guard has no equivalent. The trap does reach JavaScript as a
  catchable `WebAssembly.RuntimeError`, and catching it does not make the
  instance sound. Every export was audited for a panic reachable from
  caller-controlled input, and none was found.
- The C and Python test helpers that built a stored public key by slicing the
  bundle at a fixed offset now recompute it through `PublicKey::stored_form`.
- The stateful durability rule gains its one exception. A caller still
  exports and persists the advanced key after every signing call, including
  a call that failed, because a stateful signer advances its leaf counter on
  failure as well as on success. A call that threw `PqHybridSignPanic` is the
  exception: the instance is gone, there is no advanced key to export, and
  the caller's leaf journal is the only durable record of what was spent.

### Fixed

- `adopt_key` refuses adoption when the journal binding read faults. A bridge
  reports a throwing `boundKey` to the abi as `None`, which the abi reads as
  never-bound: it would call `bindKey` and only then let the deferred
  exception surface, silently replacing an existing binding on a journal whose
  `bindKey` is not write-once. The read now happens once, before anything can
  write, and the fault surfaces first.
- Both journal bridges clear their memoized binding read when `bindKey`
  succeeds, so a read after a write cannot return a cached `None`. No current
  caller reads the binding again after binding it, so this maintains an
  invariant rather than repairing a reachable fault.
- Every continuous integration job now runs in merge-request pipelines. A job
  that declares no rules is excluded from one by GitLab's own default,
  whatever the `workflow` block allows, so a merge-request pipeline contained
  one job, and that job is allowed to fail. The merge widget showed green over
  a pipeline that had compiled nothing.
- `DESIGN.md` stated the section 7 label registry holds 16 rows including
  four rotation rows. It holds 13 rows, and rotation is one templated row
  whose four byte counts are one per profile and cover all eight composed
  labels.
- `cargo test --workspace` now fails when the checked-in wasm TypeScript
  definitions are stale. The check ran only in the `wasm-npm` CI job before.
- CI runs the `wasm32-unknown-unknown` test target. Nothing ran it before.

## 0.0.0-rc5

rc5 completes the hybrid VRF across every suite and closes two ways the
stateful suites let a caller spend key material the specification reserves for
something else. It carries one silent breaking change: stateful verification
now requires the caller to name a path, and the entry point that changed
behaviour kept its name and signature. Read the first `Changed` entry before
upgrading. The signature suites and the wire format do not change, and a build
that enables no new feature is unchanged from rc4.

### Added

- `vrf::derive_stateless_key` (behind the `vrf` feature), which derives a
  SHRINCS key dedicated to a stateful suite's hybrid VRF stateless binding
  from a master seed, under a new HKDF info label, `derive_stateless_vrf_seed`
  in `derive`. Opt-in: nothing calls it automatically, so a deployment that
  never evaluates a VRF pays nothing extra, and the identity key's exported
  blob, `VERIFY_PUBLIC_KEY_LEN` and keygen path are all unchanged.
- An RFC 9381 `ECVRF-EDWARDS25519-SHA512-TAI` for the ed25519 component, which
  gives `hybrid-ed25519-mldsa44-v1`, `hybrid-ed25519-falcon512-v1` and
  `hybrid-ed25519-shrincs-*-v1` a hybrid VRF. Every suite now supports the
  mechanism. rc4 shipped it for the sr25519 suites only. The construction is
  unchanged: the classical pre-output carries uniqueness, and the
  post-quantum binding is verified but never enters the output derivation.
  The test suite runs the RFC's own Appendix B.3 vectors as known answers. A
  pre-output followed by its proof is exactly the RFC's 80-byte `pi_string`,
  so any other RFC 9381 code can read a proof. `alpha_string` is
  the suite label and the caller's input, each length-prefixed, which
  separates two suites derived from one classical key. Key validation (RFC
  9381 section 5.4.5) is always on, and point decoding follows RFC 8032
  section 5.1.3 rather than the ZIP-215 rule this component's signature
  verifier takes: a VRF that two honest verifiers read differently is a chain
  split.

### Changed

- **Breaking, and a silent one.** Verification of the stateful suites now
  requires the caller to name a path, the way signing already did. The
  composite `verify` is gone, replaced by `verify_stateful` and
  `verify_stateless`, each refusing a signature that carries the other path's
  selector before either component signature is checked. The old call decoded
  the wire `PathSelector` byte and dispatched on it, so the signature chose
  its own verification path. Specification section 20.2 requires the opposite:
  the stateless key is reserved for rotation and recovery and must not be
  accepted for ordinary application messages.

  The part to watch is the entry point whose name and signature did not
  change. `verify` in the abi, `pqhs_verify` in C, and their Python and
  WebAssembly mirrors stay total over all six suites, but for H5 and H6 they
  now accept the stateful path only. A stateless-signed message that used to
  verify through them returns `false` with no error to distinguish it from a
  bad signature. Call `verify_stateless` for that case.
  `verify_with_stored_public_key` is replaced outright by
  `verify_with_stored_public_key_stateful` and `_stateless`.

- **Breaking.** `vrf::HEADER_LEN` and `vrf::CLASSICAL_PROOF_LEN`, both public
  in rc4, are removed. The two classical components do not share a proof
  width: schnorrkel's DLEQ proof is 64 bytes and the ed25519 ECVRF's `c || s`
  is 48, so a single constant cannot describe both. The width now lives on
  `ClassicalVrf::PROOF_LEN`, and `vrf::header_len` computes the header per
  component. Size a buffer from `vrf::proof_len`,
  `vrf::max_proof_len_delta` or `vrf::proof_len_stateless` instead. Only a
  caller of the non-default `vrf` feature is affected.
- `vrf::sign_stateless` and `vrf::verify_stateless` (behind the `vrf`
  feature) now document, and their known-answer test now checks, that `sk`
  and `pk` MUST be a key dedicated to the VRF binding, never the suite's
  rotation/recovery identity key. Both entry points already took an arbitrary
  key; passing the identity key there charged the same few-time SHRINCS
  budget its own rotation and recovery authorizations draw on, which
  specification section 21 forbids. `vrf::derive_stateless_key` gives an
  opt-in way to obtain a disjoint key for callers who do not already manage
  one. The `2^20` (`2^18` under `profile-128s-q18`) bound is unchanged and
  applies per key, not per role.
- The compile-fail test asserting that an ed25519 suite cannot be used with
  the VRF is deleted, along with the claim in the `vrf` module documentation
  and the README. It pinned a missing primitive as though it were a design
  decision.

## 0.0.0-rc4

rc4 adds three optional capabilities and changes nothing in the signature
suites or the wire format. A build that enables no new feature is unchanged
from rc3.

### Added

- A hybrid VRF for the sr25519 suites, behind the new non-default `vrf`
  feature (specification section 15). The sr25519 VRF supplies the output and
  a post-quantum binding signature over the same input proves post-quantum key
  possession. Every consensus-decisive byte derives from the classical
  pre-output alone, which is unique per key and input, and the binding is
  verified but never enters that derivation. Post-quantum signatures are not
  unique for a fixed message, so an output that read the binding could be
  ground by the signer that produced it. `hybrid-sr25519-mldsa44-v1` and
  `hybrid-sr25519-falcon512-v1` bind with a deterministic signature.
  `hybrid-sr25519-shrincs-*-v1` binds through the SHRINCS stateless path,
  spending one unit of the few-time budget and no one-time leaf, which suits a
  low-frequency VRF rather than per-slot leader election. The entry points are
  bounded on a new `ClassicalVrf` trait that only sr25519 implements, so
  naming an ed25519 suite does not compile.
- BIP39 master-seed derivation, behind the new non-default `mnemonic` feature.
  `master_seed_from_mnemonic` reproduces Substrate's derivation, which runs
  PBKDF2-HMAC-SHA512 over the mnemonic's entropy bytes rather than over the
  phrase text, so one phrase yields one key both here and on chain. Golden
  vectors taken from the chain's own derivation hold that parity.
- Hard-junction derivation, `derive_hard_junction` and
  `derive_hard_junction_path` (specification section 10). A junction derives a
  new master seed from a parent seed and a 32-byte chain code, and both
  components are re-derived from it. Hard derivation only: a soft junction
  yields a child public key and no child secret, so no derived master seed
  exists for one. Parsing junction strings into chain codes stays with the
  Substrate integration. A hard-derived child of a stateful suite is a fresh
  SHRINCS tree at leaf 1, so derive such a child once, persist it, and restore
  it through the validating import path.
- Stateful signing (H5 and H6) in the WebAssembly binding. Secret keys cross
  the boundary only as exported byte blobs, so the binding holds no key object
  a `structuredClone` could fork. `signStateful` takes the blob and a
  caller-supplied synchronous `LeafJournal` and returns the signature with the
  advanced key. The journal records the spent leaf durably before a signature
  exists and binds to the key's identity, so a stale or forked blob is refused
  rather than reissuing a one-time leaf. `signStateless` covers the few-time
  path with a `StatelessBudgetStore` of the same shape. This is the safety
  model the C and Python bindings already shipped.

### Changed

- `verify` and the length accessors in the WebAssembly binding are now total
  over all six suites. The stateless entry points still refuse H5 and H6, and
  the refusal now names `signStateful`.

## 0.0.0-rc3

The workspace collapses to a single published crate, `pqhybridsign`. This is
a breaking change to the crate layout and import paths. The signature suites
and wire format do not change.

### Changed

- `pqhybridsign-core` and `pqhybridsign-shrincs` are merged into
  `pqhybridsign`. The composite foundation and the lattice suites are the
  crate's top-level modules. The stateful hash-based suites move to
  `pqhybridsign::shrincs`. Import paths change: `pqhybridsign_core::X`
  becomes `pqhybridsign::X`, and `pqhybridsign_shrincs::X` becomes
  `pqhybridsign::shrincs::X`.
- The stateful suites H5 and H6 are behind the `stateful` feature, on by
  default. Turning it off drops the SHRINCS code and the `hashsigs-rs`
  dependency, so a lattice-only build never compiles or downloads them. The
  `profile-*` features still select one SHRINCS parameter set per build.
- `pqhybridsign-abi` is no longer published to crates.io. The C, Python, and
  WebAssembly bindings reach it by path, and no published crate depends on
  it. crates.io now holds one crate, `pqhybridsign`.

## 0.0.0-rc2

rc2 keeps the signature suites, wire format, and public API from rc1. This
release candidate hardens the build and the supply chain.

### Added

- A dependency cooldown. `scripts/check-dependency-cooldown.py` fails the
  build when any locked crates.io dependency is newer than seven days. It
  reads the publish time from the local Cargo sparse-index cache and falls
  back to the crates.io API. The `cooldown` CI job runs it over the whole
  lockfile, `release:validate` waits for that job, and a pre-commit hook
  runs it against a staged `Cargo.lock`. `scripts/cooldown-allowlist.toml`
  holds the reviewed first-party exemptions.

### Changed

- Every dependency-resolving `cargo` command in CI now passes `--locked`, so
  a drifted `Cargo.lock` fails the pipeline instead of re-resolving.
- `arrayref` comes from crates.io again at the legitimate 0.3.9. An attacker
  replaced it during rc2 development. The crate was vendored while the attack
  was live, then returned to the registry source once crates.io removed the
  malicious version.

## 0.0.0-rc1

First release candidate. The wire format is not frozen.

### Suites

- **H1** (ed25519 + ML-DSA-44) and **H3** (sr25519 + ML-DSA-44). Fixed-length
  composite signatures.
- **H2** (ed25519 + FN-DSA-512) and **H4** (sr25519 + FN-DSA-512). Delta-length
  wire format, over `fn-dsa` 0.4.0.
- **H5** (ed25519 + SHRINCS) and **H6** (sr25519 + SHRINCS). Stateful
  hash-based, over `hashsigs-rs`. Four SHRINCS profiles, one per build.

The suite label is the domain separator. It carries a trailing null byte and
is checked against a registry literal when the crate compiles, so a signature
made for one suite cannot verify under another.

### Crates

- `pqhybridsign-core` — composition layer, `no_std`. Every primitive lives in a
  component crate.
- `pqhybridsign` — H1 through H4.
- `pqhybridsign-shrincs` — H5 and H6.
- `pqhybridsign-abi` — runtime suite enum and type-erased dispatch, with pinned
  discriminants and error codes.
- `pqhybridsign-cffi` — C ABI, `cdylib` and `staticlib`, with a generated
  header that is diff-tested against the source.
- `pqhybridsign-wasm` — WebAssembly and npm.
- `pqhybridsign-py` — Python wheels through PyO3 and maturin.

### Stateful signing

- One-time leaf budget, at most 4096 leaves per key.
- The secret key does not implement `Clone`. A `trybuild` test asserts it.
- `sign_stateful` takes a `LeafJournal` and commits the advanced leaf index
  before it returns a signature.
- **Every signing attempt spends its leaf**, including an attempt the
  component refuses. Validation runs after the signature exists, so a refused
  message becomes an explicit error rather than a signature that could never
  verify. A signing path able to return without advancing the counter is a
  leaf-reuse hazard, and reuse is total security failure for the key, while a
  spent leaf costs availability alone.
- Validating export and import for the composite secret key, cross-checking
  the leaf counter against the component key it restores.
- Key rotation, gated on both components. Neither the classical co-signature
  nor the stateless SHRINCS signature is sufficient alone.
- Verifier-side ports: `LeafJournal` for the signer, `LeafIndexStore` with
  `accept_monotonic_leaf` for the verifier, a total fail-closed leaf-tracking
  policy machine, and stateless budget accounting keyed to the stateless key
  material.

### Known limits

- **The golden vectors pin this implementation against itself.** They catch
  wire-format drift. They cannot catch an error present when they were
  generated, and no vectors are shared with another conforming implementation.
- **H2 and H4 predate a final FIPS 206.** A signature made under either today
  may not verify against a later conforming implementation.
- **The `FalconLen` field is wider than the current component needs.**
  `fn-dsa` 0.4.0 emits a fixed 666-byte signature, so the delta always carries
  the same value. The field stays because the format specifies it.
- **The WebAssembly binding exposes H1 through H4 only.** A JavaScript object
  holding a stateful secret key can be structured-cloned, which forks the leaf
  counter. Use the C ABI or the Python binding for H5 and H6.
- **The Python binding accepts `bytes` and `bytearray`, not arbitrary buffer
  objects.** The `abi3-py39` stable ABI cannot reach the buffer-protocol C API
  below CPython 3.11.
- **The `profile-128s-q20` stateless budget is not yet security-analysed.**
  The SHRINCS parameter-set overview records that its 2^20 budget wants
  profile security-analysis backing before production use. It is otherwise
  identical to `q18`.
- **Key generation under the 128s profiles takes about 47 seconds**, and a
  stateless signature about three minutes, because those profiles use a
  single-layer height-18 hypertree. See the performance table in the README.

### Packaging

- Four distribution channels. crates.io holds `pqhybridsign-core`,
  `pqhybridsign`, `pqhybridsign-shrincs`, and `pqhybridsign-abi`. npm holds
  `@quip.network/pqhybridsign`. PyPI holds `pqhybridsign`. GitLab holds the
  C library as a release asset.
- `hashsigs-rs` now comes from crates.io instead of a pinned git revision.
  Version 0.2.1-rc2 carries the same feature set as the revision it
  replaces.
- The minimum supported Rust version moved to 1.95, set by `hashsigs-rs`.
