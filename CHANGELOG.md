# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- The minimum supported Rust version is 1.82, set by `fn-dsa`.
