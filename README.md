# pqhybridsign

Hybrid post-quantum signatures in Rust. Each suite pairs a classical
signature with a post-quantum signature. A composite signature verifies only
when both halves verify, so the composite stays unforgeable while either
component survives.

The crates are a standalone reference implementation. They do not depend on
Substrate.

**Status: pre-release.** The wire format is not frozen, and no
cross-implementation test vectors exist yet. See
[Limitations](#limitations).

## Suites

| Suite | Classical | Post-quantum | State |
|---|---|---|---|
| H1 | ed25519 | ML-DSA-44 | stateless |
| H2 | ed25519 | FN-DSA-512 | stateless |
| H3 | sr25519 | ML-DSA-44 | stateless |
| H4 | sr25519 | FN-DSA-512 | stateless |
| H5 | ed25519 | SHRINCS | stateful |
| H6 | sr25519 | SHRINCS | stateful |

H2 and H4 ship against the `fn-dsa` crate rather than waiting for a final
FIPS 206. Read the caveat under [Limitations](#limitations) before you use
them.

The suite name is the domain separator. `H1` signs under the label
`hybrid-ed25519-mldsa44-v1`, plus a trailing null byte, and the label is
checked against a registry literal when the crate compiles. A signature made
for one suite cannot verify under another.

## Crates

| Crate | Contents |
|---|---|
| `pqhybridsign-core` | Composition layer: suite macros, message binding, key derivation, wire encoding, and the stateful signer and verifier ports. Carries no cryptography of its own. |
| `pqhybridsign` | H1 through H4, over `ed25519-zebra`, `schnorrkel`, `fips204`, and `fn-dsa`. |
| `pqhybridsign-shrincs` | H5 and H6, over `hashsigs-rs` pinned by revision. Depends on `pqhybridsign-core` and `pqhybridsign`. |

H5 and H6 reuse the lattice crate classical components. They do not write
those schemes again. Those components come from `ed25519-zebra` and
`schnorrkel` through `pqhybridsign`. A license or dependency audit that
reads only this table misses those crates.

## Stateless signing, H1 and H3

```rust
use pqhybridsign::H1;
use pqhybridsign_core::composite::{keypair_from_seed, sign, verify};
use pqhybridsign_core::error::Error;
use pqhybridsign_core::suite::Suite;

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
with a bitwise `&`, so it evaluates both halves whatever the first one
decides.

`sign_deterministic` takes a nonce, but not every component uses it. ed25519
and ML-DSA-44 are deterministic by their own specifications and ignore it.
sr25519 binds it. The function documentation states the consequence for each
suite.

## Stateful signing, H5 and H6

Read this section before using H5 or H6.

**Stateful suites suit transactional systems only** — systems that already
keep durable, ordered, per-key state. Every signature consumes one one-time
leaf, a key has at most 4096 of them, and signing the same leaf twice
destroys the security of the post-quantum half. A signer restored from a seed
backup restarts at leaf 1 and reissues spent leaves. Any deployment that
restores from seed, replicates the signer, or runs it statelessly must use H1
or H3 instead.

Two rules follow, and the API enforces both:

- The secret key does not implement `Clone`. A clone forks the leaf counter.
- `sign_stateful` takes a `&mut impl LeafJournal` and commits the advanced
  leaf index through it before it returns a signature. A caller cannot hold a
  signature whose leaf is not already durable.

Every signing attempt spends its leaf, including an attempt the component
refuses. A signing path that can return without advancing the counter is a
reuse hazard, and reuse is total security failure, while a spent leaf costs
availability alone. Authenticate and rate-limit requests before they reach
the signer.

### Profiles

`pqhybridsign-shrincs` selects one SHRINCS parameter set at compile time.
Exactly one profile feature must be active.

| Feature | Default | Stateful signature at leaf 1 |
|---|---|---|
| `profile-256s` | yes | 2185 bytes |
| `profile-256s-sha2` | no | 2185 bytes |
| `profile-128s-q18` | no | 1161 bytes |
| `profile-128s-q20` | no | 1161 bytes |

The `q18` and `q20` profiles are identical except for the stateless budget
(2^18 against 2^20). The SHRINCS parameter-set overview records that the
`q20` budget wants profile security analysis before production use. That
caveat travels with this crate, which exposes both.

The profile name goes into the suite label, so `H5` under `profile-256s`
signs under `hybrid-ed25519-shrincs-256s-v1` and cannot be confused with the
same suite under another parameter set.

## Platforms

`pqhybridsign-core` must build for a target that provides no `std`, both with
and without the `alloc` feature. Treat a failure there as a defect in core.
`DESIGN.md` states the requirement in full, with the rule it puts on authors:
core has no `std` prelude, so every `alloc` type needs an import by its full
path.

Continuous integration builds core for `thumbv7em-none-eabi`, which has no
`std` to link against, and for `wasm32-unknown-unknown`, which the workspace
ships to.

The minimum supported Rust version is 1.89, set by `hashsigs-rs`.

## Testing

```bash
cargo test --workspace                    # default profile
cargo test -p pqhybridsign-core --no-default-features --features alloc
cargo test -p pqhybridsign-shrincs --no-default-features --features profile-128s-q20
cargo test -p pqhybridsign-shrincs --no-default-features --features profile-128s-q18
```

`cargo test --workspace` finishes in about 16.5 seconds under the default
profile (292 tests across 36 binaries on this machine). Any one profile
suite takes 0.24 s to 7.4 s. All four profiles together take about 8.2 s.

The default suite is fast because the workspace `Cargo.toml` builds
dependencies at `opt-level = 3` while workspace crates stay unoptimized.
Before that change, one binary took 184.80 seconds.

Tests read per-profile fixtures from
`crates/pqhybridsign-shrincs/tests/vectors/` instead of generating keys and
signatures. Regenerate a fixture with the command in `generate_fixtures.rs`.

One real 128s key generation still runs per commit, in `smoke_128s.rs`. It
carries `#[ignore]`, so run it explicitly:

```bash
cargo test -p pqhybridsign-shrincs --release --no-default-features \
    --features profile-128s-q18 --test smoke_128s -- --ignored
```

That ignored smoke takes about 46 seconds in release. Debug builds run
roughly 67 times slower than release for this code, so measure in release.

## Performance

Measured on one machine in release mode, for one H5 key with four leaves.
Reproduce with:

```bash
cargo test -p pqhybridsign-shrincs --release --no-default-features \
    --features profile-128s-q18 --test profile_timing -- --ignored --nocapture
```

| Profile | keygen | sign_stateful | sign_stateless | Stateless signature |
|---|---|---|---|---|
| `profile-256s` | 0.09 s | under 0.01 s | 1.16 s | 29,157 B |
| `profile-256s-sha2` | 0.03 s | under 0.01 s | 0.33 s | 29,157 B |
| `profile-128s-q18` | 46.85 s | under 0.01 s | 176.60 s | 5,769 B |
| `profile-128s-q20` | 47.47 s | under 0.01 s | 166.51 s | 5,769 B |

Stateful signing and verification are too fast to measure at this
resolution under every profile. Two consequences are worth planning around.

**The 128s profiles cost about 47 seconds to generate a key.** They set
`NUM_HYPERTREE_LAYERS = 1` over a height-18 tree, so key generation
materialises all 262,144 leaves, where the 256s profiles build one 256-leaf
subtree of an eight-layer hypertree. The gain is a stateless signature five
times smaller. Nothing about it is a defect; it is the parameter set doing
what it was chosen to do.

**A stateless signature takes about three minutes at 128s.** The stateless
path is the rotation and recovery path, so a recovery runbook for a 128s
deployment must budget minutes, not milliseconds.

**A 128s stateless signature is tree building, not grinding.** Of about 176
seconds, roughly 117 seconds builds the five FORS trees of 2^24 leaves each,
about 47 seconds builds the 262,144-leaf hypertree subtree, and 11.3 seconds
is the FORS-C counter grind. No message avoids the tree work, so the time is
stable rather than variable. Plan for the measured figure.

**About 1 stateless signature in 9 million fails at 128s.** The FORS-C
counter search gives up at 2^28 attempts and returns an error. The outcome is
deterministic for one key, message and context, so retrying the same message
does not help. Changing the message does. The failure is loud and
carries no security consequence. `DESIGN.md` records the analysis.

**Restoring a signer from a stored key is not a fast path.**
`SecretKey::import` costs about the same as `keygen` at 128s, because it
re-derives the hypertree root to validate the blob.

The C and Python bindings call `import` on every stateful signature.
A C or Python H5 signer under a 128s profile spends about 47 seconds
per signature. The in-process Rust API signs in under 0.01 seconds.
The performance table measures the Rust API. It does not measure the
bindings.

## Limitations

Stated plainly, because a release candidate should not imply more than it
delivers.

- **The golden vectors pin this implementation against itself.** They catch
  wire-format drift. They cannot catch an error that was present when they
  were generated, and no vectors are shared with another conforming
  implementation.
- **No external known-answer tests exist for the composition layer.** The
  component crates carry their own tests for the underlying primitives.
- **H2 and H4 predate the standard.** FIPS 206 is not final. A signature
  made under H2 or H4 today may not verify against a later, conforming
  implementation. Use them where you control both sides, or use H1 or H3.
- **The H2/H4 length field is wider than it needs to be.** `fn-dsa` 0.4.0
  emits a fixed 666-byte signature, so the one-byte `FalconLen` delta always
  carries the same value. The field stays because the format specifies it.
- **The WebAssembly binding signs under H1 through H4 only.** A JavaScript
  object holding a stateful secret key can be structured-cloned, which forks
  the leaf counter. H5 and H6 verification is available through
  `verifyWithStoredPublicKey`. To sign under H5 or H6, use the C ABI or the
  Python binding.
- **The Python binding accepts `bytes` and `bytearray`, not arbitrary buffer
  objects.** The `abi3-py39` stable ABI cannot reach the buffer-protocol C API
  below CPython 3.11.
- **Golden vectors pin every profile, but only against this implementation.**
  All four profiles carry verify-only vectors in
  `crates/pqhybridsign-shrincs/tests/vectors/`. Live re-signing runs under
  `profile-256s` alone, because obtaining a secret key at 128s costs about 47
  seconds.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
