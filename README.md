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
| H3 | sr25519 | ML-DSA-44 | stateless |
| H5 | ed25519 | SHRINCS | stateful |
| H6 | sr25519 | SHRINCS | stateful |

H2 and H4 pair the classical components with Falcon-512. They wait on a
final FIPS 206 and are not implemented.

The suite name is the domain separator. `H1` signs under the label
`hybrid-ed25519-mldsa44-v1`, plus a trailing null byte, and the label is
checked against a registry literal when the crate compiles. A signature made
for one suite cannot verify under another.

## Crates

| Crate | Contents |
|---|---|
| `pqhybridsign-core` | Composition layer: suite macros, message binding, key derivation, wire encoding, and the stateful signer and verifier ports. Carries no cryptography of its own. |
| `pqhybridsign` | H1 and H3, over `ed25519-zebra`, `schnorrkel`, and `fips204`. |
| `pqhybridsign-shrincs` | H5 and H6, over `hashsigs-rs`. |

## Stateless signing, H1 and H3

```rust
use pqhybridsign::H1;
use pqhybridsign_core::composite::{keypair_from_seed, sign, verify};
use pqhybridsign_core::{Error, Suite};

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

The profile name goes into the suite label, so `H5` under `profile-256s`
signs under `hybrid-ed25519-shrincs-256s-v1` and cannot be confused with the
same suite under another parameter set.

## Platforms

`pqhybridsign-core` builds without `std`. `alloc` is a separate feature. The
workspace builds for `wasm32-unknown-unknown`, and continuous integration
checks it.

## Testing

```bash
cargo test --workspace                    # default profile
cargo test -p pqhybridsign-shrincs --no-default-features --features profile-128s-q20
```

The suite runs in about five minutes. The stateless SHRINCS path dominates
that time: it grinds a target sum, which takes 60 to 180 seconds per
signature.

## Limitations

Stated plainly, because a release candidate should not imply more than it
delivers.

- **The golden vectors pin this implementation against itself.** They catch
  wire-format drift. They cannot catch an error that was present when they
  were generated, and no vectors are shared with another conforming
  implementation.
- **No external known-answer tests exist for the composition layer.** The
  component crates carry their own tests for the underlying primitives.
- **H2 and H4 do not exist.** Falcon waits on a final FIPS 206.
- **Rotation and the verifier-side acceptance policy are in progress.**

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
