# Cycle 1: core crate and H1/H3 lattice hybrids — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `pqhybridsign-core` and `pqhybridsign`, giving working H1 (ed25519 + ML-DSA-44) and H3 (sr25519 + ML-DSA-44) composite signatures with golden vectors.

**Architecture:** One generic composite layer takes a classical component and a post-quantum component, in the style of the Noise Protocol Framework. A macro declares each suite, composes its domain separation label from the component names, and checks the result against the specification registry at compile time. Component traits work on byte slices with caller-supplied output buffers, so no allocation is needed and the arithmetic that stable Rust cannot express in const generics moves to the macro.

**Tech Stack:** Rust 2021, `ed25519-zebra`, `schnorrkel`, `fips204`, `hkdf`, `sha2`, `subtle`, `zeroize`.

**Design document:** `docs/design/2026-08-10-hybrid-pq-signatures-design.md`
**Specification:** Hybrid Post-Quantum Signature Constructions, version 2.0, 2026-07-18
**Tracker:** beads epic `pqhs-8ep`

## Global Constraints

- Every crate is licensed AGPL-3.0-or-later. Fetch the license body from the SPDX license list. Never write it from memory.
- Every library crate sets `#![forbid(unsafe_code)]` and `#![cfg_attr(not(feature = "std"), no_std)]`.
- Pin this dependency generation exactly. Do not take the current stable releases: `rand_core = "0.6.4"`, `sha2 = "0.10.8"`, `hkdf = "0.12"`, `subtle = "2.6.1"`, `zeroize = { version = "1.8", features = ["derive"] }`, `ed25519-zebra = "4.2"`, `schnorrkel = "0.11.5"`, `fips204 = "0.4.6"`. All three component crates require `rand_core ^0.6` and `sha2 ^0.10`. Taking `rand_core` 0.10 or `sha2` 0.11 fractures the dependency graph.
- A suite label always includes its trailing null byte. `hybrid-ed25519-mldsa44-v1` is 25 characters and 26 bytes.
- The sr25519 signing context is the suite's own null-terminated label. See beads `pqhs-8ep.9`.
- ML-DSA signing always passes an empty `ctx` to `fips204`. Domain separation lives in `M'`. See beads `pqhs-8ep.10`.
- Deterministic ML-DSA signing uses `try_sign_with_seed(&[0u8; 32], m_prime, &[])`.
- Verification never reveals which component failed. Combine with `subtle::Choice`, never with `&&`.
- No `unwrap` or `expect` in library code. Tests may use them.
- Run every test suite in release mode as well as debug. The `subtle` crate uses `debug_assert` with secret-dependent branches.
- Work on branch `feat/cycle-1-core-lattice`. Commit after every task.

---

### Task 1: Workspace scaffold and license

**Files:**
- Create: `Cargo.toml`, `LICENSE`, `.gitignore`, `rust-toolchain.toml`
- Create: `crates/pqhybridsign-core/Cargo.toml`, `crates/pqhybridsign-core/src/lib.rs`
- Create: `crates/pqhybridsign/Cargo.toml`, `crates/pqhybridsign/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: a workspace that builds, with `pqhybridsign_core` and `pqhybridsign` as library crates.

- [ ] **Step 1: Fetch the license text**

Never write license text from memory. Run:

```bash
curl -sL https://raw.githubusercontent.com/spdx/license-list-data/main/text/AGPL-3.0-or-later.txt -o LICENSE
wc -l LICENSE   # expect roughly 600-700 lines; fail loudly if it is short
```

If that path 404s, use `https://www.gnu.org/licenses/agpl-3.0.txt` instead.

- [ ] **Step 2: Write the workspace manifest**

Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/pqhybridsign-core", "crates/pqhybridsign"]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.75"
license = "AGPL-3.0-or-later"
repository = "https://gitlab.com/quip.network/pqhybridsign"

[workspace.dependencies]
subtle = { version = "2.6.1", default-features = false }
zeroize = { version = "1.8", default-features = false, features = ["derive"] }
hkdf = { version = "0.12", default-features = false }
sha2 = { version = "0.10.8", default-features = false }
rand_core = { version = "0.6.4", default-features = false }
ed25519-zebra = { version = "4.2", default-features = false }
schnorrkel = { version = "0.11.5", default-features = false }
fips204 = { version = "0.4.6", default-features = false }
hex = { version = "0.4", default-features = false, features = ["alloc"] }
```

- [ ] **Step 3: Write the two crate manifests**

Create `crates/pqhybridsign-core/Cargo.toml`:

```toml
[package]
name = "pqhybridsign-core"
description = "Composite layer for hybrid post-quantum signature constructions"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
subtle.workspace = true
zeroize.workspace = true
hkdf.workspace = true
sha2.workspace = true
rand_core.workspace = true

[features]
default = ["std", "alloc"]
std = ["alloc"]
alloc = []
```

Create `crates/pqhybridsign/Cargo.toml`:

```toml
[package]
name = "pqhybridsign"
description = "Hybrid post-quantum signatures: H1 (ed25519 + ML-DSA-44) and H3 (sr25519 + ML-DSA-44)"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
pqhybridsign-core = { path = "../pqhybridsign-core", default-features = false }
subtle.workspace = true
zeroize.workspace = true
rand_core.workspace = true
ed25519-zebra.workspace = true
schnorrkel.workspace = true
fips204.workspace = true

[dev-dependencies]
hex.workspace = true
rand_core = { version = "0.6.4", features = ["getrandom"] }

[features]
default = ["std"]
std = ["pqhybridsign-core/std", "schnorrkel/std", "ed25519-zebra/std"]
```

- [ ] **Step 4: Write the crate roots**

Create `crates/pqhybridsign-core/src/lib.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = "Composite layer for hybrid post-quantum signature constructions."]

#[cfg(feature = "alloc")]
extern crate alloc;
```

Create `crates/pqhybridsign/src/lib.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![doc = "Hybrid post-quantum signatures: H1 and H3."]
```

Create `.gitignore`:

```
/target
Cargo.lock.bak
```

Create `rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
targets = ["wasm32-unknown-unknown"]
```

- [ ] **Step 5: Verify the workspace builds**

Run: `cargo build --workspace`
Expected: success, two crates compiled.

Run: `cargo tree -i rand_core | head -20`
Expected: exactly one `rand_core v0.6.x`. If two major versions appear, stop and fix the pins before continuing.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock LICENSE .gitignore rust-toolchain.toml crates/
git commit -m "feat: scaffold AGPL workspace with core and lattice crates

Pins the rand_core 0.6 / sha2 0.10 / digest 0.10 generation. All three
component crates require it, so the current stable releases of rand_core,
sha2 and hkdf would fracture the dependency graph.

Closes pqhs-8ep.1"
```

---

### Task 2: Error type

**Files:**
- Create: `crates/pqhybridsign-core/src/error.rs`
- Modify: `crates/pqhybridsign-core/src/lib.rs`
- Test: inline `#[cfg(test)]` module in `error.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `pqhybridsign_core::Error`, `pqhybridsign_core::Result<T>`.

Error variants are specific because they describe public data. Verification failure is deliberately absent: verification returns `bool`, never an error, so it cannot leak which component failed.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign-core/src/error.rs` with only this test module at first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_copy_and_displays() {
        let e = Error::BadLength { expected: 32, actual: 31 };
        let copied = e;
        assert_eq!(copied, e);
        #[cfg(feature = "std")]
        assert!(!std::string::ToString::to_string(&e).is_empty());
    }

    #[test]
    fn context_too_long_is_distinct_from_bad_length() {
        assert_ne!(Error::ContextTooLong, Error::BadLength { expected: 1, actual: 2 });
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign-core`
Expected: FAIL, `cannot find type Error in this scope`.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `error.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use core::fmt;

/// Errors from encoding, decoding and key handling.
///
/// Every variant describes public data. Verification failure is not an
/// error variant: verification returns `bool` so it cannot reveal which
/// component failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A byte string had the wrong length.
    BadLength { expected: usize, actual: usize },
    /// The application context exceeded 255 bytes.
    ContextTooLong,
    /// A caller-supplied output buffer was too small.
    OutputBufferTooSmall { needed: usize, actual: usize },
    /// A soft derivation junction was supplied. Only hard junctions exist.
    SoftJunctionRejected,
    /// A component crate reported an internal failure.
    ComponentFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { expected, actual } => {
                write!(f, "bad length: expected {expected} bytes, got {actual}")
            }
            Self::ContextTooLong => write!(f, "context exceeds 255 bytes"),
            Self::OutputBufferTooSmall { needed, actual } => {
                write!(f, "output buffer too small: need {needed} bytes, got {actual}")
            }
            Self::SoftJunctionRejected => {
                write!(f, "soft derivation junctions are rejected for every hybrid suite")
            }
            Self::ComponentFailure => write!(f, "component algorithm failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
```

Add to `lib.rs`:

```rust
pub mod error;
pub use error::{Error, Result};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign-core`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign-core/src/
git commit -m "feat(core): add error type

Verification failure is deliberately not an error variant. Verification
returns bool so the error channel cannot reveal which component failed.

Refs pqhs-8ep.7"
```

---

### Task 3: Component traits

**Files:**
- Create: `crates/pqhybridsign-core/src/component.rs`
- Modify: `crates/pqhybridsign-core/src/lib.rs`

**Interfaces:**
- Consumes: `Error`, `Result` from Task 2.
- Produces: traits `ClassicalScheme` and `PqScheme`, both with these exact signatures. Later tasks implement them for ed25519, sr25519 and ML-DSA-44.

The traits take output buffers instead of returning arrays. That keeps them usable without an allocator and without const generic arithmetic, which stable Rust cannot express.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign-core/src/component.rs` with this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use subtle::Choice;

    struct Stub;

    impl ClassicalScheme for Stub {
        const NAME: &'static str = "stub";
        const PUBLIC_KEY_LEN: usize = 2;
        const SECRET_KEY_LEN: usize = 4;
        const SIGNATURE_LEN: usize = 8;

        fn derive(_seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
            sk_out.fill(1);
            pk_out.fill(2);
            Ok(())
        }
        fn sign(
            _sk: &[u8], _msg: &[u8], _label: &'static [u8],
            _rng: &mut impl rand_core::CryptoRngCore, sig_out: &mut [u8],
        ) -> Result<()> {
            sig_out.fill(3);
            Ok(())
        }
        fn sign_deterministic(
            _sk: &[u8], _msg: &[u8], _nonce: &[u8], _label: &'static [u8], sig_out: &mut [u8],
        ) -> Result<()> {
            sig_out.fill(4);
            Ok(())
        }
        fn verify(_pk: &[u8], _msg: &[u8], _label: &'static [u8], _sig: &[u8]) -> Choice {
            Choice::from(1u8)
        }
    }

    #[test]
    fn trait_constants_are_reachable() {
        assert_eq!(Stub::NAME, "stub");
        assert_eq!(Stub::SIGNATURE_LEN, 8);
    }

    #[test]
    fn derive_fills_both_buffers() {
        let mut sk = [0u8; 4];
        let mut pk = [0u8; 2];
        Stub::derive(&[0u8; 32], &mut sk, &mut pk).expect("stub derive");
        assert_eq!(sk, [1u8; 4]);
        assert_eq!(pk, [2u8; 2]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign-core component`
Expected: FAIL, `cannot find trait ClassicalScheme`.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `component.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Result;
use subtle::Choice;

/// A classical signature component, for example ed25519 or sr25519.
///
/// Corresponds to the DH functions abstraction in the Noise Protocol
/// Framework: a named primitive with fixed sizes that the generic
/// composite layer never needs to look inside.
pub trait ClassicalScheme {
    /// Name token used to compose the suite label, for example `"ed25519"`.
    const NAME: &'static str;
    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;

    /// Derive the component keypair from a 32-byte seed.
    ///
    /// Writes `SECRET_KEY_LEN` bytes into `sk_out` and `PUBLIC_KEY_LEN`
    /// bytes into `pk_out`.
    fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()>;

    /// Hedged signing. `label` is the suite label, used as the schnorrkel
    /// signing context where the component needs one.
    fn sign(
        sk: &[u8],
        msg: &[u8],
        label: &'static [u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()>;

    /// Deterministic signing. The nonce is mixed with the secret key as
    /// `k = H(sk || nonce || msg)`. The secret key must always take part,
    /// or the signing key becomes trivially recoverable.
    fn sign_deterministic(
        sk: &[u8],
        msg: &[u8],
        nonce: &[u8],
        label: &'static [u8],
        sig_out: &mut [u8],
    ) -> Result<()>;

    /// Verify. Returns a `Choice`, never a `bool`, so the composite layer
    /// can combine components without a short-circuiting branch.
    fn verify(pk: &[u8], msg: &[u8], label: &'static [u8], sig: &[u8]) -> Choice;
}

/// A post-quantum signature component, for example ML-DSA-44.
///
/// Corresponds to the cipher functions abstraction in the Noise Protocol
/// Framework.
pub trait PqScheme {
    /// Name token used to compose the suite label, for example `"mldsa44"`.
    const NAME: &'static str;
    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    /// Seed length this component consumes from HKDF. 32 for ML-DSA-44.
    const SEED_LEN: usize;
    /// True when the algorithm is message-deterministic by specification.
    const IS_DETERMINISTIC: bool;

    fn derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()>;

    fn sign(
        sk: &[u8],
        msg: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()>;

    /// Deterministic signing. A component that is deterministic by
    /// specification ignores the nonce.
    fn sign_deterministic(sk: &[u8], msg: &[u8], nonce: &[u8], sig_out: &mut [u8]) -> Result<()>;

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Choice;
}
```

Add to `lib.rs`:

```rust
pub mod component;
pub use component::{ClassicalScheme, PqScheme};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign-core component`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign-core/src/
git commit -m "feat(core): add ClassicalScheme and PqScheme component traits

Buffer-out signatures keep the traits usable without an allocator and
avoid const generic arithmetic that stable Rust cannot express.

Closes pqhs-8ep.2"
```

---

### Task 4: Message binding, `M'`

**Files:**
- Create: `crates/pqhybridsign-core/src/message.rs`
- Modify: `crates/pqhybridsign-core/src/lib.rs`

**Interfaces:**
- Consumes: `Error`, `Result`.
- Produces: `m_prime_len(label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<usize>`, `write_m_prime(out: &mut [u8], label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<usize>`, and under `alloc` the helper `m_prime(label, ctx, msg) -> Result<alloc::vec::Vec<u8>>`.

`M' = Prefix(0x01) || Label || len(ctx) || ctx || M`, per specification section 7. `Label` always includes its trailing null byte.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign-core/src/message.rs` with this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const H1: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

    #[test]
    fn layout_matches_the_specification() {
        let out = m_prime(H1, b"chain", b"hello").expect("build");
        assert_eq!(out[0], 0x01, "prefix");
        assert_eq!(&out[1..1 + H1.len()], H1, "label including the null byte");
        assert_eq!(out[1 + H1.len()], 5, "len(ctx)");
        assert_eq!(&out[2 + H1.len()..7 + H1.len()], b"chain");
        assert_eq!(&out[7 + H1.len()..], b"hello");
    }

    #[test]
    fn empty_context_encodes_a_zero_length() {
        let out = m_prime(H1, b"", b"m").expect("build");
        assert_eq!(out[1 + H1.len()], 0);
        assert_eq!(&out[2 + H1.len()..], b"m");
    }

    #[test]
    fn context_over_255_bytes_is_rejected() {
        let ctx = [0u8; 256];
        assert_eq!(m_prime(H1, &ctx, b"m").unwrap_err(), Error::ContextTooLong);
        assert_eq!(m_prime_len(H1, &ctx, b"m").unwrap_err(), Error::ContextTooLong);
    }

    #[test]
    fn context_of_exactly_255_bytes_is_accepted() {
        let ctx = [7u8; 255];
        let out = m_prime(H1, &ctx, b"m").expect("255 is the maximum");
        assert_eq!(out[1 + H1.len()], 255);
    }

    #[test]
    fn declared_length_matches_written_length() {
        let need = m_prime_len(H1, b"ab", b"cde").expect("len");
        let mut buf = [0u8; 64];
        let wrote = write_m_prime(&mut buf[..need], H1, b"ab", b"cde").expect("write");
        assert_eq!(need, wrote);
        assert_eq!(need, 1 + H1.len() + 1 + 2 + 3);
    }

    #[test]
    fn a_short_buffer_is_rejected_and_not_partially_written() {
        let need = m_prime_len(H1, b"", b"m").expect("len");
        let mut buf = alloc::vec![0u8; need - 1];
        let err = write_m_prime(&mut buf, H1, b"", b"m").unwrap_err();
        assert_eq!(err, Error::OutputBufferTooSmall { needed: need, actual: need - 1 });
        assert!(buf.iter().all(|b| *b == 0), "must not partially write");
    }

    #[test]
    fn different_labels_give_different_bindings() {
        const H3: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";
        assert_ne!(m_prime(H1, b"", b"m").unwrap(), m_prime(H3, b"", b"m").unwrap());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign-core message`
Expected: FAIL, `cannot find function m_prime`.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `message.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{Error, Result};

/// Hybrid construction version prefix, specification section 7.
pub const PREFIX: u8 = 0x01;

/// Length in bytes of `M'` for these inputs.
///
/// Returns [`Error::ContextTooLong`] when `ctx` exceeds 255 bytes, because
/// the length field is a single byte.
pub fn m_prime_len(label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<usize> {
    if ctx.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    Ok(1 + label.len() + 1 + ctx.len() + msg.len())
}

/// Write `M' = Prefix || Label || len(ctx) || ctx || M` into `out`.
///
/// `label` must already include its trailing null byte. Returns the number
/// of bytes written. Writes nothing when `out` is too small.
pub fn write_m_prime(out: &mut [u8], label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<usize> {
    let needed = m_prime_len(label, ctx, msg)?;
    if out.len() < needed {
        return Err(Error::OutputBufferTooSmall { needed, actual: out.len() });
    }
    let mut at = 0;
    out[at] = PREFIX;
    at += 1;
    out[at..at + label.len()].copy_from_slice(label);
    at += label.len();
    // The cast is exact: m_prime_len already rejected ctx longer than 255.
    out[at] = ctx.len() as u8;
    at += 1;
    out[at..at + ctx.len()].copy_from_slice(ctx);
    at += ctx.len();
    out[at..at + msg.len()].copy_from_slice(msg);
    at += msg.len();
    Ok(at)
}

/// Allocating convenience wrapper around [`write_m_prime`].
#[cfg(feature = "alloc")]
pub fn m_prime(label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    let needed = m_prime_len(label, ctx, msg)?;
    let mut out = alloc::vec![0u8; needed];
    write_m_prime(&mut out, label, ctx, msg)?;
    Ok(out)
}
```

Add `use` for `alloc` inside the test module by putting `extern crate alloc;` at the top of `message.rs` test module, or rely on the crate-level `extern crate alloc;` from Task 1.

Add to `lib.rs`:

```rust
pub mod message;
pub use message::{m_prime_len, write_m_prime, PREFIX};
#[cfg(feature = "alloc")]
pub use message::m_prime;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign-core message`
Expected: PASS, 7 tests.

Run: `cargo test -p pqhybridsign-core --release`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign-core/src/
git commit -m "feat(core): add M-prime message binding

Splits the length calculation from the write so a no_std caller with a
bounded message can stack-allocate. The alloc helper is a wrapper.

Closes pqhs-8ep.4"
```

---

### Task 5: Suite trait and the `hybrid_suite!` macro

**Files:**
- Create: `crates/pqhybridsign-core/src/suite.rs`
- Modify: `crates/pqhybridsign-core/src/lib.rs`
- Test: `crates/pqhybridsign-core/tests/suite_macro.rs`

**Interfaces:**
- Consumes: `ClassicalScheme`, `PqScheme`.
- Produces: `trait Suite` with associated items `LABEL: &'static [u8]`, `Classical`, `Pq`, `PUBLIC_KEY_LEN`, `SECRET_KEY_LEN`, `SIGNATURE_LEN`; and the exported macro `hybrid_suite!`.

This is the Noise-style naming rule. All 16 rows of the specification registry regenerate from `"hybrid-" classical "-" pq ["-rotate"] "-v1"` plus a null byte.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign-core/tests/suite_macro.rs`:

```rust
use pqhybridsign_core::{hybrid_suite, ClassicalScheme, PqScheme, Suite};
use pqhybridsign_core::Result;
use subtle::Choice;

struct Ed25519Stub;
struct MlDsaStub;

impl ClassicalScheme for Ed25519Stub {
    const NAME: &'static str = "ed25519";
    const PUBLIC_KEY_LEN: usize = 32;
    const SECRET_KEY_LEN: usize = 64;
    const SIGNATURE_LEN: usize = 64;
    fn derive(_s: &[u8; 32], _sk: &mut [u8], _pk: &mut [u8]) -> Result<()> { Ok(()) }
    fn sign(_a: &[u8], _b: &[u8], _c: &'static [u8], _r: &mut impl rand_core::CryptoRngCore, _o: &mut [u8]) -> Result<()> { Ok(()) }
    fn sign_deterministic(_a: &[u8], _b: &[u8], _n: &[u8], _c: &'static [u8], _o: &mut [u8]) -> Result<()> { Ok(()) }
    fn verify(_a: &[u8], _b: &[u8], _c: &'static [u8], _d: &[u8]) -> Choice { Choice::from(1u8) }
}

impl PqScheme for MlDsaStub {
    const NAME: &'static str = "mldsa44";
    const PUBLIC_KEY_LEN: usize = 1312;
    const SECRET_KEY_LEN: usize = 2560;
    const SIGNATURE_LEN: usize = 2420;
    const SEED_LEN: usize = 32;
    const IS_DETERMINISTIC: bool = true;
    fn derive(_s: &[u8], _sk: &mut [u8], _pk: &mut [u8]) -> Result<()> { Ok(()) }
    fn sign(_a: &[u8], _b: &[u8], _r: &mut impl rand_core::CryptoRngCore, _o: &mut [u8]) -> Result<()> { Ok(()) }
    fn sign_deterministic(_a: &[u8], _b: &[u8], _n: &[u8], _o: &mut [u8]) -> Result<()> { Ok(()) }
    fn verify(_a: &[u8], _b: &[u8], _c: &[u8]) -> Choice { Choice::from(1u8) }
}

hybrid_suite! {
    /// H1 test instance.
    H1Test,
    classical = Ed25519Stub as "ed25519",
    pq = MlDsaStub as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

#[test]
fn label_carries_the_trailing_null_byte() {
    assert_eq!(H1Test::LABEL, b"hybrid-ed25519-mldsa44-v1\0");
    assert_eq!(H1Test::LABEL.len(), 26);
    assert_eq!(*H1Test::LABEL.last().unwrap(), 0u8);
}

#[test]
fn composite_sizes_are_the_component_sums() {
    assert_eq!(H1Test::PUBLIC_KEY_LEN, 1344);
    assert_eq!(H1Test::SECRET_KEY_LEN, 2624);
    assert_eq!(H1Test::SIGNATURE_LEN, 2484);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign-core --test suite_macro`
Expected: FAIL, `cannot find macro hybrid_suite`.

- [ ] **Step 3: Write the minimal implementation**

Create `crates/pqhybridsign-core/src/suite.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{ClassicalScheme, PqScheme};

/// One hybrid construction: a classical component, a post-quantum
/// component, and the label that separates it from every other suite.
///
/// Modelled on the Noise Protocol Framework, where the protocol name is
/// composed from its primitives and then bound cryptographically. Here the
/// composed name is the label prepended into `M'`.
pub trait Suite {
    type Classical: ClassicalScheme;
    type Pq: PqScheme;

    /// Null-terminated registry label from specification section 7.
    const LABEL: &'static [u8];

    const PUBLIC_KEY_LEN: usize =
        <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
            + <Self::Pq as PqScheme>::PUBLIC_KEY_LEN;
    const SECRET_KEY_LEN: usize =
        <Self::Classical as ClassicalScheme>::SECRET_KEY_LEN
            + <Self::Pq as PqScheme>::SECRET_KEY_LEN;
    const SIGNATURE_LEN: usize =
        <Self::Classical as ClassicalScheme>::SIGNATURE_LEN
            + <Self::Pq as PqScheme>::SIGNATURE_LEN;
    /// Byte offset where the post-quantum half begins.
    const SPLIT: usize = <Self::Classical as ClassicalScheme>::SIGNATURE_LEN;
}

/// Declare a hybrid suite.
///
/// Composes the label as `"hybrid-" classical "-" pq "-v1"` plus a null
/// byte, then checks the result against the registry literal and its byte
/// count at compile time. A typo becomes a build failure, not a silently
/// incompatible signature.
#[macro_export]
macro_rules! hybrid_suite {
    (
        $(#[$meta:meta])*
        $name:ident,
        classical = $classical:ty as $ctok:literal,
        pq = $pq:ty as $ptok:literal,
        label = $label:literal,
        label_len = $len:literal $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl $crate::Suite for $name {
            type Classical = $classical;
            type Pq = $pq;
            const LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1", "\0").as_bytes();
        }

        const _: () = {
            // The composed name must equal the registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1"),
                    $label,
                ),
                "composed suite label does not match the registry literal",
            );
            // The byte count must equal the registry byte count, which
            // includes the trailing null byte.
            assert!(
                $label.len() + 1 == $len,
                "label length does not match the registry byte count",
            );
            // Each name token must equal its component's NAME constant.
            assert!(
                $crate::suite::const_str_eq(
                    <$classical as $crate::ClassicalScheme>::NAME, $ctok,
                ),
                "classical name token does not match ClassicalScheme::NAME",
            );
            assert!(
                $crate::suite::const_str_eq(
                    <$pq as $crate::PqScheme>::NAME, $ptok,
                ),
                "post-quantum name token does not match PqScheme::NAME",
            );
        };
    };
}

/// Compare two string literals in a const context.
#[doc(hidden)]
pub const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
```

Add to `lib.rs`:

```rust
pub mod suite;
pub use suite::Suite;
```

Add `subtle` to `pqhybridsign-core` dev-dependencies so the integration test compiles:

```toml
[dev-dependencies]
subtle.workspace = true
rand_core.workspace = true
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign-core --test suite_macro`
Expected: PASS, 2 tests.

- [ ] **Step 5: Prove the compile-time guard actually fires**

Temporarily change `label_len = 26` to `label_len = 25` in the test file.
Run: `cargo test -p pqhybridsign-core --test suite_macro`
Expected: compile error, "label length does not match the registry byte count".
Revert the change. A guard nobody has seen fail is a guard nobody knows works.

- [ ] **Step 6: Commit**

```bash
git add crates/pqhybridsign-core/
git commit -m "feat(core): add Suite trait and hybrid_suite! macro

Composes each label from its component name tokens and checks it against
the section 7 registry at compile time. All 16 registry rows regenerate
from this grammar, rotation rows included.

Closes pqhs-8ep.3"
```

---

### Task 6: Suite-separated HKDF derivation

**Files:**
- Create: `crates/pqhybridsign-core/src/derive.rs`
- Modify: `crates/pqhybridsign-core/src/lib.rs`

**Interfaces:**
- Consumes: `Error`, `Result`.
- Produces: `derive_component_seeds(master: &[u8; 32], label: &[u8], classical_out: &mut [u8; 32], pq_out: &mut [u8]) -> Result<()>`.

Specification section 9 requires the HKDF `info` to bind the suite label. `Label` means the full null-terminated registry value, matching its use in `M'`. See Finding 2 in the design document.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign-core/src/derive.rs` with this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const H1: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";
    const H3: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";

    fn seeds(master: &[u8; 32], label: &[u8]) -> ([u8; 32], [u8; 32]) {
        let (mut c, mut p) = ([0u8; 32], [0u8; 32]);
        derive_component_seeds(master, label, &mut c, &mut p).expect("derive");
        (c, p)
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(seeds(&[9u8; 32], H1), seeds(&[9u8; 32], H1));
    }

    #[test]
    fn classical_and_pq_seeds_differ() {
        let (c, p) = seeds(&[9u8; 32], H1);
        assert_ne!(c, p, "info strings must separate the two components");
    }

    #[test]
    fn suites_derive_independent_trees() {
        // Specification section 9: without suite separation two suites from
        // one master seed collide. For H5/H6 that collision means leaf reuse.
        assert_ne!(seeds(&[9u8; 32], H1), seeds(&[9u8; 32], H3));
    }

    #[test]
    fn different_master_seeds_differ() {
        assert_ne!(seeds(&[1u8; 32], H1), seeds(&[2u8; 32], H1));
    }

    #[test]
    fn pq_output_length_is_caller_chosen() {
        let (mut c, mut p) = ([0u8; 32], [0u8; 48]);
        derive_component_seeds(&[3u8; 32], H1, &mut c, &mut p).expect("48-byte pq seed");
        assert!(p.iter().any(|b| *b != 0));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign-core derive`
Expected: FAIL, `cannot find function derive_component_seeds`.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `derive.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF salt from specification section 9.
const SALT: &[u8] = b"hybrid-sig";
/// Info prefix for the classical component.
const CLASSICAL_INFO_PREFIX: &[u8] = b"classical/";
/// Info prefix for the post-quantum component.
const PQ_INFO_PREFIX: &[u8] = b"pq/";
/// Longest label in the registry is 43 bytes. 64 leaves headroom.
const MAX_INFO: usize = 64 + 16;

/// Expand a master seed into the two component seeds.
///
/// `info` binds the suite label, as specification section 9 requires, so
/// two suites derived from one master seed produce independent keys.
/// `label` must be the full null-terminated registry value, exactly as it
/// appears in `M'`.
///
/// This differs from the deployed `quip-crypto-primitives`, which uses a
/// fixed info value for every suite. See QuipNetwork/quip-protocol-rs#9.
pub fn derive_component_seeds(
    master: &[u8; 32],
    label: &[u8],
    classical_out: &mut [u8; 32],
    pq_out: &mut [u8],
) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), master);

    let mut info = [0u8; MAX_INFO];
    let write_info = |info: &mut [u8; MAX_INFO], prefix: &[u8]| -> Result<usize> {
        let n = prefix.len() + label.len();
        if n > MAX_INFO {
            return Err(Error::OutputBufferTooSmall { needed: n, actual: MAX_INFO });
        }
        info[..prefix.len()].copy_from_slice(prefix);
        info[prefix.len()..n].copy_from_slice(label);
        Ok(n)
    };

    let n = write_info(&mut info, CLASSICAL_INFO_PREFIX)?;
    hk.expand(&info[..n], classical_out).map_err(|_| Error::ComponentFailure)?;

    let n = write_info(&mut info, PQ_INFO_PREFIX)?;
    let result = hk.expand(&info[..n], pq_out).map_err(|_| Error::ComponentFailure);
    info.zeroize();
    result
}
```

Add to `lib.rs`:

```rust
pub mod derive;
pub use derive::derive_component_seeds;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign-core derive`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign-core/src/
git commit -m "feat(core): add suite-separated HKDF derivation

Binds the suite label into the HKDF info string, as specification section
9 requires. The label includes its trailing null byte, matching its use in
M-prime. This is a recorded incompatibility with the deployed
quip-crypto-primitives, which uses a fixed info value.

Closes pqhs-8ep.5"
```

---

### Task 7: ed25519 component

**Files:**
- Create: `crates/pqhybridsign/src/classical/mod.rs`, `crates/pqhybridsign/src/classical/ed25519.rs`
- Modify: `crates/pqhybridsign/src/lib.rs`

**Interfaces:**
- Consumes: `ClassicalScheme` from Task 3.
- Produces: `pqhybridsign::classical::Ed25519` implementing `ClassicalScheme` with `NAME = "ed25519"`, `PUBLIC_KEY_LEN = 32`, `SECRET_KEY_LEN = 64`, `SIGNATURE_LEN = 64`.

The composite secret key holds 64 bytes, seed then public key, per specification section 3. `ed25519-zebra` keeps only the 32-byte seed, so the implementation stores both and passes the seed half to the crate.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign/src/classical/ed25519.rs` with this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::ClassicalScheme;

    const LABEL: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

    fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
        let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
        Ed25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn secret_key_holds_seed_then_public_key() {
        let (sk, pk) = keypair(1);
        assert_eq!(&sk[..32], &[1u8; 32], "first half is the seed");
        assert_eq!(&sk[32..], &pk[..], "second half is the public key");
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(2);
        let mut sig = [0u8; 64];
        Ed25519::sign_deterministic(&sk, b"msg", b"nonce", LABEL, &mut sig).expect("sign");
        assert!(bool::from(Ed25519::verify(&pk, b"msg", LABEL, &sig)));
    }

    #[test]
    fn a_wrong_message_fails() {
        let (sk, pk) = keypair(3);
        let mut sig = [0u8; 64];
        Ed25519::sign_deterministic(&sk, b"msg", b"nonce", LABEL, &mut sig).expect("sign");
        assert!(!bool::from(Ed25519::verify(&pk, b"other", LABEL, &sig)));
    }

    #[test]
    fn deterministic_signing_is_canonical() {
        let (sk, _) = keypair(4);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        Ed25519::sign_deterministic(&sk, b"m", b"n", LABEL, &mut a).expect("sign");
        Ed25519::sign_deterministic(&sk, b"m", b"n", LABEL, &mut b).expect("sign");
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_nonce_gives_a_different_signature() {
        let (sk, _) = keypair(5);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        Ed25519::sign_deterministic(&sk, b"m", b"n1", LABEL, &mut a).expect("sign");
        Ed25519::sign_deterministic(&sk, b"m", b"n2", LABEL, &mut b).expect("sign");
        assert_ne!(a, b);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign ed25519`
Expected: FAIL, `cannot find struct Ed25519`.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `ed25519.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use ed25519_zebra::{SigningKey, VerificationKey};
use pqhybridsign_core::{ClassicalScheme, Error, Result};
use sha2::{Digest, Sha512};
use subtle::Choice;
use zeroize::Zeroize;

/// ed25519 classical component, per RFC 8032.
#[derive(Clone, Copy, Debug)]
pub struct Ed25519;

impl ClassicalScheme for Ed25519 {
    const NAME: &'static str = "ed25519";
    const PUBLIC_KEY_LEN: usize = 32;
    const SECRET_KEY_LEN: usize = 64;
    const SIGNATURE_LEN: usize = 64;

    fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
        check_len(sk_out, Self::SECRET_KEY_LEN)?;
        check_len(pk_out, Self::PUBLIC_KEY_LEN)?;
        let signing = SigningKey::from(*seed);
        let public: [u8; 32] = VerificationKey::from(&signing).into();
        sk_out[..32].copy_from_slice(seed);
        sk_out[32..].copy_from_slice(&public);
        pk_out.copy_from_slice(&public);
        Ok(())
    }

    fn sign(
        sk: &[u8],
        msg: &[u8],
        _label: &'static [u8],
        _rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()> {
        // ed25519 is deterministic by specification, so hedged signing and
        // deterministic signing coincide when no nonce is supplied.
        raw_sign(sk, msg, sig_out)
    }

    fn sign_deterministic(
        sk: &[u8],
        msg: &[u8],
        nonce: &[u8],
        _label: &'static [u8],
        sig_out: &mut [u8],
    ) -> Result<()> {
        // Specification section 8 and 14: the Schnorr nonce must always
        // include the secret key. Bind the network nonce by deriving a
        // per-signature seed as H(seed || nonce), then sign with it.
        check_len(sk, Self::SECRET_KEY_LEN)?;
        let mut hasher = Sha512::new();
        hasher.update(&sk[..32]);
        hasher.update(nonce);
        let digest = hasher.finalize();
        let mut derived = [0u8; 32];
        derived.copy_from_slice(&digest[..32]);
        let result = raw_sign_with_seed(&derived, msg, sig_out);
        derived.zeroize();
        result
    }

    fn verify(pk: &[u8], msg: &[u8], _label: &'static [u8], sig: &[u8]) -> Choice {
        let Ok(pk): core::result::Result<[u8; 32], _> = pk.try_into() else {
            return Choice::from(0u8);
        };
        let Ok(sig): core::result::Result<[u8; 64], _> = sig.try_into() else {
            return Choice::from(0u8);
        };
        let Ok(vk) = VerificationKey::try_from(pk) else {
            return Choice::from(0u8);
        };
        Choice::from(u8::from(vk.verify(&sig.into(), msg).is_ok()))
    }
}

fn check_len(buf: &[u8], want: usize) -> Result<()> {
    if buf.len() == want {
        Ok(())
    } else {
        Err(Error::BadLength { expected: want, actual: buf.len() })
    }
}

fn raw_sign(sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<()> {
    check_len(sk, 64)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk[..32]);
    let result = raw_sign_with_seed(&seed, msg, sig_out);
    seed.zeroize();
    result
}

fn raw_sign_with_seed(seed: &[u8; 32], msg: &[u8], sig_out: &mut [u8]) -> Result<()> {
    check_len(sig_out, 64)?;
    let signing = SigningKey::from(*seed);
    let sig: [u8; 64] = signing.sign(msg).into();
    sig_out.copy_from_slice(&sig);
    Ok(())
}
```

Create `crates/pqhybridsign/src/classical/mod.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
mod ed25519;
pub use ed25519::Ed25519;
```

Add to `crates/pqhybridsign/src/lib.rs`:

```rust
pub mod classical;
```

Add `sha2` to `crates/pqhybridsign/Cargo.toml` dependencies:

```toml
sha2.workspace = true
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign ed25519`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign/
git commit -m "feat(lattice): add ed25519 classical component

The composite secret key holds seed then public key, 64 bytes, per
specification section 3. Deterministic signing derives a per-signature
seed as H(seed || nonce), so the secret key always takes part in the
nonce and stays unrecoverable.

Closes pqhs-8ep.12"
```

---

### Task 8: sr25519 component

**Files:**
- Create: `crates/pqhybridsign/src/classical/sr25519.rs`
- Modify: `crates/pqhybridsign/src/classical/mod.rs`

**Interfaces:**
- Consumes: `ClassicalScheme`.
- Produces: `pqhybridsign::classical::Sr25519` with `NAME = "sr25519"`, sizes 32 / 64 / 64.

The `label` argument is the schnorrkel signing context, per beads `pqhs-8ep.9`. That is the second separation layer below `M'`, and it stops the classical half verifying under a stock Substrate sr25519 verifier.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign/src/classical/sr25519.rs` with this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::ClassicalScheme;

    const H1: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";
    const H3: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";

    fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
        let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
        Sr25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(1);
        let mut sig = [0u8; 64];
        Sr25519::sign_deterministic(&sk, b"msg", b"nonce", H3, &mut sig).expect("sign");
        assert!(bool::from(Sr25519::verify(&pk, b"msg", H3, &sig)));
    }

    #[test]
    fn a_signature_does_not_verify_under_another_suite_context() {
        // The signing context is the suite label. This is the second
        // separation layer below M-prime, per beads pqhs-8ep.9.
        let (sk, pk) = keypair(2);
        let mut sig = [0u8; 64];
        Sr25519::sign_deterministic(&sk, b"msg", b"nonce", H3, &mut sig).expect("sign");
        assert!(!bool::from(Sr25519::verify(&pk, b"msg", H1, &sig)));
    }

    #[test]
    fn deterministic_signing_is_canonical() {
        let (sk, _) = keypair(3);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        Sr25519::sign_deterministic(&sk, b"m", b"n", H3, &mut a).expect("sign");
        Sr25519::sign_deterministic(&sk, b"m", b"n", H3, &mut b).expect("sign");
        assert_eq!(a, b);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(keypair(4), keypair(4));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign sr25519`
Expected: FAIL, `cannot find struct Sr25519`.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `sr25519.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use pqhybridsign_core::{ClassicalScheme, Error, Result};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use schnorrkel::{signing_context, ExpansionMode, MiniSecretKey, PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha512};
use subtle::Choice;
use zeroize::Zeroize;

/// sr25519 classical component, Schnorr over Ristretto.
#[derive(Clone, Copy, Debug)]
pub struct Sr25519;

/// A deterministic RNG seeded from `H(sk || nonce || msg)`.
///
/// schnorrkel draws its Schnorr nonce from this RNG. Seeding it from the
/// secret key keeps the nonce secret, which specification section 14
/// requires: a public nonce makes the signing key trivially recoverable.
struct SeededRng {
    state: [u8; 32],
    counter: u64,
    buffer: [u8; 64],
    used: usize,
}

impl SeededRng {
    fn new(seed: [u8; 32]) -> Self {
        Self { state: seed, counter: 0, buffer: [0u8; 64], used: 64 }
    }
    fn refill(&mut self) {
        let mut hasher = Sha512::new();
        hasher.update(self.state);
        hasher.update(self.counter.to_be_bytes());
        self.buffer.copy_from_slice(&hasher.finalize());
        self.counter += 1;
        self.used = 0;
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.used == self.buffer.len() {
                self.refill();
            }
            *byte = self.buffer[self.used];
            self.used += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

impl Drop for SeededRng {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
    }
}

impl ClassicalScheme for Sr25519 {
    const NAME: &'static str = "sr25519";
    const PUBLIC_KEY_LEN: usize = 32;
    const SECRET_KEY_LEN: usize = 64;
    const SIGNATURE_LEN: usize = 64;

    fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
        check_len(sk_out, Self::SECRET_KEY_LEN)?;
        check_len(pk_out, Self::PUBLIC_KEY_LEN)?;
        let mini = MiniSecretKey::from_bytes(seed).map_err(|_| Error::ComponentFailure)?;
        let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);
        sk_out.copy_from_slice(&keypair.secret.to_bytes());
        pk_out.copy_from_slice(&keypair.public.to_bytes());
        Ok(())
    }

    fn sign(
        sk: &[u8],
        msg: &[u8],
        label: &'static [u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let result = sign_with_rng(sk, msg, label, &mut SeededRng::new(seed), sig_out);
        seed.zeroize();
        result
    }

    fn sign_deterministic(
        sk: &[u8],
        msg: &[u8],
        nonce: &[u8],
        label: &'static [u8],
        sig_out: &mut [u8],
    ) -> Result<()> {
        check_len(sk, Self::SECRET_KEY_LEN)?;
        // k = H(sk || nonce || msg). The secret key always takes part.
        let mut hasher = Sha512::new();
        hasher.update(sk);
        hasher.update(nonce);
        hasher.update(msg);
        let digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        let result = sign_with_rng(sk, msg, label, &mut SeededRng::new(seed), sig_out);
        seed.zeroize();
        result
    }

    fn verify(pk: &[u8], msg: &[u8], label: &'static [u8], sig: &[u8]) -> Choice {
        let Ok(public) = PublicKey::from_bytes(pk) else {
            return Choice::from(0u8);
        };
        let Ok(signature) = Signature::from_bytes(sig) else {
            return Choice::from(0u8);
        };
        let ctx = signing_context(label);
        Choice::from(u8::from(public.verify(ctx.bytes(msg), &signature).is_ok()))
    }
}

fn check_len(buf: &[u8], want: usize) -> Result<()> {
    if buf.len() == want {
        Ok(())
    } else {
        Err(Error::BadLength { expected: want, actual: buf.len() })
    }
}

fn sign_with_rng(
    sk: &[u8],
    msg: &[u8],
    label: &'static [u8],
    rng: &mut SeededRng,
    sig_out: &mut [u8],
) -> Result<()> {
    check_len(sk, 64)?;
    check_len(sig_out, 64)?;
    let secret = SecretKey::from_bytes(sk).map_err(|_| Error::ComponentFailure)?;
    let public = secret.to_public();
    let ctx = signing_context(label);
    let sig = secret.sign(ctx.bytes(msg).with_rng(rng), &public);
    sig_out.copy_from_slice(&sig.to_bytes());
    Ok(())
}
```

Add to `crates/pqhybridsign/src/classical/mod.rs`:

```rust
mod sr25519;
pub use sr25519::Sr25519;
```

Note on the schnorrkel API: `ctx.bytes(msg)` returns a transcript, and `.with_rng(rng)` attaches the nonce source. If the installed `schnorrkel` version names this differently, check `cargo doc -p schnorrkel --open` for `SigningTranscript` and adapt. Do not fall back to `secret.sign_simple`, which draws from the operating system RNG and breaks the canonicality test.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign sr25519`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign/
git commit -m "feat(lattice): add sr25519 classical component

The signing context is the suite label, so a stock Substrate sr25519
verifier cannot validate the classical half on its own. That supports the
key non-reuse requirement in specification sections 5 and 14.

Deterministic signing seeds a hash-based RNG from H(sk || nonce || msg),
keeping the Schnorr nonce secret.

Closes pqhs-8ep.13"
```

---

### Task 9: ML-DSA-44 component

**Files:**
- Create: `crates/pqhybridsign/src/pq/mod.rs`, `crates/pqhybridsign/src/pq/mldsa44.rs`
- Modify: `crates/pqhybridsign/src/lib.rs`

**Interfaces:**
- Consumes: `PqScheme`.
- Produces: `pqhybridsign::pq::MlDsa44` with `NAME = "mldsa44"`, sizes 1312 / 2560 / 2420, `SEED_LEN = 32`, `IS_DETERMINISTIC = true`.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign/src/pq/mldsa44.rs` with this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::PqScheme;

    fn keypair(seed: u8) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
        let mut sk = alloc::vec![0u8; MlDsa44::SECRET_KEY_LEN];
        let mut pk = alloc::vec![0u8; MlDsa44::PUBLIC_KEY_LEN];
        MlDsa44::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn sizes_match_the_specification() {
        assert_eq!(MlDsa44::PUBLIC_KEY_LEN, 1312);
        assert_eq!(MlDsa44::SECRET_KEY_LEN, 2560);
        assert_eq!(MlDsa44::SIGNATURE_LEN, 2420);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(keypair(1), keypair(1));
        assert_ne!(keypair(1), keypair(2));
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(3);
        let mut sig = alloc::vec![0u8; MlDsa44::SIGNATURE_LEN];
        MlDsa44::sign_deterministic(&sk, b"msg", b"ignored", &mut sig).expect("sign");
        assert!(bool::from(MlDsa44::verify(&pk, b"msg", &sig)));
        assert!(!bool::from(MlDsa44::verify(&pk, b"other", &sig)));
    }

    #[test]
    fn deterministic_signing_is_canonical() {
        let (sk, _) = keypair(4);
        let mut a = alloc::vec![0u8; MlDsa44::SIGNATURE_LEN];
        let mut b = alloc::vec![0u8; MlDsa44::SIGNATURE_LEN];
        MlDsa44::sign_deterministic(&sk, b"m", b"n1", &mut a).expect("sign");
        MlDsa44::sign_deterministic(&sk, b"m", b"n2", &mut b).expect("sign");
        assert_eq!(a, b, "the nonce is ignored: ML-DSA is deterministic by specification");
    }
}
```

Add `extern crate alloc;` at the top of `mldsa44.rs` if the crate is not already `std`-only.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign mldsa44`
Expected: FAIL, `cannot find struct MlDsa44`.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `mldsa44.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use pqhybridsign_core::{Error, PqScheme, Result};
use subtle::Choice;

/// ML-DSA-44 post-quantum component, FIPS 204.
#[derive(Clone, Copy, Debug)]
pub struct MlDsa44;

/// The `ctx` argument to `fips204`. Always empty: specification section 7
/// already binds every suite through `M'`, and using the crate context as
/// well would add a second, unspecified separation layer.
const EMPTY_CTX: &[u8] = &[];

/// The FIPS 204 deterministic variant supplies an all-zero `rnd` value.
const ZERO_SEED: [u8; 32] = [0u8; 32];

impl PqScheme for MlDsa44 {
    const NAME: &'static str = "mldsa44";
    const PUBLIC_KEY_LEN: usize = ml_dsa_44::PK_LEN;
    const SECRET_KEY_LEN: usize = ml_dsa_44::SK_LEN;
    const SIGNATURE_LEN: usize = ml_dsa_44::SIG_LEN;
    const SEED_LEN: usize = 32;
    const IS_DETERMINISTIC: bool = true;

    fn derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
        let seed: &[u8; 32] = seed.try_into().map_err(|_| Error::BadLength {
            expected: 32,
            actual: seed.len(),
        })?;
        check_len(sk_out, Self::SECRET_KEY_LEN)?;
        check_len(pk_out, Self::PUBLIC_KEY_LEN)?;
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(seed);
        sk_out.copy_from_slice(&sk.into_bytes());
        pk_out.copy_from_slice(&pk.into_bytes());
        Ok(())
    }

    fn sign(
        sk: &[u8],
        msg: &[u8],
        _rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()> {
        // ML-DSA-44 is deterministic by specification, so hedged and
        // deterministic signing coincide here.
        Self::sign_deterministic(sk, msg, &[], sig_out)
    }

    fn sign_deterministic(sk: &[u8], msg: &[u8], _nonce: &[u8], sig_out: &mut [u8]) -> Result<()> {
        check_len(sig_out, Self::SIGNATURE_LEN)?;
        let bytes: [u8; ml_dsa_44::SK_LEN] = sk.try_into().map_err(|_| Error::BadLength {
            expected: Self::SECRET_KEY_LEN,
            actual: sk.len(),
        })?;
        let private = ml_dsa_44::PrivateKey::try_from_bytes(bytes)
            .map_err(|_| Error::ComponentFailure)?;
        let sig = private
            .try_sign_with_seed(&ZERO_SEED, msg, EMPTY_CTX)
            .map_err(|_| Error::ComponentFailure)?;
        sig_out.copy_from_slice(&sig);
        Ok(())
    }

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Choice {
        let Ok(pk_bytes): core::result::Result<[u8; ml_dsa_44::PK_LEN], _> = pk.try_into() else {
            return Choice::from(0u8);
        };
        let Ok(sig_bytes): core::result::Result<[u8; ml_dsa_44::SIG_LEN], _> = sig.try_into()
        else {
            return Choice::from(0u8);
        };
        let Ok(public) = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes) else {
            return Choice::from(0u8);
        };
        Choice::from(u8::from(public.verify(msg, &sig_bytes, EMPTY_CTX)))
    }
}

fn check_len(buf: &[u8], want: usize) -> Result<()> {
    if buf.len() == want {
        Ok(())
    } else {
        Err(Error::BadLength { expected: want, actual: buf.len() })
    }
}
```

Create `crates/pqhybridsign/src/pq/mod.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
mod mldsa44;
pub use mldsa44::MlDsa44;
```

Add to `crates/pqhybridsign/src/lib.rs`:

```rust
pub mod pq;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign mldsa44`
Expected: PASS, 4 tests.

If `try_sign_with_seed` or `Verifier::verify` differ in arity, run `cargo doc -p fips204 --open` and adapt. Do not change the empty `ctx` decision.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign/
git commit -m "feat(lattice): add ML-DSA-44 post-quantum component

Uses keygen_from_seed for the section 9 derivation and
try_sign_with_seed with an all-zero seed for the deterministic path. The
fips204 ctx argument stays empty: M-prime already carries every suite
binding.

Closes pqhs-8ep.14"
```

---

### Task 10: Composite signing, verification and encoding

**Files:**
- Create: `crates/pqhybridsign-core/src/composite.rs`
- Modify: `crates/pqhybridsign-core/src/lib.rs`
- Test: `crates/pqhybridsign-core/tests/composite.rs` uses the stubs, real coverage lands in Task 11.

**Interfaces:**
- Consumes: `Suite`, `ClassicalScheme`, `PqScheme`, `write_m_prime`, `derive_component_seeds`.
- Produces: on a `Suite` type `S`: `keypair_from_seed::<S>(master, sk_out, pk_out)`, `sign::<S>(sk, msg, ctx, rng, sig_out)`, `sign_deterministic::<S>(sk, msg, ctx, nonce, sig_out)`, `verify::<S>(pk, msg, ctx, sig) -> bool`.

Layout is classical first, post-quantum second, split at a constant offset, per specification section 6.

- [ ] **Step 1: Write the failing test**

Create `crates/pqhybridsign-core/tests/composite.rs`. Reuse the stub components from `tests/suite_macro.rs` by copying them into this file, then:

```rust
#[test]
fn signature_splits_classical_then_pq() {
    let mut sig = alloc::vec![0u8; <H1Test as Suite>::SIGNATURE_LEN];
    let sk = alloc::vec![0u8; <H1Test as Suite>::SECRET_KEY_LEN];
    pqhybridsign_core::composite::sign_deterministic::<H1Test>(&sk, b"m", b"", b"n", &mut sig)
        .expect("sign");
    assert_eq!(sig.len(), 2484);
    assert_eq!(<H1Test as Suite>::SPLIT, 64);
}

#[test]
fn verify_rejects_a_wrong_length_signature() {
    let pk = alloc::vec![0u8; <H1Test as Suite>::PUBLIC_KEY_LEN];
    let short = alloc::vec![0u8; <H1Test as Suite>::SIGNATURE_LEN - 1];
    assert!(!pqhybridsign_core::composite::verify::<H1Test>(&pk, b"m", b"", &short));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign-core --test composite`
Expected: FAIL, `cannot find module composite`.

- [ ] **Step 3: Write the minimal implementation**

Create `crates/pqhybridsign-core/src/composite.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    derive_component_seeds, m_prime_len, write_m_prime, ClassicalScheme, Error, PqScheme, Result,
    Suite,
};
use subtle::Choice;
use zeroize::Zeroize;

/// Largest `M'` this crate builds on the stack. Longer messages need the
/// `alloc` feature.
const STACK_M_PRIME: usize = 512;

/// Derive a composite keypair from a 32-byte master seed.
///
/// Layout is classical first, post-quantum second, split at a constant
/// offset, per specification sections 5 and 6.
pub fn keypair_from_seed<S: Suite>(
    master: &[u8; 32],
    sk_out: &mut [u8],
    pk_out: &mut [u8],
) -> Result<()> {
    exact(sk_out, S::SECRET_KEY_LEN)?;
    exact(pk_out, S::PUBLIC_KEY_LEN)?;

    let mut classical_seed = [0u8; 32];
    let mut pq_seed = [0u8; 64];
    let pq_len = <S::Pq as PqScheme>::SEED_LEN;
    if pq_len > pq_seed.len() {
        return Err(Error::OutputBufferTooSmall { needed: pq_len, actual: pq_seed.len() });
    }

    let result = (|| {
        derive_component_seeds(master, S::LABEL, &mut classical_seed, &mut pq_seed[..pq_len])?;
        let c_sk = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
        let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
        <S::Classical as ClassicalScheme>::derive(
            &classical_seed,
            &mut sk_out[..c_sk],
            &mut pk_out[..c_pk],
        )?;
        <S::Pq as PqScheme>::derive(&pq_seed[..pq_len], &mut sk_out[c_sk..], &mut pk_out[c_pk..])
    })();

    classical_seed.zeroize();
    pq_seed.zeroize();
    result
}

/// Hedged composite signing.
pub fn sign<S: Suite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    sig_out: &mut [u8],
) -> Result<()> {
    with_m_prime::<S>(msg, ctx, |m| {
        let (c_sk, c_sig) = split_secret::<S>(sk, sig_out)?;
        <S::Classical as ClassicalScheme>::sign(c_sk.0, m, S::LABEL, rng, c_sig.0)?;
        <S::Pq as PqScheme>::sign(c_sk.1, m, rng, c_sig.1)
    })
}

/// Deterministic composite signing.
pub fn sign_deterministic<S: Suite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
    sig_out: &mut [u8],
) -> Result<()> {
    with_m_prime::<S>(msg, ctx, |m| {
        let (c_sk, c_sig) = split_secret::<S>(sk, sig_out)?;
        <S::Classical as ClassicalScheme>::sign_deterministic(c_sk.0, m, nonce, S::LABEL, c_sig.0)?;
        <S::Pq as PqScheme>::sign_deterministic(c_sk.1, m, nonce, c_sig.1)
    })
}

/// Composite verification.
///
/// Combines both components with a non-short-circuiting `Choice`
/// conjunction, so the result never reveals which component failed.
/// Returns `false` for any malformed input rather than an error, for the
/// same reason.
pub fn verify<S: Suite>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != S::PUBLIC_KEY_LEN || sig.len() != S::SIGNATURE_LEN {
        return false;
    }
    let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
    let c_sig = <S::Classical as ClassicalScheme>::SIGNATURE_LEN;

    let outcome = with_m_prime::<S>(msg, ctx, |m| {
        let classical_ok =
            <S::Classical as ClassicalScheme>::verify(&pk[..c_pk], m, S::LABEL, &sig[..c_sig]);
        let pq_ok = <S::Pq as PqScheme>::verify(&pk[c_pk..], m, &sig[c_sig..]);
        // Bitwise AND, never `&&`: no short circuit, no timing signal.
        Ok(classical_ok & pq_ok)
    });

    match outcome {
        Ok(choice) => bool::from(choice),
        Err(_) => false,
    }
}

type Halves<'a> = (&'a [u8], &'a [u8]);
type HalvesMut<'a> = (&'a mut [u8], &'a mut [u8]);

fn split_secret<'a, S: Suite>(
    sk: &'a [u8],
    sig_out: &'a mut [u8],
) -> Result<(Halves<'a>, HalvesMut<'a>)> {
    exact(sk, S::SECRET_KEY_LEN)?;
    exact(sig_out, S::SIGNATURE_LEN)?;
    let c_sk = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
    let c_sig = <S::Classical as ClassicalScheme>::SIGNATURE_LEN;
    let (sk_a, sk_b) = sk.split_at(c_sk);
    let (sig_a, sig_b) = sig_out.split_at_mut(c_sig);
    Ok(((sk_a, sk_b), (sig_a, sig_b)))
}

fn exact(buf: &[u8], want: usize) -> Result<()> {
    if buf.len() == want {
        Ok(())
    } else {
        Err(Error::BadLength { expected: want, actual: buf.len() })
    }
}

fn with_m_prime<S: Suite, T>(
    msg: &[u8],
    ctx: &[u8],
    f: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    let needed = m_prime_len(S::LABEL, ctx, msg)?;
    if needed <= STACK_M_PRIME {
        let mut buf = [0u8; STACK_M_PRIME];
        let n = write_m_prime(&mut buf[..needed], S::LABEL, ctx, msg)?;
        let out = f(&buf[..n]);
        buf.zeroize();
        return out;
    }
    #[cfg(feature = "alloc")]
    {
        let mut buf = alloc::vec![0u8; needed];
        let n = write_m_prime(&mut buf, S::LABEL, ctx, msg)?;
        let out = f(&buf[..n]);
        buf.zeroize();
        out
    }
    #[cfg(not(feature = "alloc"))]
    {
        Err(Error::OutputBufferTooSmall { needed, actual: STACK_M_PRIME })
    }
}
```

Add to `lib.rs`:

```rust
pub mod composite;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pqhybridsign-core --test composite`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign-core/
git commit -m "feat(core): add composite signing, verification and encoding

Verification combines both components with a bitwise Choice conjunction
and returns false for malformed input, so neither the result nor the error
channel reveals which component failed.

Closes pqhs-8ep.7, closes pqhs-8ep.8"
```

---

### Task 11: Wire H1 and H3, and the specification test suite

**Files:**
- Create: `crates/pqhybridsign/src/suites.rs`
- Modify: `crates/pqhybridsign/src/lib.rs`
- Test: `crates/pqhybridsign/tests/spec_tests.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: `pqhybridsign::H1`, `pqhybridsign::H3`.

Covers specification section 17 tests 1, 2, 3, 5, 6, 7, 8, 9 and 10. Test 4 is Falcon-only and does not apply.

- [ ] **Step 1: Write the suite declarations**

Create `crates/pqhybridsign/src/suites.rs`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::classical::{Ed25519, Sr25519};
use crate::pq::MlDsa44;
use pqhybridsign_core::hybrid_suite;

hybrid_suite! {
    /// H1: ed25519 + ML-DSA-44. Composite sizes 1344 / 2624 / 2484.
    H1,
    classical = Ed25519 as "ed25519",
    pq = MlDsa44 as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

hybrid_suite! {
    /// H3: sr25519 + ML-DSA-44. Composite sizes 1344 / 2624 / 2484.
    H3,
    classical = Sr25519 as "sr25519",
    pq = MlDsa44 as "mldsa44",
    label = "hybrid-sr25519-mldsa44-v1",
    label_len = 26,
}
```

Add to `crates/pqhybridsign/src/lib.rs`:

```rust
mod suites;
pub use suites::{H1, H3};
```

- [ ] **Step 2: Write the failing specification tests**

Create `crates/pqhybridsign/tests/spec_tests.rs`:

```rust
// Specification section 17, tests 1 to 10. Test 4 is Falcon-only.
use pqhybridsign::{H1, H3};
use pqhybridsign_core::composite::{keypair_from_seed, sign, sign_deterministic, verify};
use pqhybridsign_core::Suite;
use rand_core::OsRng;

macro_rules! keys {
    ($suite:ty, $seed:expr) => {{
        let mut sk = vec![0u8; <$suite as Suite>::SECRET_KEY_LEN];
        let mut pk = vec![0u8; <$suite as Suite>::PUBLIC_KEY_LEN];
        keypair_from_seed::<$suite>(&[$seed; 32], &mut sk, &mut pk).expect("keygen");
        (sk, pk)
    }};
}

macro_rules! suite_tests {
    ($mod_name:ident, $suite:ty) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn t1_round_trip() {
                let (sk, pk) = keys!($suite, 1);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign::<$suite>(&sk, b"hello", b"ctx", &mut OsRng, &mut sig).expect("sign");
                assert!(verify::<$suite>(&pk, b"hello", b"ctx", &sig));
            }

            #[test]
            fn t3_deterministic_canonicality() {
                let (sk, _) = keys!($suite, 3);
                let mut a = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                let mut b = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"nonce", &mut a).expect("sign");
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"nonce", &mut b).expect("sign");
                assert_eq!(a, b);
            }

            #[test]
            fn t5_cross_mode_interop() {
                let (sk, pk) = keys!($suite, 5);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"n", &mut sig).expect("sign");
                assert!(verify::<$suite>(&pk, b"m", b"c", &sig));
            }

            #[test]
            fn t6_domain_separation_by_context() {
                let (sk, pk) = keys!($suite, 6);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"ctx-a", b"n", &mut sig).expect("sign");
                assert!(!verify::<$suite>(&pk, b"m", b"ctx-b", &sig));
            }

            #[test]
            fn t9_truncated_signature_is_rejected() {
                let (sk, pk) = keys!($suite, 9);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"n", &mut sig).expect("sign");
                // Classical half alone must never verify as a composite.
                assert!(!verify::<$suite>(&pk, b"m", b"c", &sig[..64]));
                // A signature with the post-quantum half zeroed must fail.
                let mut tampered = sig.clone();
                tampered[64..].fill(0);
                assert!(!verify::<$suite>(&pk, b"m", b"c", &tampered));
                // A signature with the classical half zeroed must fail.
                let mut tampered = sig.clone();
                tampered[..64].fill(0);
                assert!(!verify::<$suite>(&pk, b"m", b"c", &tampered));
            }

            #[test]
            fn t10_different_messages_give_different_signatures() {
                let (sk, _) = keys!($suite, 10);
                let mut a = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                let mut b = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m1", b"c", b"n", &mut a).expect("sign");
                sign_deterministic::<$suite>(&sk, b"m2", b"c", b"n", &mut b).expect("sign");
                assert_ne!(&a[..64], &b[..64], "classical halves must differ");
            }

            #[test]
            fn t7_composite_sizes() {
                assert_eq!(<$suite as Suite>::PUBLIC_KEY_LEN, 1344);
                assert_eq!(<$suite as Suite>::SECRET_KEY_LEN, 2624);
                assert_eq!(<$suite as Suite>::SIGNATURE_LEN, 2484);
            }
        }
    };
}

suite_tests!(h1, H1);
suite_tests!(h3, H3);

#[test]
fn t6_cross_suite_signatures_never_verify() {
    // A signature made under H1 must not verify under H3, and the reverse.
    let mut sk1 = vec![0u8; <H1 as Suite>::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; <H1 as Suite>::PUBLIC_KEY_LEN];
    keypair_from_seed::<H1>(&[42u8; 32], &mut sk1, &mut pk1).expect("keygen");
    let mut sig = vec![0u8; <H1 as Suite>::SIGNATURE_LEN];
    sign_deterministic::<H1>(&sk1, b"m", b"c", b"n", &mut sig).expect("sign");
    assert!(verify::<H1>(&pk1, b"m", b"c", &sig));
    assert!(!verify::<H3>(&pk1, b"m", b"c", &sig));
}

#[test]
fn one_master_seed_gives_two_independent_suites() {
    // Specification section 9: suite-separated derivation. Without it, H1
    // and H3 would share a post-quantum key.
    let mut sk1 = vec![0u8; <H1 as Suite>::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; <H1 as Suite>::PUBLIC_KEY_LEN];
    let mut sk3 = vec![0u8; <H3 as Suite>::SECRET_KEY_LEN];
    let mut pk3 = vec![0u8; <H3 as Suite>::PUBLIC_KEY_LEN];
    keypair_from_seed::<H1>(&[7u8; 32], &mut sk1, &mut pk1).expect("keygen");
    keypair_from_seed::<H3>(&[7u8; 32], &mut sk3, &mut pk3).expect("keygen");
    assert_ne!(&sk1[64..], &sk3[64..], "post-quantum halves must differ");
}

#[test]
fn t2_hedged_signing_is_not_deterministic_for_sr25519() {
    // H1 is deterministic in both halves by specification, so this applies
    // to H3 only.
    let (sk, _) = keys!(H3, 2);
    let mut a = vec![0u8; <H3 as Suite>::SIGNATURE_LEN];
    let mut b = vec![0u8; <H3 as Suite>::SIGNATURE_LEN];
    sign::<H3>(&sk, b"m", b"c", &mut OsRng, &mut a).expect("sign");
    sign::<H3>(&sk, b"m", b"c", &mut OsRng, &mut b).expect("sign");
    assert_ne!(&a[..64], &b[..64], "hedged sr25519 must not repeat a signature");
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p pqhybridsign --test spec_tests`
Expected: FAIL, `cannot find H1`.

- [ ] **Step 4: Make them pass**

The suite declarations from Step 1 should be enough. Fix whatever the compiler reports. Do not weaken a test to make it pass. If `t9` fails because a short signature is accepted, that is a real defect in `composite::verify` and must be fixed there.

Run: `cargo test -p pqhybridsign --test spec_tests`
Expected: PASS, 17 tests.

Run: `cargo test --workspace --release`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign/
git commit -m "feat(lattice): wire the H1 and H3 suites with specification tests

Covers section 17 tests 1, 2, 3, 5, 6, 7, 9 and 10 for both suites, plus
cross-suite rejection and the section 9 suite separation property.

Closes pqhs-8ep.15, closes pqhs-8ep.16"
```

---

### Task 12: Golden vectors

**Files:**
- Create: `crates/pqhybridsign/tests/vectors/h1.json`, `crates/pqhybridsign/tests/vectors/h3.json`
- Create: `crates/pqhybridsign/tests/golden.rs`
- Create: `crates/pqhybridsign/tests/generate_vectors.rs`

**Interfaces:**
- Consumes: `H1`, `H3`, `keypair_from_seed`, `sign_deterministic`.
- Produces: checked-in vectors that pin the wire format.

Each vector records the derivation rule it covers, because this crate differs from the deployed `quip-crypto-primitives`. See Finding 3.

- [ ] **Step 1: Write the failing golden test**

Create `crates/pqhybridsign/tests/golden.rs`:

```rust
use pqhybridsign::{H1, H3};
use pqhybridsign_core::composite::{keypair_from_seed, sign_deterministic, verify};
use pqhybridsign_core::Suite;

#[derive(serde::Deserialize)]
struct Vector {
    suite: String,
    label_hex: String,
    hkdf_info_includes_label_null_byte: bool,
    master_seed_hex: String,
    ctx_hex: String,
    msg_hex: String,
    nonce_hex: String,
    public_key_hex: String,
    signature_hex: String,
}

fn check<S: Suite>(v: &Vector) {
    let master: [u8; 32] = hex::decode(&v.master_seed_hex).expect("seed")
        .try_into().expect("32 bytes");
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    keypair_from_seed::<S>(&master, &mut sk, &mut pk).expect("keygen");
    assert_eq!(hex::encode(&pk), v.public_key_hex, "{} public key drifted", v.suite);

    assert_eq!(hex::encode(S::LABEL), v.label_hex, "{} label drifted", v.suite);
    assert!(v.hkdf_info_includes_label_null_byte, "this crate pins the null byte inside info");

    let ctx = hex::decode(&v.ctx_hex).expect("ctx");
    let msg = hex::decode(&v.msg_hex).expect("msg");
    let nonce = hex::decode(&v.nonce_hex).expect("nonce");
    let mut sig = vec![0u8; S::SIGNATURE_LEN];
    sign_deterministic::<S>(&sk, &msg, &ctx, &nonce, &mut sig).expect("sign");
    assert_eq!(hex::encode(&sig), v.signature_hex, "{} signature drifted", v.suite);
    assert!(verify::<S>(&pk, &msg, &ctx, &sig));
}

#[test]
fn h1_matches_the_golden_vector() {
    let v: Vector = serde_json::from_str(include_str!("vectors/h1.json")).expect("parse");
    check::<H1>(&v);
}

#[test]
fn h3_matches_the_golden_vector() {
    let v: Vector = serde_json::from_str(include_str!("vectors/h3.json")).expect("parse");
    check::<H3>(&v);
}
```

Add dev-dependencies to `crates/pqhybridsign/Cargo.toml`:

```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pqhybridsign --test golden`
Expected: FAIL, the vector files do not exist.

- [ ] **Step 3: Generate the vectors**

Create `crates/pqhybridsign/tests/generate_vectors.rs` as an ignored test that prints the JSON:

```rust
use pqhybridsign::{H1, H3};
use pqhybridsign_core::composite::{keypair_from_seed, sign_deterministic};
use pqhybridsign_core::Suite;

fn emit<S: Suite>(name: &str) {
    let master = [0x2au8; 32];
    let (ctx, msg, nonce) = (b"quip-testnet".as_slice(), b"golden vector".as_slice(), b"nonce-0".as_slice());
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    keypair_from_seed::<S>(&master, &mut sk, &mut pk).expect("keygen");
    let mut sig = vec![0u8; S::SIGNATURE_LEN];
    sign_deterministic::<S>(&sk, msg, ctx, nonce, &mut sig).expect("sign");
    println!("{{");
    println!("  \"suite\": \"{name}\",");
    println!("  \"label_hex\": \"{}\",", hex::encode(S::LABEL));
    println!("  \"hkdf_info_includes_label_null_byte\": true,");
    println!("  \"master_seed_hex\": \"{}\",", hex::encode(master));
    println!("  \"ctx_hex\": \"{}\",", hex::encode(ctx));
    println!("  \"msg_hex\": \"{}\",", hex::encode(msg));
    println!("  \"nonce_hex\": \"{}\",", hex::encode(nonce));
    println!("  \"public_key_hex\": \"{}\",", hex::encode(&pk));
    println!("  \"signature_hex\": \"{}\"", hex::encode(&sig));
    println!("}}");
}

#[test]
#[ignore = "generator, run explicitly with --ignored"]
fn generate_h1() { emit::<H1>("H1"); }

#[test]
#[ignore = "generator, run explicitly with --ignored"]
fn generate_h3() { emit::<H3>("H3"); }
```

Run and capture:

```bash
mkdir -p crates/pqhybridsign/tests/vectors
cargo test -p pqhybridsign --test generate_vectors generate_h1 -- --ignored --nocapture \
  | sed -n '/^{/,/^}/p' > crates/pqhybridsign/tests/vectors/h1.json
cargo test -p pqhybridsign --test generate_vectors generate_h3 -- --ignored --nocapture \
  | sed -n '/^{/,/^}/p' > crates/pqhybridsign/tests/vectors/h3.json
```

Inspect both files. Confirm `label_hex` for H1 ends in `00` and decodes to 26 bytes.

- [ ] **Step 4: Run the golden test to verify it passes**

Run: `cargo test -p pqhybridsign --test golden`
Expected: PASS, 2 tests.

Then prove the vector is load-bearing: change one byte of `signature_hex` in `h1.json`, run the test, confirm it fails, and revert.

- [ ] **Step 5: Commit**

```bash
git add crates/pqhybridsign/
git commit -m "test(lattice): add golden vectors for H1 and H3

Each vector records the suite label and states that the HKDF info string
includes the label null byte. That resolves the section 9 ambiguity
recorded as Finding 2, and marks the deliberate difference from the
deployed quip-crypto-primitives derivation.

Closes pqhs-8ep.17"
```

---

### Task 13: Continuous integration gates

**Files:**
- Create: `.gitlab-ci.yml`
- Create: `crates/pqhybridsign-core/tests/compile_fail/secret_key_not_clone.rs` (deferred to Cycle 2, see note)

**Interfaces:**
- Consumes: the whole workspace.
- Produces: an automated gate matching the design's testing section.

- [ ] **Step 1: Write the pipeline**

Create `.gitlab-ci.yml`:

```yaml
stages: [check, test]

default:
  image: rust:1.83
  before_script:
    - rustup component add clippy rustfmt
    - rustup target add wasm32-unknown-unknown

fmt:
  stage: check
  script:
    - cargo fmt --all -- --check

clippy:
  stage: check
  script:
    - cargo clippy --workspace --all-targets -- -D warnings

deps:
  stage: check
  script:
    # All three component crates need rand_core 0.6. Two major versions in
    # the graph means a pin regressed.
    - test "$(cargo tree -i rand_core --workspace | grep -c '^rand_core v')" -eq 1

wasm:
  stage: check
  script:
    - cargo build -p pqhybridsign-core --target wasm32-unknown-unknown --no-default-features
    - cargo build -p pqhybridsign-core --target wasm32-unknown-unknown --no-default-features --features alloc

test-debug:
  stage: test
  script:
    - cargo test --workspace

test-release:
  stage: test
  script:
    # subtle uses debug_assert with secret-dependent branches, so release
    # mode exercises different code.
    - cargo test --workspace --release
```

- [ ] **Step 2: Run the same gates locally**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p pqhybridsign-core --target wasm32-unknown-unknown --no-default-features
cargo test --workspace
cargo test --workspace --release
```

Expected: all pass. Fix every clippy warning. The zero-warnings rule has no exceptions without an inline justification comment.

- [ ] **Step 3: Note the deferred gates**

`trybuild` compile-fail tests and `cargo-mutants` belong to the stateful work, where the negative guarantees carry security weight. Record that:

```bash
bd note pqhs-8ep.18 "trybuild and cargo-mutants gates deferred to Cycle 2 (pqhs-bz1.3),
where the !Clone guarantee on stateful secret keys makes them load-bearing. Cycle 1 ships
fmt, clippy with -D warnings, a single-rand_core dependency check, a wasm32-unknown-unknown
build of core, and the debug plus release test matrix."
```

- [ ] **Step 4: Commit**

```bash
git add .gitlab-ci.yml
git commit -m "ci: gate on fmt, clippy, wasm32 build and a debug/release test matrix

Includes a dependency check that fails when a second rand_core major
version enters the graph, which would break all three component crates.

Closes pqhs-8ep.18"
```

---

## Self-review

**Spec coverage.** Design sections map to tasks as follows. Component traits, Task 3. Suite declaration and the label grammar, Task 5. Message binding, Task 4. Fixed encoding, Task 10. Seed derivation, Task 6. Error handling, Tasks 2 and 10. Testing, Tasks 11, 12 and 13. Out-of-scope items stay out. Finding 4 blocks Cycle 4 only and needs no Cycle 1 task.

**Deliberately deferred.** Property tests with `proptest`, `trybuild` compile-fail tests, and `cargo-mutants` all move to Cycle 2, recorded in Task 13 Step 3. Cycle 1 has no secret type whose `Clone` absence carries security weight, so those gates would guard nothing yet.

**Type consistency.** `ClassicalScheme::sign` takes `(sk, msg, label, rng, sig_out)` in Tasks 3, 7 and 8. `PqScheme::sign` takes `(sk, msg, rng, sig_out)` in Tasks 3 and 9, with no label, because `M'` already carries it. `Suite::LABEL` is `&'static [u8]` throughout. `composite::verify` returns `bool`, never `Result`, in Tasks 10, 11 and 12.

**Known risk.** The `schnorrkel` transcript API in Task 8 (`ctx.bytes(msg).with_rng(rng)`) is the part most likely to differ from the installed version. Task 8 Step 3 says to check `cargo doc` and adapt, and names the fallback that must not be used.
