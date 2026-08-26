// SPDX-License-Identifier: AGPL-3.0-or-later
// This crate genuinely forbids `unsafe`. `forbid` is stricter than the
// workspace `[lints.rust] unsafe-code = "deny"` and, unlike `deny`,
// cannot be relaxed by a downstream `#![allow(unsafe_code)]` -- which
// `clippy::allow_attributes` would not flag, because it does not fire on
// crate-scope inner attributes.
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = "Hybrid classical/post-quantum signatures.

Six suites, all AND-composed from a classical and a post-quantum half:

- **EdMl44** ed25519 + ML-DSA-44, **SrMl44** sr25519 + ML-DSA-44
- **EdFn512** ed25519 + FN-DSA-512, **SrFn512** sr25519 + FN-DSA-512
- **EdSh** ed25519 + SHRINCS, **SrSh** sr25519 + SHRINCS (stateful, behind the
  `stateful` feature)

# Module layout

The composite foundation is a toolkit: every module is public API and is
reached through its own path, `pqhybridsign::error::Error`,
`pqhybridsign::policy::LeafPolicyMachine`. There are no root re-exports of
it, because a partial set gave two access patterns for one type. The
lattice suites `EdMl44` through `SrFn512` are re-exported at the crate root. The
stateful hash-based suites live under `pqhybridsign::shrincs`, compiled only
when the `stateful` feature is on.
"]
// Test-only fixtures use `unwrap`/`expect`/`panic` freely (test failure is
// the desired outcome of a bad input), and the `hybrid_stateful_suite!`
// macro's generated `pub struct` is unreachable when a test invokes it
// inside a private `mod tests`, which is how several fixtures build their
// fake suites.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        unreachable_pub
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Test-only. The crate is `no_std` whenever the `std` feature is off, so
// `std` is not otherwise in scope here, but the test harness links it in
// every configuration `cargo test` can build. Test fakes use it for
// `thread_local!`, which `core` does not provide and which is what keeps a
// fake's call counters private to the test that drives them. `cargo build`
// does not compile `cfg(test)` code, so the `thumbv7em-none-eabi` builds
// that prove the `no_std` claim never see this.
#[cfg(test)]
extern crate std;

// Composite foundation. Generic over the classical and post-quantum halves,
// `no_std`, no signature backend of its own.
pub mod budget;
pub mod component;
pub mod composite;
pub mod composite_delta;
pub mod derive;
pub mod encoding_delta;
pub mod encoding_path;
pub mod error;
pub mod message;
#[cfg(feature = "mnemonic")]
pub mod mnemonic;
pub mod policy;
pub mod rotation;
pub mod stateful;
#[cfg(feature = "alloc")]
pub mod stateful_composite;
pub mod suite;
// Hybrid VRF for every suite, specification section 15. Behind the `vrf`
// feature: a signing-only build has no use for it and should not carry
// schnorrkel's VRF code or the ed25519 ECVRF.
#[cfg(feature = "vrf")]
pub mod vrf;

// Lattice suites EdMl44 through SrFn512, over `ed25519-zebra`, `schnorrkel`,
// `fips204`, and `fn-dsa`. Always compiled.
pub mod classical;
pub mod pq;
mod suites;

pub use suites::{EdFn512, EdMl44, SrFn512, SrMl44, MIN_FALCON512_SIG_LEN};

// Stateful hash-based suites EdSh and SrSh, over `hashsigs-rs`. Compiled when
// any SHRINCS profile is active. The `stateful` feature (on by default)
// selects the 256s profile; a caller may instead name another profile
// directly. With no profile, the SHRINCS code and the `hashsigs-rs`
// dependency are dropped entirely.
#[cfg(any(
    feature = "profile-256s",
    feature = "profile-256s-sha2",
    feature = "profile-128s-q18",
    feature = "profile-128s-q20"
))]
pub mod shrincs;
