// SPDX-License-Identifier: AGPL-3.0-or-later
// This crate genuinely forbids `unsafe`. `forbid` is stricter than the
// workspace `[lints.rust] unsafe-code = "deny"` and, unlike `deny`,
// cannot be relaxed by a downstream `#![allow(unsafe_code)]` -- which
// `clippy::allow_attributes` would not flag, because it does not fire on
// crate-scope inner attributes.
#![forbid(unsafe_code)]
// Test-only fixtures use `unwrap`/`expect` freely; test failure is the
// desired outcome of a bad input.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![doc = "Stateful hash-based hybrid signatures: H5 (ed25519 + SHRINCS) and H6 (sr25519 + SHRINCS)."]

// Upstream hashsigs-rs allows at most one profile feature to be active at a
// time. Enabling more than one is a build-time error rather than a silent
// pick of whichever the resolver saw first.
#[cfg(any(
    all(feature = "profile-256s", feature = "profile-256s-sha2"),
    all(feature = "profile-256s", feature = "profile-128s-q18"),
    all(feature = "profile-256s", feature = "profile-128s-q20"),
    all(feature = "profile-256s-sha2", feature = "profile-128s-q18"),
    all(feature = "profile-256s-sha2", feature = "profile-128s-q20"),
    all(feature = "profile-128s-q18", feature = "profile-128s-q20"),
))]
compile_error!("pqhybridsign-shrincs: exactly one profile-* feature may be enabled at a time");

// Zero profile features selected. Without this the build still fails, but it
// fails deep inside `scheme.rs` on a missing associated constant followed by
// a cascade of unresolved imports, none of which names the cause. Say it
// here, next to the too-many case, so both mistakes read the same.
#[cfg(not(any(
    feature = "profile-256s",
    feature = "profile-256s-sha2",
    feature = "profile-128s-q18",
    feature = "profile-128s-q20",
)))]
compile_error!(
    "pqhybridsign-shrincs: no profile-* feature is enabled; select exactly one of \
     profile-256s, profile-256s-sha2, profile-128s-q18, profile-128s-q20 \
     (the crate's default is profile-256s, so this needs --no-default-features to reach)"
);

pub mod action;
pub mod bundle;
pub mod scheme;
pub mod suites;

pub use pqhybridsign_core::stateful_composite::{keygen, PublicKey, SecretKey};
pub use scheme::ShrincsScheme;
pub use suites::{H5, H6};
