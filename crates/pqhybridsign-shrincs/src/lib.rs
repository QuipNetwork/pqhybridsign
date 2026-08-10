// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
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

pub mod action;
pub mod bundle;
pub mod scheme;
pub mod suites;

pub use pqhybridsign_core::stateful_composite::{keygen, PublicKey, SecretKey};
pub use scheme::ShrincsScheme;
pub use suites::{H5, H6};
