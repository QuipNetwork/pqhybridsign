// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stateful hash-based hybrid signatures: H5 (ed25519 + SHRINCS) and H6
//! (sr25519 + SHRINCS), over `hashsigs-rs`.
//!
//! This module is compiled only when a SHRINCS profile is active. The
//! `stateful` feature (on by default) selects the 256s profile; a caller may
//! name another profile instead. `hashsigs-rs` allows one profile per build.

// hashsigs-rs allows at most one profile feature at a time. Enabling two is a
// build-time error here, with a clearer message than the panic its build
// script would raise. The no-profile case needs no guard: without a profile
// this module is not compiled at all, and the build is a lattice-only one.
#[cfg(any(
    all(feature = "profile-256s", feature = "profile-256s-sha2"),
    all(feature = "profile-256s", feature = "profile-128s-q18"),
    all(feature = "profile-256s", feature = "profile-128s-q20"),
    all(feature = "profile-256s-sha2", feature = "profile-128s-q18"),
    all(feature = "profile-256s-sha2", feature = "profile-128s-q20"),
    all(feature = "profile-128s-q18", feature = "profile-128s-q20"),
))]
compile_error!(
    "pqhybridsign: exactly one profile-* feature may be enabled at a time \
     (profile-256s, profile-256s-sha2, profile-128s-q18, profile-128s-q20)"
);

pub mod action;
pub mod bundle;
pub mod scheme;
pub mod suites;

pub use crate::stateful_composite::{keygen, PublicKey, SecretKey};
pub use scheme::ShrincsScheme;
pub use suites::{H5, H6};
