// SPDX-License-Identifier: AGPL-3.0-or-later
//! ED-SH (ed25519 + SHRINCS) and SR-SH (sr25519 + SHRINCS): suite
//! declarations.
//!
//! Labels for the active profile only, using
//! [`crate::hybrid_stateful_suite!`]. Exactly one profile
//! feature is active per build (enforced in `lib.rs`), so exactly one pair
//! below compiles. `EdSh`/`SrSh` get a working
//! `crate::stateful::StatefulHybridSignatureScheme` for free,
//! from the blanket implementation in
//! `crate::stateful_composite` over every
//! `crate::suite::StatefulSuite` -- there is nothing to implement here
//! beyond the label declarations themselves.

use crate::classical::{Ed25519, Sr25519};
use crate::hybrid_stateful_suite;

use crate::shrincs::scheme::ShrincsScheme;

#[cfg(feature = "profile-256s")]
hybrid_stateful_suite! {
    /// ED-SH: ed25519 + SHRINCS (256s profile).
    EdSh,
    classical = Ed25519 as "ed25519",
    pq = ShrincsScheme as "shrincs-256s",
    label = "hybrid-ed25519-shrincs-256s-v1",
    label_len = 31,
    rotate_label = "hybrid-ed25519-shrincs-256s-rotate-v1",
    rotate_label_len = 38,
}
#[cfg(feature = "profile-256s")]
hybrid_stateful_suite! {
    /// SR-SH: sr25519 + SHRINCS (256s profile).
    SrSh,
    classical = Sr25519 as "sr25519",
    pq = ShrincsScheme as "shrincs-256s",
    label = "hybrid-sr25519-shrincs-256s-v1",
    label_len = 31,
    rotate_label = "hybrid-sr25519-shrincs-256s-rotate-v1",
    rotate_label_len = 38,
}

#[cfg(feature = "profile-256s-sha2")]
hybrid_stateful_suite! {
    /// ED-SH: ed25519 + SHRINCS (256s-sha2 profile).
    EdSh,
    classical = Ed25519 as "ed25519",
    pq = ShrincsScheme as "shrincs-256s-sha2",
    label = "hybrid-ed25519-shrincs-256s-sha2-v1",
    label_len = 36,
    rotate_label = "hybrid-ed25519-shrincs-256s-sha2-rotate-v1",
    rotate_label_len = 43,
}
#[cfg(feature = "profile-256s-sha2")]
hybrid_stateful_suite! {
    /// SR-SH: sr25519 + SHRINCS (256s-sha2 profile).
    SrSh,
    classical = Sr25519 as "sr25519",
    pq = ShrincsScheme as "shrincs-256s-sha2",
    label = "hybrid-sr25519-shrincs-256s-sha2-v1",
    label_len = 36,
    rotate_label = "hybrid-sr25519-shrincs-256s-sha2-rotate-v1",
    rotate_label_len = 43,
}

#[cfg(feature = "profile-128s-q18")]
hybrid_stateful_suite! {
    /// ED-SH: ed25519 + SHRINCS (128s-q18 profile).
    EdSh,
    classical = Ed25519 as "ed25519",
    pq = ShrincsScheme as "shrincs-128s-q18",
    label = "hybrid-ed25519-shrincs-128s-q18-v1",
    label_len = 35,
    rotate_label = "hybrid-ed25519-shrincs-128s-q18-rotate-v1",
    rotate_label_len = 42,
}
#[cfg(feature = "profile-128s-q18")]
hybrid_stateful_suite! {
    /// SR-SH: sr25519 + SHRINCS (128s-q18 profile).
    SrSh,
    classical = Sr25519 as "sr25519",
    pq = ShrincsScheme as "shrincs-128s-q18",
    label = "hybrid-sr25519-shrincs-128s-q18-v1",
    label_len = 35,
    rotate_label = "hybrid-sr25519-shrincs-128s-q18-rotate-v1",
    rotate_label_len = 42,
}

#[cfg(feature = "profile-128s-q20")]
hybrid_stateful_suite! {
    /// ED-SH: ed25519 + SHRINCS (128s-q20 profile).
    EdSh,
    classical = Ed25519 as "ed25519",
    pq = ShrincsScheme as "shrincs-128s-q20",
    label = "hybrid-ed25519-shrincs-128s-q20-v1",
    label_len = 35,
    rotate_label = "hybrid-ed25519-shrincs-128s-q20-rotate-v1",
    rotate_label_len = 42,
}
#[cfg(feature = "profile-128s-q20")]
hybrid_stateful_suite! {
    /// SR-SH: sr25519 + SHRINCS (128s-q20 profile).
    SrSh,
    classical = Sr25519 as "sr25519",
    pq = ShrincsScheme as "shrincs-128s-q20",
    label = "hybrid-sr25519-shrincs-128s-q20-v1",
    label_len = 35,
    rotate_label = "hybrid-sr25519-shrincs-128s-q20-rotate-v1",
    rotate_label_len = 42,
}
