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
