// SPDX-License-Identifier: AGPL-3.0-or-later
//! A `rotate_label` literal that does not match the label
//! `hybrid_stateful_suite!` composes from its tokens must fail to compile,
//! exactly like a wrong `label` literal does: the label is the domain
//! separator, so a typo here must be a build failure, not a silently
//! incompatible rotation signature.

use pqhybridsign::classical::Ed25519;
use pqhybridsign::hybrid_stateful_suite;
use pqhybridsign::shrincs::ShrincsScheme;

hybrid_stateful_suite! {
    WrongRotateLabel,
    classical = Ed25519 as "ed25519",
    pq = ShrincsScheme as "shrincs-256s",
    label = "hybrid-ed25519-shrincs-256s-v1",
    label_len = 31,
    rotate_label = "hybrid-ed25519-shrincs-256s-rotate-v2",
    rotate_label_len = 38,
}

fn main() {}
