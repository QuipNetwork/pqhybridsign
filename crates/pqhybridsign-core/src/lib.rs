// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = "Composite layer for hybrid post-quantum signature constructions.

# Module layout

This is a toolkit crate. Every module is public API and is reached
through its own path: `pqhybridsign_core::error::Error`,
`pqhybridsign_core::policy::LeafPolicyMachine`. There are no root
re-exports, because a partial set of them gave the crate two access
patterns and made `Error` reachable two ways while `LeafPolicyMachine`
was reachable one.
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

pub mod budget;
pub mod component;
pub mod composite;
pub mod composite_delta;
pub mod derive;
pub mod encoding_delta;
pub mod encoding_path;
pub mod error;
pub mod message;
pub mod policy;
pub mod rotation;
pub mod stateful;
#[cfg(feature = "alloc")]
pub mod stateful_composite;
pub mod suite;
