// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg_attr(not(feature = "std"), no_std)]
// Test-only fixtures use `unwrap`/`expect` freely; test failure is the
// desired outcome of a bad input, and a golden-vector mismatch is meant to
// panic the test rather than propagate a `Result`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![doc = "Hybrid post-quantum signatures: H1/H3 (ML-DSA-44) and H2/H4 (FN-DSA-512)."]

pub mod classical;
pub mod pq;
mod suites;

pub use suites::{H1, H3};
pub use suites::{H2, H4, MIN_FALCON512_SIG_LEN};
