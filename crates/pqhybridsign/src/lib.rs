// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = "Hybrid post-quantum signatures: H1/H3 (ML-DSA-44) and H2/H4 (FN-DSA-512)."]

pub mod classical;
pub mod pq;
mod suites;

pub use suites::{H1, H3};
pub use suites::{H2, H4, MIN_FALCON512_SIG_LEN};
