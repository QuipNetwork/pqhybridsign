// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = "Hybrid post-quantum signatures: H1 and H3."]

pub mod classical;
pub mod pq;
mod suites;

pub use suites::{H1, H3};
