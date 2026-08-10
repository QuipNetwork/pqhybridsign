// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = "Composite layer for hybrid post-quantum signature constructions."]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub use error::{Error, Result};

pub mod component;
pub mod composite;
pub mod derive;
pub mod message;
pub mod suite;

pub use component::{ClassicalScheme, PqScheme};
pub use derive::derive_component_seeds;
#[cfg(feature = "alloc")]
pub use message::m_prime;
pub use message::{m_prime_len, write_m_prime, PREFIX};
pub use suite::Suite;
