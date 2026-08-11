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
pub mod composite_delta;
pub mod derive;
pub mod encoding_delta;
pub mod encoding_path;
pub mod message;
pub mod policy;
pub mod rotation;
pub mod stateful;
#[cfg(feature = "alloc")]
pub mod stateful_composite;
pub mod suite;

pub use component::{ClassicalScheme, PqScheme, PqStatefulScheme};
pub use derive::derive_component_seeds;
#[cfg(feature = "alloc")]
pub use message::m_prime;
pub use message::{m_prime_len, write_m_prime, PREFIX};
pub use suite::DeltaSuite;
pub use suite::{StatefulSuite, Suite};
