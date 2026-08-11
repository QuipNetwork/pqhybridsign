// SPDX-License-Identifier: AGPL-3.0-or-later
//! Classical signature components: [`Ed25519`] and [`Sr25519`].

mod ed25519;
mod sr25519;

pub use ed25519::Ed25519;
pub use sr25519::Sr25519;
