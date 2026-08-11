// SPDX-License-Identifier: AGPL-3.0-or-later
//! Post-quantum signature components: [`Falcon512`] and [`MlDsa44`].

mod falcon;
mod mldsa44;

pub use falcon::Falcon512;
pub use mldsa44::MlDsa44;
