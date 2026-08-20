// SPDX-License-Identifier: AGPL-3.0-or-later
//! The H5 secret key must not be `Clone`: a clone is a second holder of the
//! same one-time leaf budget, and the two copies would reissue every leaf.

use pqhybridsign::shrincs::{keygen, H5};

fn main() {
    let (sk, _pk) = keygen::<H5>(&[1u8; 32], 4).expect("keygen");
    let _cloned = sk.clone();
}
