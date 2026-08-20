// SPDX-License-Identifier: AGPL-3.0-or-later
//! The H5 secret key must not be `PartialEq`. Comparing secret key material
//! for equality is a side channel and is not part of the type's contract.

use pqhybridsign::shrincs::{keygen, H5};

fn main() {
    let (sk, _pk) = keygen::<H5>(&[1u8; 32], 4).expect("keygen");
    let (sk2, _pk2) = keygen::<H5>(&[2u8; 32], 4).expect("keygen");
    let _eq = sk == sk2;
}
