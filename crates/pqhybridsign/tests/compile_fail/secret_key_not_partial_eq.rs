// SPDX-License-Identifier: AGPL-3.0-or-later
//! The EdSh secret key must not be `PartialEq`. Comparing secret key material
//! for equality is a side channel and is not part of the type's contract.

use pqhybridsign::shrincs::{keygen, EdSh};

fn main() {
    let (sk, _pk) = keygen::<EdSh>(&[1u8; 32], 4).expect("keygen");
    let (sk2, _pk2) = keygen::<EdSh>(&[2u8; 32], 4).expect("keygen");
    let _eq = sk == sk2;
}
