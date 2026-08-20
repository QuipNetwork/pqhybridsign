// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sign_rotation` must be unreachable without a stateless budget store.
//!
//! A rotation authorization is itself a stateless signature and decrements
//! the same few-time budget (specification section 21). A rotation that
//! could be signed without charging would let an integrator refill a hard
//! security bound by rotating, so the store is a required parameter here
//! too, and calling without one is a build failure.

use pqhybridsign::rotation::{self, RotationKind, RotationPayload};
use pqhybridsign::shrincs::{keygen, H5};

fn main() {
    let (sk, _pk) = keygen::<H5>(&[1u8; 32], 4).expect("keygen");
    let payload = RotationPayload {
        kind: RotationKind::StatefulGraft,
        current_commitment: [0u8; 32],
        next_commitment: [1u8; 32],
        next_classical_pk: [2u8; 32],
    };
    let mut sig = vec![0u8; rotation::rotation_signature_len::<H5>()];
    let _n = rotation::sign_rotation::<H5>(&sk, b"ctx", &payload, &mut sig);
}
