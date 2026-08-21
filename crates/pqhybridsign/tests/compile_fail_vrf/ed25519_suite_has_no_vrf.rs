// SPDX-License-Identifier: AGPL-3.0-or-later
//! Only the sr25519 component has a VRF in this stack, so only the sr25519
//! suites have a hybrid VRF. Naming an ed25519 suite here must be a build
//! failure rather than a runtime refusal: a consensus integration that
//! discovered the gap through an `Err` would already have shipped.

use pqhybridsign::vrf;
use pqhybridsign::H1;

fn main() {
    let sk = [0u8; 1];
    let mut proof = [0u8; 1];
    let _ = vrf::sign_deterministic::<H1>(&sk, b"input", &mut proof);
}
