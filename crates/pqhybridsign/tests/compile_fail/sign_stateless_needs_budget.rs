// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sign_stateless` must be unreachable without a stateless budget store.
//!
//! The few-time bound of specification section 21 is a security assumption
//! of the underlying scheme, not a quota a deployment may enforce loosely,
//! so an integrator must not be able to reach the stateless path by simply
//! not knowing the budget module exists. The store is a required parameter,
//! and this case locks that in: calling with the old argument list is a
//! build failure, not a signature produced against an unenforced bound.

use pqhybridsign::stateful::StatefulHybridSignatureScheme;
use pqhybridsign::shrincs::{keygen, EdSh};

fn main() {
    let (sk, _pk) = keygen::<EdSh>(&[1u8; 32], 4).expect("keygen");
    let _sig = EdSh::sign_stateless(&sk, b"message", b"ctx");
}
