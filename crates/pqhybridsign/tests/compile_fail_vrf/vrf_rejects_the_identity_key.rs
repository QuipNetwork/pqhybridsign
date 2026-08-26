// SPDX-License-Identifier: AGPL-3.0-or-later
//! The identity key carries rotation and recovery authority. Passing it to
//! the VRF spends the reserve those depend on, so it must not compile:
//! `sign_stateless` takes a `DedicatedVrfKey`, not a bare `SecretKey`.

use pqhybridsign::budget::{BudgetKey, StatelessBudgetStore};
use pqhybridsign::shrincs::{keygen, SrSh};

/// A minimal store, since no public `StatelessBudgetStore` implementation
/// ships with the crate. This case never runs; it only needs to type-check
/// up to the one call it exists to reject.
struct NoopBudget;

impl StatelessBudgetStore for NoopBudget {
    type Error = core::convert::Infallible;

    fn consumed(&self, _key: &BudgetKey) -> Option<u64> {
        None
    }

    fn record(&mut self, _key: &BudgetKey, _count: u64) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn main() {
    let (identity, _pk) = keygen::<SrSh>(&[3u8; 32], 8).expect("keygen");

    let mut budget = NoopBudget;
    let mut rng = rand_core::OsRng;
    let mut proof = [0u8; 4096];

    let _ = pqhybridsign::vrf::sign_stateless::<SrSh>(
        &identity,
        &mut budget,
        b"input",
        &mut rng,
        &mut proof,
    );
}
