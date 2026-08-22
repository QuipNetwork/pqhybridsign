// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stateful (SHRINCS) suite test. Compiled only under a profile feature.
#![cfg(any(
    feature = "profile-256s",
    feature = "profile-256s-sha2",
    feature = "profile-128s-q18",
    feature = "profile-128s-q20"
))]
// Integration test binary: `cfg(test)` is always true here. `unwrap`/
// `expect`/`panic` are the normal way a test fails; the `hybrid_suite!`
// family of macros generates undocumented, unconditionally `pub` fixture
// structs, which is fine for a binary with no public API of its own.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        missing_docs,
        unreachable_pub
    )
)]
//! Times the three costly SHRINCS operations under the active profile.
//!
//! `#[ignore]`d: this is a measurement, not an assertion, and under the
//! 128s profiles it runs for 221.97 seconds. Invoke it deliberately:
//!
//! ```text
//! cargo test -p pqhybridsign-shrincs --release --no-default-features \
//!     --features profile-128s-q18 --test profile_timing -- --ignored --nocapture
//! ```
//!
//! It exists because an earlier estimate attributed the 128s profiles' cost
//! to stateless signature grinding. That was an inference from suite totals,
//! and it was wrong: the `cross_profile` test does one keygen and no signing
//! at all, yet accounted for 3259 s under `profile-128s-q18` against 0.39 s
//! under `profile-256s`. Per-operation numbers settle it.
use pqhybridsign::budget::{BudgetKey, StatelessBudgetStore};
use pqhybridsign::component::PqStatefulScheme;
use pqhybridsign::shrincs::{keygen, ShrincsScheme, H5};
use pqhybridsign::stateful::{adopt_key, KeyIdentity, LeafJournal, StatefulHybridSignatureScheme};
use std::time::Instant;

const SEED: [u8; 32] = [0x42; 32];
const MAX_SIGNATURES: u32 = 4;

struct CountingJournal(u32, Option<KeyIdentity>);

impl LeafJournal for CountingJournal {
    type Error = core::convert::Infallible;
    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.0 = leaf + 1;
        Ok(())
    }
    fn next_leaf(&self) -> u32 {
        self.0
    }
    fn bound_key(&self) -> Option<KeyIdentity> {
        self.1
    }
    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        self.1 = Some(key);
        Ok(())
    }
}

#[test]
#[ignore = "measurement only; runs for hours under the 128s profiles"]
fn time_the_costly_operations() {
    let profile = <ShrincsScheme as PqStatefulScheme>::NAME;

    let t = Instant::now();
    let (mut sk, pk) = keygen::<H5>(&SEED, MAX_SIGNATURES).expect("keygen");
    let keygen_secs = t.elapsed().as_secs_f64();

    let mut journal = CountingJournal(0, None);
    adopt_key(&mut journal, sk.key_identity()).expect("adopt");
    let t = Instant::now();
    let stateful = H5::sign_stateful(&mut sk, &mut journal, b"message", b"ctx").expect("stateful");
    let stateful_secs = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let stateless = H5::sign_stateless(&sk, &mut MemoryBudget::default(), b"message", b"ctx")
        .expect("stateless");
    let stateless_secs = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let ok = H5::verify_stateful(&pk, b"message", b"ctx", &stateful);
    let verify_secs = t.elapsed().as_secs_f64();
    assert!(ok, "the stateful signature must verify");

    println!(
        "PROFILE_TIMING profile={profile} keygen={keygen_secs:.2}s \
         sign_stateful={stateful_secs:.2}s sign_stateless={stateless_secs:.2}s \
         verify_stateful={verify_secs:.2}s stateful_sig_bytes={} stateless_sig_bytes={}",
        stateful.len(),
        stateless.len(),
    );
}

/// An in-memory `StatelessBudgetStore`. Not durable across a process
/// restart, which is fine for a test: the property under test is that the
/// count is consulted and advanced at all, not real persistence. A
/// deployment must persist this, or the few-time bound of specification
/// section 21 can be exceeded silently after any restart.
#[derive(Default)]
struct MemoryBudget(std::collections::HashMap<[u8; 32], u64>);

impl StatelessBudgetStore for MemoryBudget {
    type Error = core::convert::Infallible;

    fn consumed(&self, key: &BudgetKey) -> Option<u64> {
        self.0.get(key.as_bytes()).copied()
    }

    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
        self.0.insert(*key.as_bytes(), count);
        Ok(())
    }
}
