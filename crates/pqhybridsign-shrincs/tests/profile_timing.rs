// SPDX-License-Identifier: AGPL-3.0-or-later
//! Times the three costly SHRINCS operations under the active profile.
//!
//! `#[ignore]`d: this is a measurement, not an assertion, and under the
//! 128s profiles it runs for hours. Invoke it deliberately:
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
use pqhybridsign_core::stateful::{LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign_core::PqStatefulScheme;
use pqhybridsign_shrincs::{keygen, ShrincsScheme, H5};
use std::time::Instant;

const SEED: [u8; 32] = [0x42; 32];
const MAX_SIGNATURES: u32 = 4;

struct CountingJournal(u32);

impl LeafJournal for CountingJournal {
    type Error = core::convert::Infallible;
    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.0 = leaf + 1;
        Ok(())
    }
    fn next_leaf(&self) -> u32 {
        self.0
    }
}

#[test]
#[ignore = "measurement only; runs for hours under the 128s profiles"]
fn time_the_costly_operations() {
    let profile = <ShrincsScheme as PqStatefulScheme>::NAME;

    let t = Instant::now();
    let (mut sk, pk) = keygen::<H5>(&SEED, MAX_SIGNATURES).expect("keygen");
    let keygen_secs = t.elapsed().as_secs_f64();

    let mut journal = CountingJournal(0);
    let t = Instant::now();
    let stateful = H5::sign_stateful(&mut sk, &mut journal, b"message", b"ctx").expect("stateful");
    let stateful_secs = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let stateless = H5::sign_stateless(&sk, b"message", b"ctx").expect("stateless");
    let stateless_secs = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let ok = H5::verify(&pk, b"message", b"ctx", &stateful);
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
