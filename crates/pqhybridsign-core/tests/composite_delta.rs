// SPDX-License-Identifier: AGPL-3.0-or-later
//! `composite_delta`: sign/verify over a `DeltaSuite`, with stubs whose
//! post-quantum signature length differs from the classical component's, so
//! a test that happened to line the two up would not catch a swapped
//! offset.
mod common;

use common::{HashClassical, HashClassicalSr, HashPqDelta};
use pqhybridsign_core::composite_delta::{keypair_from_seed, sign, sign_deterministic, verify};
use pqhybridsign_core::{hybrid_delta_suite, DeltaSuite, Error};

/// `HashPqDelta::SIGNATURE_LEN` is 96; `min_pq_sig_len` sits well below it
/// so the wire `DeltaLen` byte is not pinned at either edge of its range.
const MIN_PQ_SIG_LEN: usize = 40;

hybrid_delta_suite! {
    DeltaH2Test,
    classical = HashClassical as "ed25519",
    pq = HashPqDelta as "falcon512",
    label = "hybrid-ed25519-falcon512-v1",
    label_len = 28,
    min_pq_sig_len = MIN_PQ_SIG_LEN,
}

hybrid_delta_suite! {
    DeltaH4Test,
    classical = HashClassicalSr as "sr25519",
    pq = HashPqDelta as "falcon512",
    label = "hybrid-sr25519-falcon512-v1",
    label_len = 28,
    min_pq_sig_len = MIN_PQ_SIG_LEN,
}

/// Counter-based RNG. Hedged signing must not depend on real entropy for a
/// test to be reproducible. Mirrors `tests/composite.rs`'s `CountingRng`.
struct CountingRng(u64);

impl rand_core::RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let n = chunk.len();
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..n]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for CountingRng {}

fn keys<S: DeltaSuite>(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    keypair_from_seed::<S>(&[seed; 32], &mut sk, &mut pk).expect("keypair");
    (sk, pk)
}

#[test]
fn a_signature_round_trips() {
    let (sk, pk) = keys::<DeltaH2Test>(1);
    let mut sig = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN];
    let written =
        sign_deterministic::<DeltaH2Test>(&sk, b"m", b"chain", b"n", &mut sig).expect("sign");
    sig.truncate(written);
    assert!(verify::<DeltaH2Test>(&pk, b"m", b"chain", &sig));
}

#[test]
fn the_wire_layout_carries_a_real_delta_field() {
    let (sk, _pk) = keys::<DeltaH2Test>(2);
    let mut sig = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<DeltaH2Test>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    sig.truncate(written);

    let pq_len = <HashPqDelta as pqhybridsign_core::PqScheme>::SIGNATURE_LEN;
    assert_eq!(sig.len(), 64 + 1 + pq_len);
    assert_eq!(sig[64], (pq_len - MIN_PQ_SIG_LEN) as u8, "DeltaLen byte");
}

#[test]
fn hedged_signatures_verify() {
    let (sk, pk) = keys::<DeltaH2Test>(3);
    let mut sig = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN];
    let mut rng = CountingRng(1);
    let written = sign::<DeltaH2Test>(&sk, b"hello", b"", &mut rng, &mut sig).expect("sign");
    sig.truncate(written);
    assert!(verify::<DeltaH2Test>(&pk, b"hello", b"", &sig));
}

#[test]
fn a_signature_made_under_one_suite_does_not_verify_under_the_other() {
    let (sk2, pk2) = keys::<DeltaH2Test>(4);
    let mut sig2 = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN];
    let written =
        sign_deterministic::<DeltaH2Test>(&sk2, b"m", b"", b"n", &mut sig2).expect("sign");
    sig2.truncate(written);

    // Same-shaped key material under the other suite's label.
    let (sk4, pk4) = keys::<DeltaH4Test>(4);
    let mut sig4 = vec![0u8; DeltaH4Test::MAX_SIGNATURE_LEN];
    let written =
        sign_deterministic::<DeltaH4Test>(&sk4, b"m", b"", b"n", &mut sig4).expect("sign");
    sig4.truncate(written);

    assert_ne!(sig2, sig4, "different suite labels must not collide");
    assert!(!verify::<DeltaH4Test>(&pk2, b"m", b"", &sig2));
    assert!(!verify::<DeltaH2Test>(&pk4, b"m", b"", &sig4));
}

#[test]
fn a_flipped_byte_anywhere_fails() {
    let (sk, pk) = keys::<DeltaH2Test>(5);
    let mut sig = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<DeltaH2Test>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    sig.truncate(written);

    for i in 0..sig.len() {
        let mut bad = sig.clone();
        bad[i] ^= 1;
        assert!(!verify::<DeltaH2Test>(&pk, b"m", b"", &bad), "byte {i}");
    }
}

#[test]
fn a_declared_length_that_overruns_the_buffer_is_rejected_not_panicked_on() {
    let (_sk, pk) = keys::<DeltaH2Test>(6);
    let mut too_long_delta = vec![0u8; 128];
    too_long_delta[64] = 255; // implies a body far longer than 63 bytes on hand
    assert!(!verify::<DeltaH2Test>(&pk, b"m", b"", &too_long_delta));
}

#[test]
fn trailing_bytes_are_rejected() {
    let (sk, pk) = keys::<DeltaH2Test>(7);
    let mut sig = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<DeltaH2Test>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    sig.truncate(written);
    assert!(verify::<DeltaH2Test>(&pk, b"m", b"", &sig));

    sig.push(0xaa);
    assert!(!verify::<DeltaH2Test>(&pk, b"m", b"", &sig));
}

#[test]
fn a_truncated_signature_is_rejected() {
    let (sk, pk) = keys::<DeltaH2Test>(8);
    let mut sig = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<DeltaH2Test>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    sig.truncate(written - 1);
    assert!(!verify::<DeltaH2Test>(&pk, b"m", b"", &sig));
}

#[test]
fn signing_reports_a_buffer_that_is_too_small() {
    let (sk, _pk) = keys::<DeltaH2Test>(9);
    let mut sig = vec![0u8; DeltaH2Test::MAX_SIGNATURE_LEN - 1];
    assert_eq!(
        sign_deterministic::<DeltaH2Test>(&sk, b"m", b"", b"n", &mut sig),
        Err(Error::OutputBufferTooSmall {
            needed: DeltaH2Test::MAX_SIGNATURE_LEN,
            actual: DeltaH2Test::MAX_SIGNATURE_LEN - 1,
        })
    );
}

#[test]
fn keypair_from_seed_rejects_wrong_length_buffers() {
    let mut sk = [0u8; DeltaH2Test::SECRET_KEY_LEN];
    let mut pk = [0u8; DeltaH2Test::PUBLIC_KEY_LEN];
    assert_eq!(
        keypair_from_seed::<DeltaH2Test>(&[0u8; 32], &mut sk[1..], &mut pk),
        Err(Error::BadLength {
            expected: DeltaH2Test::SECRET_KEY_LEN,
            actual: DeltaH2Test::SECRET_KEY_LEN - 1,
        })
    );
}

#[test]
fn two_suites_from_one_master_seed_have_independent_keys() {
    let (sk2, pk2) = keys::<DeltaH2Test>(11);
    let (sk4, pk4) = keys::<DeltaH4Test>(11);
    assert_ne!(sk2, sk4);
    assert_ne!(pk2, pk4);
}

/// `sig_out` only needs to be *at least* `MAX_SIGNATURE_LEN`: mirrors
/// `composite.rs`'s `sig_out_accepts_exact_or_larger_and_rejects_shorter`
/// for the two `DeltaSuite`s. `signing_reports_a_buffer_that_is_too_small`
/// above already pins the short case for H2; this rounds it out with H4 and
/// the accept-larger side of the contract for both.
#[test]
fn sig_out_accepts_exact_or_larger_and_rejects_shorter() {
    fn check<S: DeltaSuite>(seed: u8) {
        let (sk, pk) = keys::<S>(seed);

        let mut short = vec![0u8; S::MAX_SIGNATURE_LEN - 1];
        assert_eq!(
            sign_deterministic::<S>(&sk, b"m", b"", b"n", &mut short),
            Err(Error::OutputBufferTooSmall {
                needed: S::MAX_SIGNATURE_LEN,
                actual: S::MAX_SIGNATURE_LEN - 1,
            })
        );
        let mut rng = CountingRng(1);
        assert_eq!(
            sign::<S>(&sk, b"m", b"", &mut rng, &mut short),
            Err(Error::OutputBufferTooSmall {
                needed: S::MAX_SIGNATURE_LEN,
                actual: S::MAX_SIGNATURE_LEN - 1,
            })
        );

        let mut exact = vec![0u8; S::MAX_SIGNATURE_LEN];
        let written =
            sign_deterministic::<S>(&sk, b"m", b"", b"n", &mut exact).expect("exact-size sig_out");
        assert!(verify::<S>(&pk, b"m", b"", &exact[..written]));

        let mut oversized = vec![0xffu8; S::MAX_SIGNATURE_LEN + 64];
        let written = sign_deterministic::<S>(&sk, b"m", b"", b"n", &mut oversized)
            .expect("oversized sig_out");
        assert_eq!(
            oversized[..written],
            exact[..written],
            "the written signature must not depend on the buffer's extra length"
        );
        assert!(
            oversized[written..].iter().all(|&b| b == 0xff),
            "bytes past the written length must be left untouched"
        );
        assert!(verify::<S>(&pk, b"m", b"", &oversized[..written]));
    }

    check::<DeltaH2Test>(31);
    check::<DeltaH4Test>(32);
}
