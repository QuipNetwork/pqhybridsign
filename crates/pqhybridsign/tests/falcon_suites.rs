// SPDX-License-Identifier: AGPL-3.0-or-later
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
//! H2 (ed25519 + FN-DSA-512) and H4 (sr25519 + FN-DSA-512): round trips and
//! cross-suite rejection, over the real `fn-dsa` component rather than a
//! stub. `pqhybridsign_core::tests::composite_delta` covers the wire-layout
//! edge cases (buffer sizing, trailing bytes, truncation) against a
//! cheaper stub component; this file only needs to show the real
//! composition works end to end.
use pqhybridsign::{H1, H2, H4};
use pqhybridsign_core::composite_delta::{keypair_from_seed, sign, sign_deterministic, verify};
use pqhybridsign_core::suite::DeltaSuite;
use rand_core::OsRng;

fn keys<S: DeltaSuite>(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    keypair_from_seed::<S>(&[seed; 32], &mut sk, &mut pk).expect("keygen");
    (sk, pk)
}

#[test]
fn h2_round_trips() {
    let (sk, pk) = keys::<H2>(1);
    let mut sig = vec![0u8; H2::MAX_SIGNATURE_LEN];
    let written =
        sign_deterministic::<H2>(&sk, b"hello", b"chain", b"nonce", &mut sig).expect("sign");
    sig.truncate(written);
    assert!(verify::<H2>(&pk, b"hello", b"chain", &sig));
}

#[test]
fn h4_round_trips() {
    let (sk, pk) = keys::<H4>(2);
    let mut sig = vec![0u8; H4::MAX_SIGNATURE_LEN];
    let written =
        sign_deterministic::<H4>(&sk, b"hello", b"chain", b"nonce", &mut sig).expect("sign");
    sig.truncate(written);
    assert!(verify::<H4>(&pk, b"hello", b"chain", &sig));
}

#[test]
fn h2_hedged_signing_verifies() {
    let (sk, pk) = keys::<H2>(3);
    let mut sig = vec![0u8; H2::MAX_SIGNATURE_LEN];
    let written = sign::<H2>(&sk, b"hello", b"", &mut OsRng, &mut sig).expect("sign");
    sig.truncate(written);
    assert!(verify::<H2>(&pk, b"hello", b"", &sig));
}

#[test]
fn h2_wire_layout_matches_the_specification() {
    let (sk, _pk) = keys::<H2>(4);
    let mut sig = vec![0u8; H2::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<H2>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    sig.truncate(written);
    // `fn-dsa` 0.4.0's FN-DSA-512 signature is always exactly 666 bytes
    // (`pqhybridsign::pq::Falcon512::SIGNATURE_LEN`), so the wire form is
    // fixed at 64 + 1 + 666 = 731 bytes, and the delta byte is always 255.
    assert_eq!(sig.len(), 731);
    assert_eq!(sig[64], 255);
}

/// A signature made under one delta suite must not verify under another,
/// nor under a fixed-length suite that shares its classical component: the
/// suite label is the only thing that ties a signature to its suite, so a
/// composite key holder cannot mix Falcon and ML-DSA-44 signatures across
/// H1/H2 or H3/H4.
#[test]
fn a_signature_does_not_verify_under_a_different_suite() {
    let (sk2, pk2) = keys::<H2>(5);
    let mut sig2 = vec![0u8; H2::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<H2>(&sk2, b"m", b"", b"n", &mut sig2).expect("sign");
    sig2.truncate(written);

    let (sk4, pk4) = keys::<H4>(5);
    let mut sig4 = vec![0u8; H4::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<H4>(&sk4, b"m", b"", b"n", &mut sig4).expect("sign");
    sig4.truncate(written);

    assert!(
        !verify::<H4>(&pk2, b"m", b"", &sig2),
        "H2 sig must not verify under H4"
    );
    assert!(
        !verify::<H2>(&pk4, b"m", b"", &sig4),
        "H4 sig must not verify under H2"
    );

    // Neither verifies under H1: an unrelated H1 key, and a wire length
    // (731 bytes) that does not even match H1::SIGNATURE_LEN (2484 bytes),
    // which `composite::verify`'s length check rejects outright.
    use pqhybridsign_core::{composite, suite::Suite};
    let (_h1_sk, h1_pk) = {
        let mut sk = vec![0u8; H1::SECRET_KEY_LEN];
        let mut pk = vec![0u8; H1::PUBLIC_KEY_LEN];
        composite::keypair_from_seed::<H1>(&[5u8; 32], &mut sk, &mut pk).expect("keygen");
        (sk, pk)
    };
    assert!(!composite::verify::<H1>(&h1_pk, b"m", b"", &sig2));
}

#[test]
fn a_flipped_byte_in_the_post_quantum_half_fails() {
    let (sk, pk) = keys::<H2>(6);
    let mut sig = vec![0u8; H2::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<H2>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    sig.truncate(written);

    let mut bad = sig.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(!verify::<H2>(&pk, b"m", b"", &bad));
}

#[test]
fn a_flipped_byte_in_the_classical_half_fails() {
    let (sk, pk) = keys::<H2>(7);
    let mut sig = vec![0u8; H2::MAX_SIGNATURE_LEN];
    let written = sign_deterministic::<H2>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    sig.truncate(written);

    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(!verify::<H2>(&pk, b"m", b"", &bad));
}
