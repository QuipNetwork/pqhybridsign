// SPDX-License-Identifier: AGPL-3.0-or-later
//! QPA-02: reject the sr25519 identity even when the PQ signature is valid.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use pqhybridsign::{
    classical::Sr25519,
    component::ClassicalScheme,
    composite, composite_delta,
    suite::{DeltaSuite, Suite},
    SrFn512, SrMl44,
};

const LABEL: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";

fn identity_forgeries() -> [[u8; 64]; 2] {
    let mut zero = [0; 64]; // R = identity, s = 0.
    zero[63] = 0x80; // schnorrkel's required signature marker.
    let mut one = zero;
    one[..32].copy_from_slice(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    one[32] = 1; // R = B, s = 1: screening only R would miss this forgery.
    [zero, one]
}

fn keypair() -> ([u8; 64], [u8; 32]) {
    let (mut sk, mut pk) = ([0; 64], [0; 32]);
    Sr25519::derive(&[42; 32], &mut sk, &mut pk).unwrap();
    (sk, pk)
}

#[test]
fn identity_forgeries_are_rejected_for_every_message_and_label() {
    let pk = [0; 32];
    let upstream = schnorrkel::PublicKey::from_bytes(&pk).unwrap();
    for sig in identity_forgeries() {
        let parsed = schnorrkel::Signature::from_bytes(&sig).unwrap();
        for (msg, label) in [
            (b"first".as_slice(), LABEL),
            (b"second".as_slice(), LABEL),
            (b"first".as_slice(), b"another-label".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            // A positive control: these are valid upstream signatures, not
            // malformed inputs that would be rejected without the new guard.
            assert!(upstream
                .verify(schnorrkel::signing_context(label).bytes(msg), &parsed)
                .is_ok());
            assert!(!bool::from(Sr25519::verify(&pk, msg, label, &sig)));
        }
    }
}

#[test]
fn admission_rejects_identity_and_malformed_keys() {
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0xee; // y = p + 1 is not a valid Ristretto encoding.
    noncanonical[31] = 0x7f;
    assert!(schnorrkel::PublicKey::from_bytes(&noncanonical).is_err());
    for bad in [
        &[][..],
        &[0; 31][..],
        &[0; 32][..],
        &[0; 33][..],
        &noncanonical[..],
        &[0xff; 32][..],
    ] {
        assert!(!Sr25519::public_key_is_valid(bad));
        assert!(!bool::from(Sr25519::verify(
            bad,
            b"msg",
            LABEL,
            &identity_forgeries()[0]
        )));
    }
    assert!(Sr25519::public_key_is_valid(&keypair().1));
}

#[test]
fn honest_signatures_still_bind_the_message_and_label() {
    let (sk, pk) = keypair();
    let mut sig = [0; 64];
    Sr25519::sign_deterministic(&sk, b"message", b"nonce", LABEL, &mut sig).unwrap();
    assert!(bool::from(Sr25519::verify(&pk, b"message", LABEL, &sig)));
    assert!(!bool::from(Sr25519::verify(&pk, b"changed", LABEL, &sig)));
    assert!(!bool::from(Sr25519::verify(
        &pk,
        b"message",
        b"other-label",
        &sig
    )));
    assert!(!bool::from(Sr25519::verify(
        &pk,
        b"message",
        LABEL,
        &sig[..63]
    )));
    sig[63] &= 0x7f;
    assert!(!bool::from(Sr25519::verify(&pk, b"message", LABEL, &sig)));
    for forged in identity_forgeries() {
        assert!(!bool::from(Sr25519::verify(
            &pk, b"message", LABEL, &forged
        )));
    }
}

fn fixed_suite_rejects_identity<S: Suite<Classical = Sr25519>>() {
    let mut sk = vec![0; S::SECRET_KEY_LEN];
    let mut pk = vec![0; S::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<S>(&[42; 32], &mut sk, &mut pk).unwrap();
    let mut sig = vec![0; S::SIGNATURE_LEN];
    composite::sign_deterministic::<S>(&sk, b"message", b"context", b"nonce", &mut sig).unwrap();
    assert!(composite::verify::<S>(&pk, b"message", b"context", &sig));
    pk[..32].fill(0);
    for forged in identity_forgeries() {
        sig[..64].copy_from_slice(&forged); // Preserve the valid PQ half.
        assert!(!composite::verify::<S>(&pk, b"message", b"context", &sig));
    }
}

#[test]
fn srml44_rejects_identity_with_a_valid_pq_signature() {
    fixed_suite_rejects_identity::<SrMl44>();
}

#[test]
fn srfn512_delta_rejects_identity_with_a_valid_pq_signature() {
    let mut sk = vec![0; <SrFn512 as DeltaSuite>::SECRET_KEY_LEN];
    let mut pk = vec![0; <SrFn512 as DeltaSuite>::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<SrFn512>(&[42; 32], &mut sk, &mut pk).unwrap();
    let mut sig = vec![0; SrFn512::MAX_SIGNATURE_LEN];
    let len = composite_delta::sign_deterministic::<SrFn512>(
        &sk, b"message", b"context", b"nonce", &mut sig,
    )
    .unwrap();
    sig.truncate(len);
    assert!(composite_delta::verify::<SrFn512>(
        &pk, b"message", b"context", &sig
    ));
    pk[..32].fill(0);
    for forged in identity_forgeries() {
        sig[..64].copy_from_slice(&forged);
        assert!(!composite_delta::verify::<SrFn512>(
            &pk, b"message", b"context", &sig
        ));
    }
}

#[cfg(feature = "vrf")]
#[test]
fn vrf_public_key_entry_points_apply_the_same_admission_policy() {
    use pqhybridsign::{error::Error, vrf::ClassicalVrf};
    let (sk, pk) = keypair();
    let mut pre_output = [0; 32];
    let mut proof = [0; 64];
    Sr25519::vrf_evaluate_deterministic(&sk, LABEL, b"input", &mut pre_output, &mut proof).unwrap();
    assert!(bool::from(Sr25519::vrf_verify(
        &pk,
        LABEL,
        b"input",
        &pre_output,
        &proof
    )));
    assert!(Sr25519::vrf_make_bytes::<[u8; 32]>(&pk, LABEL, b"input", &pre_output, b"ctx").is_ok());
    // Non-identity pre-output ensures rejection cannot rely solely on the
    // downstream VRF pre-output check; the public key itself is inadmissible.
    for bad in [&[0; 32][..], &[0; 31][..], &[0xff; 32][..]] {
        assert!(!bool::from(Sr25519::vrf_verify(
            bad,
            LABEL,
            b"input",
            &pre_output,
            &proof
        )));
        assert_eq!(
            Sr25519::vrf_make_bytes::<[u8; 32]>(bad, LABEL, b"input", &pre_output, b"ctx"),
            Err(Error::ComponentFailure),
        );
    }
}
