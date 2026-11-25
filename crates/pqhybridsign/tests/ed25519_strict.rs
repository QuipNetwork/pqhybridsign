// SPDX-License-Identifier: AGPL-3.0-or-later
//! ed25519 strict RFC 8032 checks. Need std (curve25519-dalek, getrandom, alloc).
#![cfg(feature = "std")]
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
//! QPA-01: public-key admission and signature verification must reject
//! small-order Ed25519 keys, while preserving the remaining ZIP-215 rules.
//! All security verdicts are hard assertions, including the legacy vectors.

#[path = "support/mod.rs"]
mod support;

use curve25519_dalek::edwards::CompressedEdwardsY;
use pqhybridsign::classical::Ed25519;
use pqhybridsign::EdMl44;
use pqhybridsign::{component::ClassicalScheme, composite, suite::Suite};
use support::{strict, weak_public_keys};

const LABEL: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
    let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
    Ed25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
    (sk, pk)
}

/// Hard-failing tests: this crate's own ed25519 output must stay valid under
/// both ZIP-215 and strict RFC 8032, for every seed and message tried.
mod own_outputs {
    use super::*;

    #[test]
    fn our_signatures_are_strict_rfc8032_valid() {
        for seed in 0u8..8 {
            let (sk, pk) = keypair(seed);
            let mut sig = [0u8; 64];
            Ed25519::sign_deterministic(&sk, b"strict rfc8032 check", b"nonce", LABEL, &mut sig)
                .expect("sign");

            assert!(
                bool::from(Ed25519::verify(&pk, b"strict rfc8032 check", LABEL, &sig)),
                "seed {seed}: ed25519-zebra (ZIP-215) must accept our own output",
            );

            let outcome = strict::check(&pk, b"strict rfc8032 check", &sig);
            assert!(
                outcome.strict_accepts(),
                "seed {seed}: our own signature must also be strict-RFC-8032-valid: {outcome:?}",
            );
        }
    }

    #[test]
    fn our_public_keys_are_canonical_and_not_small_order() {
        for seed in 0u8..8 {
            let (_, pk) = keypair(seed);
            assert!(
                strict::is_canonical_y(&pk),
                "seed {seed}: derived public key must be canonically encoded",
            );
            let point = CompressedEdwardsY(pk)
                .decompress()
                .expect("derived public key must decode");
            assert!(
                !point.is_small_order(),
                "seed {seed}: derived public key must not be small-order",
            );
        }
    }

    /// The checked-in golden vectors are this crate's own pinned output, so
    /// they belong to the hard-failing class: a golden ed25519 half that
    /// stops satisfying the strict equation means the signing path
    /// regressed, not that some third-party verifier changed its mind.
    ///
    /// Covers EdMl44 and EdFn512, the two ed25519-based suites. The ed25519
    /// component signs `M'`, which the composite layer builds, so the
    /// strict check runs against `M'` and not against the bare message.
    #[test]
    fn golden_vector_ed25519_halves_are_strict_valid() {
        use pqhybridsign::EdFn512;
        use pqhybridsign::{message, suite::DeltaSuite};

        #[derive(serde::Deserialize)]
        struct Vector {
            ctx_hex: String,
            msg_hex: String,
            public_key_hex: String,
            signature_hex: String,
        }

        fn check(label: &[u8], json: &str, case: &str) {
            let v: Vector = serde_json::from_str(json).expect("golden vector must parse");
            let pk = hex::decode(&v.public_key_hex).expect("pk hex");
            let sig = hex::decode(&v.signature_hex).expect("sig hex");
            let ctx = hex::decode(&v.ctx_hex).expect("ctx hex");
            let msg = hex::decode(&v.msg_hex).expect("msg hex");
            let m_prime = message::m_prime(label, &ctx, &msg).expect("M'");

            // Classical-first serialization: the ed25519 half is the leading
            // 32 bytes of the composite public key and the leading 64 of the
            // composite signature.
            let a: [u8; 32] = pk[..32].try_into().expect("32-byte classical public key");
            let s: [u8; 64] = sig[..64].try_into().expect("64-byte classical signature");

            let outcome = strict::check(&a, &m_prime, &s);
            assert!(
                outcome.strict_accepts(),
                "{case}: pinned golden ed25519 half must be strict-RFC-8032-valid: {outcome:?}",
            );
        }

        check(
            EdMl44::LABEL,
            include_str!("vectors/h1.json"),
            "EdMl44 golden",
        );
        check(
            EdFn512::LABEL,
            include_str!("vectors/h2.json"),
            "EdFn512 golden",
        );
    }
}

#[derive(serde::Deserialize)]
struct NegativeVector {
    description: String,
    public_key_hex: String,
    msg_hex: String,
    signature_hex: String,
}

fn parse_vector(v: &NegativeVector) -> ([u8; 32], Vec<u8>, [u8; 64]) {
    let pk: [u8; 32] = hex::decode(&v.public_key_hex)
        .expect("pk hex")
        .try_into()
        .expect("32 bytes");
    let msg = hex::decode(&v.msg_hex).expect("msg hex");
    let sig: [u8; 64] = hex::decode(&v.signature_hex)
        .expect("sig hex")
        .try_into()
        .expect("64 bytes");
    (pk, msg, sig)
}

#[test]
fn pinned_weak_key_vectors_are_rejected() {
    let vectors: Vec<NegativeVector> =
        serde_json::from_str(include_str!("vectors/ed25519_zip215_negative.json")).unwrap();
    assert_eq!(vectors.len(), 3);
    for vector in vectors {
        let (pk, msg, sig) = parse_vector(&vector);
        // Control: this remains a valid ZIP-215 forgery; our additional key
        // policy is what must reject it.
        assert!(ed25519_zebra::VerificationKey::try_from(pk)
            .unwrap()
            .verify(&sig.into(), &msg)
            .is_ok());
        assert!(!Ed25519::public_key_is_valid(&pk), "{}", vector.description);
        assert!(!bool::from(Ed25519::verify(&pk, &msg, LABEL, &sig)));
    }
}

#[test]
fn all_small_order_keys_and_aliases_are_rejected_for_every_message() {
    let mut sig = [0u8; 64];
    sig[0] = 1; // R = identity, s = 0.
    for pk in weak_public_keys() {
        assert!(CompressedEdwardsY(pk)
            .decompress()
            .unwrap()
            .is_small_order());
        assert!(!Ed25519::public_key_is_valid(&pk));
        for msg in [b"first".as_slice(), b"second".as_slice(), b""] {
            assert!(ed25519_zebra::VerificationKey::try_from(pk)
                .unwrap()
                .verify(&sig.into(), msg)
                .is_ok());
            assert!(!bool::from(Ed25519::verify(&pk, msg, LABEL, &sig)));
        }
    }
}

#[test]
fn malformed_keys_and_signatures_are_rejected() {
    let (_, pk) = keypair(42);
    let mut invalid = [0u8; 32];
    invalid[0] = 2;
    assert!(CompressedEdwardsY(invalid).decompress().is_none());
    for key in [&invalid[..], &pk[..31], &[0u8; 33][..], &[]] {
        assert!(!Ed25519::public_key_is_valid(key));
        assert!(!bool::from(Ed25519::verify(key, b"", LABEL, &[0; 64])));
    }
    assert!(Ed25519::public_key_is_valid(&pk));
    for sig in [&[0u8; 63][..], &[0u8; 65][..], &[]] {
        assert!(!bool::from(Ed25519::verify(&pk, b"", LABEL, sig)));
    }
}

#[test]
fn other_zip215_key_encodings_remain_admissible() {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
    assert!(!mixed.is_torsion_free());
    assert!(Ed25519::public_key_is_valid(&mixed.compress().to_bytes()));
    let mut checked = 0;
    for y in 2..19 {
        let mut canonical = [0u8; 32];
        canonical[0] = y;
        let Some(point) = CompressedEdwardsY(canonical).decompress() else {
            continue;
        };
        if point.is_small_order() {
            continue;
        }
        for sign in [0, 0x80] {
            canonical[31] = sign;
            let mut alias = [0xff; 32];
            alias[0] = 0xed + y;
            alias[31] = 0x7f | sign;
            assert_eq!(
                CompressedEdwardsY(alias).decompress(),
                CompressedEdwardsY(canonical).decompress()
            );
            assert!(Ed25519::public_key_is_valid(&alias));
            checked += 1;
        }
    }
    assert!(checked > 0);
}

#[test]
fn cofactored_verification_and_small_order_r_remain_supported() {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};
    let msg = b"QPA-01 restricts the public key, not R";
    for point in [
        ED25519_BASEPOINT_POINT,
        ED25519_BASEPOINT_POINT + EIGHT_TORSION[1],
    ] {
        let pk = point.compress().to_bytes();
        // Keep non-canonical R encodings and the scalar bound pinned too.
        for r in weak_public_keys() {
            // Known prime-order secret = 1, nonce = 0. R has small order.
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&r);
            let challenge = Scalar::from_hash(
                Sha512::new()
                    .chain_update(&sig[..32])
                    .chain_update(pk)
                    .chain_update(msg),
            );
            sig[32..].copy_from_slice(&challenge.to_bytes());
            assert!(ed25519_zebra::VerificationKey::try_from(pk)
                .unwrap()
                .verify(&sig.into(), msg)
                .is_ok());
            assert!(bool::from(Ed25519::verify(&pk, msg, LABEL, &sig)));
            assert!(!bool::from(Ed25519::verify(&pk, b"changed", LABEL, &sig)));
            sig[32..].fill(0xff);
            assert!(!bool::from(Ed25519::verify(&pk, msg, LABEL, &sig)));
        }
    }
}

#[test]
fn edml44_rejects_weak_classical_keys_even_with_valid_pq_signatures() {
    let mut sk = vec![0; EdMl44::SECRET_KEY_LEN];
    let mut pk = vec![0; EdMl44::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<EdMl44>(&[0x7b; 32], &mut sk, &mut pk).unwrap();
    let mut sig = vec![0; EdMl44::SIGNATURE_LEN];
    composite::sign_deterministic::<EdMl44>(&sk, b"message", b"ctx", b"", &mut sig).unwrap();
    assert!(composite::verify::<EdMl44>(&pk, b"message", b"ctx", &sig));
    assert!(!composite::verify::<EdMl44>(&pk, b"changed", b"ctx", &sig));
    sig[..64].fill(0);
    sig[0] = 1;
    for weak in weak_public_keys() {
        pk[..32].copy_from_slice(&weak);
        assert!(!composite::verify::<EdMl44>(&pk, b"message", b"ctx", &sig));
    }
}

#[test]
fn edfn512_rejects_weak_classical_keys_even_with_valid_pq_signatures() {
    use pqhybridsign::{composite_delta, suite::DeltaSuite, EdFn512};
    let mut sk = vec![0; EdFn512::SECRET_KEY_LEN];
    let mut pk = vec![0; EdFn512::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<EdFn512>(&[0x5a; 32], &mut sk, &mut pk).unwrap();
    let mut sig = vec![0; EdFn512::MAX_SIGNATURE_LEN];
    let len =
        composite_delta::sign_deterministic::<EdFn512>(&sk, b"message", b"ctx", b"", &mut sig)
            .unwrap();
    sig.truncate(len);
    assert!(composite_delta::verify::<EdFn512>(
        &pk, b"message", b"ctx", &sig
    ));
    assert!(!composite_delta::verify::<EdFn512>(
        &pk, b"changed", b"ctx", &sig
    ));
    sig[..64].fill(0);
    sig[0] = 1;
    for weak in weak_public_keys() {
        pk[..32].copy_from_slice(&weak);
        assert!(!composite_delta::verify::<EdFn512>(
            &pk, b"message", b"ctx", &sig
        ));
    }
}
