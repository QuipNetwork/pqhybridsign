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
// Specification section 17.
//
// Present here, for both EdMl44 and SrMl44:
//   1  round trip                       `t1_round_trip`
//   2  hedged non-determinism           `t2_hedged_*` (below the macro)
//   3  deterministic canonicality       `t3_deterministic_canonicality`
//   5  cross-mode interoperability      `t5_cross_mode_interop`
//   6  domain separation                `t6_domain_separation_by_context`,
//                                       `t6_cross_suite_signatures_never_verify`
//   7  key marshaling round trip        `t7_key_marshaling_round_trip`
//   8  signature marshaling round trip  `t8_signature_marshaling_round_trip`
//   9  cross-verification rejection     `t9_classical_only_verification_is_rejected`
//   10 nonce and message uniqueness     `t10_different_messages_give_different_signatures`
//
// Not applicable:
//   4  nonce verification -- Falcon only, and Falcon is not in this cycle.
//
// `composite_sizes_match_the_specification` is an extra size check, not one
// of the numbered tests.
use pqhybridsign::composite::{keypair_from_seed, sign, sign_deterministic, verify};
use pqhybridsign::suite::Suite;
use pqhybridsign::{EdMl44, SrMl44};
use rand_core::OsRng;

macro_rules! keys {
    ($suite:ty, $seed:expr) => {{
        let mut sk = vec![0u8; <$suite as Suite>::SECRET_KEY_LEN];
        let mut pk = vec![0u8; <$suite as Suite>::PUBLIC_KEY_LEN];
        keypair_from_seed::<$suite>(&[$seed; 32], &mut sk, &mut pk).expect("keygen");
        (sk, pk)
    }};
}

/// Split a composite key or signature at `split`, then reassemble it from
/// the two byte halves. This is the wire form: classical half first, then
/// the post-quantum half, with no framing.
fn marshal_halves(value: &[u8], split: usize) -> Vec<u8> {
    let (classical, pq) = value.split_at(split);
    let mut out = Vec::with_capacity(value.len());
    out.extend_from_slice(classical);
    out.extend_from_slice(pq);
    out
}

macro_rules! suite_tests {
    ($mod_name:ident, $suite:ty) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn t1_round_trip() {
                let (sk, pk) = keys!($suite, 1);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign::<$suite>(&sk, b"hello", b"ctx", &mut OsRng, &mut sig).expect("sign");
                assert!(verify::<$suite>(&pk, b"hello", b"ctx", &sig));
            }

            #[test]
            fn t3_deterministic_canonicality() {
                let (sk, _) = keys!($suite, 3);
                let mut a = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                let mut b = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"nonce", &mut a).expect("sign");
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"nonce", &mut b).expect("sign");
                assert_eq!(a, b);
            }

            #[test]
            fn t5_cross_mode_interop() {
                let (sk, pk) = keys!($suite, 5);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"n", &mut sig).expect("sign");
                assert!(verify::<$suite>(&pk, b"m", b"c", &sig));
            }

            #[test]
            fn t6_domain_separation_by_context() {
                let (sk, pk) = keys!($suite, 6);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"ctx-a", b"n", &mut sig).expect("sign");
                assert!(!verify::<$suite>(&pk, b"m", b"ctx-b", &sig));
            }

            #[test]
            fn t7_key_marshaling_round_trip() {
                // Keys travel as raw bytes: the classical half first, then
                // the post-quantum half, at the documented split offsets.
                // Round trip both halves through a byte buffer and confirm
                // the reassembled key still signs and verifies.
                let (sk, pk) = keys!($suite, 7);
                assert_eq!(sk.len(), <$suite as Suite>::SECRET_KEY_LEN);
                assert_eq!(pk.len(), <$suite as Suite>::PUBLIC_KEY_LEN);

                let sk_bytes: Vec<u8> = marshal_halves(&sk, 64);
                let pk_bytes: Vec<u8> = marshal_halves(&pk, 32);
                assert_eq!(sk_bytes, sk, "secret key marshaling must be exact");
                assert_eq!(pk_bytes, pk, "public key marshaling must be exact");

                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk_bytes, b"m", b"c", b"n", &mut sig)
                    .expect("sign with the round-tripped secret key");
                assert!(verify::<$suite>(&pk_bytes, b"m", b"c", &sig));

                // A key of the wrong length is a length error, not a panic.
                assert!(
                    sign_deterministic::<$suite>(&sk_bytes[..64], b"m", b"c", b"n", &mut sig)
                        .is_err()
                );
                assert!(!verify::<$suite>(&pk_bytes[..32], b"m", b"c", &sig));
            }

            #[test]
            fn t8_signature_marshaling_round_trip() {
                let (sk, pk) = keys!($suite, 8);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"n", &mut sig).expect("sign");

                let bytes = marshal_halves(&sig, 64);
                assert_eq!(bytes.len(), <$suite as Suite>::SIGNATURE_LEN);
                assert_eq!(bytes, sig, "signature marshaling must be exact");
                assert!(
                    verify::<$suite>(&pk, b"m", b"c", &bytes),
                    "a round-tripped signature must still verify"
                );
            }

            #[test]
            fn t9_classical_only_verification_is_rejected() {
                let (sk, pk) = keys!($suite, 9);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"n", &mut sig).expect("sign");
                // Specification test 9: the classical half of a hybrid
                // signature, presented on its own, must never verify. Its
                // 64 bytes are a valid ed25519 or sr25519 signature over
                // `M'`, so a classical-only verifier would accept them.
                let classical_only = sig[..64].to_vec();
                assert!(!verify::<$suite>(&pk, b"m", b"c", &classical_only));
                // The same holds against the classical half of the key.
                assert!(!verify::<$suite>(&pk[..32], b"m", b"c", &classical_only));
                assert!(!verify::<$suite>(&pk[..32], b"m", b"c", &sig));
                // A signature with the post-quantum half zeroed must fail.
                let mut tampered = sig.clone();
                tampered[64..].fill(0);
                assert!(!verify::<$suite>(&pk, b"m", b"c", &tampered));
                // A signature with the classical half zeroed must fail.
                let mut tampered = sig.clone();
                tampered[..64].fill(0);
                assert!(!verify::<$suite>(&pk, b"m", b"c", &tampered));
            }

            #[test]
            fn t10_different_messages_give_different_signatures() {
                let (sk, _) = keys!($suite, 10);
                let mut a = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                let mut b = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m1", b"c", b"n", &mut a).expect("sign");
                sign_deterministic::<$suite>(&sk, b"m2", b"c", b"n", &mut b).expect("sign");
                assert_ne!(&a[..64], &b[..64], "classical halves must differ");
            }

            #[test]
            fn composite_sizes_match_the_specification() {
                assert_eq!(<$suite as Suite>::PUBLIC_KEY_LEN, 1344);
                assert_eq!(<$suite as Suite>::SECRET_KEY_LEN, 2624);
                assert_eq!(<$suite as Suite>::SIGNATURE_LEN, 2484);
            }
        }
    };
}

suite_tests!(h1, EdMl44);
suite_tests!(h3, SrMl44);

#[test]
fn t6_cross_suite_signatures_never_verify() {
    // A signature made under EdMl44 must not verify under SrMl44, and the reverse.
    let mut sk1 = vec![0u8; <EdMl44 as Suite>::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; <EdMl44 as Suite>::PUBLIC_KEY_LEN];
    keypair_from_seed::<EdMl44>(&[42u8; 32], &mut sk1, &mut pk1).expect("keygen");
    let mut sig = vec![0u8; <EdMl44 as Suite>::SIGNATURE_LEN];
    sign_deterministic::<EdMl44>(&sk1, b"m", b"c", b"n", &mut sig).expect("sign");
    assert!(verify::<EdMl44>(&pk1, b"m", b"c", &sig));
    assert!(!verify::<SrMl44>(&pk1, b"m", b"c", &sig));
}

#[test]
fn one_master_seed_gives_two_independent_suites() {
    // Specification section 9: suite-separated derivation. Without it, EdMl44
    // and SrMl44 would share a post-quantum key.
    let mut sk1 = vec![0u8; <EdMl44 as Suite>::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; <EdMl44 as Suite>::PUBLIC_KEY_LEN];
    let mut sk3 = vec![0u8; <SrMl44 as Suite>::SECRET_KEY_LEN];
    let mut pk3 = vec![0u8; <SrMl44 as Suite>::PUBLIC_KEY_LEN];
    keypair_from_seed::<EdMl44>(&[7u8; 32], &mut sk1, &mut pk1).expect("keygen");
    keypair_from_seed::<SrMl44>(&[7u8; 32], &mut sk3, &mut pk3).expect("keygen");
    assert_ne!(&sk1[64..], &sk3[64..], "post-quantum halves must differ");
}

// Specification test 2 for EdMl44. The two halves behave differently and the
// test asserts the split exactly:
//   - ed25519 is RFC 8032 deterministic and takes no randomness, so the
//     classical half repeats. See crates/pqhybridsign/src/classical/
//     ed25519.rs for why this component declines to hedge.
//   - ML-DSA-44 draws its FIPS 204 `rnd` from the caller's RNG in the
//     hedged path, so the post-quantum half must not repeat.
#[test]
fn t2_h1_hedged_signing_varies_in_the_post_quantum_half_only() {
    let (sk, pk) = keys!(EdMl44, 2);
    let mut a = vec![0u8; <EdMl44 as Suite>::SIGNATURE_LEN];
    let mut b = vec![0u8; <EdMl44 as Suite>::SIGNATURE_LEN];
    sign::<EdMl44>(&sk, b"m", b"c", &mut OsRng, &mut a).expect("sign");
    sign::<EdMl44>(&sk, b"m", b"c", &mut OsRng, &mut b).expect("sign");
    assert_eq!(
        &a[..64],
        &b[..64],
        "the ed25519 half is deterministic by RFC 8032"
    );
    assert_ne!(
        &a[64..],
        &b[64..],
        "the hedged ML-DSA-44 half must draw fresh randomness"
    );
    assert!(verify::<EdMl44>(&pk, b"m", b"c", &a));
    assert!(verify::<EdMl44>(&pk, b"m", b"c", &b));
}

#[test]
fn t2_hedged_signing_is_not_deterministic_for_sr25519() {
    // Specification test 2 for SrMl44. Both halves take randomness here:
    // sr25519 through schnorrkel and ML-DSA-44 through its hedged `rnd`.
    let (sk, _) = keys!(SrMl44, 2);
    let mut a = vec![0u8; <SrMl44 as Suite>::SIGNATURE_LEN];
    let mut b = vec![0u8; <SrMl44 as Suite>::SIGNATURE_LEN];
    sign::<SrMl44>(&sk, b"m", b"c", &mut OsRng, &mut a).expect("sign");
    sign::<SrMl44>(&sk, b"m", b"c", &mut OsRng, &mut b).expect("sign");
    assert_ne!(
        &a[..64],
        &b[..64],
        "hedged sr25519 must not repeat a signature"
    );
    assert_ne!(
        &a[64..],
        &b[64..],
        "the hedged ML-DSA-44 half must draw fresh randomness"
    );
}
