// Specification section 17, tests 1 to 10. Test 4 is Falcon-only.
use pqhybridsign::{H1, H3};
use pqhybridsign_core::composite::{keypair_from_seed, sign, sign_deterministic, verify};
use pqhybridsign_core::Suite;
use rand_core::OsRng;

macro_rules! keys {
    ($suite:ty, $seed:expr) => {{
        let mut sk = vec![0u8; <$suite as Suite>::SECRET_KEY_LEN];
        let mut pk = vec![0u8; <$suite as Suite>::PUBLIC_KEY_LEN];
        keypair_from_seed::<$suite>(&[$seed; 32], &mut sk, &mut pk).expect("keygen");
        (sk, pk)
    }};
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
            fn t9_truncated_signature_is_rejected() {
                let (sk, pk) = keys!($suite, 9);
                let mut sig = vec![0u8; <$suite as Suite>::SIGNATURE_LEN];
                sign_deterministic::<$suite>(&sk, b"m", b"c", b"n", &mut sig).expect("sign");
                // Classical half alone must never verify as a composite.
                assert!(!verify::<$suite>(&pk, b"m", b"c", &sig[..64]));
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
            fn t7_composite_sizes() {
                assert_eq!(<$suite as Suite>::PUBLIC_KEY_LEN, 1344);
                assert_eq!(<$suite as Suite>::SECRET_KEY_LEN, 2624);
                assert_eq!(<$suite as Suite>::SIGNATURE_LEN, 2484);
            }
        }
    };
}

suite_tests!(h1, H1);
suite_tests!(h3, H3);

#[test]
fn t6_cross_suite_signatures_never_verify() {
    // A signature made under H1 must not verify under H3, and the reverse.
    let mut sk1 = vec![0u8; <H1 as Suite>::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; <H1 as Suite>::PUBLIC_KEY_LEN];
    keypair_from_seed::<H1>(&[42u8; 32], &mut sk1, &mut pk1).expect("keygen");
    let mut sig = vec![0u8; <H1 as Suite>::SIGNATURE_LEN];
    sign_deterministic::<H1>(&sk1, b"m", b"c", b"n", &mut sig).expect("sign");
    assert!(verify::<H1>(&pk1, b"m", b"c", &sig));
    assert!(!verify::<H3>(&pk1, b"m", b"c", &sig));
}

#[test]
fn one_master_seed_gives_two_independent_suites() {
    // Specification section 9: suite-separated derivation. Without it, H1
    // and H3 would share a post-quantum key.
    let mut sk1 = vec![0u8; <H1 as Suite>::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; <H1 as Suite>::PUBLIC_KEY_LEN];
    let mut sk3 = vec![0u8; <H3 as Suite>::SECRET_KEY_LEN];
    let mut pk3 = vec![0u8; <H3 as Suite>::PUBLIC_KEY_LEN];
    keypair_from_seed::<H1>(&[7u8; 32], &mut sk1, &mut pk1).expect("keygen");
    keypair_from_seed::<H3>(&[7u8; 32], &mut sk3, &mut pk3).expect("keygen");
    assert_ne!(&sk1[64..], &sk3[64..], "post-quantum halves must differ");
}

// H1 is deterministic in both halves by specification (ed25519 is
// RFC 8032 deterministic and ignores any supplied nonce; ML-DSA-44 signs
// with a fixed all-zero `rnd`), so hedged signing repeats for H1. This is
// the mirror image of t2 below: H3's classical half (sr25519) does bind
// the caller-supplied randomness through schnorrkel, so its hedged
// signatures do not repeat. See
// crates/pqhybridsign/src/classical/ed25519.rs for the documented
// rationale.
#[test]
fn t2_h1_hedged_is_deterministic_by_construction() {
    let (sk, _) = keys!(H1, 2);
    let mut a = vec![0u8; <H1 as Suite>::SIGNATURE_LEN];
    let mut b = vec![0u8; <H1 as Suite>::SIGNATURE_LEN];
    sign::<H1>(&sk, b"m", b"c", &mut OsRng, &mut a).expect("sign");
    sign::<H1>(&sk, b"m", b"c", &mut OsRng, &mut b).expect("sign");
    assert_eq!(a, b, "hedged H1 signatures must repeat: both halves are message-deterministic");
}

#[test]
fn t2_hedged_signing_is_not_deterministic_for_sr25519() {
    // H1 is deterministic in both halves by specification, so this applies
    // to H3 only.
    let (sk, _) = keys!(H3, 2);
    let mut a = vec![0u8; <H3 as Suite>::SIGNATURE_LEN];
    let mut b = vec![0u8; <H3 as Suite>::SIGNATURE_LEN];
    sign::<H3>(&sk, b"m", b"c", &mut OsRng, &mut a).expect("sign");
    sign::<H3>(&sk, b"m", b"c", &mut OsRng, &mut b).expect("sign");
    assert_ne!(&a[..64], &b[..64], "hedged sr25519 must not repeat a signature");
}
