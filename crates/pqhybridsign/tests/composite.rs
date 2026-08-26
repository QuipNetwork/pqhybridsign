// SPDX-License-Identifier: AGPL-3.0-or-later
// Integration test binary: `cfg(test)` is always true here. `unwrap`/
// `expect`/`panic` are the normal way a test fails; `hybrid_suite!`
// generates undocumented, unconditionally `pub` fixture structs, which is
// fine for a binary with no public API of its own.
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
mod common;

use common::{Ed25519Stub, HashClassical, HashClassicalSr, HashPq, MlDsaStub};
use pqhybridsign::composite::{keypair_from_seed, sign, sign_deterministic, verify};
use pqhybridsign::{error::Error, hybrid_suite, suite::Suite};

hybrid_suite! {
    /// EdMl44 sizes, with the accept-everything stubs.
    EdMl44Test,
    classical = Ed25519Stub as "ed25519",
    pq = MlDsaStub as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

hybrid_suite! {
    /// EdMl44 shape, with stubs that reject a modified signature.
    HashEdMl44,
    classical = HashClassical as "ed25519",
    pq = HashPq as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

hybrid_suite! {
    /// A second suite, to show one master seed gives independent keys.
    HashSrMl44,
    classical = HashClassicalSr as "sr25519",
    pq = HashPq as "mldsa44",
    label = "hybrid-sr25519-mldsa44-v1",
    label_len = 26,
}

/// Counter-based RNG. Hedged signing must not depend on real entropy for a
/// test to be reproducible.
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

/// A keypair and a signature over `msg` under the hash stubs.
fn signed(msg: &[u8], ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut sk = vec![0u8; HashEdMl44::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashEdMl44::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashEdMl44>(&[7u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut sig = vec![0u8; HashEdMl44::SIGNATURE_LEN];
    sign_deterministic::<HashEdMl44>(&sk, msg, ctx, b"nonce", &mut sig).expect("sign");
    (pk, sig)
}

#[test]
fn signature_splits_classical_then_pq() {
    let mut sig = vec![0u8; EdMl44Test::SIGNATURE_LEN];
    let sk = vec![0u8; EdMl44Test::SECRET_KEY_LEN];
    sign_deterministic::<EdMl44Test>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    assert_eq!(sig.len(), 2484);
    assert_eq!(EdMl44Test::SPLIT, 64);
}

#[test]
fn verify_rejects_a_wrong_length_signature() {
    let pk = vec![0u8; EdMl44Test::PUBLIC_KEY_LEN];
    let short = vec![0u8; EdMl44Test::SIGNATURE_LEN - 1];
    assert!(!verify::<EdMl44Test>(&pk, b"m", b"", &short));
}

#[test]
fn a_signature_verifies() {
    let (pk, sig) = signed(b"hello", b"chain");
    assert!(verify::<HashEdMl44>(&pk, b"hello", b"chain", &sig));
}

#[test]
fn hedged_signatures_verify() {
    let mut sk = vec![0u8; HashEdMl44::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashEdMl44::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashEdMl44>(&[3u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut sig = vec![0u8; HashEdMl44::SIGNATURE_LEN];
    let mut rng = CountingRng(1);
    sign::<HashEdMl44>(&sk, b"hello", b"", &mut rng, &mut sig).expect("sign");
    assert!(verify::<HashEdMl44>(&pk, b"hello", b"", &sig));
}

#[test]
fn a_flipped_byte_in_the_classical_half_fails() {
    let (pk, sig) = signed(b"hello", b"");
    for i in 0..HashEdMl44::SPLIT {
        let mut bad = sig.clone();
        bad[i] ^= 1;
        assert!(
            !verify::<HashEdMl44>(&pk, b"hello", b"", &bad),
            "classical byte {i} was not covered"
        );
    }
}

#[test]
fn a_flipped_byte_in_the_post_quantum_half_fails() {
    let (pk, sig) = signed(b"hello", b"");
    for i in HashEdMl44::SPLIT..HashEdMl44::SIGNATURE_LEN {
        let mut bad = sig.clone();
        bad[i] ^= 1;
        assert!(
            !verify::<HashEdMl44>(&pk, b"hello", b"", &bad),
            "post-quantum byte {i} was not covered"
        );
    }
}

#[test]
fn a_flipped_byte_in_either_public_key_half_fails() {
    let (pk, sig) = signed(b"hello", b"");
    for i in 0..HashEdMl44::PUBLIC_KEY_LEN {
        let mut bad = pk.clone();
        bad[i] ^= 1;
        assert!(
            !verify::<HashEdMl44>(&bad, b"hello", b"", &sig),
            "pk byte {i}"
        );
    }
}

#[test]
fn a_changed_message_or_context_fails() {
    let (pk, sig) = signed(b"hello", b"chain");
    assert!(!verify::<HashEdMl44>(&pk, b"hellp", b"chain", &sig));
    assert!(!verify::<HashEdMl44>(&pk, b"hello", b"other", &sig));
    assert!(!verify::<HashEdMl44>(&pk, b"hello", b"", &sig));
}

#[test]
fn malformed_input_returns_false_and_never_panics() {
    let (pk, sig) = signed(b"hello", b"");
    let long_ctx = vec![0u8; 256];
    let cases: [(&[u8], &[u8], &[u8]); 7] = [
        (&[], b"hello", &sig),
        (&pk, b"hello", &[]),
        (&pk[..pk.len() - 1], b"hello", &sig),
        (&sig, b"hello", &sig),
        (&pk, b"hello", &sig[..sig.len() - 1]),
        (&pk, b"hello", &pk),
        (&pk, b"hello", &sig),
    ];
    for (i, (bad_pk, msg, bad_sig)) in cases.iter().enumerate() {
        let ok = verify::<HashEdMl44>(bad_pk, msg, b"", bad_sig);
        // The last case is the well formed one.
        assert_eq!(ok, i == cases.len() - 1, "case {i}");
    }
    // A context over 255 bytes cannot be encoded, and is still a false.
    assert!(!verify::<HashEdMl44>(&pk, b"hello", &long_ctx, &sig));
}

#[cfg(feature = "alloc")]
#[test]
fn a_message_longer_than_the_stack_buffer_round_trips() {
    let msg = vec![0xa5u8; 4096];
    let (pk, sig) = signed(&msg, b"chain");
    assert!(verify::<HashEdMl44>(&pk, &msg, b"chain", &sig));
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(!verify::<HashEdMl44>(&pk, &msg, b"chain", &bad));
}

/// Without `alloc`, `M'` lives in a 512-byte stack buffer. For the 26-byte
/// suite label that leaves 484 bytes for `ctx` and `msg` together. Signing
/// past the ceiling must report `OutputBufferTooSmall` rather than truncate.
///
/// Run with `cargo test -p pqhybridsign-core --no-default-features`.
#[cfg(not(feature = "alloc"))]
#[test]
fn without_alloc_an_oversized_message_reports_the_ceiling() {
    let mut sk = vec![0u8; HashEdMl44::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashEdMl44::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashEdMl44>(&[9u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut sig = vec![0u8; HashEdMl44::SIGNATURE_LEN];

    // 1 prefix + 26 label + 1 length byte + 0 ctx + 484 msg = 512 exactly.
    let at_ceiling = vec![0xa5u8; 484];
    sign_deterministic::<HashEdMl44>(&sk, &at_ceiling, b"", b"n", &mut sig)
        .expect("484 bytes is the largest message that fits");
    assert!(verify::<HashEdMl44>(&pk, &at_ceiling, b"", &sig));

    let over = vec![0xa5u8; 1024];
    assert_eq!(
        sign_deterministic::<HashEdMl44>(&sk, &over, b"", b"n", &mut sig).unwrap_err(),
        Error::OutputBufferTooSmall {
            needed: 1 + 26 + 1 + 1024,
            actual: 512,
        }
    );
    // Verification of an oversized message is a `false`, never a panic.
    assert!(!verify::<HashEdMl44>(&pk, &over, b"", &sig));
}

#[test]
fn two_suites_from_one_master_seed_have_independent_keys() {
    let mut sk1 = vec![0u8; HashEdMl44::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; HashEdMl44::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashEdMl44>(&[7u8; 32], &mut sk1, &mut pk1).expect("ed_ml44");
    let mut sk3 = vec![0u8; HashSrMl44::SECRET_KEY_LEN];
    let mut pk3 = vec![0u8; HashSrMl44::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashSrMl44>(&[7u8; 32], &mut sk3, &mut pk3).expect("sr_ml44");
    assert_ne!(sk1, sk3, "the suite label must separate the two trees");
    assert_ne!(pk1, pk3);
}

#[test]
fn the_suite_label_reaches_the_classical_component() {
    // Same key material, same message, different suite label: the classical
    // half must differ, because the label is its signing context.
    let mut sk = vec![0u8; HashEdMl44::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashEdMl44::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashEdMl44>(&[7u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut ed_ml44 = vec![0u8; HashEdMl44::SIGNATURE_LEN];
    let mut sr_ml44 = vec![0u8; HashSrMl44::SIGNATURE_LEN];
    sign_deterministic::<HashEdMl44>(&sk, b"m", b"", b"n", &mut ed_ml44).expect("ed_ml44");
    sign_deterministic::<HashSrMl44>(&sk, b"m", b"", b"n", &mut sr_ml44).expect("sr_ml44");
    assert_ne!(ed_ml44[..HashEdMl44::SPLIT], sr_ml44[..HashSrMl44::SPLIT]);
}

#[test]
fn keypair_from_seed_rejects_wrong_length_buffers() {
    let mut sk = vec![0u8; HashEdMl44::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashEdMl44::PUBLIC_KEY_LEN];
    assert_eq!(
        keypair_from_seed::<HashEdMl44>(&[0u8; 32], &mut sk[1..], &mut pk),
        Err(Error::BadLength {
            expected: HashEdMl44::SECRET_KEY_LEN,
            actual: HashEdMl44::SECRET_KEY_LEN - 1
        })
    );
    assert_eq!(
        keypair_from_seed::<HashEdMl44>(&[0u8; 32], &mut sk, &mut pk[1..]),
        Err(Error::BadLength {
            expected: HashEdMl44::PUBLIC_KEY_LEN,
            actual: HashEdMl44::PUBLIC_KEY_LEN - 1
        })
    );
}

#[test]
fn signing_rejects_wrong_length_buffers() {
    let sk = vec![0u8; HashEdMl44::SECRET_KEY_LEN];
    let mut sig = vec![0u8; HashEdMl44::SIGNATURE_LEN];
    assert!(sign_deterministic::<HashEdMl44>(&sk[1..], b"m", b"", b"n", &mut sig).is_err());
    assert!(sign_deterministic::<HashEdMl44>(&sk, b"m", b"", b"n", &mut sig[1..]).is_err());
    let long_ctx = vec![0u8; 256];
    assert_eq!(
        sign_deterministic::<HashEdMl44>(&sk, b"m", &long_ctx, b"n", &mut sig),
        Err(Error::ContextTooLong)
    );
}

/// `sig_out` only needs to be *at least* `SIGNATURE_LEN`: a caller sizing
/// one scratch buffer for the largest of the six suites and reusing it for
/// every suite must not be turned away by EdMl44 or SrMl44. Pins the relaxed
/// contract for both `sign` and `sign_deterministic`, and for both suites
/// this module exercises.
#[test]
fn sig_out_accepts_exact_or_larger_and_rejects_shorter() {
    fn check<S: Suite>(seed: u8) {
        let mut sk = vec![0u8; S::SECRET_KEY_LEN];
        let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
        keypair_from_seed::<S>(&[seed; 32], &mut sk, &mut pk).expect("keypair");

        // Short: rejected with `OutputBufferTooSmall`, not `BadLength` --
        // the wrong argument name misleads a caller into resizing `sk`.
        let mut short = vec![0u8; S::SIGNATURE_LEN - 1];
        assert_eq!(
            sign_deterministic::<S>(&sk, b"m", b"", b"n", &mut short),
            Err(Error::OutputBufferTooSmall {
                needed: S::SIGNATURE_LEN,
                actual: S::SIGNATURE_LEN - 1,
            })
        );
        let mut rng = CountingRng(1);
        assert_eq!(
            sign::<S>(&sk, b"m", b"", &mut rng, &mut short),
            Err(Error::OutputBufferTooSmall {
                needed: S::SIGNATURE_LEN,
                actual: S::SIGNATURE_LEN - 1,
            })
        );

        // Exact: succeeds.
        let mut exact = vec![0u8; S::SIGNATURE_LEN];
        sign_deterministic::<S>(&sk, b"m", b"", b"n", &mut exact).expect("exact-size sig_out");
        assert!(verify::<S>(&pk, b"m", b"", &exact));

        // Larger: succeeds too, and only the first `SIGNATURE_LEN` bytes are
        // the real signature -- the tail is left as the caller supplied it.
        let mut oversized = vec![0xffu8; S::SIGNATURE_LEN + 64];
        sign_deterministic::<S>(&sk, b"m", b"", b"n", &mut oversized).expect("oversized sig_out");
        assert_eq!(
            oversized[..S::SIGNATURE_LEN],
            exact[..],
            "the written signature must not depend on the buffer's extra length"
        );
        assert!(
            oversized[S::SIGNATURE_LEN..].iter().all(|&b| b == 0xff),
            "bytes past SIGNATURE_LEN must be left untouched"
        );
        assert!(verify::<S>(&pk, b"m", b"", &oversized[..S::SIGNATURE_LEN]));
    }

    check::<HashEdMl44>(21);
    check::<HashSrMl44>(22);
}
