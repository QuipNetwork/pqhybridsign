// SPDX-License-Identifier: AGPL-3.0-or-later
mod common;

use common::{Ed25519Stub, HashClassical, HashClassicalSr, HashPq, MlDsaStub};
use pqhybridsign_core::composite::{keypair_from_seed, sign, sign_deterministic, verify};
use pqhybridsign_core::{hybrid_suite, Error, Suite};

hybrid_suite! {
    /// H1 sizes, with the accept-everything stubs.
    H1Test,
    classical = Ed25519Stub as "ed25519",
    pq = MlDsaStub as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

hybrid_suite! {
    /// H1 shape, with stubs that reject a modified signature.
    HashH1,
    classical = HashClassical as "ed25519",
    pq = HashPq as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

hybrid_suite! {
    /// A second suite, to show one master seed gives independent keys.
    HashH3,
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
    let mut sk = vec![0u8; HashH1::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashH1::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashH1>(&[7u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut sig = vec![0u8; HashH1::SIGNATURE_LEN];
    sign_deterministic::<HashH1>(&sk, msg, ctx, b"nonce", &mut sig).expect("sign");
    (pk, sig)
}

#[test]
fn signature_splits_classical_then_pq() {
    let mut sig = vec![0u8; H1Test::SIGNATURE_LEN];
    let sk = vec![0u8; H1Test::SECRET_KEY_LEN];
    sign_deterministic::<H1Test>(&sk, b"m", b"", b"n", &mut sig).expect("sign");
    assert_eq!(sig.len(), 2484);
    assert_eq!(H1Test::SPLIT, 64);
}

#[test]
fn verify_rejects_a_wrong_length_signature() {
    let pk = vec![0u8; H1Test::PUBLIC_KEY_LEN];
    let short = vec![0u8; H1Test::SIGNATURE_LEN - 1];
    assert!(!verify::<H1Test>(&pk, b"m", b"", &short));
}

#[test]
fn a_signature_verifies() {
    let (pk, sig) = signed(b"hello", b"chain");
    assert!(verify::<HashH1>(&pk, b"hello", b"chain", &sig));
}

#[test]
fn hedged_signatures_verify() {
    let mut sk = vec![0u8; HashH1::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashH1::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashH1>(&[3u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut sig = vec![0u8; HashH1::SIGNATURE_LEN];
    let mut rng = CountingRng(1);
    sign::<HashH1>(&sk, b"hello", b"", &mut rng, &mut sig).expect("sign");
    assert!(verify::<HashH1>(&pk, b"hello", b"", &sig));
}

#[test]
fn a_flipped_byte_in_the_classical_half_fails() {
    let (pk, sig) = signed(b"hello", b"");
    for i in 0..HashH1::SPLIT {
        let mut bad = sig.clone();
        bad[i] ^= 1;
        assert!(
            !verify::<HashH1>(&pk, b"hello", b"", &bad),
            "classical byte {i} was not covered"
        );
    }
}

#[test]
fn a_flipped_byte_in_the_post_quantum_half_fails() {
    let (pk, sig) = signed(b"hello", b"");
    for i in HashH1::SPLIT..HashH1::SIGNATURE_LEN {
        let mut bad = sig.clone();
        bad[i] ^= 1;
        assert!(
            !verify::<HashH1>(&pk, b"hello", b"", &bad),
            "post-quantum byte {i} was not covered"
        );
    }
}

#[test]
fn a_flipped_byte_in_either_public_key_half_fails() {
    let (pk, sig) = signed(b"hello", b"");
    for i in 0..HashH1::PUBLIC_KEY_LEN {
        let mut bad = pk.clone();
        bad[i] ^= 1;
        assert!(!verify::<HashH1>(&bad, b"hello", b"", &sig), "pk byte {i}");
    }
}

#[test]
fn a_changed_message_or_context_fails() {
    let (pk, sig) = signed(b"hello", b"chain");
    assert!(!verify::<HashH1>(&pk, b"hellp", b"chain", &sig));
    assert!(!verify::<HashH1>(&pk, b"hello", b"other", &sig));
    assert!(!verify::<HashH1>(&pk, b"hello", b"", &sig));
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
        let ok = verify::<HashH1>(bad_pk, msg, b"", bad_sig);
        // The last case is the well formed one.
        assert_eq!(ok, i == cases.len() - 1, "case {i}");
    }
    // A context over 255 bytes cannot be encoded, and is still a false.
    assert!(!verify::<HashH1>(&pk, b"hello", &long_ctx, &sig));
}

#[cfg(feature = "alloc")]
#[test]
fn a_message_longer_than_the_stack_buffer_round_trips() {
    let msg = vec![0xa5u8; 4096];
    let (pk, sig) = signed(&msg, b"chain");
    assert!(verify::<HashH1>(&pk, &msg, b"chain", &sig));
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(!verify::<HashH1>(&pk, &msg, b"chain", &bad));
}

/// Without `alloc`, `M'` lives in a 512-byte stack buffer. For the 26-byte
/// suite label that leaves 484 bytes for `ctx` and `msg` together. Signing
/// past the ceiling must report `OutputBufferTooSmall` rather than truncate.
///
/// Run with `cargo test -p pqhybridsign-core --no-default-features`.
#[cfg(not(feature = "alloc"))]
#[test]
fn without_alloc_an_oversized_message_reports_the_ceiling() {
    let mut sk = vec![0u8; HashH1::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashH1::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashH1>(&[9u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut sig = vec![0u8; HashH1::SIGNATURE_LEN];

    // 1 prefix + 26 label + 1 length byte + 0 ctx + 484 msg = 512 exactly.
    let at_ceiling = vec![0xa5u8; 484];
    sign_deterministic::<HashH1>(&sk, &at_ceiling, b"", b"n", &mut sig)
        .expect("484 bytes is the largest message that fits");
    assert!(verify::<HashH1>(&pk, &at_ceiling, b"", &sig));

    let over = vec![0xa5u8; 1024];
    assert_eq!(
        sign_deterministic::<HashH1>(&sk, &over, b"", b"n", &mut sig).unwrap_err(),
        Error::OutputBufferTooSmall {
            needed: 1 + 26 + 1 + 1024,
            actual: 512,
        }
    );
    // Verification of an oversized message is a `false`, never a panic.
    assert!(!verify::<HashH1>(&pk, &over, b"", &sig));
}

#[test]
fn two_suites_from_one_master_seed_have_independent_keys() {
    let mut sk1 = vec![0u8; HashH1::SECRET_KEY_LEN];
    let mut pk1 = vec![0u8; HashH1::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashH1>(&[7u8; 32], &mut sk1, &mut pk1).expect("h1");
    let mut sk3 = vec![0u8; HashH3::SECRET_KEY_LEN];
    let mut pk3 = vec![0u8; HashH3::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashH3>(&[7u8; 32], &mut sk3, &mut pk3).expect("h3");
    assert_ne!(sk1, sk3, "the suite label must separate the two trees");
    assert_ne!(pk1, pk3);
}

#[test]
fn the_suite_label_reaches_the_classical_component() {
    // Same key material, same message, different suite label: the classical
    // half must differ, because the label is its signing context.
    let mut sk = vec![0u8; HashH1::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashH1::PUBLIC_KEY_LEN];
    keypair_from_seed::<HashH1>(&[7u8; 32], &mut sk, &mut pk).expect("keypair");
    let mut h1 = vec![0u8; HashH1::SIGNATURE_LEN];
    let mut h3 = vec![0u8; HashH3::SIGNATURE_LEN];
    sign_deterministic::<HashH1>(&sk, b"m", b"", b"n", &mut h1).expect("h1");
    sign_deterministic::<HashH3>(&sk, b"m", b"", b"n", &mut h3).expect("h3");
    assert_ne!(h1[..HashH1::SPLIT], h3[..HashH3::SPLIT]);
}

#[test]
fn keypair_from_seed_rejects_wrong_length_buffers() {
    let mut sk = vec![0u8; HashH1::SECRET_KEY_LEN];
    let mut pk = vec![0u8; HashH1::PUBLIC_KEY_LEN];
    assert_eq!(
        keypair_from_seed::<HashH1>(&[0u8; 32], &mut sk[1..], &mut pk),
        Err(Error::BadLength {
            expected: HashH1::SECRET_KEY_LEN,
            actual: HashH1::SECRET_KEY_LEN - 1
        })
    );
    assert_eq!(
        keypair_from_seed::<HashH1>(&[0u8; 32], &mut sk, &mut pk[1..]),
        Err(Error::BadLength {
            expected: HashH1::PUBLIC_KEY_LEN,
            actual: HashH1::PUBLIC_KEY_LEN - 1
        })
    );
}

#[test]
fn signing_rejects_wrong_length_buffers() {
    let sk = vec![0u8; HashH1::SECRET_KEY_LEN];
    let mut sig = vec![0u8; HashH1::SIGNATURE_LEN];
    assert!(sign_deterministic::<HashH1>(&sk[1..], b"m", b"", b"n", &mut sig).is_err());
    assert!(sign_deterministic::<HashH1>(&sk, b"m", b"", b"n", &mut sig[1..]).is_err());
    let long_ctx = vec![0u8; 256];
    assert_eq!(
        sign_deterministic::<HashH1>(&sk, b"m", &long_ctx, b"n", &mut sig),
        Err(Error::ContextTooLong)
    );
}
