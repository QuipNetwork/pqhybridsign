// SPDX-License-Identifier: AGPL-3.0-or-later
//! Profile-dependent conformance checks that must run under every active
//! `profile-*` feature.
//!
//! These three tests read verify-only fixture data (`public_key` and the
//! exported secret-key blob layout). They do not call `keygen`,
//! `sign_stateless`, or `SecretKey::import`, so they stay under a second
//! even at the 128s profiles.

mod fixture;

use hashsigs_rs::shrincs::PROFILE_NAME;
use pqhybridsign_core::stateful_composite::{PublicKey, SecretKey};
use pqhybridsign_core::{PqStatefulScheme, StatefulSuite};
use pqhybridsign_shrincs::{ShrincsScheme, H5, H6};
use sha3::{Digest, Keccak256};

// Composite sizes are exactly 64 / 196 / 328 (specification section 4).

#[test]
fn composite_sizes_match_the_specification() {
    // Stored form (classical 32 + SHRINCS commitment 32).
    assert_eq!(H5::STORED_PUBLIC_KEY_LEN, 64);
    // Verify form (classical 32 + SHRINCS bundle 164).
    assert_eq!(H5::VERIFY_PUBLIC_KEY_LEN, 196);
    // Secret key (classical 64 + SHRINCS Keys 264).
    assert_eq!(H5::SECRET_KEY_LEN, 328);
    assert_eq!(H6::STORED_PUBLIC_KEY_LEN, 64);
    assert_eq!(H6::VERIFY_PUBLIC_KEY_LEN, 196);
    assert_eq!(H6::SECRET_KEY_LEN, 328);

    for (f, suite) in [(fixture::h5(), "H5"), (fixture::h6(), "H6")] {
        assert_eq!(f.suite, suite);
        assert_eq!(f.profile_name, <ShrincsScheme as PqStatefulScheme>::NAME);
        assert_eq!(f.max_signatures, 4);
        assert_eq!(f.master_seed.len(), 32);
        assert_eq!(f.stateful_leaf_index, 1);
        assert_eq!(f.public_key.len(), H5::VERIFY_PUBLIC_KEY_LEN);
        assert_eq!(f.secret_key.len(), SecretKey::<H5>::exported_len());
        // Recorded messages and signatures match the generator in generate_fixtures.rs.
        assert_eq!(f.stateful_ctx.as_slice(), b"fixture-stateful");
        assert_eq!(f.stateful_msg.as_slice(), b"fixture leaf 1");
        assert!(!f.stateful_signature.is_empty());
        assert_eq!(f.stateless_ctx.as_slice(), b"fixture-stateless");
        assert_eq!(f.stateless_msg.as_slice(), b"fixture stateless message");
        assert!(!f.stateless_signature.is_empty());
    }
}

// The commitment preimage binds the active profile name, so two keys built
// from identical seeds under different profiles commit to different values.

#[test]
fn the_commitment_binds_the_profile_name() {
    // Cross-profile separation cannot be tested inside one build: exactly one
    // `profile-*` feature compiles, so the wrong-profile key does not exist
    // here as a type. What can be tested, and is the mechanism that makes a
    // wrong-profile key fail, is that the active profile name is bound into
    // the commitment: two keys built from identical seeds under different
    // profiles commit to different values, so neither can verify against the
    // other's stored commitment.
    let f = fixture::h5();
    let pk = PublicKey::<H5>::from_bytes(&f.public_key).expect("public key");
    let vk = pk.pq_verify_key();
    let (stateful_public_key, rest) = vk.split_at(68);
    let carried_commitment = &rest[..32];
    let pk_seed = &rest[32..64];
    let hypertree_root = &rest[64..96];

    let commitment = |profile: &str| -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"shrincs-public-key/");
        hasher.update(profile.as_bytes());
        hasher.update(stateful_public_key);
        hasher.update(pk_seed);
        hasher.update(hypertree_root);
        hasher.finalize().into()
    };

    // The active profile reproduces the commitment the key actually carries,
    // which is what makes the next assertion meaningful.
    assert_eq!(
        commitment(PROFILE_NAME).as_slice(),
        carried_commitment,
        "the commitment preimage is keccak256(prefix || profile || fields)"
    );

    for other in ["shrincs-128s-q18", "shrincs-256s-sha2", "shrincs-256s"] {
        if other == PROFILE_NAME {
            continue;
        }
        assert_ne!(
            commitment(other).as_slice(),
            carried_commitment,
            "profile {other} must commit to a different value from identical fields"
        );
    }
}

// Composite secret-key blob layout: ClassicalSK || PqSecretKey || nextLeaf(4)
// || PqVerifyKey. Reads the fixture export blob without importing it.

/// Offset of the composite blob's 4-byte leaf-counter field, and of the
/// upstream `Keys` blob nested ahead of it.
const PQ_AT: usize = 64;
const COUNTER_AT: usize = PQ_AT + <ShrincsScheme as PqStatefulScheme>::SECRET_KEY_LEN;

#[test]
fn the_blob_layout_is_the_documented_one() {
    let f = fixture::h5();
    let blob = &f.secret_key;
    let pk = PublicKey::<H5>::from_bytes(&f.public_key).expect("public key");

    assert_eq!(blob.len(), SecretKey::<H5>::exported_len());
    assert_eq!(
        blob.len(),
        <H5 as StatefulSuite>::SECRET_KEY_LEN
            + 4
            + <ShrincsScheme as PqStatefulScheme>::VERIFY_KEY_LEN,
        "the composite secret key, then the counter, then the cached verify key"
    );
    assert_eq!(
        &blob[COUNTER_AT + 4..],
        pk.pq_verify_key(),
        "the trailing field is the same verify key the public key carries"
    );
}
