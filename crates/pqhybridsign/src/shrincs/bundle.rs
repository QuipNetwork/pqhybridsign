// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verification of the SHRINCS public-key commitment bundle.
//!
//! A SHRINCS public key is too large to store on an account, so the account
//! stores only a 32-byte commitment. The signer supplies the full 164-byte
//! bundle at verification time, and the verifier here recomputes the
//! commitment from that bundle and rejects any mismatch — the commitment
//! field carried inside the bundle itself is never trusted.
//!
//! ```text
//! commitment = keccak256("shrincs-public-key/" || PROFILE_NAME
//!                         || statefulPublicKey(68) || pkSeed(32) || hypertreeRoot(32))
//!
//! bundle (164 bytes) = statefulPublicKey(68) || publicKeyCommitment(32)
//!                       || pkSeed(32) || hypertreeRoot(32)
//! ```

use hashsigs_rs::shrincs::{PublicKey, ShrincsVerifier};

/// Number of bytes in a commitment bundle.
pub const BUNDLE_LEN: usize = 164;

const STATEFUL_PUBLIC_KEY_LEN: usize = 68;
const COMMITMENT_LEN: usize = 32;
const PK_SEED_LEN: usize = 32;
const HYPERTREE_ROOT_LEN: usize = 32;

const PK_SEED_OFFSET: usize = STATEFUL_PUBLIC_KEY_LEN + COMMITMENT_LEN;
const HYPERTREE_ROOT_OFFSET: usize = PK_SEED_OFFSET + PK_SEED_LEN;

/// Offset of the stateless key material -- `pkSeed || hypertreeRoot` -- within
/// the bundle. `pkSeed` and `hypertreeRoot` are adjacent in the bundle layout
/// (`statefulPublicKey || commitment || pkSeed || hypertreeRoot`), so this is
/// one contiguous 64-byte range, not two fields to stitch together.
///
/// This is the material specification section 21's few-time stateless budget
/// is keyed to. It is deliberately not `PK_SEED_OFFSET` re-exported under a
/// second name: this constant documents *why* the range matters (the budget
/// key), where `PK_SEED_OFFSET` documents only where `pkSeed` starts.
pub const STATELESS_KEY_MATERIAL_OFFSET: usize = PK_SEED_OFFSET;

/// Length of the stateless key material: `pkSeed(32) || hypertreeRoot(32)`.
pub const STATELESS_KEY_MATERIAL_LEN: usize = PK_SEED_LEN + HYPERTREE_ROOT_LEN;

/// Offset of the big-endian `maxSignatures` field within `statefulPublicKey`
/// (and therefore within the bundle, since `statefulPublicKey` starts at 0).
const MAX_SIGNATURES_OFFSET: usize = 64;

/// Failure modes for [`verify_bundle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// `bundle` is not exactly [`BUNDLE_LEN`] bytes.
    InvalidLength,
    /// `stored_commitment` is all-zero (an uninitialized or never-installed
    /// commitment can never authorize a bundle).
    ZeroCommitment,
    /// The bundle's recomputed commitment does not match `stored_commitment`.
    CommitmentMismatch,
}

/// Recompute the commitment `bundle`'s own key material implies.
///
/// This is the value [`verify_bundle`] compares against the stored one. It
/// is derived from `bundle`'s `statefulPublicKey`, `pkSeed` and
/// `hypertreeRoot`, never read from the commitment `bundle` carries at
/// bytes 68..100: a carried commitment proves only internal consistency,
/// which an attacker-generated bundle also has.
///
/// # Errors
///
/// [`BundleError::InvalidLength`] if `bundle` is not [`BUNDLE_LEN`] bytes.
pub fn commitment(bundle: &[u8]) -> Result<[u8; COMMITMENT_LEN], BundleError> {
    if bundle.len() != BUNDLE_LEN {
        return Err(BundleError::InvalidLength);
    }

    let stateful_public_key = &bundle[0..STATEFUL_PUBLIC_KEY_LEN];

    let mut pk_seed = [0u8; PK_SEED_LEN];
    pk_seed.copy_from_slice(&bundle[PK_SEED_OFFSET..PK_SEED_OFFSET + PK_SEED_LEN]);

    let mut hypertree_root = [0u8; HYPERTREE_ROOT_LEN];
    hypertree_root.copy_from_slice(
        &bundle[HYPERTREE_ROOT_OFFSET..HYPERTREE_ROOT_OFFSET + HYPERTREE_ROOT_LEN],
    );

    Ok(ShrincsVerifier::new().public_key_commitment(stateful_public_key, pk_seed, hypertree_root))
}

/// Recompute the commitment from a 164-byte `bundle` and check it against
/// `stored_commitment`.
///
/// Returns the parsed [`PublicKey`] on success, with its
/// `public_key_commitment` field set to the freshly recomputed commitment —
/// never to the (untrusted) value carried inside `bundle`.
pub fn verify_bundle(
    bundle: &[u8],
    stored_commitment: &[u8; COMMITMENT_LEN],
) -> Result<PublicKey, BundleError> {
    if bundle.len() != BUNDLE_LEN {
        return Err(BundleError::InvalidLength);
    }
    if *stored_commitment == [0u8; COMMITMENT_LEN] {
        return Err(BundleError::ZeroCommitment);
    }

    let recomputed = commitment(bundle)?;

    let stateful_public_key = &bundle[0..STATEFUL_PUBLIC_KEY_LEN];
    let carried_commitment = &bundle[STATEFUL_PUBLIC_KEY_LEN..PK_SEED_OFFSET];
    let pk_seed = &bundle[PK_SEED_OFFSET..PK_SEED_OFFSET + PK_SEED_LEN];
    let hypertree_root = &bundle[HYPERTREE_ROOT_OFFSET..HYPERTREE_ROOT_OFFSET + HYPERTREE_ROOT_LEN];

    // The commitment carried inside the bundle is never trusted as the
    // source of truth for the comparison below — `recomputed` is derived
    // independently from the other three fields. It is, however, checked
    // for self-consistency against `recomputed`: the bundle is a single
    // 164-byte unit, and a tampered carried-commitment field (even though
    // unused as an input) must still cause the whole bundle to be rejected.
    if carried_commitment != recomputed.as_slice() {
        return Err(BundleError::CommitmentMismatch);
    }

    if recomputed != *stored_commitment {
        return Err(BundleError::CommitmentMismatch);
    }

    Ok(PublicKey {
        stateful_public_key: stateful_public_key.to_vec(),
        public_key_commitment: recomputed.to_vec(),
        pk_seed: pk_seed.to_vec(),
        hypertree_root: hypertree_root.to_vec(),
    })
}

/// Extract the big-endian `maxSignatures` field carried inside a 164-byte
/// bundle's `statefulPublicKey` (bytes 64..68), without recomputing or
/// checking the commitment.
pub fn max_signatures(bundle: &[u8]) -> Result<u32, BundleError> {
    if bundle.len() != BUNDLE_LEN {
        return Err(BundleError::InvalidLength);
    }
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bundle[MAX_SIGNATURES_OFFSET..MAX_SIGNATURES_OFFSET + 4]);
    Ok(u32::from_be_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_signatures_rejects_wrong_length() {
        assert_eq!(max_signatures(&[0u8; 10]), Err(BundleError::InvalidLength));
    }

    // The remaining tests call `ShrincsSigner::keygen`, which costs about 47
    // seconds at the 128s profiles. Commitment recomputation and length
    // checks do not depend on the SHRINCS parameter set.
    #[cfg(feature = "profile-256s")]
    mod with_keygen {
        use super::*;
        use hashsigs_rs::profiles::selected::{SelectedProfile, NUM_CHAINS, NUM_LAYERS};
        use hashsigs_rs::shrincs::ShrincsSigner;

        /// Build a raw 164-byte bundle from a generated `PublicKey`'s fields, in
        /// the order the spec defines: statefulPublicKey || commitment || pkSeed
        /// || hypertreeRoot. This is a flat concatenation, not the crate's ABI
        /// encoding (`PublicKey::to_bytes`), matching the on-chain bundle format.
        fn build_bundle(public_key: &PublicKey) -> Vec<u8> {
            let mut bundle = Vec::with_capacity(BUNDLE_LEN);
            bundle.extend_from_slice(&public_key.stateful_public_key);
            bundle.extend_from_slice(&public_key.public_key_commitment);
            bundle.extend_from_slice(&public_key.pk_seed);
            bundle.extend_from_slice(&public_key.hypertree_root);
            bundle
        }

        fn generate(seed: &[u8], max_signatures: u32) -> ([u8; 32], PublicKey) {
            let (keys, public_key) =
                ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
                    seed,
                    max_signatures,
                )
                .expect("keygen with valid seed/max must succeed");
            let stored_commitment = *keys.public_key_commitment().as_bytes();
            (stored_commitment, public_key)
        }

        #[test]
        fn round_trip_recomputes_stored_commitment() {
            let (stored_commitment, public_key) = generate(b"bundle round trip seed", 4);
            let bundle = build_bundle(&public_key);
            assert_eq!(bundle.len(), BUNDLE_LEN);

            let recovered =
                verify_bundle(&bundle, &stored_commitment).expect("valid bundle must verify");

            assert_eq!(
                recovered.stateful_public_key,
                public_key.stateful_public_key
            );
            assert_eq!(recovered.public_key_commitment, stored_commitment.to_vec());
            assert_eq!(recovered.pk_seed, public_key.pk_seed);
            assert_eq!(recovered.hypertree_root, public_key.hypertree_root);
        }

        #[test]
        fn single_byte_flip_anywhere_is_rejected() {
            let (stored_commitment, public_key) = generate(b"bundle byte flip seed", 4);
            let bundle = build_bundle(&public_key);

            // Sample several positions across each of the four fields, not one
            // hand-picked byte: first, middle, and last byte of each field.
            let field_bounds = [
                (0usize, STATEFUL_PUBLIC_KEY_LEN),
                (STATEFUL_PUBLIC_KEY_LEN, PK_SEED_OFFSET),
                (PK_SEED_OFFSET, HYPERTREE_ROOT_OFFSET),
                (HYPERTREE_ROOT_OFFSET, BUNDLE_LEN),
            ];

            let mut positions = Vec::new();
            for (start, end) in field_bounds {
                positions.push(start);
                positions.push(start + (end - start) / 2);
                positions.push(end - 1);
            }

            for position in positions {
                let mut tampered = bundle.clone();
                tampered[position] ^= 0x01;
                assert_eq!(
                    verify_bundle(&tampered, &stored_commitment),
                    Err(BundleError::CommitmentMismatch),
                    "flipping byte at position {position} must be rejected"
                );
            }
        }

        #[test]
        fn all_zero_stored_commitment_is_rejected_outright() {
            let (_stored_commitment, public_key) = generate(b"bundle zero commitment seed", 4);
            let bundle = build_bundle(&public_key);

            assert_eq!(
                verify_bundle(&bundle, &[0u8; 32]),
                Err(BundleError::ZeroCommitment)
            );
        }

        #[test]
        fn wrong_length_is_rejected_before_hashing() {
            let (_stored_commitment, public_key) = generate(b"bundle wrong length seed", 4);
            let mut bundle = build_bundle(&public_key);
            bundle.pop();

            // Pair the short bundle with an all-zero stored commitment: if the
            // length check did not run first (i.e. hashing were attempted
            // first), the zero-commitment guard would fire instead and this
            // would observe `ZeroCommitment` rather than `InvalidLength`.
            assert_eq!(
                verify_bundle(&bundle, &[0u8; 32]),
                Err(BundleError::InvalidLength)
            );

            let mut too_long = build_bundle(&public_key);
            too_long.push(0);
            assert_eq!(
                verify_bundle(&too_long, &[0u8; 32]),
                Err(BundleError::InvalidLength)
            );
        }

        #[test]
        fn max_signatures_recovered_from_big_endian_bytes() {
            let (_stored_commitment, public_key) = generate(b"bundle max signatures seed", 4);
            let bundle = build_bundle(&public_key);

            // Independently decode bytes 64..68 of statefulPublicKey to cross
            // check against the helper under test.
            let expected =
                u32::from_be_bytes(public_key.stateful_public_key[64..68].try_into().unwrap());
            assert_eq!(expected, 4);

            assert_eq!(max_signatures(&bundle).unwrap(), expected);
        }
    } // mod with_keygen
}
