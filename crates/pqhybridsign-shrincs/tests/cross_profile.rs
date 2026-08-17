// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-profile separation: half of a check that one build cannot make.
//!
//! Exactly one `profile-*` feature compiles at a time (`suites.rs`), so a key
//! belonging to another profile cannot exist as a value inside this build.
//! `stateful_spec.rs` tests the mechanism that makes a wrong-profile key fail
//! -- the active profile name is bound into the commitment preimage -- but it
//! cannot test the outcome, because it has no second profile to compare
//! against.
//!
//! This file supplies the missing half, twice over.
//!
//! [`print_the_cross_profile_fingerprint`] prints a fingerprint derived from
//! the per-profile fixture public key under whichever profile is active.
//! Continuous integration runs it once per profile and asserts the
//! fingerprints differ; see the `cross-profile` job in `.gitlab-ci.yml`.
//! Running it in a single build proves only that the fingerprint is
//! derivable, which is why the assertions there are limited to that.
//!
//! [`a_signature_does_not_verify_under_another_profiles_commitment`] closes
//! the gap that fingerprint diffing leaves open: the fingerprint job never
//! calls `verify`, so it proves the four profiles *commit* differently
//! without proving the verifier *depends* on the commitment. A change that
//! stopped comparing the commitment during verification, while keygen still
//! wrote distinct commitments, would pass the job untouched. That test
//! splices a foreign profile's recorded commitment into the active
//! profile's public key and requires `verify` to refuse.
//!
//! Cost: public-key reconstruction and verification from fixture bytes, no
//! keygen and no signing. Stateless signing grinds: 1.16 s at
//! `profile-256s` in release, 176.60 s at `profile-128s-q18`, and roughly 70
//! times those figures in a debug build. Verification does not grind. Keygen
//! and `SecretKey::import` both cost about 47 s at the 128s profiles; the
//! fixture path keeps this file under a second at every profile.

// Shared loader exposes fields for every consumer. This binary does not use
// the secret key or the master seed; the loader allows the unused rest.
mod fixture;

use pqhybridsign_core::stateful::StatefulHybridSignatureScheme;
use pqhybridsign_core::{PqStatefulScheme, StatefulSuite};
use pqhybridsign_shrincs::{PublicKey, H5};

/// Prefix that the continuous integration job greps for. Changing it breaks
/// the `cross-profile` job.
const MARKER: &str = "CROSS_PROFILE_FINGERPRINT";

/// Offset of the 32-byte `publicKeyCommitment` inside the SHRINCS bundle
/// (`statefulPublicKey(68) || commitment(32) || pkSeed(32) ||
/// hypertreeRoot(32)`).
const BUNDLE_COMMITMENT_OFFSET: usize = 68;

/// Length of that commitment.
const COMMITMENT_LEN: usize = 32;

/// Where the commitment starts inside the composite public key wire bytes
/// (`ClassicalPK || bundle`). Derived from the suite's own constants so a
/// change to either component's key size moves this with it.
fn commitment_offset() -> usize {
    let classical_len = <H5 as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN
        - <<H5 as StatefulSuite>::Pq as PqStatefulScheme>::VERIFY_KEY_LEN;
    classical_len + BUNDLE_COMMITMENT_OFFSET
}

#[test]
fn print_the_cross_profile_fingerprint() {
    let f = fixture::h5();
    let pk = PublicKey::<H5>::from_bytes(&f.public_key).expect("public key from fixture");

    // Same stored form the golden vectors pin: classical public key followed
    // by the 32-byte SHRINCS commitment out of the bundle.
    let commitment = &pk.pq_verify_key()[68..100];
    let mut stored = Vec::with_capacity(pk.classical().len() + 32);
    stored.extend_from_slice(pk.classical());
    stored.extend_from_slice(commitment);

    let profile = <<H5 as StatefulSuite>::Pq as PqStatefulScheme>::NAME;
    let label = hex::encode(<H5 as StatefulSuite>::LABEL);

    // The classical half is profile-independent by construction: it comes
    // from the classical component, which knows nothing about SHRINCS. Only
    // the commitment and the label can separate two profiles, so the
    // fingerprint carries exactly those.
    println!(
        "{MARKER} profile={profile} label={label} commitment={}",
        hex::encode(commitment)
    );

    assert_eq!(stored.len(), 64, "stored public key is 64 bytes");
    assert!(
        <H5 as StatefulSuite>::LABEL.ends_with(&[0u8]),
        "label carries its trailing null byte"
    );
    assert!(
        label.contains(&hex::encode(profile.as_bytes())),
        "the active profile name appears inside the label, so a fingerprint \
         from another profile cannot collide by label alone"
    );
}

/// Splice another profile's recorded commitment into this profile's public
/// key, and require `verify` to refuse the signatures that key really made.
///
/// This is the assertion no single build can make with two live keys, and
/// the one the `cross-profile` fingerprint job cannot make at all, because
/// it never calls `verify`. The four fixture files are checked in and
/// parseable whatever profile compiles, so a foreign profile's commitment
/// bytes are available here even though a foreign profile's *key* is not.
///
/// Both signing paths are covered, because they read the bundle through
/// different code: `verify_stateful` and `verify_stateless` each
/// re-derive the commitment for themselves.
///
/// H5 only. H6 differs from H5 in the classical component alone, and the
/// property under test is the SHRINCS half's dependence on the commitment,
/// so running both would double the cost for the same evidence.
#[test]
fn a_signature_does_not_verify_under_another_profiles_commitment() {
    let f = fixture::h5();
    let at = commitment_offset();

    // The honest key verifies both of its own signatures. Without this the
    // rejections below would also be satisfied by a verifier that refuses
    // everything.
    let honest = PublicKey::<H5>::from_bytes(&f.public_key).expect("public key from fixture");
    assert!(
        H5::verify(
            &honest,
            &f.stateful_msg,
            &f.stateful_ctx,
            &f.stateful_signature
        ),
        "the fixture's own stateful signature must verify under its own key"
    );
    assert!(
        H5::verify(
            &honest,
            &f.stateless_msg,
            &f.stateless_ctx,
            &f.stateless_signature
        ),
        "the fixture's own stateless signature must verify under its own key"
    );

    let foreign = fixture::foreign_profiles("H5");
    assert_eq!(
        foreign.len(),
        3,
        "four profiles are checked in, so three of them are not the active one"
    );

    for other in foreign {
        let mut spliced = f.public_key.clone();
        spliced[at..at + COMMITMENT_LEN]
            .copy_from_slice(&other.public_key[at..at + COMMITMENT_LEN]);
        assert_ne!(
            spliced, f.public_key,
            "profile {} must commit to different bytes, or this splice tests nothing",
            other.profile_name
        );

        let pk = PublicKey::<H5>::from_bytes(&spliced).expect("spliced public key");
        assert!(
            !H5::verify(&pk, &f.stateful_msg, &f.stateful_ctx, &f.stateful_signature),
            "a stateful signature must not verify once the commitment comes \
             from profile {}",
            other.profile_name
        );
        assert!(
            !H5::verify(
                &pk,
                &f.stateless_msg,
                &f.stateless_ctx,
                &f.stateless_signature
            ),
            "a stateless signature must not verify once the commitment comes \
             from profile {}",
            other.profile_name
        );
    }
}
