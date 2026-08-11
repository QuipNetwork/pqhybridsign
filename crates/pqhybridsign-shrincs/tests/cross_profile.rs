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
//! This test supplies the missing half. It prints a fingerprint derived from
//! the per-profile fixture public key under whichever profile is active.
//! Continuous integration runs it once per profile and asserts the
//! fingerprints differ; see the `cross-profile` job in `.gitlab-ci.yml`.
//! Running it in a single build proves only that the fingerprint is
//! derivable, which is why the assertions here are limited to that.
//!
//! Cost: public-key reconstruction from fixture bytes, no keygen and no
//! signing. Stateless signing grinds: 1.16 s at `profile-256s` in release,
//! 176.60 s at `profile-128s-q18`, and roughly 70 times those figures in a
//! debug build. Keygen and `SecretKey::import` both cost about 47 s at the
//! 128s profiles; the fixture path keeps this test under a second at every
//! profile.

// Shared loader exposes fields for every consumer. This binary only needs
// the H5 public key, so the rest is unused here.
#[allow(dead_code)]
mod fixture;

use pqhybridsign_core::{PqStatefulScheme, StatefulSuite};
use pqhybridsign_shrincs::{PublicKey, H5};

/// Prefix that the continuous integration job greps for. Changing it breaks
/// the `cross-profile` job.
const MARKER: &str = "CROSS_PROFILE_FINGERPRINT";

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
