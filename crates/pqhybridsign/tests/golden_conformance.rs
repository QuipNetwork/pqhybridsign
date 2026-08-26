// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stateful (SHRINCS) suite test. Compiled only under a profile feature.
#![cfg(any(
    feature = "profile-256s",
    feature = "profile-256s-sha2",
    feature = "profile-128s-q18",
    feature = "profile-128s-q20"
))]
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
//! Fixture shape and verify-only golden vector coverage for every SHRINCS profile.
//!
//! This binary is the single place that proves the per-profile fixtures are
//! well formed and that the recorded signatures verify. It checks field
//! shape, reconstructs each suite public key, verifies the stored stateful
//! and stateless signatures, rejects a flipped bit and a cross-suite public
//! key, and (on the 256s profiles only) imports the secret key and checks
//! the leaf counter.
//!
//! `golden_stateful.rs` re-signs stateful leaves live and only compiles under
//! `profile-256s`. Obtaining a secret key to re-sign with requires `keygen`
//! or `SecretKey::import`, and both cost about 47 seconds at the 128s
//! profiles. This binary never signs under any profile: the import path is
//! gated to 256s so the 128s suites stay under a second.
//!
//! Verification costs under a second at every profile. See the cost trap in
//! `fixture/mod.rs` before adding any path that imports a secret key at 128s.

mod fixture;

use pqhybridsign::component::PqStatefulScheme;
use pqhybridsign::shrincs::{EdSh, PublicKey, ShrincsScheme, SrSh};
use pqhybridsign::stateful::StatefulHybridSignatureScheme;

#[cfg(any(feature = "profile-256s", feature = "profile-256s-sha2"))]
use pqhybridsign::shrincs::SecretKey;

fn check_suite<S>(f: &fixture::Fixture, want_suite: &str, other_pk_bytes: &[u8])
where
    S: StatefulHybridSignatureScheme<Signature = Vec<u8>, PublicKey = PublicKey<S>>,
    S: pqhybridsign::suite::StatefulSuite<Pq = ShrincsScheme>,
{
    assert_eq!(f.suite, want_suite);
    assert_eq!(
        f.profile_name,
        <ShrincsScheme as PqStatefulScheme>::NAME,
        "{} fixture profile_name must match the active profile",
        f.suite
    );
    assert_eq!(f.max_signatures, 4);
    assert_eq!(f.master_seed.len(), 32);
    assert_eq!(f.stateful_leaf_index, 1);
    assert!(!f.secret_key.is_empty());
    assert!(!f.public_key.is_empty());
    assert!(!f.stateful_signature.is_empty());
    assert!(!f.stateless_signature.is_empty());

    let pk = PublicKey::<S>::from_bytes(&f.public_key).expect("public key from fixture");

    assert!(
        S::verify_stateful(&pk, &f.stateful_msg, &f.stateful_ctx, &f.stateful_signature),
        "{} stateful fixture signature must verify",
        f.suite
    );
    assert!(
        S::verify_stateless(
            &pk,
            &f.stateless_msg,
            &f.stateless_ctx,
            &f.stateless_signature
        ),
        "{} stateless fixture signature must verify",
        f.suite
    );

    let mut bad_stateful = f.stateful_signature.clone();
    bad_stateful[0] ^= 0x01;
    assert!(
        !S::verify_stateful(&pk, &f.stateful_msg, &f.stateful_ctx, &bad_stateful),
        "{} must reject a stateful signature with one bit flipped",
        f.suite
    );

    let mut bad_stateless = f.stateless_signature.clone();
    bad_stateless[0] ^= 0x01;
    assert!(
        !S::verify_stateless(&pk, &f.stateless_msg, &f.stateless_ctx, &bad_stateless),
        "{} must reject a stateless signature with one bit flipped",
        f.suite
    );

    // Cross-suite: EdSh signature against SrSh public key (and the reverse) must
    // fail. Reconstruct the other suite's public key as `S::PublicKey` so
    // the same `verify` path is exercised; the wire bytes differ by classical
    // algorithm, so a true verify rejects them.
    let other_pk =
        PublicKey::<S>::from_bytes(other_pk_bytes).expect("other suite public key length matches");
    assert!(
        !S::verify_stateful(
            &other_pk,
            &f.stateful_msg,
            &f.stateful_ctx,
            &f.stateful_signature
        ),
        "{} must reject its stateful signature under the other suite public key",
        f.suite
    );
    assert!(
        !S::verify_stateless(
            &other_pk,
            &f.stateless_msg,
            &f.stateless_ctx,
            &f.stateless_signature
        ),
        "{} must reject its stateless signature under the other suite public key",
        f.suite
    );

    // Import re-derives the hypertree root to validate the blob, which costs
    // about 47 seconds at 128s. Keep the coverage only where import is cheap.
    #[cfg(any(feature = "profile-256s", feature = "profile-256s-sha2"))]
    {
        let sk = SecretKey::<S>::import(&f.secret_key).expect("import");
        assert_eq!(sk.next_leaf(), 0, "exported key is still at the first leaf");
    }
}

#[test]
fn h5_fixture_golden_vectors_verify() {
    let f = fixture::h5();
    let other = fixture::h6();
    check_suite::<EdSh>(f, "ED-SH", &other.public_key);
}

#[test]
fn h6_fixture_golden_vectors_verify() {
    let f = fixture::h6();
    let other = fixture::h5();
    check_suite::<SrSh>(f, "SR-SH", &other.public_key);
}
