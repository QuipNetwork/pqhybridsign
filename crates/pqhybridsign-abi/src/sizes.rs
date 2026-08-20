// SPDX-License-Identifier: AGPL-3.0-or-later
use pqhybridsign::encoding_path::{CLASSICAL_SIG_LEN, LEAF_COUNT_LEN, SELECTOR_LEN};
use pqhybridsign::shrincs::{H5, H6};
use pqhybridsign::stateful_composite::SecretKey;
use pqhybridsign::{
    component::PqStatefulScheme,
    suite::{DeltaSuite, StatefulSuite, Suite as CoreSuite},
};
use pqhybridsign::{H1, H2, H3, H4};

use crate::suite::Suite;

/// Public key length for `suite`, in bytes.
///
/// For H5 and H6 this is the verify-key form ([`StatefulSuite::VERIFY_PUBLIC_KEY_LEN`]):
/// the form [`crate::verify`] and [`crate::keygen_stateful_from_seed`]'s
/// `pk_out` both use, larger than the on-storage commitment form because a
/// verifier needs the full verify key, not just a commitment to it.
#[must_use]
pub fn public_key_len(suite: Suite) -> usize {
    match suite {
        Suite::H1 => <H1 as CoreSuite>::PUBLIC_KEY_LEN,
        Suite::H3 => <H3 as CoreSuite>::PUBLIC_KEY_LEN,
        Suite::H2 => <H2 as DeltaSuite>::PUBLIC_KEY_LEN,
        Suite::H4 => <H4 as DeltaSuite>::PUBLIC_KEY_LEN,
        Suite::H5 => <H5 as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN,
        Suite::H6 => <H6 as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN,
    }
}

/// Stored public key length for `suite`, in bytes: the form a verifier
/// keeps, which is what [`crate::verify_with_stored_public_key`] takes as
/// `stored_public_key`.
///
/// For H5 and H6 this is [`StatefulSuite::STORED_PUBLIC_KEY_LEN`]: the
/// classical public key and a 32-byte commitment to the post-quantum verify
/// key, smaller than [`public_key_len`] reports for the same suite because
/// the verify key itself is supplied per signature rather than stored. For
/// H1-H4 the stored and verify forms are the same bytes, so this equals
/// [`public_key_len`].
#[must_use]
pub fn stored_public_key_len(suite: Suite) -> usize {
    match suite {
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => public_key_len(suite),
        Suite::H5 => <H5 as StatefulSuite>::STORED_PUBLIC_KEY_LEN,
        Suite::H6 => <H6 as StatefulSuite>::STORED_PUBLIC_KEY_LEN,
    }
}

/// Secret key length for `suite`, in bytes.
///
/// For H1-H4 this is the raw composite secret key
/// (`ClassicalSK || PqSecretKey`). For H5 and H6 it is the length of the
/// blob [`crate::keygen_stateful_from_seed`], [`crate::sign_stateful`] and
/// [`crate::sign_stateless`] read and write: the composite secret key plus
/// the leaf counter and the cached verify key
/// (see [`SecretKey::exported_len`]), because a stateful secret key is not
/// safe to serialize as raw component bytes alone -- the leaf counter is
/// part of the key's state, and losing it on a round trip through a
/// language boundary reissues every leaf already spent.
#[must_use]
pub fn secret_key_len(suite: Suite) -> usize {
    match suite {
        Suite::H1 => <H1 as CoreSuite>::SECRET_KEY_LEN,
        Suite::H3 => <H3 as CoreSuite>::SECRET_KEY_LEN,
        Suite::H2 => <H2 as DeltaSuite>::SECRET_KEY_LEN,
        Suite::H4 => <H4 as DeltaSuite>::SECRET_KEY_LEN,
        Suite::H5 => SecretKey::<H5>::exported_len(),
        Suite::H6 => SecretKey::<H6>::exported_len(),
    }
}

/// Signature length for `suite`, in bytes.
///
/// H1 and H3 have a single, fixed signature length. H2 and H4 are
/// variable-length: FN-DSA-512's wire form carries a 1-byte length field
/// (specification section 6), so the value returned here is the maximum
/// [`DeltaSuite::MAX_SIGNATURE_LEN`] can produce, sized for the shipped
/// `fn-dsa` 0.4.0's actual (fixed, per that crate) FN-DSA-512 signature
/// length; a caller sizes `sig_out` with this and reads back the actual
/// written length. H5 and H6 are variable-length for a different reason:
/// their post-quantum half is a stateful hash-based signature whose
/// authentication path grows with the leaf index, so the value here is the
/// worst case over every leaf a key with the largest allowed budget
/// ([`PqStatefulScheme::LEAF_CAPACITY_LIMIT`]) could spend, not the length
/// any one signature actually reaches.
#[must_use]
pub fn signature_len(suite: Suite) -> usize {
    match suite {
        Suite::H1 => <H1 as CoreSuite>::SIGNATURE_LEN,
        Suite::H3 => <H3 as CoreSuite>::SIGNATURE_LEN,
        Suite::H2 => <H2 as DeltaSuite>::MAX_SIGNATURE_LEN,
        Suite::H4 => <H4 as DeltaSuite>::MAX_SIGNATURE_LEN,
        Suite::H5 => stateful_signature_max_len::<H5>(),
        Suite::H6 => stateful_signature_max_len::<H6>(),
    }
}

/// Worst-case path-selected signature length for `S`
/// (`pqhybridsign::encoding_path`): the classical signature, the
/// 1-byte path selector, and the larger of the stateful body at the
/// component's largest allowed leaf budget or the fixed-length stateless
/// body.
fn stateful_signature_max_len<S: StatefulSuite>() -> usize {
    let stateful_body = LEAF_COUNT_LEN
        + <S::Pq as PqStatefulScheme>::max_stateful_sig_len(
            <S::Pq as PqStatefulScheme>::LEAF_CAPACITY_LIMIT,
        );
    let stateless_body = <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN;
    CLASSICAL_SIG_LEN + SELECTOR_LEN + stateful_body.max(stateless_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every size must be positive, and the delta/stateful suites' maximum
    /// must be at least as large as the fixed-offset suites' comparable
    /// figure so a caller can never under-allocate by trusting this
    /// function.
    #[test]
    fn sizes_are_positive_for_every_suite() {
        for suite in [
            Suite::H1,
            Suite::H2,
            Suite::H3,
            Suite::H4,
            Suite::H5,
            Suite::H6,
        ] {
            assert!(public_key_len(suite) > 0, "{suite}");
            assert!(
                stored_public_key_len(suite) <= public_key_len(suite),
                "{suite}"
            );
            assert!(secret_key_len(suite) > 0, "{suite}");
            assert!(signature_len(suite) > 0, "{suite}");
        }
    }

    /// Pins every size a binding allocates against, under the default
    /// `profile-256s`.
    ///
    /// These are the measured values, not a rule about which suite ought to
    /// be larger. An earlier version of this test asserted that the stateful
    /// suites carried the longer secret key, which is false: ML-DSA-44's
    /// secret key is 2560 bytes against SHRINCS's 264, so H5 is a fifth the
    /// size of H1. Pinning the numbers catches a real change; asserting an
    /// invented ordering only encoded a guess.
    ///
    /// H5 and H6 report the verify-key form for the public key, which is why
    /// theirs is 196 rather than the 64-byte stored commitment form.
    #[test]
    fn every_advertised_size_matches_its_measured_value() {
        let expected = [
            (Suite::H1, 2624, 1344),
            (Suite::H2, 1409, 929),
            (Suite::H3, 2624, 1344),
            (Suite::H4, 1409, 929),
            (Suite::H5, 496, 196),
            (Suite::H6, 496, 196),
        ];
        for (suite, sk, pk) in expected {
            assert_eq!(secret_key_len(suite), sk, "secret key length for {suite:?}");
            assert_eq!(public_key_len(suite), pk, "public key length for {suite:?}");
        }

        // The stored form for H5 and H6: a 32-byte classical public key and
        // a 32-byte commitment, against the 196-byte verify form above.
        assert_eq!(stored_public_key_len(Suite::H5), 64);
        assert_eq!(stored_public_key_len(Suite::H6), 64);
    }
}
