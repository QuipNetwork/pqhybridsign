// SPDX-License-Identifier: AGPL-3.0-or-later
use pqhybridsign::encoding_path::{CLASSICAL_SIG_LEN, LEAF_COUNT_LEN, SELECTOR_LEN};
use pqhybridsign::shrincs::{EdSh, SrSh};
use pqhybridsign::stateful_composite::SecretKey;
use pqhybridsign::{
    component::PqStatefulScheme,
    suite::{DeltaSuite, StatefulSuite, Suite as CoreSuite},
};
use pqhybridsign::{EdFn512, EdMl44, SrFn512, SrMl44};

use crate::suite::Suite;

/// Public key length for `suite`, in bytes.
///
/// For EdSh and SrSh this is the verify-key form ([`StatefulSuite::VERIFY_PUBLIC_KEY_LEN`]):
/// the form [`crate::verify`] and [`crate::keygen_stateful_from_seed`]'s
/// `pk_out` both use, larger than the on-storage commitment form because a
/// verifier needs the full verify key, not just a commitment to it.
#[must_use]
pub fn public_key_len(suite: Suite) -> usize {
    match suite {
        Suite::EdMl44 => <EdMl44 as CoreSuite>::PUBLIC_KEY_LEN,
        Suite::SrMl44 => <SrMl44 as CoreSuite>::PUBLIC_KEY_LEN,
        Suite::EdFn512 => <EdFn512 as DeltaSuite>::PUBLIC_KEY_LEN,
        Suite::SrFn512 => <SrFn512 as DeltaSuite>::PUBLIC_KEY_LEN,
        Suite::EdSh => <EdSh as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN,
        Suite::SrSh => <SrSh as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN,
    }
}

/// Stored public key length for `suite`, in bytes: the form a verifier
/// keeps, which is what [`crate::verify_with_stored_public_key_stateful`]
/// and [`crate::verify_with_stored_public_key_stateless`] take as
/// `stored_public_key`.
///
/// For EdSh and SrSh this is [`StatefulSuite::STORED_PUBLIC_KEY_LEN`]: the
/// classical public key and a 32-byte commitment to the post-quantum verify
/// key, smaller than [`public_key_len`] reports for the same suite because
/// the verify key itself is supplied per signature rather than stored. For
/// EdMl44-SrFn512 the stored and verify forms are the same bytes, so this equals
/// [`public_key_len`].
#[must_use]
pub fn stored_public_key_len(suite: Suite) -> usize {
    match suite {
        Suite::EdMl44 | Suite::EdFn512 | Suite::SrMl44 | Suite::SrFn512 => public_key_len(suite),
        Suite::EdSh => <EdSh as StatefulSuite>::STORED_PUBLIC_KEY_LEN,
        Suite::SrSh => <SrSh as StatefulSuite>::STORED_PUBLIC_KEY_LEN,
    }
}

/// Secret key length for `suite`, in bytes.
///
/// For EdMl44-SrFn512 this is the raw composite secret key
/// (`ClassicalSK || PqSecretKey`). For EdSh and SrSh it is the length of the
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
        Suite::EdMl44 => <EdMl44 as CoreSuite>::SECRET_KEY_LEN,
        Suite::SrMl44 => <SrMl44 as CoreSuite>::SECRET_KEY_LEN,
        Suite::EdFn512 => <EdFn512 as DeltaSuite>::SECRET_KEY_LEN,
        Suite::SrFn512 => <SrFn512 as DeltaSuite>::SECRET_KEY_LEN,
        Suite::EdSh => SecretKey::<EdSh>::exported_len(),
        Suite::SrSh => SecretKey::<SrSh>::exported_len(),
    }
}

/// Signature length for `suite`, in bytes.
///
/// EdMl44 and SrMl44 have a single, fixed signature length. EdFn512 and SrFn512 are
/// variable-length: FN-DSA-512's wire form carries a 1-byte length field
/// (specification section 6), so the value returned here is the maximum
/// [`DeltaSuite::MAX_SIGNATURE_LEN`] can produce, sized for the shipped
/// `fn-dsa` 0.4.0's actual (fixed, per that crate) FN-DSA-512 signature
/// length; a caller sizes `sig_out` with this and reads back the actual
/// written length. EdSh and SrSh are variable-length for a different reason:
/// their post-quantum half is a stateful hash-based signature whose
/// authentication path grows with the leaf index, so the value here is the
/// worst case over every leaf a key with the largest allowed budget
/// ([`PqStatefulScheme::LEAF_CAPACITY_LIMIT`]) could spend, not the length
/// any one signature actually reaches.
#[must_use]
pub fn signature_len(suite: Suite) -> usize {
    match suite {
        Suite::EdMl44 => <EdMl44 as CoreSuite>::SIGNATURE_LEN,
        Suite::SrMl44 => <SrMl44 as CoreSuite>::SIGNATURE_LEN,
        Suite::EdFn512 => <EdFn512 as DeltaSuite>::MAX_SIGNATURE_LEN,
        Suite::SrFn512 => <SrFn512 as DeltaSuite>::MAX_SIGNATURE_LEN,
        Suite::EdSh => stateful_signature_max_len::<EdSh>(),
        Suite::SrSh => stateful_signature_max_len::<SrSh>(),
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
            Suite::EdMl44,
            Suite::EdFn512,
            Suite::SrMl44,
            Suite::SrFn512,
            Suite::EdSh,
            Suite::SrSh,
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
    /// secret key is 2560 bytes against SHRINCS's 264, so EdSh is a fifth the
    /// size of EdMl44. Pinning the numbers catches a real change; asserting an
    /// invented ordering only encoded a guess.
    ///
    /// EdSh and SrSh report the verify-key form for the public key, which is why
    /// theirs is 196 rather than the 64-byte stored commitment form.
    #[test]
    fn every_advertised_size_matches_its_measured_value() {
        let expected = [
            (Suite::EdMl44, 2624, 1344),
            (Suite::EdFn512, 1409, 929),
            (Suite::SrMl44, 2624, 1344),
            (Suite::SrFn512, 1409, 929),
            (Suite::EdSh, 496, 196),
            (Suite::SrSh, 496, 196),
        ];
        for (suite, sk, pk) in expected {
            assert_eq!(secret_key_len(suite), sk, "secret key length for {suite:?}");
            assert_eq!(public_key_len(suite), pk, "public key length for {suite:?}");
        }

        // The stored form for EdSh and SrSh: a 32-byte classical public key and
        // a 32-byte commitment, against the 196-byte verify form above.
        assert_eq!(stored_public_key_len(Suite::EdSh), 64);
        assert_eq!(stored_public_key_len(Suite::SrSh), 64);
    }
}
