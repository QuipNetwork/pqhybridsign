// SPDX-License-Identifier: AGPL-3.0-or-later
//! Entry points for the four stateless suites, EdMl44 through SrFn512.
//!
//! Every function here rejects EdSh and SrSh with
//! [`AbiError::WrongEntryPointForSuite`] rather than silently doing
//! something else with them. See the crate documentation for why: EdSh and
//! SrSh spend a one-time leaf per signature, and a call shaped like an
//! ordinary stateless sign must never be able to consume one.

use pqhybridsign::{composite, composite_delta, suite::Suite as CoreSuite};
use pqhybridsign::{EdMl44, EdFn512, SrMl44, SrFn512};
use rand_core::CryptoRngCore;

use crate::error::AbiError;
use crate::suite::Suite;

/// Derive a keypair for `suite` from a 32-byte master seed.
///
/// `sk_out` and `pk_out` must be exactly [`crate::secret_key_len`] and
/// [`crate::public_key_len`] bytes for `suite`.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for EdSh or SrSh: use
/// [`crate::keygen_stateful_from_seed`] instead. [`AbiError::BadLength`] if
/// `seed` is not 32 bytes, or `sk_out`/`pk_out` are not exactly the
/// suite's key lengths.
pub fn keygen_from_seed(
    suite: Suite,
    seed: &[u8],
    sk_out: &mut [u8],
    pk_out: &mut [u8],
) -> Result<(), AbiError> {
    let seed: &[u8; 32] = seed.try_into().map_err(|_| AbiError::BadLength)?;
    match suite {
        Suite::EdMl44 => composite::keypair_from_seed::<EdMl44>(seed, sk_out, pk_out).map_err(Into::into),
        Suite::SrMl44 => composite::keypair_from_seed::<SrMl44>(seed, sk_out, pk_out).map_err(Into::into),
        Suite::EdFn512 => {
            composite_delta::keypair_from_seed::<EdFn512>(seed, sk_out, pk_out).map_err(Into::into)
        }
        Suite::SrFn512 => {
            composite_delta::keypair_from_seed::<SrFn512>(seed, sk_out, pk_out).map_err(Into::into)
        }
        Suite::EdSh | Suite::SrSh => Err(AbiError::WrongEntryPointForSuite),
    }
}

/// Hedged signing for `suite`. Returns the number of bytes written into
/// `sig_out`.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for EdSh or SrSh: use
/// [`crate::sign_stateful`] instead. [`AbiError::OutputBufferTooSmall`] if
/// `sig_out` is smaller than [`crate::signature_len`] needs for this
/// message.
pub fn sign(
    suite: Suite,
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl CryptoRngCore,
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    match suite {
        Suite::EdMl44 => {
            composite::sign::<EdMl44>(sk, msg, ctx, rng, sig_out)?;
            Ok(<EdMl44 as CoreSuite>::SIGNATURE_LEN)
        }
        Suite::SrMl44 => {
            composite::sign::<SrMl44>(sk, msg, ctx, rng, sig_out)?;
            Ok(<SrMl44 as CoreSuite>::SIGNATURE_LEN)
        }
        Suite::EdFn512 => composite_delta::sign::<EdFn512>(sk, msg, ctx, rng, sig_out).map_err(Into::into),
        Suite::SrFn512 => composite_delta::sign::<SrFn512>(sk, msg, ctx, rng, sig_out).map_err(Into::into),
        Suite::EdSh | Suite::SrSh => Err(AbiError::WrongEntryPointForSuite),
    }
}

/// Deterministic signing for `suite`. Returns the number of bytes written
/// into `sig_out`.
///
/// See [`pqhybridsign::composite::sign_deterministic`] for which
/// components honour `nonce`; not every suite does.
///
/// # Errors
///
/// The same as [`sign`].
pub fn sign_deterministic(
    suite: Suite,
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    match suite {
        Suite::EdMl44 => {
            composite::sign_deterministic::<EdMl44>(sk, msg, ctx, nonce, sig_out)?;
            Ok(<EdMl44 as CoreSuite>::SIGNATURE_LEN)
        }
        Suite::SrMl44 => {
            composite::sign_deterministic::<SrMl44>(sk, msg, ctx, nonce, sig_out)?;
            Ok(<SrMl44 as CoreSuite>::SIGNATURE_LEN)
        }
        Suite::EdFn512 => composite_delta::sign_deterministic::<EdFn512>(sk, msg, ctx, nonce, sig_out)
            .map_err(Into::into),
        Suite::SrFn512 => composite_delta::sign_deterministic::<SrFn512>(sk, msg, ctx, nonce, sig_out)
            .map_err(Into::into),
        Suite::EdSh | Suite::SrSh => Err(AbiError::WrongEntryPointForSuite),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn stateless_entry_points_reject_ed_sh_and_sr_sh() {
        for suite in [Suite::EdSh, Suite::SrSh] {
            assert_eq!(
                keygen_from_seed(suite, &[0u8; 32], &mut [0u8; 64], &mut [0u8; 64]),
                Err(AbiError::WrongEntryPointForSuite)
            );
            assert_eq!(
                sign(suite, &[0u8; 64], b"msg", b"", &mut OsRng, &mut [0u8; 64]),
                Err(AbiError::WrongEntryPointForSuite)
            );
            assert_eq!(
                sign_deterministic(suite, &[0u8; 64], b"msg", b"", b"nonce", &mut [0u8; 64]),
                Err(AbiError::WrongEntryPointForSuite)
            );
        }
    }

    #[test]
    fn keygen_rejects_a_seed_of_the_wrong_length() {
        let mut sk = [0u8; 4096];
        let mut pk = [0u8; 4096];
        assert_eq!(
            keygen_from_seed(Suite::EdMl44, &[0u8; 31], &mut sk, &mut pk),
            Err(AbiError::BadLength)
        );
        assert_eq!(
            keygen_from_seed(Suite::EdMl44, &[0u8; 33], &mut sk, &mut pk),
            Err(AbiError::BadLength)
        );
    }

    #[test]
    fn a_short_output_buffer_returns_the_length_error_rather_than_panicking() {
        let short_sk = &mut [0u8; 1][..];
        let ok_pk = &mut [0u8; 4096][..];
        assert_eq!(
            keygen_from_seed(Suite::EdMl44, &[0u8; 32], short_sk, ok_pk),
            Err(AbiError::BadLength)
        );

        let ok_sk = &mut [0u8; 4096][..];
        let short_pk = &mut [0u8; 1][..];
        assert_eq!(
            keygen_from_seed(Suite::EdMl44, &[0u8; 32], ok_sk, short_pk),
            Err(AbiError::BadLength)
        );

        let mut sk = vec![0u8; crate::secret_key_len(Suite::EdMl44)];
        let mut pk = vec![0u8; crate::public_key_len(Suite::EdMl44)];
        keygen_from_seed(Suite::EdMl44, &[7u8; 32], &mut sk, &mut pk).expect("keygen");

        // `OutputBufferTooSmall`, not `BadLength`: `sig_out` is a caller
        // buffer the suite writes into, so a short one is a capacity fault
        // and names the right argument. All six suites report it the same
        // way, and an oversized `sig_out` is accepted with the true length
        // reported through the bytes-written out-parameter.
        let mut short_sig = [0u8; 1];
        assert_eq!(
            sign(Suite::EdMl44, &sk, b"msg", b"", &mut OsRng, &mut short_sig),
            Err(AbiError::OutputBufferTooSmall)
        );
        assert_eq!(
            sign_deterministic(Suite::EdMl44, &sk, b"msg", b"", b"n", &mut short_sig),
            Err(AbiError::OutputBufferTooSmall)
        );
    }
}
