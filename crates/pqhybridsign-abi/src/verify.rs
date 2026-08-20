// SPDX-License-Identifier: AGPL-3.0-or-later
use pqhybridsign::shrincs::{H5, H6};
use pqhybridsign::stateful::StatefulHybridSignatureScheme;
use pqhybridsign::stateful_composite::PublicKey;
use pqhybridsign::{composite, composite_delta, suite::StatefulSuite};
use pqhybridsign::{H1, H2, H3, H4};

use crate::suite::Suite;

/// Verify `sig` over `msg` under `ctx` for `suite`, against `pk`.
///
/// Covers all six suites: unlike signing, verification never has to be
/// kept apart by statefulness, because verifying never spends anything.
///
/// Returns `false`, never an error, for a malformed `pk` or `sig` -- the
/// same design every underlying verify function in this workspace uses:
/// an error channel here would tell a caller which component or encoding
/// rejected, which is exactly the timing/error side channel signature
/// verification is built to avoid. `pk` must be
/// [`crate::public_key_len`] bytes for `suite`; a `pk` of any other length
/// simply fails to verify.
#[must_use]
pub fn verify(suite: Suite, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    match suite {
        Suite::H1 => composite::verify::<H1>(pk, msg, ctx, sig),
        Suite::H3 => composite::verify::<H3>(pk, msg, ctx, sig),
        Suite::H2 => composite_delta::verify::<H2>(pk, msg, ctx, sig),
        Suite::H4 => composite_delta::verify::<H4>(pk, msg, ctx, sig),
        Suite::H5 => verify_stateful::<H5>(pk, msg, ctx, sig),
        Suite::H6 => verify_stateful::<H6>(pk, msg, ctx, sig),
    }
}

fn verify_stateful<S: StatefulSuite>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = PublicKey::<S>::from_bytes(pk) else {
        return false;
    };
    let sig = sig.to_vec();
    <S as StatefulHybridSignatureScheme>::verify(&pk, msg, ctx, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_public_key_fails_verification_rather_than_erroring() {
        for suite in [
            Suite::H1,
            Suite::H2,
            Suite::H3,
            Suite::H4,
            Suite::H5,
            Suite::H6,
        ] {
            assert!(!verify(suite, &[0u8; 1], b"msg", b"", &[0u8; 1]));
        }
    }
}
