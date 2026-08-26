// SPDX-License-Identifier: AGPL-3.0-or-later
use pqhybridsign::{composite, composite_delta};
use pqhybridsign::{EdMl44, EdFn512, SrMl44, SrFn512};

use crate::stateful_suites::verify_stateful_pk;
use crate::suite::Suite;

/// Verify `sig` over `msg` under `ctx` for `suite`, against `pk`.
///
/// Covers all six suites: unlike signing, verification never has to be
/// kept apart by statefulness, because verifying never spends anything.
///
/// For EdMl44 through SrFn512 there is only one signing path, so there is nothing
/// this function could accept by mistake. For EdSh and SrSh -- the two suites
/// whose post-quantum half pairs a stateful fast path with a stateless
/// few-time one -- this function accepts only a signature produced by
/// `sign_stateful`, the same behaviour
/// [`crate::verify_stateful`] gives directly. Specification section 20.2
/// requires this: the primary stateless path is reserved for rotation and
/// recovery, and a verifier for an ordinary application message MUST NOT
/// accept it. A caller that genuinely needs to verify a stateless-path EdSh
/// or SrSh signature -- a rotation or recovery authorization, or a message an
/// application has deliberately signed on the few-time path -- calls
/// [`crate::verify_stateless`] instead of this function.
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
        Suite::EdMl44 => composite::verify::<EdMl44>(pk, msg, ctx, sig),
        Suite::SrMl44 => composite::verify::<SrMl44>(pk, msg, ctx, sig),
        Suite::EdFn512 => composite_delta::verify::<EdFn512>(pk, msg, ctx, sig),
        Suite::SrFn512 => composite_delta::verify::<SrFn512>(pk, msg, ctx, sig),
        Suite::EdSh => verify_stateful_pk::<pqhybridsign::shrincs::EdSh>(pk, msg, ctx, sig),
        Suite::SrSh => verify_stateful_pk::<pqhybridsign::shrincs::SrSh>(pk, msg, ctx, sig),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_public_key_fails_verification_rather_than_erroring() {
        for suite in [
            Suite::EdMl44,
            Suite::EdFn512,
            Suite::SrMl44,
            Suite::SrFn512,
            Suite::EdSh,
            Suite::SrSh,
        ] {
            assert!(!verify(suite, &[0u8; 1], b"msg", b"", &[0u8; 1]));
        }
    }
}
