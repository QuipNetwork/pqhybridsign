// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signing and verification for the four stateless suites, ED-ML-44 through SR-FN-512,
//! plus [`pqhs_verify`] which covers all six.

use std::os::raw::c_int;

use rand_core::OsRng;

use crate::error::{PQHS_ERR_NULL_POINTER, PQHS_OK};
use crate::ffi::{borrow_slice, borrow_slice_mut, guard, write_out};
use crate::suite::suite_from_code;

/// Hedged (randomized) signing for `suite`. Writes the signature into
/// `sig_out` and the number of bytes written into `*sig_written`.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for ED-SH or SR-SH: use
/// [`pqhs_sign_stateful`](crate::pqhs_sign_stateful) or
/// [`pqhs_sign_stateless`](crate::pqhs_sign_stateless) instead.
/// `PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL` if `sig_out` is smaller than
/// [`pqhs_signature_len`](crate::pqhs_signature_len) needs for this
/// message. `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero
/// length is null, or if `sig_written` is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `sk`/`msg`/`ctx`, writes for `sig_out`/`sig_written`)
/// for exactly its paired length in bytes, and must not be aliased by
/// another live pointer for the duration of this call. A null pointer is
/// only valid when its paired length is `0`; `sig_written` has no paired
/// length and must be a valid, non-null, writable `usize` pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_sign(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    sig_written: *mut usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // Checked here rather than at the `write_out` that consumes it, so
        // that `PQHS_ERR_NULL_POINTER` uniformly means nothing happened.
        // Discovering it after signing returns an error for a call that
        // fully succeeded, and a caller reading that as a rejection will
        // discard a perfectly good signature and sign the message again.
        if sig_written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig_out = match unsafe { borrow_slice_mut(sig_out, sig_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::sign(suite, sk, msg, ctx, &mut OsRng, sig_out) {
            Ok(n) => match unsafe { write_out(sig_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Deterministic signing for `suite`. Writes the signature into `sig_out`
/// and the number of bytes written into `*sig_written`.
///
/// Not every component honours `nonce`; see
/// `pqhybridsign::composite::sign_deterministic`'s documentation for
/// which do.
///
/// # Errors
///
/// The same as [`pqhs_sign`].
///
/// # Safety
///
/// The same as [`pqhs_sign`]; `nonce` follows the same reads-for-its-paired-
/// length contract as `sk`/`msg`/`ctx`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_sign_deterministic(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    sig_written: *mut usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // See `pqhs_sign` for why this is checked here and not at the
        // `write_out` that consumes it.
        if sig_written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let nonce = match unsafe { borrow_slice(nonce, nonce_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig_out = match unsafe { borrow_slice_mut(sig_out, sig_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::sign_deterministic(suite, sk, msg, ctx, nonce, sig_out) {
            Ok(n) => match unsafe { write_out(sig_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Verify `sig` over `msg` under `ctx` for `suite`, against `pk`. Covers all
/// six suites.
///
/// Writes `true` or `false` into `*valid_out` and returns `PQHS_OK` in both
/// cases: an invalid signature is not a call failure. A malformed `pk` or
/// `sig` simply fails to verify -- the same design every underlying verify
/// function in this workspace uses, so a caller cannot learn which
/// component or encoding rejected from a timing or error-code side channel.
///
/// `*valid_out` is set to `false` before anything else happens, so it is
/// `false` on every path that returns a code other than `PQHS_OK` as well
/// (an unknown suite, a null buffer). Ignoring the return code is the most
/// common mistake a C caller makes, and the only safe reading of
/// `*valid_out` after a call that did not verify anything is `false`. The
/// one case that cannot fail closed is a null `valid_out` itself, which is
/// rejected before any other check.
///
/// # Errors
///
/// `PQHS_ERR_INVALID_SUITE` if `suite` is not `1..=6`.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is
/// null, or if `valid_out` is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `pk`/`msg`/`ctx`/`sig`, a write for `valid_out`) for
/// exactly its paired length in bytes, and must not be aliased by another
/// live pointer for the duration of this call. A null pointer is only
/// valid when its paired length is `0`; `valid_out` has no paired length
/// and must be a valid, non-null, writable `bool` pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_verify(
    suite: u8,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
    valid_out: *mut bool,
) -> c_int {
    guard(move || {
        // `valid_out` is checked and set to `false` ahead of every other
        // check, including the suite code. A caller that ignores the return
        // code -- the common C mistake -- then reads `false` from a call
        // that verified nothing, instead of whatever it happened to
        // initialise the flag to. Failing open on a cryptographic boolean
        // is not a defensible default, however well documented.
        if valid_out.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if let Err(e) = unsafe { write_out(valid_out, false) } {
            return e;
        }
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let pk = match unsafe { borrow_slice(pk, pk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig = match unsafe { borrow_slice(sig, sig_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let valid = pqhybridsign_abi::verify(suite, pk, msg, ctx, sig);
        match unsafe { write_out(valid_out, valid) } {
            Ok(()) => PQHS_OK,
            Err(e) => e,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE;
    use crate::keygen::pqhs_keygen_from_seed;

    #[test]
    fn ed_ml44_sign_and_verify_round_trip() {
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        unsafe {
            let mut sk =
                vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::EdMl44)];
            let mut pk =
                vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdMl44)];
            let seed = [9u8; 32];
            assert_eq!(
                pqhs_keygen_from_seed(
                    1,
                    seed.as_ptr(),
                    32,
                    sk.as_mut_ptr(),
                    sk.len(),
                    pk.as_mut_ptr(),
                    pk.len()
                ),
                PQHS_OK
            );

            let msg = b"the message";
            let ctx = b"ctx";
            let mut sig =
                vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::EdMl44)];
            let mut sig_written = 0usize;
            assert_eq!(
                pqhs_sign(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    msg.as_ptr(),
                    msg.len(),
                    ctx.as_ptr(),
                    ctx.len(),
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut sig_written,
                ),
                PQHS_OK
            );

            let mut valid = false;
            assert_eq!(
                pqhs_verify(
                    1,
                    pk.as_ptr(),
                    pk.len(),
                    msg.as_ptr(),
                    msg.len(),
                    ctx.as_ptr(),
                    ctx.len(),
                    sig.as_ptr(),
                    sig_written,
                    &mut valid,
                ),
                PQHS_OK
            );
            assert!(valid);

            // A tampered message must fail to verify, not error.
            let other = b"a different message";
            let mut still_valid = true;
            assert_eq!(
                pqhs_verify(
                    1,
                    pk.as_ptr(),
                    pk.len(),
                    other.as_ptr(),
                    other.len(),
                    ctx.as_ptr(),
                    ctx.len(),
                    sig.as_ptr(),
                    sig_written,
                    &mut still_valid,
                ),
                PQHS_OK
            );
            assert!(!still_valid);
        }
    }

    #[test]
    fn sign_rejects_ed_sh_and_sr_sh() {
        let mut sig = [0u8; 4096];
        let mut n = 0usize;
        for code in [5u8, 6u8] {
            // SAFETY: `sig` is a live local buffer of the length passed.
            let rc = unsafe {
                pqhs_sign(
                    code,
                    [0u8; 64].as_ptr(),
                    64,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut n,
                )
            };
            assert_eq!(rc, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
        }
    }

    #[test]
    fn a_short_sig_out_returns_an_output_buffer_too_small_error_rather_than_panicking() {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let seed = [9u8; 32];
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_keygen_from_seed(
                1,
                seed.as_ptr(),
                32,
                sk.as_mut_ptr(),
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
            );

            let mut short_sig = [0u8; 1];
            let mut n = 0usize;
            pqhs_sign(
                1,
                sk.as_ptr(),
                sk.len(),
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                short_sig.as_mut_ptr(),
                short_sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL);
    }

    /// A null `sig_written` must be refused before anything is signed. It
    /// used to be discovered at the very end of the success path, so the
    /// caller got an error code for a call that had already produced a
    /// valid signature.
    #[test]
    fn a_null_sig_written_is_refused_before_the_signature_is_produced() {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let seed = [21u8; 32];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::EdMl44)];
        // SAFETY: every pointer below is either null with a zero length, the
        // null `sig_written` under test, or a live, correctly sized local
        // buffer for the duration of the call.
        unsafe {
            assert_eq!(
                pqhs_keygen_from_seed(
                    1,
                    seed.as_ptr(),
                    32,
                    sk.as_mut_ptr(),
                    sk.len(),
                    pk.as_mut_ptr(),
                    pk.len(),
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_sign(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    sig.as_mut_ptr(),
                    sig.len(),
                    std::ptr::null_mut(),
                ),
                PQHS_ERR_NULL_POINTER
            );
            assert_eq!(
                pqhs_sign_deterministic(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    sig.as_mut_ptr(),
                    sig.len(),
                    std::ptr::null_mut(),
                ),
                PQHS_ERR_NULL_POINTER
            );
        }
        assert!(
            sig.iter().all(|&b| b == 0),
            "nothing may be written into sig_out for a call that is refused"
        );
    }

    /// `sig_out` only needs to be *at least*
    /// [`pqhybridsign_abi::signature_len`]: a caller that allocates one
    /// scratch buffer sized for the largest of ED-ML-44 through SR-FN-512 and reuses it for
    /// every suite must not be turned away. Pins the contract for
    /// `pqhs_sign` and `pqhs_sign_deterministic` across all four suites this
    /// entry point serves: short is `PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL`,
    /// exact and oversized both succeed and report the same `sig_written`.
    #[test]
    fn sig_out_accepts_exact_or_larger_and_rejects_shorter_for_every_suite() {
        for code in 1u8..=4 {
            let sk_len =
                pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::from_code(code).unwrap());
            let pk_len =
                pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::from_code(code).unwrap());
            let needed =
                pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::from_code(code).unwrap());
            let mut sk = vec![0u8; sk_len];
            let mut pk = vec![0u8; pk_len];
            let seed = [code; 32];
            // SAFETY: every pointer below is either null with a zero length
            // or points at a live, correctly sized local buffer for the
            // duration of the call.
            unsafe {
                assert_eq!(
                    pqhs_keygen_from_seed(
                        code,
                        seed.as_ptr(),
                        32,
                        sk.as_mut_ptr(),
                        sk.len(),
                        pk.as_mut_ptr(),
                        pk.len(),
                    ),
                    PQHS_OK,
                    "suite {code}"
                );

                // Short: rejected, nothing written.
                let mut short = vec![0u8; needed - 1];
                let mut n = 0usize;
                let rc = pqhs_sign(
                    code,
                    sk.as_ptr(),
                    sk.len(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    short.as_mut_ptr(),
                    short.len(),
                    &mut n,
                );
                assert_eq!(
                    rc,
                    crate::error::PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL,
                    "suite {code} short pqhs_sign"
                );
                let rc = pqhs_sign_deterministic(
                    code,
                    sk.as_ptr(),
                    sk.len(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    b"n".as_ptr(),
                    1,
                    short.as_mut_ptr(),
                    short.len(),
                    &mut n,
                );
                assert_eq!(
                    rc,
                    crate::error::PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL,
                    "suite {code} short pqhs_sign_deterministic"
                );

                // Exact: succeeds.
                let mut exact = vec![0u8; needed];
                let mut n_exact = 0usize;
                assert_eq!(
                    pqhs_sign_deterministic(
                        code,
                        sk.as_ptr(),
                        sk.len(),
                        b"m".as_ptr(),
                        1,
                        std::ptr::null(),
                        0,
                        b"n".as_ptr(),
                        1,
                        exact.as_mut_ptr(),
                        exact.len(),
                        &mut n_exact,
                    ),
                    PQHS_OK,
                    "suite {code} exact-size sig_out"
                );

                // Oversized: succeeds, reports the same length, and does not
                // touch the tail past what it wrote.
                let mut oversized = vec![0xffu8; needed + 64];
                let mut n_oversized = 0usize;
                assert_eq!(
                    pqhs_sign_deterministic(
                        code,
                        sk.as_ptr(),
                        sk.len(),
                        b"m".as_ptr(),
                        1,
                        std::ptr::null(),
                        0,
                        b"n".as_ptr(),
                        1,
                        oversized.as_mut_ptr(),
                        oversized.len(),
                        &mut n_oversized,
                    ),
                    PQHS_OK,
                    "suite {code} oversized sig_out"
                );
                assert_eq!(n_oversized, n_exact, "suite {code} sig_written");
                assert_eq!(
                    oversized[..n_oversized],
                    exact[..n_exact],
                    "suite {code} signature bytes must not depend on buffer size"
                );
                assert!(
                    oversized[n_oversized..].iter().all(|&b| b == 0xff),
                    "suite {code} bytes past sig_written must be left untouched"
                );

                let mut valid = false;
                assert_eq!(
                    pqhs_verify(
                        code,
                        pk.as_ptr(),
                        pk.len(),
                        b"m".as_ptr(),
                        1,
                        std::ptr::null(),
                        0,
                        oversized.as_ptr(),
                        n_oversized,
                        &mut valid,
                    ),
                    PQHS_OK
                );
                assert!(valid, "suite {code} oversized-buffer signature must verify");
            }
        }
    }

    /// Every `pqhs_verify` path that does not actually verify must leave
    /// `*valid_out` `false`, so that ignoring the return code fails closed.
    #[test]
    fn verify_writes_false_on_every_path_that_verifies_nothing() {
        // An unknown suite: rejected before dispatch, so nothing was
        // verified.
        let mut valid = true;
        // SAFETY: `valid` is a live local `bool`; every other pointer is
        // null with a zero length or a short live literal.
        let rc = unsafe {
            pqhs_verify(
                99,
                b"p".as_ptr(),
                1,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                b"s".as_ptr(),
                1,
                &mut valid,
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_INVALID_SUITE);
        assert!(!valid, "an unknown suite must leave valid_out false");

        // A null buffer paired with a nonzero length: likewise.
        let mut valid = true;
        // SAFETY: as above; the null `pk` is the pointer under test and is
        // never dereferenced.
        let rc = unsafe {
            pqhs_verify(
                1,
                std::ptr::null(),
                64,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                b"s".as_ptr(),
                1,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_ERR_NULL_POINTER);
        assert!(!valid, "a null buffer must leave valid_out false");

        // A malformed but non-null public key reaches the verifier and
        // fails to verify: `PQHS_OK`, `false`, no error code.
        let mut valid = true;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify(
                1,
                [0u8; 7].as_ptr(),
                7,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                [0u8; 5].as_ptr(),
                5,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(!valid, "a wrong-length pk must fail to verify, not error");

        // A null `valid_out` is the one case that cannot fail closed, so it
        // is refused outright.
        // SAFETY: every pointer is null with a zero length or a short live
        // literal; `valid_out` is the null pointer under test.
        let rc = unsafe {
            pqhs_verify(
                1,
                b"p".as_ptr(),
                1,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                b"s".as_ptr(),
                1,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, PQHS_ERR_NULL_POINTER);
    }
}
