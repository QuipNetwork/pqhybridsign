// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signing and verification for the four stateless suites, H1 through H4,
//! plus [`pqhs_verify`] which covers all six.

use std::os::raw::c_int;

use rand_core::OsRng;

use crate::error::PQHS_OK;
use crate::ffi::{borrow_slice, borrow_slice_mut, guard, write_out};
use crate::suite::suite_from_code;

/// Hedged (randomized) signing for `suite`. Writes the signature into
/// `sig_out` and the number of bytes written into `*sig_written`.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H5 or H6: use
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
/// `pqhybridsign_core::composite::sign_deterministic`'s documentation for
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
/// cases: an invalid signature is not a call failure. A return code other
/// than `PQHS_OK` means the call itself could not be made (a null pointer,
/// an unknown suite) and `*valid_out` was not written. A malformed `pk` or
/// `sig` simply fails to verify -- the same design every underlying verify
/// function in this workspace uses, so a caller cannot learn which
/// component or encoding rejected from a timing or error-code side channel.
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
    fn h1_sign_and_verify_round_trip() {
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        unsafe {
            let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::H1)];
            let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::H1)];
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
            let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H1)];
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
    fn sign_rejects_h5_and_h6() {
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
    fn a_short_sig_out_returns_a_length_error_rather_than_panicking() {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::H1)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::H1)];
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
        assert_eq!(rc, crate::error::PQHS_ERR_BAD_LENGTH);
    }
}
