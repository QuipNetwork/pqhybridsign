// SPDX-License-Identifier: AGPL-3.0-or-later
//! Buffer-sizing entry points. A caller allocates `sk_out`, `pk_out` and
//! `sig_out` from these before calling anything that writes into one.

use std::os::raw::c_int;

use crate::error::PQHS_OK;
use crate::ffi::{guard, write_out};
use crate::suite::suite_from_code;

/// Write the public key length for `suite`, in bytes, into `*out`.
///
/// For H5 and H6 this is the verify-key form: the form every function in
/// this crate that reads or writes a public key uses.
///
/// # Errors
///
/// `PQHS_ERR_INVALID_SUITE` if `suite` is not `1..=6`.
/// `PQHS_ERR_NULL_POINTER` if `out` is null.
///
/// # Safety
///
/// `out`, if non-null, must be a valid, writable `usize` pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_public_key_len(suite: u8, out: *mut usize) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match unsafe { write_out(out, pqhybridsign_abi::public_key_len(suite)) } {
            Ok(()) => PQHS_OK,
            Err(e) => e,
        }
    })
}

/// Write the secret key length for `suite`, in bytes, into `*out`.
///
/// For H5 and H6 this is the exported stateful key blob length -- the
/// composite secret key plus the leaf counter and cached verify key -- not
/// the raw component secret key length. See
/// [`pqhs_keygen_stateful_from_seed`](crate::pqhs_keygen_stateful_from_seed).
///
/// # Errors
///
/// The same as [`pqhs_public_key_len`].
///
/// # Safety
///
/// The same as [`pqhs_public_key_len`].
#[no_mangle]
pub unsafe extern "C" fn pqhs_secret_key_len(suite: u8, out: *mut usize) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match unsafe { write_out(out, pqhybridsign_abi::secret_key_len(suite)) } {
            Ok(()) => PQHS_OK,
            Err(e) => e,
        }
    })
}

/// Write the maximum signature length for `suite`, in bytes, into `*out`.
///
/// H2, H4, H5 and H6 produce variable-length signatures; this is the
/// maximum any signature under `suite` can reach, not the length any one
/// signature actually writes. Every signing function in this crate reports
/// the actual length written separately.
///
/// # Errors
///
/// The same as [`pqhs_public_key_len`].
///
/// # Safety
///
/// The same as [`pqhs_public_key_len`].
#[no_mangle]
pub unsafe extern "C" fn pqhs_signature_len(suite: u8, out: *mut usize) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match unsafe { write_out(out, pqhybridsign_abi::signature_len(suite)) } {
            Ok(()) => PQHS_OK,
            Err(e) => e,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_round_trip_for_every_suite() {
        for code in 1u8..=6 {
            let mut n = 0usize;
            unsafe {
                assert_eq!(pqhs_public_key_len(code, &mut n), PQHS_OK);
                assert!(n > 0);
                assert_eq!(pqhs_secret_key_len(code, &mut n), PQHS_OK);
                assert!(n > 0);
                assert_eq!(pqhs_signature_len(code, &mut n), PQHS_OK);
                assert!(n > 0);
            }
        }
    }

    #[test]
    fn invalid_suite_and_null_out_are_rejected() {
        let mut n = 0usize;
        unsafe {
            assert_eq!(
                pqhs_public_key_len(0, &mut n),
                crate::error::PQHS_ERR_INVALID_SUITE
            );
            assert_eq!(
                pqhs_public_key_len(1, std::ptr::null_mut()),
                crate::error::PQHS_ERR_NULL_POINTER
            );
        }
    }
}
