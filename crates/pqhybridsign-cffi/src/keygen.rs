// SPDX-License-Identifier: AGPL-3.0-or-later
//! Keypair derivation for both the stateless (ED-ML-44 through SR-FN-512) and stateful (ED-SH, SR-SH)
//! suites.

use std::os::raw::c_int;

use crate::error::PQHS_OK;
use crate::ffi::{borrow_slice, borrow_slice_mut, guard};
use crate::suite::suite_from_code;

/// Derive a stateless (ED-ML-44 through SR-FN-512) keypair for `suite` from a 32-byte master
/// `seed`.
///
/// `sk_out` and `pk_out` must be exactly
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) and
/// [`pqhs_public_key_len`](crate::pqhs_public_key_len) bytes for `suite`.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for ED-SH or SR-SH: use
/// [`pqhs_keygen_stateful_from_seed`](crate::pqhs_keygen_stateful_from_seed)
/// instead. `PQHS_ERR_BAD_LENGTH` if `seed` is not 32 bytes, or `sk_out`/
/// `pk_out` are not exactly the suite's key lengths.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is
/// null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `seed`, writes for `sk_out`/`pk_out`) for exactly its
/// paired length in bytes, and must not be aliased by another live pointer
/// for the duration of this call. A null pointer is only valid when its
/// paired length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_keygen_from_seed(
    suite: u8,
    seed: *const u8,
    seed_len: usize,
    sk_out: *mut u8,
    sk_out_len: usize,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let seed = match unsafe { borrow_slice(seed, seed_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sk_out = match unsafe { borrow_slice_mut(sk_out, sk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let pk_out = match unsafe { borrow_slice_mut(pk_out, pk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::keygen_from_seed(suite, seed, sk_out, pk_out) {
            Ok(()) => PQHS_OK,
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Derive a stateful (ED-SH, SR-SH) keypair for `suite` from a 32-byte master
/// `seed`, giving it a budget of `max_stateful_signatures` one-time leaves.
///
/// `sk_out` and `pk_out` must be exactly
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) and
/// [`pqhs_public_key_len`](crate::pqhs_public_key_len) bytes for `suite`.
/// `sk_out` is the exported secret key blob every stateful signing entry
/// point in this crate expects back: it carries the leaf counter and cached
/// verify key, both required to resume signing correctly. It is not the raw
/// component secret key.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for ED-ML-44 through SR-FN-512: use
/// [`pqhs_keygen_from_seed`](crate::pqhs_keygen_from_seed) instead.
/// `PQHS_ERR_BAD_LENGTH` if `seed` is not 32 bytes, or `sk_out`/`pk_out` are
/// not exactly the suite's key lengths. `PQHS_ERR_COMPONENT_FAILURE` if
/// `max_stateful_signatures` is zero or exceeds the component's leaf
/// capacity limit. `PQHS_ERR_NULL_POINTER` if a pointer paired with a
/// nonzero length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `seed`, writes for `sk_out`/`pk_out`) for exactly its
/// paired length in bytes, and must not be aliased by another live pointer
/// for the duration of this call. A null pointer is only valid when its
/// paired length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_keygen_stateful_from_seed(
    suite: u8,
    seed: *const u8,
    seed_len: usize,
    max_stateful_signatures: u32,
    sk_out: *mut u8,
    sk_out_len: usize,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let seed = match unsafe { borrow_slice(seed, seed_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sk_out = match unsafe { borrow_slice_mut(sk_out, sk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let pk_out = match unsafe { borrow_slice_mut(pk_out, pk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::keygen_stateful_from_seed(
            suite,
            seed,
            max_stateful_signatures,
            sk_out,
            pk_out,
        ) {
            Ok(()) => PQHS_OK,
            Err(e) => crate::error::code_of(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{PQHS_ERR_BAD_LENGTH, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE};

    #[test]
    fn ed_ml44_keygen_round_trips() {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let seed = [7u8; 32];
        let rc = unsafe {
            pqhs_keygen_from_seed(
                1,
                seed.as_ptr(),
                32,
                sk.as_mut_ptr(),
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(sk.iter().any(|&b| b != 0));
    }

    #[test]
    fn ed_ml44_rejects_a_seed_of_the_wrong_length() {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let seed = [7u8; 31];
        let rc = unsafe {
            pqhs_keygen_from_seed(
                1,
                seed.as_ptr(),
                31,
                sk.as_mut_ptr(),
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
            )
        };
        assert_eq!(rc, PQHS_ERR_BAD_LENGTH);
    }

    #[test]
    fn ed_sh_rejects_the_stateless_entry_point() {
        let seed = [1u8; 32];
        let mut sk = [0u8; 4096];
        let mut pk = [0u8; 4096];
        let rc = unsafe {
            pqhs_keygen_from_seed(
                5,
                seed.as_ptr(),
                32,
                sk.as_mut_ptr(),
                4096,
                pk.as_mut_ptr(),
                4096,
            )
        };
        assert_eq!(rc, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
    }

    #[test]
    fn ed_sh_stateful_keygen_round_trips() {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::EdSh)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdSh)];
        let seed = [3u8; 32];
        let rc = unsafe {
            pqhs_keygen_stateful_from_seed(
                5,
                seed.as_ptr(),
                32,
                4,
                sk.as_mut_ptr(),
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
            )
        };
        assert_eq!(rc, PQHS_OK);
    }
}
