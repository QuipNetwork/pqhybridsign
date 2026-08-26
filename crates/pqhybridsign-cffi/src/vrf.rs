// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hybrid verifiable random function, spanning all six suites.

use std::os::raw::c_int;

use rand_core::OsRng;

use pqhybridsign_abi::{VrfStatelessKey, VRF_OUTPUT_LEN};

use crate::error::{code_of, PQHS_ERR_BAD_LENGTH, PQHS_ERR_NULL_POINTER, PQHS_OK};
use crate::ffi::{borrow_slice, borrow_slice_mut, guard, guard_infallible, write_out};
use crate::stateful::{FfiBudget, PqhsStatelessBudget};
use crate::suite::suite_from_code;

/// Width in bytes of the output [`pqhs_vrf_make_bytes`] writes.
///
/// See [`crate::PQHS_BUDGET_KEY_LEN`] for why this is a literal rather than
/// a reference to the Rust constant it mirrors.
pub const PQHS_VRF_OUTPUT_LEN: usize = 32;

const _: () = assert!(PQHS_VRF_OUTPUT_LEN == VRF_OUTPUT_LEN);

/// Write the hybrid VRF proof length for `suite`, in bytes, into `*out`.
///
/// For ED-ML-44 and SR-ML-44 this is exact. For ED-FN-512 and SR-FN-512 this is the maximum a
/// delta-length binding can occupy. For ED-SH and SR-SH this is exact.
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
pub unsafe extern "C" fn pqhs_vrf_proof_len(suite: u8, out: *mut usize) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::vrf_proof_len(suite) {
            Ok(n) => match unsafe { write_out(out, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => code_of(e),
        }
    })
}

/// Evaluate the hybrid VRF for `suite`, hedged with the process's secure
/// random source. Writes the proof into `proof_out` and the number of bytes
/// written into `*proof_written`.
///
/// ED-ML-44 through SR-FN-512 only. ED-SH and SR-SH spend one unit of a few-time stateless
/// budget on every evaluation and need a durable store to record it, so
/// they prove through [`pqhs_vrf_prove_stateless`] instead, on the same terms
/// [`crate::pqhs_sign`] refuses them: a call that looks free and is not is
/// the worst failure mode this crate could offer.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for ED-SH or SR-SH: use
/// [`pqhs_vrf_prove_stateless`] instead. `PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL` if
/// `proof_out` is smaller than [`pqhs_vrf_proof_len`] needs for this input.
/// `PQHS_ERR_BAD_LENGTH` if `sk` is not the suite's secret-key length.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is
/// null, or if `proof_written` is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `sk`/`input`, writes for `proof_out`/`proof_written`)
/// for exactly its paired length in bytes, and must not be aliased by
/// another live pointer for the duration of this call. A null pointer is
/// only valid when its paired length is `0`; `proof_written` has no paired
/// length and must be a valid, non-null, writable `usize` pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_vrf_prove(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    input: *const u8,
    input_len: usize,
    proof_out: *mut u8,
    proof_out_len: usize,
    proof_written: *mut usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // Checked here rather than at the `write_out` that consumes it, so
        // that `PQHS_ERR_NULL_POINTER` uniformly means nothing happened. See
        // `pqhs_sign` for the same reasoning.
        if proof_written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let input = match unsafe { borrow_slice(input, input_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let proof_out = match unsafe { borrow_slice_mut(proof_out, proof_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::vrf_prove(suite, sk, input, &mut OsRng, proof_out) {
            Ok(n) => match unsafe { write_out(proof_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => code_of(e),
        }
    })
}

/// Evaluate the hybrid VRF for `suite` with a reproducible classical proof.
/// Writes the proof into `proof_out` and the number of bytes written into
/// `*proof_written`.
///
/// ED-ML-44 through SR-FN-512 only, on the same terms as [`pqhs_vrf_prove`]: ED-SH and SR-SH
/// spend a few-time budget unit and prove through [`pqhs_vrf_prove_stateless`].
///
/// # Errors
///
/// The same as [`pqhs_vrf_prove`].
///
/// # Safety
///
/// The same as [`pqhs_vrf_prove`].
#[no_mangle]
pub unsafe extern "C" fn pqhs_vrf_prove_deterministic(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    input: *const u8,
    input_len: usize,
    proof_out: *mut u8,
    proof_out_len: usize,
    proof_written: *mut usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if proof_written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let input = match unsafe { borrow_slice(input, input_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let proof_out = match unsafe { borrow_slice_mut(proof_out, proof_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::vrf_prove_deterministic(suite, sk, input, proof_out) {
            Ok(n) => match unsafe { write_out(proof_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => code_of(e),
        }
    })
}

/// Verify a hybrid VRF `proof` over `input` for `suite`, against `pk`.
/// Covers all six suites: verifying never spends anything, so there is
/// nothing to keep apart by statefulness.
///
/// Writes `true` or `false` into `*valid_out` and returns `PQHS_OK` in both
/// cases: an invalid proof is not a call failure. A malformed `pk` or
/// `proof` simply fails to verify, on the same terms as
/// [`crate::pqhs_verify`].
///
/// `*valid_out` is set to `false` before anything else happens, so it is
/// `false` on every path that returns a code other than `PQHS_OK` too. The
/// one case that cannot fail closed is a null `valid_out` itself, which is
/// rejected before any other check.
///
/// `proof_len` is the exact byte count [`crate::pqhs_vrf_prove`] or
/// [`crate::pqhs_vrf_prove_stateless`] wrote through `*proof_written`, not
/// the capacity of the buffer that held it. For ED-ML-44, SR-ML-44, ED-SH and SR-SH those are
/// the same number, because [`crate::pqhs_vrf_proof_len`] is exact for
/// those suites. For ED-FN-512 and SR-FN-512, [`crate::pqhs_vrf_proof_len`] reports only a
/// maximum, and passing that maximum here instead of `*proof_written`
/// verifies a proof that is not the one produced: this function fails
/// closed on it, the same as any other malformed `proof`, with no error
/// code naming the cause.
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
/// access (reads for `pk`/`input`/`proof`, a write for `valid_out`) for
/// exactly its paired length in bytes, and must not be aliased by another
/// live pointer for the duration of this call. A null pointer is only
/// valid when its paired length is `0`; `valid_out` has no paired length
/// and must be a valid, non-null, writable `bool` pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_vrf_verify(
    suite: u8,
    pk: *const u8,
    pk_len: usize,
    input: *const u8,
    input_len: usize,
    proof: *const u8,
    proof_len: usize,
    valid_out: *mut bool,
) -> c_int {
    guard(move || {
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
        let input = match unsafe { borrow_slice(input, input_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let proof = match unsafe { borrow_slice(proof, proof_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let valid = pqhybridsign_abi::vrf_verify(suite, pk, input, proof);
        match unsafe { write_out(valid_out, valid) } {
            Ok(()) => PQHS_OK,
            Err(e) => e,
        }
    })
}

/// Derive `PQHS_VRF_OUTPUT_LEN` output bytes from a verified `proof`.
///
/// **Verify the proof first**, with [`pqhs_vrf_verify`]. That is what
/// establishes that the pre-output belongs to this key and this input.
/// Deriving bytes from an unverified proof derives bytes from whatever an
/// attacker supplied, and this function performs no verification of its
/// own.
///
/// `context` separates two uses of one proof: the same proof under
/// `b"leadership"` and `b"randomness"` gives unrelated bytes, so one
/// evaluation can feed two consumers without either learning the other's
/// value early.
///
/// `proof_len` is the exact byte count [`crate::pqhs_vrf_prove`] or
/// [`crate::pqhs_vrf_prove_stateless`] wrote through `*proof_written`, not
/// the capacity of the buffer that held it, on the same terms as
/// [`pqhs_vrf_verify`]'s `proof_len`. Passing
/// [`crate::pqhs_vrf_proof_len`]'s maximum for ED-FN-512 or SR-FN-512 instead derives
/// bytes from the wrong proof.
///
/// # Errors
///
/// `PQHS_ERR_INVALID_SUITE` if `suite` is not `1..=6`.
/// `PQHS_ERR_BAD_LENGTH` if `out_len` is not `PQHS_VRF_OUTPUT_LEN`, if
/// `proof` is shorter than the proof header, or if `pk` is shorter than
/// the classical public key. `PQHS_ERR_COMPONENT_FAILURE` if `pk` or the
/// pre-output does not decode. `PQHS_ERR_NULL_POINTER` if a pointer paired
/// with a nonzero length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `pk`/`input`/`proof`/`context`, a write for `out`) for
/// exactly its paired length in bytes, and must not be aliased by another
/// live pointer for the duration of this call. A null pointer is only
/// valid when its paired length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_vrf_make_bytes(
    suite: u8,
    pk: *const u8,
    pk_len: usize,
    input: *const u8,
    input_len: usize,
    proof: *const u8,
    proof_len: usize,
    context: *const u8,
    context_len: usize,
    out: *mut u8,
    out_len: usize,
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
        let input = match unsafe { borrow_slice(input, input_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let proof = match unsafe { borrow_slice(proof, proof_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let context = match unsafe { borrow_slice(context, context_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match unsafe { borrow_slice_mut(out, out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out: &mut [u8; VRF_OUTPUT_LEN] = match out.try_into() {
            Ok(a) => a,
            Err(_) => return PQHS_ERR_BAD_LENGTH,
        };
        match pqhybridsign_abi::vrf_make_bytes(suite, pk, input, proof, context, out) {
            Ok(()) => PQHS_OK,
            Err(e) => code_of(e),
        }
    })
}

/// A SHRINCS key dedicated to VRF evaluation under ED-SH or SR-SH, held across
/// calls.
///
/// ED-SH and SR-SH evaluate the VRF through their post-quantum half's few-time
/// stateless path, which draws on a budget shared with rotation and
/// recovery. The key that carries an identity's rotation and recovery
/// authority must not also spend that budget on VRF evaluations, so this
/// handle always wraps a **separate** key: [`pqhs_vrf_key_derive`] derives
/// it from the master seed under a label disjoint from the identity key's,
/// so the two never collide.
///
/// The key lives only in memory. There is no export: a dedicated VRF key is
/// derived from the master seed when it is needed, not stored.
///
/// Not thread-safe in the general sense every opaque handle in this crate
/// is not: nothing stops two threads from calling [`pqhs_vrf_prove_stateless`]
/// against one handle concurrently, and the caller's own `budget` vtable,
/// not this handle, is what must serialise the spends that follow.
pub struct PqhsVrfKey {
    inner: VrfStatelessKey,
}

/// Derive a dedicated VRF key from `master` for `suite`, writing its public
/// key into `pk_out` and returning an opaque handle through `out`.
///
/// `master` is a `PQHS_MASTER_SEED_LEN`-byte master seed, the same one
/// [`crate::pqhs_master_seed_from_mnemonic`] or
/// [`crate::pqhs_derive_hard_junction`] produces. `pk_out` must be exactly
/// [`crate::pqhs_public_key_len`] bytes for `suite`.
///
/// **This key is not the identity key.** Deriving it under the same master
/// seed as an ED-SH/SR-SH identity key produces a different key, disjoint from
/// the identity's rotation and recovery authority, by construction of the
/// derivation label. Do not adopt an identity key here: doing so would
/// spend the identity's rotation and recovery budget on VRF evaluations.
///
/// On success, `*out` is a pointer the caller must later pass to
/// [`pqhs_vrf_key_free`]. On failure, `*out` is left untouched.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for ED-ML-44 through SR-FN-512: they have no stateful
/// half and therefore no dedicated stateless VRF key.
/// `PQHS_ERR_BAD_LENGTH` if `master_len` is not `PQHS_MASTER_SEED_LEN`, or
/// `pk_out_len` is not [`crate::pqhs_public_key_len`] for `suite`.
/// `PQHS_ERR_COMPONENT_FAILURE` if derivation fails.
/// `PQHS_ERR_NULL_POINTER` if `out` is null, or if `master` is null while
/// `master_len` is nonzero. `PQHS_ERR_INVALID_SUITE` if `suite` is not
/// `1..=6`.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `master`, writes for `pk_out` and one `*mut
/// PqhsVrfKey` for `out`) for exactly its paired length in bytes, and must
/// not be aliased by another live pointer for the duration of this call. A
/// null pointer is only valid when its paired length is `0`; `out` has no
/// paired length and must be a valid, non-null, writable `*mut PqhsVrfKey`
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_vrf_key_derive(
    suite: u8,
    master: *const u8,
    master_len: usize,
    pk_out: *mut u8,
    pk_out_len: usize,
    out: *mut *mut PqhsVrfKey,
) -> c_int {
    guard(move || {
        if out.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // Checked here, before the master or pk_out lengths are examined,
        // because the suite determines which length is even correct: a
        // length verdict on a suite this entry point does not serve tells
        // the caller nothing true. Written in terms of the suites this
        // entry point DOES serve, so a seventh suite added later is
        // refused by default rather than admitted by default.
        if !matches!(
            suite,
            pqhybridsign_abi::Suite::EdSh | pqhybridsign_abi::Suite::SrSh
        ) {
            return crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE;
        }
        let master = match unsafe { borrow_slice(master, master_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let master: &[u8; pqhybridsign_abi::MASTER_SEED_LEN] = match master.try_into() {
            Ok(a) => a,
            Err(_) => return PQHS_ERR_BAD_LENGTH,
        };
        let pk_out = match unsafe { borrow_slice_mut(pk_out, pk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        // Checked here rather than left to `VrfStatelessKey::derive`, which
        // only checks it after running a full keygen: at the 128s profiles
        // that is roughly 47 seconds, so a caller who sized `pk_out` for
        // the wrong suite would see a hang before an error, not instead of
        // one.
        if pk_out.len() != pqhybridsign_abi::public_key_len(suite) {
            return PQHS_ERR_BAD_LENGTH;
        }
        match VrfStatelessKey::derive(suite, master, pk_out) {
            Ok(inner) => {
                let raw = Box::into_raw(Box::new(PqhsVrfKey { inner }));
                // SAFETY: `out` is non-null, checked above; the caller
                // guarantees it is valid for a write of one pointer.
                match unsafe { write_out(out, raw) } {
                    Ok(()) => PQHS_OK,
                    Err(e) => {
                        // Unreachable if the null check above holds;
                        // recover the box so a future change to
                        // `write_out` cannot leak the key.
                        // SAFETY: `raw` came from `Box::into_raw` on the
                        // line above and has not been handed out.
                        drop(unsafe { Box::from_raw(raw) });
                        e
                    }
                }
            }
            Err(e) => code_of(e),
        }
    })
}

/// Release a handle previously returned by [`pqhs_vrf_key_derive`].
///
/// A null `key` is a no-op. After this call returns, `key` must not be
/// used again.
///
/// # Safety
///
/// `key` must be a pointer previously returned by [`pqhs_vrf_key_derive`]
/// that has not already been freed, or null. The pointer must not be used
/// after this call returns.
#[no_mangle]
pub unsafe extern "C" fn pqhs_vrf_key_free(key: *mut PqhsVrfKey) {
    guard_infallible(|| {
        if key.is_null() {
            return;
        }
        // SAFETY: `key` is non-null, checked above, and the caller
        // guarantees it is a pointer previously returned by
        // [`pqhs_vrf_key_derive`] that has not already been freed.
        drop(unsafe { Box::from_raw(key) });
    });
}

/// Evaluate the hybrid VRF under ED-SH or SR-SH through `key`, spending one unit
/// of the few-time stateless budget. Writes the proof into `proof_out` and
/// the number of bytes written into `*proof_written`.
///
/// [`pqhs_vrf_prove`] refuses these suites because a call that looks free
/// and is not is the worst failure mode this crate could offer. This entry
/// point takes the dedicated key and the durable store the spend needs, on
/// the same terms as [`crate::pqhs_sign_stateless`]. See
/// [`PqhsStatelessBudget`] for the durability contract the callbacks must
/// honour.
///
/// # Errors
///
/// `PQHS_ERR_STATELESS_BUDGET_EXHAUSTED` if this key's few-time budget is
/// spent; nothing was recorded and no proof was built.
/// `PQHS_ERR_BUDGET_STORE_FAILED` if `record` reported the write did not
/// become durable; nothing was recorded either.
/// `PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL` if `proof_out` is shorter than
/// [`pqhs_vrf_proof_len`] needs. `PQHS_ERR_COMPONENT_FAILURE` if a
/// component rejects the key. `PQHS_ERR_NULL_POINTER` if `key` is null, if
/// a pointer paired with a nonzero length is null, if `proof_written` is
/// null, if `budget` is null, or if either of `budget`'s callbacks is
/// null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `key`/`input`, writes for
/// `proof_out`/`proof_written`) for exactly its paired length in bytes,
/// and must not be aliased by another live pointer for the duration of
/// this call. A null pointer is only valid when its paired length is `0`;
/// `proof_written` has no paired length and must be a valid, non-null,
/// writable `usize` pointer. `key` must be a pointer previously returned
/// by [`pqhs_vrf_key_derive`] that has not been freed. `budget` must point
/// to a valid `PqhsStatelessBudget` whose `ctx` is a pointer its own
/// callbacks are prepared to receive, and whose callbacks do not call back
/// into this library.
#[no_mangle]
pub unsafe extern "C" fn pqhs_vrf_prove_stateless(
    key: *const PqhsVrfKey,
    budget: *const PqhsStatelessBudget,
    input: *const u8,
    input_len: usize,
    proof_out: *mut u8,
    proof_out_len: usize,
    proof_written: *mut usize,
) -> c_int {
    guard(move || {
        if key.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // See `pqhs_sign_stateless` for why this is checked here and not at
        // the `write_out` that consumes it.
        if proof_written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if budget.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // SAFETY: `budget` is non-null, checked above; the caller
        // guarantees it is valid for reads for the duration of this call.
        let budget_ref = unsafe { &*budget };
        // Both callbacks are checked here rather than at the point of use,
        // for the same reason `pqhs_sign_stateless` checks them up front.
        if budget_ref.consumed.is_none() || budget_ref.record.is_none() {
            return PQHS_ERR_NULL_POINTER;
        }
        let input = match unsafe { borrow_slice(input, input_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let proof_out = match unsafe { borrow_slice_mut(proof_out, proof_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut ffi_budget = FfiBudget(budget_ref);
        // SAFETY: `key` is non-null, checked above; the caller guarantees
        // it is a live handle from [`pqhs_vrf_key_derive`].
        let key_ref = unsafe { &*key };
        match pqhybridsign_abi::vrf_prove_stateless(
            &key_ref.inner,
            &mut ffi_budget,
            input,
            &mut OsRng,
            proof_out,
        ) {
            Ok(n) => match unsafe { write_out(proof_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => code_of(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE;
    use crate::keygen::pqhs_keygen_from_seed;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::os::raw::c_void;

    const INPUT: &[u8] = b"epoch-7/slot-42/randomness";
    const OTHER_INPUT: &[u8] = b"epoch-7/slot-43/randomness";
    const OUT_CTX: &[u8] = b"leadership-score";

    fn ed_ml44_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdMl44)];
        let seed = [5u8; 32];
        // SAFETY: every pointer below is a live local buffer of the length
        // passed.
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
        (sk, pk)
    }

    #[test]
    fn a_vrf_proof_verifies() {
        let (sk, pk) = ed_ml44_keypair();
        let mut proof_len = 0usize;
        // SAFETY: `proof_len` is a live local `usize`.
        assert_eq!(unsafe { pqhs_vrf_proof_len(1, &mut proof_len) }, PQHS_OK);
        let mut proof = vec![0u8; proof_len];
        let mut written = 0usize;
        // SAFETY: every pointer below is a live local buffer of the length
        // passed.
        let rc = unsafe {
            pqhs_vrf_prove(
                1,
                sk.as_ptr(),
                sk.len(),
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut written,
            )
        };
        assert_eq!(rc, PQHS_OK);

        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_vrf_verify(
                1,
                pk.as_ptr(),
                pk.len(),
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_ptr(),
                written,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);
    }

    #[test]
    fn a_tampered_vrf_proof_does_not_verify() {
        let (sk, pk) = ed_ml44_keypair();
        let mut proof_len = 0usize;
        // SAFETY: `proof_len` is a live local `usize`.
        assert_eq!(unsafe { pqhs_vrf_proof_len(1, &mut proof_len) }, PQHS_OK);
        let mut proof = vec![0u8; proof_len];
        let mut written = 0usize;
        // SAFETY: every pointer below is a live local buffer of the length
        // passed.
        let rc = unsafe {
            pqhs_vrf_prove(
                1,
                sk.as_ptr(),
                sk.len(),
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut written,
            )
        };
        assert_eq!(rc, PQHS_OK);
        proof[0] ^= 0x01;

        let mut valid = true;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_vrf_verify(
                1,
                pk.as_ptr(),
                pk.len(),
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_ptr(),
                written,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(!valid);
    }

    /// A tampered proof, and a proof checked against a different input,
    /// both fail closed. Distinct from the length-only checks
    /// `a_tampered_vrf_proof_does_not_verify` covers.
    #[test]
    fn a_proof_does_not_verify_against_another_input() {
        let (sk, pk) = ed_ml44_keypair();
        let mut proof_len = 0usize;
        // SAFETY: `proof_len` is a live local `usize`.
        assert_eq!(unsafe { pqhs_vrf_proof_len(1, &mut proof_len) }, PQHS_OK);
        let mut proof = vec![0u8; proof_len];
        let mut written = 0usize;
        // SAFETY: every pointer below is a live local buffer of the length
        // passed.
        let rc = unsafe {
            pqhs_vrf_prove(
                1,
                sk.as_ptr(),
                sk.len(),
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut written,
            )
        };
        assert_eq!(rc, PQHS_OK);

        let mut valid = true;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_vrf_verify(
                1,
                pk.as_ptr(),
                pk.len(),
                OTHER_INPUT.as_ptr(),
                OTHER_INPUT.len(),
                proof.as_ptr(),
                written,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(!valid);
    }

    #[test]
    fn make_bytes_is_stable_across_two_proofs_of_one_input() {
        let (sk, pk) = ed_ml44_keypair();
        let mut proof_len = 0usize;
        // SAFETY: `proof_len` is a live local `usize`.
        assert_eq!(unsafe { pqhs_vrf_proof_len(1, &mut proof_len) }, PQHS_OK);

        let mut a = vec![0u8; proof_len];
        let mut b = vec![0u8; proof_len];
        let mut na = 0usize;
        let mut nb = 0usize;
        // SAFETY: every pointer below is a live local buffer of the length
        // passed.
        unsafe {
            assert_eq!(
                pqhs_vrf_prove(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    a.as_mut_ptr(),
                    a.len(),
                    &mut na,
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_vrf_prove(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    b.as_mut_ptr(),
                    b.len(),
                    &mut nb,
                ),
                PQHS_OK
            );

            let mut out_a = [0u8; VRF_OUTPUT_LEN];
            let mut out_b = [0u8; VRF_OUTPUT_LEN];
            assert_eq!(
                pqhs_vrf_make_bytes(
                    1,
                    pk.as_ptr(),
                    pk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    a.as_ptr(),
                    na,
                    OUT_CTX.as_ptr(),
                    OUT_CTX.len(),
                    out_a.as_mut_ptr(),
                    out_a.len(),
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_vrf_make_bytes(
                    1,
                    pk.as_ptr(),
                    pk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    b.as_ptr(),
                    nb,
                    OUT_CTX.as_ptr(),
                    OUT_CTX.len(),
                    out_b.as_mut_ptr(),
                    out_b.len(),
                ),
                PQHS_OK
            );
            assert_eq!(out_a, out_b);
        }
    }

    #[test]
    fn a_deterministic_proof_repeats_byte_for_byte() {
        let (sk, _pk) = ed_ml44_keypair();
        let mut proof_len = 0usize;
        // SAFETY: `proof_len` is a live local `usize`.
        assert_eq!(unsafe { pqhs_vrf_proof_len(1, &mut proof_len) }, PQHS_OK);
        let mut a = vec![0u8; proof_len];
        let mut b = vec![0u8; proof_len];
        let mut na = 0usize;
        let mut nb = 0usize;
        // SAFETY: every pointer below is a live local buffer of the length
        // passed.
        unsafe {
            assert_eq!(
                pqhs_vrf_prove_deterministic(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    a.as_mut_ptr(),
                    a.len(),
                    &mut na,
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_vrf_prove_deterministic(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    b.as_mut_ptr(),
                    b.len(),
                    &mut nb,
                ),
                PQHS_OK
            );
        }
        assert_eq!(a[..na], b[..nb]);
    }

    #[test]
    fn proving_rejects_the_stateful_suites() {
        let mut proof = vec![0u8; 4096];
        let mut written = 0usize;
        for code in [5u8, 6u8] {
            // SAFETY: `proof` is a live local buffer of the length passed.
            let rc = unsafe {
                pqhs_vrf_prove(
                    code,
                    [0u8; 328].as_ptr(),
                    328,
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut written,
                )
            };
            assert_eq!(rc, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_vrf_prove_deterministic(
                    code,
                    [0u8; 328].as_ptr(),
                    328,
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut written,
                )
            };
            assert_eq!(rc, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
        }
    }

    #[test]
    fn a_null_pointer_in_every_position_is_refused() {
        let (sk, pk) = ed_ml44_keypair();
        let mut proof = vec![0u8; 4096];
        let mut written = 0usize;
        // SAFETY: every pointer is either the null pointer under test or a
        // live local buffer, for the duration of each call.
        unsafe {
            assert_eq!(
                pqhs_vrf_prove(
                    1,
                    std::ptr::null(),
                    sk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut written,
                ),
                PQHS_ERR_NULL_POINTER,
                "null sk"
            );
            assert_eq!(
                pqhs_vrf_prove(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    std::ptr::null_mut(),
                    proof.len(),
                    &mut written,
                ),
                PQHS_ERR_NULL_POINTER,
                "null proof_out"
            );
            assert_eq!(
                pqhs_vrf_prove(
                    1,
                    sk.as_ptr(),
                    sk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    std::ptr::null_mut(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null proof_written"
            );
            let mut valid = false;
            assert_eq!(
                pqhs_vrf_verify(
                    1,
                    std::ptr::null(),
                    pk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_ptr(),
                    proof.len(),
                    &mut valid,
                ),
                PQHS_ERR_NULL_POINTER,
                "null pk"
            );
            assert_eq!(
                pqhs_vrf_verify(
                    1,
                    pk.as_ptr(),
                    pk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_ptr(),
                    proof.len(),
                    std::ptr::null_mut(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null valid_out"
            );
            let mut out = [0u8; VRF_OUTPUT_LEN];
            assert_eq!(
                pqhs_vrf_make_bytes(
                    1,
                    std::ptr::null(),
                    pk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_ptr(),
                    proof.len(),
                    OUT_CTX.as_ptr(),
                    OUT_CTX.len(),
                    out.as_mut_ptr(),
                    out.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null pk in make_bytes"
            );
            assert_eq!(
                pqhs_vrf_make_bytes(
                    1,
                    pk.as_ptr(),
                    pk.len(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_ptr(),
                    proof.len(),
                    OUT_CTX.as_ptr(),
                    OUT_CTX.len(),
                    std::ptr::null_mut(),
                    out.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null out in make_bytes"
            );
            let mut vrf_pk =
                vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdSh)];
            let mut key_out: *mut PqhsVrfKey = std::ptr::null_mut();
            assert_eq!(
                pqhs_vrf_key_derive(
                    5,
                    std::ptr::null(),
                    pqhybridsign_abi::MASTER_SEED_LEN,
                    vrf_pk.as_mut_ptr(),
                    vrf_pk.len(),
                    &mut key_out,
                ),
                PQHS_ERR_NULL_POINTER,
                "null master"
            );
            assert_eq!(
                pqhs_vrf_key_derive(
                    5,
                    [7u8; 32].as_ptr(),
                    32,
                    vrf_pk.as_mut_ptr(),
                    vrf_pk.len(),
                    std::ptr::null_mut(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null out (key handle)"
            );

            // `pqhs_vrf_prove_stateless` has the most pointer parameters of
            // any entry point in this file and is the only one taking a
            // callback vtable, so its null and incomplete-vtable cases need
            // a real handle -- the checks above run before a handle would
            // ever be dereferenced, but these run after.
            BUDGET.with(|b| b.borrow_mut().clear());
            let mut real_pk =
                vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdSh)];
            let mut real_key: *mut PqhsVrfKey = std::ptr::null_mut();
            let master = [9u8; 32];
            assert_eq!(
                pqhs_vrf_key_derive(
                    5,
                    master.as_ptr(),
                    master.len(),
                    real_pk.as_mut_ptr(),
                    real_pk.len(),
                    &mut real_key,
                ),
                PQHS_OK
            );
            let budget = test_budget();
            assert_eq!(
                pqhs_vrf_prove_stateless(
                    std::ptr::null(),
                    &budget,
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut written,
                ),
                PQHS_ERR_NULL_POINTER,
                "null key (prove_stateless)"
            );
            assert_eq!(
                pqhs_vrf_prove_stateless(
                    real_key,
                    std::ptr::null(),
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut written,
                ),
                PQHS_ERR_NULL_POINTER,
                "null budget (prove_stateless)"
            );
            assert_eq!(
                pqhs_vrf_prove_stateless(
                    real_key,
                    &budget,
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    std::ptr::null_mut(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null proof_written (prove_stateless)"
            );
            let no_consumed = PqhsStatelessBudget {
                ctx: std::ptr::null_mut(),
                consumed: None,
                record: Some(test_record),
            };
            assert_eq!(
                pqhs_vrf_prove_stateless(
                    real_key,
                    &no_consumed,
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut written,
                ),
                PQHS_ERR_NULL_POINTER,
                "missing consumed callback (prove_stateless)"
            );
            let no_record = PqhsStatelessBudget {
                ctx: std::ptr::null_mut(),
                consumed: Some(test_consumed),
                record: None,
            };
            assert_eq!(
                pqhs_vrf_prove_stateless(
                    real_key,
                    &no_record,
                    INPUT.as_ptr(),
                    INPUT.len(),
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut written,
                ),
                PQHS_ERR_NULL_POINTER,
                "missing record callback (prove_stateless)"
            );
            assert!(
                BUDGET.with(|b| b.borrow().is_empty()),
                "a refused key, budget or vtable must never reach the store"
            );
            pqhs_vrf_key_free(real_key);
        }
    }

    #[test]
    fn freeing_a_null_vrf_key_is_a_no_op() {
        // SAFETY: a null pointer is documented as a no-op.
        unsafe { pqhs_vrf_key_free(std::ptr::null_mut()) };
    }

    // An in-memory `PqhsStatelessBudget` store, the C-shaped counterpart of
    // `pqhybridsign_abi::vrf`'s test `MemoryBudget`. Not durable: these
    // tests exercise whether the count is consulted, not persistence.
    thread_local! {
        static BUDGET: RefCell<HashMap<[u8; 32], u64>> = RefCell::new(HashMap::new());
    }

    extern "C" fn test_consumed(
        _ctx: *mut c_void,
        key: *const u8,
        key_len: usize,
        out_consumed: *mut u64,
    ) -> c_int {
        assert_eq!(key_len, 32);
        // SAFETY: `key` is valid for `key_len` reads and `out_consumed` for
        // one write, guaranteed by the caller of this callback.
        let bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(key, key_len) }
            .try_into()
            .unwrap();
        match BUDGET.with(|b| b.borrow().get(&bytes).copied()) {
            Some(count) => {
                unsafe { out_consumed.write(count) };
                0
            }
            None => 1,
        }
    }

    extern "C" fn test_record(
        _ctx: *mut c_void,
        key: *const u8,
        key_len: usize,
        count: u64,
    ) -> c_int {
        assert_eq!(key_len, 32);
        // SAFETY: `key` is valid for `key_len` reads, guaranteed by the
        // caller of this callback.
        let bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(key, key_len) }
            .try_into()
            .unwrap();
        BUDGET.with(|b| b.borrow_mut().insert(bytes, count));
        0
    }

    fn test_budget() -> PqhsStatelessBudget {
        PqhsStatelessBudget {
            ctx: std::ptr::null_mut(),
            consumed: Some(test_consumed),
            record: Some(test_record),
        }
    }

    // `VrfStatelessKey::derive` runs a real keygen: fast at profile-256s
    // (this workspace's default), about 47 seconds at a 128s profile.
    #[test]
    fn a_derived_vrf_key_proves_and_verifies_through_the_handle() {
        BUDGET.with(|b| b.borrow_mut().clear());
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::EdSh)];
        let mut key_out: *mut PqhsVrfKey = std::ptr::null_mut();
        let master = [13u8; 32];
        // SAFETY: every pointer below is a live local buffer of the length
        // passed.
        let rc = unsafe {
            pqhs_vrf_key_derive(
                5,
                master.as_ptr(),
                master.len(),
                pk.as_mut_ptr(),
                pk.len(),
                &mut key_out,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(!key_out.is_null());

        let mut proof_len = 0usize;
        // SAFETY: `proof_len` is a live local `usize`.
        assert_eq!(unsafe { pqhs_vrf_proof_len(5, &mut proof_len) }, PQHS_OK);
        let mut proof = vec![0u8; proof_len];
        let mut written = 0usize;
        let budget = test_budget();
        // SAFETY: `key_out` was just returned by `pqhs_vrf_key_derive`
        // above and has not been freed; every other pointer is a live
        // local buffer.
        let rc = unsafe {
            pqhs_vrf_prove_stateless(
                key_out,
                &budget,
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut written,
            )
        };
        assert_eq!(rc, PQHS_OK);
        // Spending the budget is the entire reason this entry point exists
        // rather than `pqhs_vrf_prove`: without this assertion, proving and
        // verifying can both succeed while `spend_stateless_budget` never
        // runs, and `PQHS_ERR_STATELESS_BUDGET_EXHAUSTED` becomes
        // unreachable with nothing reporting it.
        assert_eq!(
            BUDGET.with(|b| b.borrow().values().copied().sum::<u64>()),
            1,
            "the first proof must record one spend"
        );

        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_vrf_verify(
                5,
                pk.as_ptr(),
                pk.len(),
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_ptr(),
                written,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);

        // A second proof must advance the spend again, not repeat the
        // first one's count.
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_vrf_prove_stateless(
                key_out,
                &budget,
                INPUT.as_ptr(),
                INPUT.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut written,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert_eq!(
            BUDGET.with(|b| b.borrow().values().copied().sum::<u64>()),
            2,
            "the second proof must advance the recorded spend"
        );

        // SAFETY: `key_out` has not been freed before this call.
        unsafe { pqhs_vrf_key_free(key_out) };
    }

    #[test]
    fn the_vrf_key_handle_rejects_the_lattice_suites() {
        for code in 1u8..=4 {
            let mut pk = vec![
                0u8;
                pqhybridsign_abi::public_key_len(
                    pqhybridsign_abi::Suite::from_code(code).unwrap(),
                )
            ];
            let mut key_out: *mut PqhsVrfKey = std::ptr::null_mut();
            let master = [7u8; 32];
            // SAFETY: every pointer below is a live local buffer of the
            // length passed.
            let rc = unsafe {
                pqhs_vrf_key_derive(
                    code,
                    master.as_ptr(),
                    master.len(),
                    pk.as_mut_ptr(),
                    pk.len(),
                    &mut key_out,
                )
            };
            assert_eq!(rc, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE, "suite {code}");
            assert!(key_out.is_null(), "suite {code} left *out untouched");
        }
    }

    #[test]
    fn the_vrf_key_handle_rejects_the_lattice_suites_before_judging_the_buffer() {
        for code in 1u8..=4 {
            // The buffer is deliberately 3 bytes, a length no suite uses.
            // A correctly sized buffer does NOT discriminate this case:
            // `the_vrf_key_handle_rejects_the_lattice_suites` above uses
            // `public_key_len(suite)` and passes whether the suite gate
            // runs before or after the length check, because the gate
            // rejects ED-ML-44 through SR-FN-512 either way. Only a buffer wrong for every
            // suite proves the gate itself runs first -- if the gate
            // moved below the length check, this buffer's length would
            // trip `PQHS_ERR_BAD_LENGTH` instead, and the assertion below
            // would fail.
            let mut pk = vec![0u8; 3];
            let mut key_out: *mut PqhsVrfKey = std::ptr::null_mut();
            let master = [7u8; 32];
            // SAFETY: every pointer below is a live local buffer of the
            // length passed.
            let rc = unsafe {
                pqhs_vrf_key_derive(
                    code,
                    master.as_ptr(),
                    master.len(),
                    pk.as_mut_ptr(),
                    pk.len(),
                    &mut key_out,
                )
            };
            assert_eq!(rc, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE, "suite {code}");
            assert!(key_out.is_null(), "suite {code} left *out untouched");
        }
    }
}
