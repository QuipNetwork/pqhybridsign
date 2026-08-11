// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signing for the two stateful suites, H5 and H6.
//!
//! H5 and H6 pair a classical scheme with SHRINCS, whose post-quantum half
//! spends a one-time leaf per signature (see the crate documentation).
//! [`pqhs_sign_stateful`] is the only entry point in this crate that spends
//! one, and it takes a [`PqhsLeafJournal`] -- a durable log of spent leaves
//! the caller owns -- because losing track of which leaves are spent is
//! exactly the failure this suite exists to prevent. [`pqhs_sign_stateless`]
//! uses SHRINCS's separate few-time path instead and spends nothing.

use std::os::raw::{c_int, c_void};

use pqhybridsign_abi::LeafJournal;

use crate::error::{PQHS_ERR_NULL_POINTER, PQHS_OK};
use crate::ffi::{borrow_slice, borrow_slice_mut, guard, write_out};
use crate::suite::suite_from_code;

/// A caller-owned durable log of spent one-time leaves, passed to
/// [`pqhs_sign_stateful`].
///
/// `commit` MUST NOT return until the leaf is durably recorded -- on disk,
/// in a database, wherever the caller's integration keeps this state --
/// because a crash after `commit` returns `0` but before the write reaches
/// stable storage would let a later run replay an already-spent leaf, which
/// is a total loss of the key's post-quantum security. Returning nonzero
/// from `commit` MUST mean nothing was recorded.
///
/// `ctx` is passed back unchanged to both callbacks and is never
/// dereferenced by this crate; it exists so a caller can close over its own
/// state without a second, language-specific registration mechanism.
#[repr(C)]
pub struct PqhsLeafJournal {
    /// Opaque caller state, passed unchanged to `commit` and `next_leaf`.
    pub ctx: *mut c_void,
    /// Durably record that `leaf` is consumed. Returns `0` on success, or
    /// any nonzero value to report the leaf was not recorded.
    pub commit: Option<extern "C" fn(ctx: *mut c_void, leaf: u32) -> c_int>,
    /// The next unused leaf, as last committed. `0` for a fresh journal.
    pub next_leaf: Option<extern "C" fn(ctx: *mut c_void) -> u32>,
}

/// Wraps a caller's `&PqhsLeafJournal` as a
/// [`pqhybridsign_abi::LeafJournal`]. `ctx` is an opaque caller-owned
/// pointer that this crate never dereferences, and the callbacks it is
/// passed to are plain C function calls, so this type carries no
/// thread-safety obligation of its own beyond what the single call using it
/// already has.
struct FfiJournal<'a>(&'a PqhsLeafJournal);

impl LeafJournal for FfiJournal<'_> {
    /// The callback reported failure; no further detail crosses the FFI
    /// boundary for this path (see [`PqhsLeafJournal::commit`]).
    type Error = ();

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        let commit = self.0.commit.ok_or(())?;
        if commit(self.0.ctx, leaf) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    fn next_leaf(&self) -> u32 {
        self.0.next_leaf.map_or(0, |f| f(self.0.ctx))
    }
}

/// Sign `msg` under `ctx` for `suite`, spending one leaf recorded through
/// `journal`.
///
/// `sk` is the exported secret key blob from
/// [`pqhs_keygen_stateful_from_seed`](crate::pqhs_keygen_stateful_from_seed)
/// or a previous call to this function.
///
/// **`sk_out` is written on every outcome that reaches the component
/// signer, including a failed one** (`PQHS_ERR_GRIND_ABORT` in particular is
/// raised only after the leaf is already durably committed to `journal`).
/// Writing `sk_out` unconditionally in that case keeps the caller's copy of
/// the key in step with the journal; skipping it is exactly the
/// silent-leaf-drift failure mode this entry point exists to rule out.
/// `sk_out` is not written if `sk` fails to import or if `sk_out` itself is
/// the wrong length.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4: use
/// [`pqhs_sign`](crate::pqhs_sign) or
/// [`pqhs_sign_deterministic`](crate::pqhs_sign_deterministic) instead.
/// `PQHS_ERR_BAD_LENGTH` if `sk` or `sk_out` is not exactly
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) bytes for `suite`.
/// `PQHS_ERR_LEAVES_EXHAUSTED` if the key's leaf budget is spent, checked
/// before the journal is touched. `PQHS_ERR_JOURNAL_FAILED` if `journal`
/// could not durably commit; nothing was spent. `PQHS_ERR_NULL_POINTER` if
/// `journal` is null or either of its callbacks is null, or if any buffer
/// pointer paired with a nonzero length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `sk`/`journal`/`msg`/`ctx`, writes for
/// `sk_out`/`sig_out`/`sig_written`) for exactly its paired length in
/// bytes, and must not be aliased by another live pointer for the duration
/// of this call. A null pointer is only valid when its paired length is
/// `0`; `journal`, if non-null, must point to a valid `PqhsLeafJournal`
/// whose `ctx` is a pointer its own callbacks are prepared to receive.
#[no_mangle]
pub unsafe extern "C" fn pqhs_sign_stateful(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    journal: *const PqhsLeafJournal,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk_out: *mut u8,
    sk_out_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    sig_written: *mut usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if journal.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // SAFETY: `journal` is non-null, checked above; the caller
        // guarantees it is valid for reads for the duration of this call.
        let journal_ref = unsafe { &*journal };
        if journal_ref.commit.is_none() || journal_ref.next_leaf.is_none() {
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
        let sk_out = match unsafe { borrow_slice_mut(sk_out, sk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig_out = match unsafe { borrow_slice_mut(sig_out, sig_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut ffi_journal = FfiJournal(journal_ref);
        match pqhybridsign_abi::sign_stateful(
            suite,
            sk,
            &mut ffi_journal,
            msg,
            ctx,
            sk_out,
            sig_out,
        ) {
            Ok(n) => match unsafe { write_out(sig_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Sign `msg` under `ctx` for `suite` without spending any leaf state, using
/// SHRINCS's stateless few-time path (specification section 21).
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4. `PQHS_ERR_BAD_LENGTH`
/// if `sk` is not exactly
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) bytes for `suite`.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is
/// null, or if `sig_written` is null.
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
pub unsafe extern "C" fn pqhs_sign_stateless(
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
        match pqhybridsign_abi::sign_stateless(suite, sk, msg, ctx, sig_out) {
            Ok(n) => match unsafe { write_out(sig_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PQHS_ERR_JOURNAL_FAILED;
    use crate::keygen::pqhs_keygen_stateful_from_seed;
    use std::cell::RefCell;

    thread_local! {
        static COMMITTED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    }

    extern "C" fn test_commit(_ctx: *mut c_void, leaf: u32) -> c_int {
        COMMITTED.with(|c| c.borrow_mut().push(leaf));
        0
    }

    extern "C" fn test_next_leaf(_ctx: *mut c_void) -> u32 {
        COMMITTED.with(|c| c.borrow().iter().copied().max().map_or(0, |m| m + 1))
    }

    extern "C" fn failing_commit(_ctx: *mut c_void, _leaf: u32) -> c_int {
        1
    }

    fn h5_keypair(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::H5)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::H5)];
        let seed_bytes = [seed; 32];
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_keygen_stateful_from_seed(
                5,
                seed_bytes.as_ptr(),
                32,
                4,
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
    fn h5_stateful_sign_and_verify_round_trip() {
        COMMITTED.with(|c| c.borrow_mut().clear());
        let (sk, pk) = h5_keypair(11);
        let journal = PqhsLeafJournal {
            ctx: std::ptr::null_mut(),
            commit: Some(test_commit),
            next_leaf: Some(test_next_leaf),
        };

        let msg = b"stateful message";
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert_ne!(
            sk_out, sk,
            "the exported key must advance past the spent leaf"
        );

        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            crate::sign::pqhs_verify(
                5,
                pk.as_ptr(),
                pk.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sig.as_ptr(),
                n,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);
    }

    #[test]
    fn a_failing_journal_reports_journal_failed_and_spends_nothing() {
        let (sk, _pk) = h5_keypair(12);
        let journal = PqhsLeafJournal {
            ctx: std::ptr::null_mut(),
            commit: Some(failing_commit),
            next_leaf: Some(test_next_leaf),
        };
        let msg = b"m";
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_ERR_JOURNAL_FAILED);
    }

    #[test]
    fn a_null_journal_or_null_callback_is_rejected_not_dereferenced() {
        let (sk, _pk) = h5_keypair(13);
        let msg = b"m";
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                std::ptr::null(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_NULL_POINTER);

        let half_journal = PqhsLeafJournal {
            ctx: std::ptr::null_mut(),
            commit: Some(test_commit),
            next_leaf: None,
        };
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &half_journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_NULL_POINTER);
    }

    #[test]
    fn h5_stateless_signing_spends_no_leaf_and_can_repeat() {
        let (sk, pk) = h5_keypair(14);
        let msg = b"few-time message";
        let mut sig_a = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut sig_b = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n_a = 0usize;
        let mut n_b = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        unsafe {
            assert_eq!(
                pqhs_sign_stateless(
                    5,
                    sk.as_ptr(),
                    sk.len(),
                    msg.as_ptr(),
                    msg.len(),
                    std::ptr::null(),
                    0,
                    sig_a.as_mut_ptr(),
                    sig_a.len(),
                    &mut n_a,
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_sign_stateless(
                    5,
                    sk.as_ptr(),
                    sk.len(),
                    msg.as_ptr(),
                    msg.len(),
                    std::ptr::null(),
                    0,
                    sig_b.as_mut_ptr(),
                    sig_b.len(),
                    &mut n_b,
                ),
                PQHS_OK
            );
            let mut valid = false;
            crate::sign::pqhs_verify(
                5,
                pk.as_ptr(),
                pk.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sig_a.as_ptr(),
                n_a,
                &mut valid,
            );
            assert!(valid);
        }
    }

    #[test]
    fn stateful_entry_points_reject_h1_through_h4() {
        let journal = PqhsLeafJournal {
            ctx: std::ptr::null_mut(),
            commit: Some(test_commit),
            next_leaf: Some(test_next_leaf),
        };
        let mut buf = [0u8; 4096];
        let mut buf2 = [0u8; 4096];
        let mut n = 0usize;
        for code in 1u8..=4 {
            // SAFETY: every pointer below is either null with a zero length
            // or points at a live, correctly sized local buffer for the
            // duration of the call.
            let rc = unsafe {
                pqhs_sign_stateful(
                    code,
                    buf.as_ptr(),
                    4096,
                    &journal,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    buf2.as_mut_ptr(),
                    4096,
                    buf.as_mut_ptr(),
                    4096,
                    &mut n,
                )
            };
            assert_eq!(rc, crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateless(
                    code,
                    buf.as_ptr(),
                    4096,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    buf2.as_mut_ptr(),
                    4096,
                    &mut n,
                )
            };
            assert_eq!(rc, crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
        }
    }
}
