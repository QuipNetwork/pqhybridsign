// SPDX-License-Identifier: AGPL-3.0-or-later
//! Raw-pointer handling shared by every entry point in this crate.
//!
//! Nothing outside this module dereferences a caller-supplied pointer. Every
//! entry point converts its pointer/length pairs through the helpers here
//! before calling into [`pqhybridsign_abi`], so the rest of the crate works
//! with ordinary Rust slices and cannot forget the null check or the panic
//! guard.

use std::os::raw::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::error::{PQHS_ERR_BAD_LENGTH, PQHS_ERR_NULL_POINTER, PQHS_ERR_PANIC};

/// Borrow `len` bytes from `ptr` as `&[u8]`.
///
/// A null `ptr` with `len == 0` is read as an empty slice -- a caller
/// passing no context or no nonce need not manufacture a dangling non-null
/// pointer for it. A null `ptr` with `len > 0` is
/// [`PQHS_ERR_NULL_POINTER`], never a dereference.
///
/// A `len` above `isize::MAX` is [`PQHS_ERR_BAD_LENGTH`]. No allocation can
/// be that large, so such a length is always a caller-side arithmetic
/// mistake -- an underflowed `end - start` arriving as `(size_t)-1` is the
/// usual one -- and building a slice from it would be undefined behaviour
/// at the `from_raw_parts` call, before any length check this crate makes
/// against the suite's own sizes could run.
///
/// # Safety
///
/// The caller (across the FFI boundary) must guarantee that if `ptr` is
/// non-null, it is valid for reads of exactly `len` bytes and is not
/// mutated for the duration of this call.
pub(crate) unsafe fn borrow_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], c_int> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(PQHS_ERR_NULL_POINTER);
    }
    if len > isize::MAX as usize {
        return Err(PQHS_ERR_BAD_LENGTH);
    }
    // SAFETY: forwarded to the caller of `borrow_slice`; `ptr` is non-null,
    // `len` is nonzero, and `len` is within the `isize::MAX` bound
    // `slice::from_raw_parts` requires -- all three checked above.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Borrow `len` bytes from `ptr` as `&mut [u8]`. See [`borrow_slice`] for
/// the null/zero-length and maximum-length contract, which is identical.
///
/// # Safety
///
/// The caller must guarantee that if `ptr` is non-null, it is valid for
/// reads and writes of exactly `len` bytes, is not aliased by any other
/// pointer live for the duration of this call, and is not read by the
/// caller until this call returns.
pub(crate) unsafe fn borrow_slice_mut<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], c_int> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(PQHS_ERR_NULL_POINTER);
    }
    if len > isize::MAX as usize {
        return Err(PQHS_ERR_BAD_LENGTH);
    }
    // SAFETY: forwarded to the caller of `borrow_slice_mut`; `ptr` is
    // non-null, `len` is nonzero, and `len` is within the `isize::MAX`
    // bound `slice::from_raw_parts_mut` requires -- all three checked
    // above.
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// Whether `[a, a + a_len)` and `[b, b + b_len)` share any byte.
///
/// Used to reject an aliased `sk`/`sk_out` pair before either slice is
/// built. Comparing addresses from different allocations is well defined in
/// Rust (only pointer *arithmetic* across allocations is not), and the ends
/// saturate so a nonsense length cannot overflow here -- an over-long
/// length is separately rejected by the borrow helpers above.
///
/// A zero length occupies no bytes and so overlaps nothing.
pub(crate) fn ranges_overlap(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let a_start = a as usize;
    let b_start = b as usize;
    let a_end = a_start.saturating_add(a_len);
    let b_end = b_start.saturating_add(b_len);
    a_start < b_end && b_start < a_end
}

/// Write `value` through `ptr`.
///
/// The write is unaligned. C imposes no alignment on where a caller may
/// point a `size_t *` or a `bool *` -- `(size_t *)(buffer + 1)` and a field
/// of a `#pragma pack` struct are both ordinary C -- and an aligned write
/// through such a pointer is undefined behaviour, benign on x86-64 and a
/// fault on stricter targets. An unaligned write costs nothing where the
/// pointer happens to be aligned and is correct where it is not.
///
/// Callers must not rely on the null check here to reject a null
/// out-parameter: every entry point checks its own out-parameters up front,
/// so that a null one is refused before any work happens rather than after
/// a leaf has been spent. This check is the backstop for that.
///
/// # Errors
///
/// [`PQHS_ERR_NULL_POINTER`] if `ptr` is null: every out-parameter this
/// crate writes a single value through (a length, a validity flag) is
/// mandatory, unlike the zero-length exemption [`borrow_slice`] grants
/// buffer pointers.
///
/// # Safety
///
/// The caller must guarantee that if `ptr` is non-null, it is valid for a
/// write of one `T` and is not read by the caller until this call returns.
pub(crate) unsafe fn write_out<T>(ptr: *mut T, value: T) -> Result<(), c_int> {
    if ptr.is_null() {
        return Err(PQHS_ERR_NULL_POINTER);
    }
    // SAFETY: forwarded to the caller of `write_out`; `ptr` is non-null,
    // checked above. `write_unaligned` needs no alignment guarantee, which
    // is the one thing a C caller cannot be asked for.
    unsafe { ptr.write_unaligned(value) };
    Ok(())
}

/// Run `body`, which returns the crate's ordinary `Result<T, c_int>`
/// vocabulary, and flatten a caught panic into [`PQHS_ERR_PANIC`].
///
/// Every `#[no_mangle] extern "C"` function in this crate routes through
/// this so that a panic anywhere underneath -- in this crate, in
/// `pqhybridsign-abi`, or in one of its dependencies -- cannot unwind across
/// the language boundary, which is undefined behaviour. `pqhybridsign-abi`
/// is written not to panic, so this is a backstop, not the primary
/// contract.
pub(crate) fn guard(body: impl FnOnce() -> c_int + std::panic::UnwindSafe) -> c_int {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(PQHS_ERR_PANIC)
}

/// As [`guard`], for the handful of entry points ([`crate::pqhs_profile_name`])
/// that have no error channel to report a caught panic through. Falls back
/// to `T::default()` -- a null pointer, for the one caller this has today --
/// rather than ever unwinding across the boundary.
pub(crate) fn guard_infallible<T: Default>(body: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_with_zero_length_is_an_empty_slice_not_an_error() {
        let s = unsafe { borrow_slice(std::ptr::null(), 0) }.unwrap();
        assert!(s.is_empty());
        let m = unsafe { borrow_slice_mut(std::ptr::null_mut(), 0) }.unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn null_with_nonzero_length_is_a_null_pointer_error() {
        assert_eq!(
            unsafe { borrow_slice(std::ptr::null(), 1) },
            Err(PQHS_ERR_NULL_POINTER)
        );
        assert_eq!(
            unsafe { borrow_slice_mut(std::ptr::null_mut(), 1) },
            Err(PQHS_ERR_NULL_POINTER)
        );
    }

    /// `(size_t)-1` is the classic underflowed length computation. It must
    /// come back as a length error, not reach `from_raw_parts`, whose
    /// safety contract caps the total size at `isize::MAX`.
    #[test]
    fn a_length_above_isize_max_is_rejected_before_the_slice_is_built() {
        let byte = 0u8;
        assert_eq!(
            unsafe { borrow_slice(&byte, usize::MAX) },
            Err(PQHS_ERR_BAD_LENGTH)
        );
        assert_eq!(
            unsafe { borrow_slice(&byte, isize::MAX as usize + 1) },
            Err(PQHS_ERR_BAD_LENGTH)
        );
        let mut byte = 0u8;
        assert_eq!(
            unsafe { borrow_slice_mut(&mut byte, usize::MAX) },
            Err(PQHS_ERR_BAD_LENGTH)
        );
    }

    #[test]
    fn ranges_overlap_catches_partial_overlap_in_both_directions() {
        let buf = [0u8; 16];
        let base = buf.as_ptr();
        // Identical ranges: the in-place `sk_out == sk` case.
        assert!(ranges_overlap(base, 16, base, 16));
        // Partial overlap, second range starting inside the first, and the
        // mirror image. These are the likelier accident and the same
        // undefined behaviour as the identical case.
        assert!(ranges_overlap(base, 16, unsafe { base.add(8) }, 8));
        assert!(ranges_overlap(unsafe { base.add(8) }, 8, base, 16));
        // Adjacent but disjoint, in both orders.
        assert!(!ranges_overlap(base, 8, unsafe { base.add(8) }, 8));
        assert!(!ranges_overlap(unsafe { base.add(8) }, 8, base, 8));
        // A zero-length range occupies nothing, so it overlaps nothing.
        assert!(!ranges_overlap(base, 0, base, 16));
        assert!(!ranges_overlap(base, 16, base, 0));
        // Saturating ends: a nonsense length must not overflow the check.
        assert!(ranges_overlap(base, usize::MAX, base, 1));
    }

    #[test]
    fn write_out_rejects_a_null_pointer_and_writes_through_a_valid_one() {
        assert_eq!(
            unsafe { write_out(std::ptr::null_mut::<usize>(), 5) },
            Err(PQHS_ERR_NULL_POINTER)
        );
        let mut out = 0usize;
        assert_eq!(unsafe { write_out(&mut out, 7) }, Ok(()));
        assert_eq!(out, 7);
    }

    /// A C caller may legitimately hand back a `size_t *` that is not
    /// aligned for `size_t`. The write must land, not be undefined
    /// behaviour.
    #[test]
    fn write_out_handles_a_pointer_that_is_not_aligned_for_its_type() {
        let mut bytes = [0u8; std::mem::size_of::<usize>() * 2];
        // SAFETY: `bytes` is one allocation with room for a whole `usize`
        // starting at offset 1, and nothing else borrows it here.
        let unaligned = unsafe { bytes.as_mut_ptr().add(1) }.cast::<usize>();
        assert_eq!(unsafe { write_out(unaligned, 0x0102_0304usize) }, Ok(()));
        // SAFETY: reading back the same way it was written.
        assert_eq!(unsafe { unaligned.read_unaligned() }, 0x0102_0304usize);
    }

    #[test]
    fn a_panic_inside_guard_is_caught_and_flattened() {
        assert_eq!(guard(|| panic!("boom")), PQHS_ERR_PANIC);
    }

    #[test]
    fn guard_passes_through_an_ordinary_result() {
        assert_eq!(guard(|| 0), 0);
        assert_eq!(guard(|| 7), 7);
    }
}
