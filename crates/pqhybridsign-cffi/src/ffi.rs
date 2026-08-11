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

use crate::error::{PQHS_ERR_NULL_POINTER, PQHS_ERR_PANIC};

/// Borrow `len` bytes from `ptr` as `&[u8]`.
///
/// A null `ptr` with `len == 0` is read as an empty slice -- a caller
/// passing no context or no nonce need not manufacture a dangling non-null
/// pointer for it. A null `ptr` with `len > 0` is
/// [`PQHS_ERR_NULL_POINTER`], never a dereference.
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
    // SAFETY: forwarded to the caller of `borrow_slice`; `ptr` is non-null
    // and `len` is nonzero, checked above.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Borrow `len` bytes from `ptr` as `&mut [u8]`. See [`borrow_slice`] for
/// the null/zero-length contract, which is identical.
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
    // SAFETY: forwarded to the caller of `borrow_slice_mut`; `ptr` is
    // non-null and `len` is nonzero, checked above.
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// Write `value` through `ptr`.
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
    // checked above.
    unsafe { ptr.write(value) };
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
