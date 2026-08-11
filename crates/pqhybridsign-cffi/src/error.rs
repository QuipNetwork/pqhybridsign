// SPDX-License-Identifier: AGPL-3.0-or-later
//! The integer error codes every entry point in this crate returns, and the
//! lookup this crate offers to turn one into a message.
//!
//! Codes `1..=16` are [`pqhybridsign_abi::AbiError`]'s own codes, unchanged:
//! a C caller that already branches on the numbers the ABI crate documents
//! keeps working against this crate. Codes `100` and above are this crate's
//! own vocabulary, for failures that only exist at a raw-pointer boundary
//! and that the ABI crate -- which never sees a pointer -- has no code for.

use std::ffi::c_char;
use std::os::raw::c_int;

use pqhybridsign_abi::AbiError;

/// The call completed and every output parameter is valid.
pub const PQHS_OK: c_int = 0;

/// A byte string had the wrong length. Mirrors `AbiError::BadLength`.
pub const PQHS_ERR_BAD_LENGTH: c_int = 1;
/// The application context exceeded 255 bytes. Mirrors
/// `AbiError::ContextTooLong`.
pub const PQHS_ERR_CONTEXT_TOO_LONG: c_int = 2;
/// A caller-supplied output buffer was too small. Mirrors
/// `AbiError::OutputBufferTooSmall`.
pub const PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL: c_int = 3;
/// A soft derivation junction was supplied. Mirrors
/// `AbiError::SoftJunctionRejected`.
pub const PQHS_ERR_SOFT_JUNCTION_REJECTED: c_int = 4;
/// A path-selected signature (H5/H6) carried an unknown selector. Mirrors
/// `AbiError::BadPathSelector`.
pub const PQHS_ERR_BAD_PATH_SELECTOR: c_int = 5;
/// A stateful signature's declared leaf count was out of range. Mirrors
/// `AbiError::LeafCountOutOfRange`.
pub const PQHS_ERR_LEAF_COUNT_OUT_OF_RANGE: c_int = 6;
/// Bytes remained past the length an encoding implied. Mirrors
/// `AbiError::TrailingBytes`.
pub const PQHS_ERR_TRAILING_BYTES: c_int = 7;
/// A component crate reported an internal failure. Mirrors
/// `AbiError::ComponentFailure`.
pub const PQHS_ERR_COMPONENT_FAILURE: c_int = 8;
/// A rotation payload carried an unknown rotation kind. Mirrors
/// `AbiError::BadRotationKind`.
pub const PQHS_ERR_BAD_ROTATION_KIND: c_int = 9;
/// A delta-length-encoded (H2/H4) signature's length did not fit its field.
/// Mirrors `AbiError::DeltaLengthOutOfRange`.
pub const PQHS_ERR_DELTA_LENGTH_OUT_OF_RANGE: c_int = 10;
/// H5/H6 only: the key's one-time leaf budget is spent. Permanent; rotate
/// the key. Mirrors `AbiError::LeavesExhausted`.
pub const PQHS_ERR_LEAVES_EXHAUSTED: c_int = 11;
/// H5/H6 only: the signature-randomizer grind reached its bound. Mirrors
/// `AbiError::GrindAbort`. As with the Rust API, `sk_out` is still written
/// on this error: see [`crate::pqhs_sign_stateful`].
pub const PQHS_ERR_GRIND_ABORT: c_int = 12;
/// H5/H6 only: the caller's journal callback could not durably record the
/// advancing leaf. No leaf was consumed. Mirrors `AbiError::JournalFailed`.
pub const PQHS_ERR_JOURNAL_FAILED: c_int = 13;
/// H5/H6 only: a transient or internal failure inside the signing
/// primitive. Mirrors `AbiError::SigningFailed`.
pub const PQHS_ERR_SIGNING_FAILED: c_int = 14;
/// The suite code did not name one of the six suites this crate knows
/// (`1..=6`). Mirrors `AbiError::InvalidSuite`.
pub const PQHS_ERR_INVALID_SUITE: c_int = 15;
/// The wrong entry point was called for this suite. Mirrors
/// `AbiError::WrongEntryPointForSuite`.
pub const PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE: c_int = 16;

/// A required pointer argument was null while its paired length was
/// nonzero. This crate's own code: [`pqhybridsign_abi`] never receives a
/// raw pointer, so it has no code for a null one. A null pointer paired
/// with a length of `0` is not an error -- it is read as an empty buffer.
pub const PQHS_ERR_NULL_POINTER: c_int = 100;
/// A panic unwound out of the underlying implementation and was caught at
/// this boundary instead of crossing into the caller, which would be
/// undefined behaviour. This should never happen in practice --
/// `pqhybridsign-abi` is written not to panic -- but every entry point in
/// this crate is wrapped so that if one ever does, the caller gets this
/// code instead of a crash.
pub const PQHS_ERR_PANIC: c_int = 101;

/// The stable code [`crate::pqhs_error_message`] and every other function in
/// this crate return for `error`.
pub(crate) fn code_of(error: AbiError) -> c_int {
    c_int::from(error.code())
}

/// A human-readable, `NUL`-terminated, `'static` message for `code`.
///
/// Returns a pointer to `"unknown error code"` for any value that is not a
/// code this crate can return. The returned pointer is valid for the
/// lifetime of the process and must not be freed or written through.
#[no_mangle]
pub extern "C" fn pqhs_error_message(code: c_int) -> *const c_char {
    let msg: &'static std::ffi::CStr = match code {
        PQHS_OK => c"success",
        PQHS_ERR_BAD_LENGTH => c"a byte string had the wrong length",
        PQHS_ERR_CONTEXT_TOO_LONG => c"the application context exceeded 255 bytes",
        PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL => c"the output buffer was too small",
        PQHS_ERR_SOFT_JUNCTION_REJECTED => c"soft derivation junctions are rejected",
        PQHS_ERR_BAD_PATH_SELECTOR => c"the signature carried an unknown path selector",
        PQHS_ERR_LEAF_COUNT_OUT_OF_RANGE => c"the declared leaf count was out of range",
        PQHS_ERR_TRAILING_BYTES => c"the signature carried trailing bytes",
        PQHS_ERR_COMPONENT_FAILURE => c"a component algorithm failed",
        PQHS_ERR_BAD_ROTATION_KIND => c"the rotation payload carried an unknown rotation kind",
        PQHS_ERR_DELTA_LENGTH_OUT_OF_RANGE => {
            c"the delta-encoded signature length was out of range"
        }
        PQHS_ERR_LEAVES_EXHAUSTED => c"the key's one-time leaf budget is spent; rotate the key",
        PQHS_ERR_GRIND_ABORT => c"the randomizer grind bound was reached for this key and message",
        PQHS_ERR_JOURNAL_FAILED => c"the leaf journal could not durably commit",
        PQHS_ERR_SIGNING_FAILED => c"signing failed",
        PQHS_ERR_INVALID_SUITE => c"the suite code or name is not one of H1-H6",
        PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE => c"this entry point does not accept this suite",
        PQHS_ERR_NULL_POINTER => c"a required pointer argument was null",
        PQHS_ERR_PANIC => c"an internal panic was caught at the C boundary",
        _ => c"unknown error code",
    };
    msg.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code this table hands out for `1..=16` must equal the code
    /// [`AbiError::code`] reports for the variant it mirrors, and the
    /// message text must match [`AbiError`]'s own [`std::fmt::Display`]
    /// text, so the two crates' vocabularies cannot drift apart silently.
    #[test]
    fn mirrored_codes_and_messages_match_the_abi_crate() {
        let cases = [
            (AbiError::BadLength, PQHS_ERR_BAD_LENGTH),
            (AbiError::ContextTooLong, PQHS_ERR_CONTEXT_TOO_LONG),
            (
                AbiError::OutputBufferTooSmall,
                PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL,
            ),
            (
                AbiError::SoftJunctionRejected,
                PQHS_ERR_SOFT_JUNCTION_REJECTED,
            ),
            (AbiError::BadPathSelector, PQHS_ERR_BAD_PATH_SELECTOR),
            (
                AbiError::LeafCountOutOfRange,
                PQHS_ERR_LEAF_COUNT_OUT_OF_RANGE,
            ),
            (AbiError::TrailingBytes, PQHS_ERR_TRAILING_BYTES),
            (AbiError::ComponentFailure, PQHS_ERR_COMPONENT_FAILURE),
            (AbiError::BadRotationKind, PQHS_ERR_BAD_ROTATION_KIND),
            (
                AbiError::DeltaLengthOutOfRange,
                PQHS_ERR_DELTA_LENGTH_OUT_OF_RANGE,
            ),
            (AbiError::LeavesExhausted, PQHS_ERR_LEAVES_EXHAUSTED),
            (AbiError::GrindAbort, PQHS_ERR_GRIND_ABORT),
            (AbiError::JournalFailed, PQHS_ERR_JOURNAL_FAILED),
            (AbiError::SigningFailed, PQHS_ERR_SIGNING_FAILED),
            (AbiError::InvalidSuite, PQHS_ERR_INVALID_SUITE),
            (
                AbiError::WrongEntryPointForSuite,
                PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE,
            ),
        ];
        for (err, code) in cases {
            assert_eq!(code_of(err), code, "{err}");
            let msg = unsafe { std::ffi::CStr::from_ptr(pqhs_error_message(code)) };
            assert_eq!(msg.to_str().unwrap(), err.to_string(), "{err}");
        }
    }

    #[test]
    fn ok_and_unknown_codes_have_messages() {
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(pqhs_error_message(PQHS_OK)) }
                .to_str()
                .unwrap(),
            "success"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(pqhs_error_message(9999)) }
                .to_str()
                .unwrap(),
            "unknown error code"
        );
    }
}
