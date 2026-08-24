// SPDX-License-Identifier: AGPL-3.0-or-later
//! Master seed derivation: recovery phrases and hard junctions.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use pqhybridsign_abi::{AbiError, CHAIN_CODE_LEN, MASTER_SEED_LEN};

use crate::error::{code_of, PQHS_ERR_BAD_LENGTH, PQHS_OK};
use crate::ffi::{borrow_slice, borrow_slice_mut, guard};

/// Width in bytes of a master seed, everywhere one crosses this boundary:
/// [`pqhs_master_seed_from_mnemonic`]'s `out`,
/// [`pqhs_derive_hard_junction`]'s `parent` and `out`, and
/// [`pqhs_derive_hard_junction_path`]'s `parent` and `out`.
///
/// Written as a literal for the same reason as
/// [`crate::PQHS_BUDGET_KEY_LEN`]: cbindgen copies the initialising
/// expression into the header verbatim, and a C compiler has no Rust
/// constant to expand. The assertion below keeps it in step with the
/// library.
pub const PQHS_MASTER_SEED_LEN: usize = 32;

const _: () = assert!(PQHS_MASTER_SEED_LEN == MASTER_SEED_LEN);

/// Width in bytes of a junction chain code:
/// [`pqhs_derive_hard_junction`]'s `chain_code`, and one element of the
/// flat array [`pqhs_derive_hard_junction_path`]'s `chain_codes` packs.
///
/// See [`PQHS_MASTER_SEED_LEN`] for why this is a literal rather than a
/// reference to the Rust constant it mirrors.
pub const PQHS_CHAIN_CODE_LEN: usize = 32;

const _: () = assert!(PQHS_CHAIN_CODE_LEN == CHAIN_CODE_LEN);

/// Borrow a required NUL-terminated C string as `&str`.
///
/// # Errors
///
/// [`crate::error::PQHS_ERR_NULL_POINTER`] if `ptr` is null.
/// [`crate::error::PQHS_ERR_INVALID_MNEMONIC`] if the bytes up to the
/// terminator are not valid UTF-8: not a distinct status, because a mnemonic
/// phrase is English text and bytes that are not valid UTF-8 are exactly as
/// unusable as a wrong word.
///
/// # Safety
///
/// `ptr`, if non-null, must point at a byte sequence that is valid for
/// reads up to and including its first NUL byte, for the duration of this
/// call.
unsafe fn borrow_required_c_str<'a>(ptr: *const c_char) -> Result<&'a str, c_int> {
    if ptr.is_null() {
        return Err(crate::error::PQHS_ERR_NULL_POINTER);
    }
    // SAFETY: forwarded to the caller of `borrow_required_c_str`; `ptr` is
    // non-null, checked above.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map_err(|_| code_of(AbiError::InvalidMnemonic))
}

/// Borrow an optional NUL-terminated C string as `&str`. A null `ptr` reads
/// as absent (`None`), matching
/// [`pqhybridsign_abi::master_seed_from_mnemonic`]'s treatment of a missing
/// password as the empty string -- the same null-means-absent convention
/// this crate already uses for `ctx` and `nonce` elsewhere, extended to a
/// parameter that is a C string rather than a length-paired buffer.
///
/// # Safety
///
/// Same as [`borrow_required_c_str`].
unsafe fn borrow_optional_c_str<'a>(ptr: *const c_char) -> Result<Option<&'a str>, c_int> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: as `borrow_required_c_str`.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map(Some)
        .map_err(|_| code_of(AbiError::InvalidMnemonic))
}

/// Borrow `slice` as a reference to a `PQHS_MASTER_SEED_LEN`- or
/// `PQHS_CHAIN_CODE_LEN`-byte array, whichever `N` is, rejecting any other
/// length. Shared by every function below that takes a fixed-width seed or
/// chain code.
fn exact<const N: usize>(slice: &[u8]) -> Result<&[u8; N], c_int> {
    slice.try_into().map_err(|_| PQHS_ERR_BAD_LENGTH)
}

/// Borrow `slice` as a mutable reference to an `N`-byte array. See [`exact`].
fn exact_mut<const N: usize>(slice: &mut [u8]) -> Result<&mut [u8; N], c_int> {
    slice.try_into().map_err(|_| PQHS_ERR_BAD_LENGTH)
}

/// Turn an English BIP39 recovery phrase into a `PQHS_MASTER_SEED_LEN`-byte
/// master seed.
///
/// This is Substrate's seed derivation, not standard BIP39: PBKDF2-HMAC-
/// SHA512 runs over the mnemonic's **entropy**, not over the phrase text,
/// salted with `"mnemonic" || password`, for 2048 rounds, and the first
/// `PQHS_MASTER_SEED_LEN` bytes are the master seed. A caller that
/// reproduces this with a stock BIP39 library gets a different seed and
/// therefore a different key.
///
/// `phrase` is a required NUL-terminated C string. `password` is optional:
/// a null `password` is the empty string, matching Substrate's
/// `Pair::from_phrase`.
///
/// `out` holds secret material. Wipe it when finished.
///
/// # Errors
///
/// `PQHS_ERR_INVALID_MNEMONIC` if `phrase` is not valid UTF-8, or is not a
/// valid English BIP39 mnemonic: a wrong word count, an unknown word, or a
/// bad checksum. `PQHS_ERR_INVALID_MNEMONIC` also if `password` is
/// non-null and not valid UTF-8. None of these are distinguished, because
/// telling an attacker which part of a guessed phrase was wrong narrows the
/// search. `PQHS_ERR_BAD_LENGTH` if `out_len` is not
/// `PQHS_MASTER_SEED_LEN`. `PQHS_ERR_NULL_POINTER` if `phrase` is null, or
/// if `out` is null while `out_len` is nonzero.
///
/// # Safety
///
/// `phrase` and `password`, if non-null, must each point at a byte sequence
/// valid for reads up to and including its first NUL byte, for the
/// duration of this call. `out`, if non-null, must be valid for a write of
/// exactly `out_len` bytes for the duration of this call, and must not be
/// aliased by another live pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_master_seed_from_mnemonic(
    phrase: *const c_char,
    password: *const c_char,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    guard(move || {
        let phrase = match unsafe { borrow_required_c_str(phrase) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let password = match unsafe { borrow_optional_c_str(password) } {
            Ok(p) => p,
            Err(e) => return e,
        };
        let out = match unsafe { borrow_slice_mut(out, out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match exact_mut::<MASTER_SEED_LEN>(out) {
            Ok(a) => a,
            Err(e) => return e,
        };
        match pqhybridsign_abi::master_seed_from_mnemonic(phrase, password, out) {
            Ok(()) => PQHS_OK,
            Err(e) => code_of(e),
        }
    })
}

/// Derive a hard-junction child master seed.
///
/// `[a, b]` applied through [`pqhs_derive_hard_junction_path`] means
/// `pqhs_derive_hard_junction(pqhs_derive_hard_junction(parent, a), b)`.
/// Order is part of the derivation.
///
/// # The re-keygen hazard
///
/// Derivation is deterministic, so the same parent and the same chain code
/// reach the same child seed on every host that computes it, and therefore
/// the same stateful tree starting at leaf 1. Deriving one child twice on
/// two hosts is the same failure as importing one key twice: both hosts
/// spend leaf 1, and the post-quantum security of that key is gone.
///
/// A derived child must be derived once, then persisted and restored
/// through the validating import path. A key pool spanning several nodes
/// must give each node its own distinct junction. Never re-derive one
/// junction on a second host.
///
/// `out` holds secret material. Wipe it when finished.
///
/// # Errors
///
/// `PQHS_ERR_BAD_LENGTH` if `parent_len` is not `PQHS_MASTER_SEED_LEN`, if
/// `chain_code_len` is not `PQHS_CHAIN_CODE_LEN`, or if `out_len` is not
/// `PQHS_MASTER_SEED_LEN`. `PQHS_ERR_COMPONENT_FAILURE` if the key
/// derivation function fails. `PQHS_ERR_NULL_POINTER` if a pointer paired
/// with a nonzero length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `parent`/`chain_code`, a write for `out`) for exactly
/// its paired length in bytes, and must not be aliased by another live
/// pointer for the duration of this call. A null pointer is only valid
/// when its paired length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_derive_hard_junction(
    parent: *const u8,
    parent_len: usize,
    chain_code: *const u8,
    chain_code_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    guard(move || {
        let parent = match unsafe { borrow_slice(parent, parent_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let parent = match exact::<MASTER_SEED_LEN>(parent) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let chain_code = match unsafe { borrow_slice(chain_code, chain_code_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let chain_code = match exact::<CHAIN_CODE_LEN>(chain_code) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let out = match unsafe { borrow_slice_mut(out, out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match exact_mut::<MASTER_SEED_LEN>(out) {
            Ok(a) => a,
            Err(e) => return e,
        };
        match pqhybridsign_abi::derive_hard_junction(parent, chain_code, out) {
            Ok(()) => PQHS_OK,
            Err(e) => code_of(e),
        }
    })
}

/// Apply a sequence of chain codes in order, each child becoming the next
/// parent. `chain_codes` is a flat array of `chain_codes_len /
/// PQHS_CHAIN_CODE_LEN` codes, each `PQHS_CHAIN_CODE_LEN` bytes,
/// concatenated -- a C caller has no way to pass a slice of arrays, so the
/// boundary is one buffer and its total length.
///
/// See [`pqhs_derive_hard_junction`] for the re-keygen hazard, which
/// applies to every seed this function returns.
///
/// # The empty-path trap
///
/// **A `chain_codes_len` of `0` returns `parent` unchanged, and this
/// succeeds -- it is not an error.** That is the identity a path of no
/// junctions should have, and it is a trap for a caller building the path
/// from parsed input: a parse that silently yielded no junctions hands back
/// the parent key rather than failing. A caller that requires at least one
/// junction must check for that itself, before calling this function.
///
/// `out` holds secret material. Wipe it when finished.
///
/// # Errors
///
/// `PQHS_ERR_BAD_LENGTH` if `parent_len` is not `PQHS_MASTER_SEED_LEN`, if
/// `chain_codes_len` is not a multiple of `PQHS_CHAIN_CODE_LEN`, or if
/// `out_len` is not `PQHS_MASTER_SEED_LEN`. `PQHS_ERR_COMPONENT_FAILURE` if
/// the key derivation function fails. `PQHS_ERR_NULL_POINTER` if a pointer
/// paired with a nonzero length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `parent`/`chain_codes`, a write for `out`) for exactly
/// its paired length in bytes, and must not be aliased by another live
/// pointer for the duration of this call. A null pointer is only valid
/// when its paired length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_derive_hard_junction_path(
    parent: *const u8,
    parent_len: usize,
    chain_codes: *const u8,
    chain_codes_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    guard(move || {
        let parent = match unsafe { borrow_slice(parent, parent_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let parent = match exact::<MASTER_SEED_LEN>(parent) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let chain_codes = match unsafe { borrow_slice(chain_codes, chain_codes_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        if chain_codes.len() % CHAIN_CODE_LEN != 0 {
            return PQHS_ERR_BAD_LENGTH;
        }
        // A C caller cannot hand this crate a `&[[u8; CHAIN_CODE_LEN]]`
        // directly, so the flat buffer is split into owned, exact-width
        // copies here. The length check above guarantees the trailing
        // remainder `as_chunks` reports is always empty.
        let (whole_chain_codes, _remainder) = chain_codes.as_chunks::<CHAIN_CODE_LEN>();
        let chain_codes: Vec<[u8; CHAIN_CODE_LEN]> = whole_chain_codes.to_vec();
        let out = match unsafe { borrow_slice_mut(out, out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match exact_mut::<MASTER_SEED_LEN>(out) {
            Ok(a) => a,
            Err(e) => return e,
        };
        match pqhybridsign_abi::derive_hard_junction_path(parent, &chain_codes, out) {
            Ok(()) => PQHS_OK,
            Err(e) => code_of(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PQHS_ERR_NULL_POINTER;
    use std::ffi::CString;

    // The standard all-zero-entropy BIP39 test vector.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about";

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn a_valid_phrase_produces_the_same_seed_the_abi_produces() {
        let phrase = cstr(PHRASE);
        let mut seed = [0u8; MASTER_SEED_LEN];
        // SAFETY: `phrase.as_ptr()` is a live, NUL-terminated C string for
        // the duration of this call; `password` is null with no paired
        // length; `seed` is a live local buffer of exactly `MASTER_SEED_LEN`
        // bytes.
        let rc = unsafe {
            pqhs_master_seed_from_mnemonic(
                phrase.as_ptr(),
                std::ptr::null(),
                seed.as_mut_ptr(),
                seed.len(),
            )
        };
        assert_eq!(rc, PQHS_OK);

        let mut reference = [0u8; MASTER_SEED_LEN];
        pqhybridsign_abi::master_seed_from_mnemonic(PHRASE, None, &mut reference).unwrap();
        assert_eq!(seed, reference);
    }

    #[test]
    fn an_invalid_phrase_is_refused() {
        let phrase = cstr("not a mnemonic at all");
        let mut seed = [0u8; MASTER_SEED_LEN];
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_master_seed_from_mnemonic(
                phrase.as_ptr(),
                std::ptr::null(),
                seed.as_mut_ptr(),
                seed.len(),
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_INVALID_MNEMONIC);
    }

    #[test]
    fn a_non_utf8_phrase_is_refused() {
        // Not `main.c`-style: built directly from bytes, since a valid BIP39
        // phrase is ASCII and cannot exercise this path.
        let bytes = [b'a', b'b', 0xff, 0x00];
        let mut seed = [0u8; MASTER_SEED_LEN];
        // SAFETY: `bytes` is a live, NUL-terminated byte buffer (the last
        // byte is `0x00`) for the duration of this call; `seed` is a live
        // local buffer of exactly `MASTER_SEED_LEN` bytes.
        let rc = unsafe {
            pqhs_master_seed_from_mnemonic(
                bytes.as_ptr().cast(),
                std::ptr::null(),
                seed.as_mut_ptr(),
                seed.len(),
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_INVALID_MNEMONIC);
    }

    #[test]
    fn a_null_password_is_the_empty_string() {
        let phrase = cstr(PHRASE);
        let empty_password = cstr("");
        let mut with_null = [0u8; MASTER_SEED_LEN];
        let mut with_empty = [0u8; MASTER_SEED_LEN];
        // SAFETY: every pointer is either a live, NUL-terminated C string
        // for the duration of the call, or null with no paired length; the
        // seed buffers are live local buffers of exactly `MASTER_SEED_LEN`
        // bytes.
        unsafe {
            assert_eq!(
                pqhs_master_seed_from_mnemonic(
                    phrase.as_ptr(),
                    std::ptr::null(),
                    with_null.as_mut_ptr(),
                    with_null.len(),
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_master_seed_from_mnemonic(
                    phrase.as_ptr(),
                    empty_password.as_ptr(),
                    with_empty.as_mut_ptr(),
                    with_empty.len(),
                ),
                PQHS_OK
            );
        }
        assert_eq!(with_null, with_empty);
    }

    #[test]
    fn a_null_pointer_in_every_required_position_is_refused() {
        let phrase = cstr(PHRASE);
        let mut seed = [0u8; MASTER_SEED_LEN];
        // SAFETY: every pointer is either the null pointer under test, a
        // live NUL-terminated C string, or a live local buffer, for the
        // duration of each call.
        unsafe {
            assert_eq!(
                pqhs_master_seed_from_mnemonic(
                    std::ptr::null(),
                    std::ptr::null(),
                    seed.as_mut_ptr(),
                    seed.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null phrase"
            );
            assert_eq!(
                pqhs_master_seed_from_mnemonic(
                    phrase.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    seed.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null out with a nonzero out_len"
            );

            let parent = [1u8; MASTER_SEED_LEN];
            let chain_code = [2u8; CHAIN_CODE_LEN];
            let mut out = [0u8; MASTER_SEED_LEN];
            assert_eq!(
                pqhs_derive_hard_junction(
                    std::ptr::null(),
                    MASTER_SEED_LEN,
                    chain_code.as_ptr(),
                    chain_code.len(),
                    out.as_mut_ptr(),
                    out.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null parent"
            );
            assert_eq!(
                pqhs_derive_hard_junction(
                    parent.as_ptr(),
                    parent.len(),
                    std::ptr::null(),
                    CHAIN_CODE_LEN,
                    out.as_mut_ptr(),
                    out.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null chain_code"
            );
            assert_eq!(
                pqhs_derive_hard_junction(
                    parent.as_ptr(),
                    parent.len(),
                    chain_code.as_ptr(),
                    chain_code.len(),
                    std::ptr::null_mut(),
                    MASTER_SEED_LEN,
                ),
                PQHS_ERR_NULL_POINTER,
                "null out"
            );
            assert_eq!(
                pqhs_derive_hard_junction_path(
                    std::ptr::null(),
                    MASTER_SEED_LEN,
                    chain_code.as_ptr(),
                    chain_code.len(),
                    out.as_mut_ptr(),
                    out.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null parent (path)"
            );
            assert_eq!(
                pqhs_derive_hard_junction_path(
                    parent.as_ptr(),
                    parent.len(),
                    std::ptr::null(),
                    CHAIN_CODE_LEN,
                    out.as_mut_ptr(),
                    out.len(),
                ),
                PQHS_ERR_NULL_POINTER,
                "null chain_codes"
            );
            assert_eq!(
                pqhs_derive_hard_junction_path(
                    parent.as_ptr(),
                    parent.len(),
                    chain_code.as_ptr(),
                    chain_code.len(),
                    std::ptr::null_mut(),
                    MASTER_SEED_LEN,
                ),
                PQHS_ERR_NULL_POINTER,
                "null out (path)"
            );
        }
    }

    #[test]
    fn a_junction_path_of_the_wrong_length_is_refused() {
        let parent = [3u8; MASTER_SEED_LEN];
        let mut out = [0u8; MASTER_SEED_LEN];
        let not_a_multiple = [7u8; CHAIN_CODE_LEN + 1];
        // SAFETY: every pointer is a live local buffer for the duration of
        // this call.
        let rc = unsafe {
            pqhs_derive_hard_junction_path(
                parent.as_ptr(),
                parent.len(),
                not_a_multiple.as_ptr(),
                not_a_multiple.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, PQHS_ERR_BAD_LENGTH);
    }

    #[test]
    fn an_empty_path_returns_the_parent_unchanged() {
        let parent = [3u8; MASTER_SEED_LEN];
        let mut out = [0u8; MASTER_SEED_LEN];
        // SAFETY: every pointer is either a live local buffer or null with
        // a zero paired length, for the duration of this call.
        let rc = unsafe {
            pqhs_derive_hard_junction_path(
                parent.as_ptr(),
                parent.len(),
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert_eq!(out, parent);
    }

    #[test]
    fn a_path_applies_its_chain_codes_in_order() {
        let parent = [3u8; MASTER_SEED_LEN];
        let first = [1u8; CHAIN_CODE_LEN];
        let second = [2u8; CHAIN_CODE_LEN];
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&first);
        concatenated.extend_from_slice(&second);

        let mut stepwise = [0u8; MASTER_SEED_LEN];
        let mut path = [0u8; MASTER_SEED_LEN];
        // SAFETY: every pointer is a live local buffer for the duration of
        // each call.
        unsafe {
            assert_eq!(
                pqhs_derive_hard_junction(
                    parent.as_ptr(),
                    parent.len(),
                    first.as_ptr(),
                    first.len(),
                    stepwise.as_mut_ptr(),
                    stepwise.len(),
                ),
                PQHS_OK
            );
            let intermediate = stepwise;
            assert_eq!(
                pqhs_derive_hard_junction(
                    intermediate.as_ptr(),
                    intermediate.len(),
                    second.as_ptr(),
                    second.len(),
                    stepwise.as_mut_ptr(),
                    stepwise.len(),
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_derive_hard_junction_path(
                    parent.as_ptr(),
                    parent.len(),
                    concatenated.as_ptr(),
                    concatenated.len(),
                    path.as_mut_ptr(),
                    path.len(),
                ),
                PQHS_OK
            );
        }
        assert_eq!(stepwise, path);
    }
}
