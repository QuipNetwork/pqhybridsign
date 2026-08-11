// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovering a [`Suite`] from the `uint8_t` a C caller passes.

use std::os::raw::c_int;

use pqhybridsign_abi::Suite;

use crate::error::code_of;

/// Parse `code` as a [`Suite`], returning this crate's error-code
/// vocabulary (not [`AbiError`](pqhybridsign_abi::AbiError)) so every
/// caller in this crate can use `?` against the same `c_int` it returns.
pub(crate) fn suite_from_code(code: u8) -> Result<Suite, c_int> {
    Suite::from_code(code).map_err(code_of)
}
