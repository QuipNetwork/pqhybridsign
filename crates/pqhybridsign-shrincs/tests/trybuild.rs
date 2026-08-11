// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compile-fail guarantees for the H5/H6 stateful secret key.
//!
//! Each case in `tests/compile_fail/` locks in one negative property that
//! [`pqhybridsign_core::stateful_composite::SecretKey`] must never regain:
//! no `Clone`, no `PartialEq`, and `sign_stateful` cannot be reached through
//! a shared reference. The `.stderr` files next to each case are checked
//! verbatim by `trybuild`, so a case that starts failing for the wrong
//! reason (a typo, a missing import) is caught as a snapshot mismatch, not a
//! silent pass.

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
