// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stateful (SHRINCS) suite test. Compiled only under a profile feature.
#![cfg(any(
    feature = "profile-256s",
    feature = "profile-256s-sha2",
    feature = "profile-128s-q18",
    feature = "profile-128s-q20"
))]
// Integration test binary: `cfg(test)` is always true here. `unwrap`/
// `expect`/`panic` are the normal way a test fails; the `hybrid_suite!`
// family of macros generates undocumented, unconditionally `pub` fixture
// structs, which is fine for a binary with no public API of its own.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        missing_docs,
        unreachable_pub
    )
)]
//! Compile-fail guarantees for the H5/H6 stateful secret key.
//!
//! Each case in `tests/compile_fail/` locks in one negative property that
//! [`pqhybridsign::stateful_composite::SecretKey`] must never regain:
//! no `Clone`, no `PartialEq`, and `sign_stateful` cannot be reached through
//! a shared reference. The `.stderr` files next to each case are checked
//! verbatim by `trybuild`, so a case that starts failing for the wrong
//! reason (a typo, a missing import) is caught as a snapshot mismatch, not a
//! silent pass.

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
    // `tests/compile_fail_vrf/` holds cases that need `pqhybridsign::vrf`,
    // which only exists under the non-default `vrf` feature. Globbing them
    // in unconditionally would fail every such case for the wrong reason --
    // an unresolved `vrf` module -- whenever this binary is built without
    // that feature.
    #[cfg(feature = "vrf")]
    t.compile_fail("tests/compile_fail_vrf/*.rs");
}
