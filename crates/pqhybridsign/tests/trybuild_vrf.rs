// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid VRF test. Compiled only under the `vrf` feature.
#![cfg(feature = "vrf")]
// Integration test binary: `cfg(test)` is always true here, and `expect` is
// the normal way a test reports a failure.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Compile-fail guarantee for the hybrid VRF's suite coverage.
//!
//! The module documentation on `pqhybridsign::vrf` claims that naming an
//! ed25519 suite is a compile error rather than a runtime refusal. This is
//! what holds that claim: the entry points are bounded on `ClassicalVrf`, and
//! only `Sr25519` implements it. Kept in its own directory and its own test
//! binary, separate from `tests/trybuild.rs`, because that one is gated on the
//! SHRINCS profiles and this case needs the `vrf` feature instead.

#[test]
fn compile_fail_vrf() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail_vrf/*.rs");
}
