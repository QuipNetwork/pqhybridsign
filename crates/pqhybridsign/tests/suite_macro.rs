// SPDX-License-Identifier: AGPL-3.0-or-later
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
mod common;

use common::{Ed25519Stub, MlDsaStub};
use pqhybridsign::hybrid_suite;

hybrid_suite! {
    /// EdMl44 test instance.
    H1Test,
    classical = Ed25519Stub as "ed25519",
    pq = MlDsaStub as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

#[test]
fn label_carries_the_trailing_null_byte() {
    use pqhybridsign::suite::Suite;
    assert_eq!(H1Test::LABEL, b"hybrid-ed25519-mldsa44-v1\0");
    assert_eq!(H1Test::LABEL.len(), 26);
    assert_eq!(*H1Test::LABEL.last().unwrap(), 0u8);
}

#[test]
fn composite_sizes_are_the_component_sums() {
    use pqhybridsign::suite::Suite;
    assert_eq!(H1Test::PUBLIC_KEY_LEN, 1344);
    assert_eq!(H1Test::SECRET_KEY_LEN, 2624);
    assert_eq!(H1Test::SIGNATURE_LEN, 2484);
}
