// SPDX-License-Identifier: AGPL-3.0-or-later
mod common;

use common::{Ed25519Stub, MlDsaStub};
use pqhybridsign_core::hybrid_suite;

hybrid_suite! {
    /// H1 test instance.
    H1Test,
    classical = Ed25519Stub as "ed25519",
    pq = MlDsaStub as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

#[test]
fn label_carries_the_trailing_null_byte() {
    use pqhybridsign_core::Suite;
    assert_eq!(H1Test::LABEL, b"hybrid-ed25519-mldsa44-v1\0");
    assert_eq!(H1Test::LABEL.len(), 26);
    assert_eq!(*H1Test::LABEL.last().unwrap(), 0u8);
}

#[test]
fn composite_sizes_are_the_component_sums() {
    use pqhybridsign_core::Suite;
    assert_eq!(H1Test::PUBLIC_KEY_LEN, 1344);
    assert_eq!(H1Test::SECRET_KEY_LEN, 2624);
    assert_eq!(H1Test::SIGNATURE_LEN, 2484);
}
