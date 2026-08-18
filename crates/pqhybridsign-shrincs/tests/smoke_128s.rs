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
//! Real 128s keygen smoke against the pinned H5 fixture.
//!
//! Sections 2 and 3 of the fixture design removed every live 128s operation
//! from the ordinary matrix. Other tests verify stored signatures. This file
//! puts one real 128s operation back: `keygen` under `profile-128s-q18`. A
//! regression in the 2^18 hypertree root derivation fails on the commit that
//! introduces it.
//!
//! # Why keygen only
//!
//! A real `sign_stateless` at 128s costs about 175 seconds and breaks the
//! 120-second per-test ceiling. The grind has two independent stages, FORS-C
//! and the WOTS-C target-sum grind, so a short-grind message search is not
//! reliable. Stateless signing at 128s belongs to the scheduled job. Do not
//! add it here.
//!
//! Stateful signing of leaf 1 is free coverage. It costs under 0.01 seconds
//! and is deterministic, so this test also pins the fixture stateful
//! signature bytes.
//!
//! # Why `q18` alone
//!
//! `q20` shares the same hypertree geometry. It differs only in the
//! stateless signature budget. Running this under `q20` doubles the cost
//! without new coverage.
//!
//! # Why `#[ignore]`d
//!
//! Without the gate the four-profile matrix job would grow from about 0.24
//! seconds to about 49 seconds and defeat the tiering work. The
//! `smoke-128s-q18` job runs this test with `--ignored`.
//!
//! # Measured cost
//!
//! About 49 seconds of keygen in release mode. Debug is about 67 times
//! slower. Always run release:
//!
//! ```text
//! cargo test -p pqhybridsign-shrincs --release --no-default-features \
//!     --features profile-128s-q18 --test smoke_128s -- --ignored --nocapture
//! ```
//!
//! Do not call `SecretKey::import`. It re-derives the hypertree root and
//! costs the same as `keygen` while covering less. See `fixture/mod.rs`.
#![cfg(feature = "profile-128s-q18")]

// Shared loader exposes fields for every consumer. This binary only needs the
// H5 public key and stateful leaf-1 material; the loader allows the unused
// rest.
mod fixture;

use pqhybridsign_core::stateful::{
    adopt_key, KeyIdentity, LeafJournal, StatefulHybridSignatureScheme,
};
use pqhybridsign_shrincs::{keygen, H5};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default, Clone)]
struct MemoryJournal {
    committed: Rc<RefCell<Vec<u32>>>,
    /// Which key this journal is the leaf record for, as durable here as
    /// the counter. A journal that has never been bound owns no key.
    bound: Rc<RefCell<Option<KeyIdentity>>>,
}

impl MemoryJournal {
    /// A journal already adopted by the key `identity` names: the one-off
    /// act an integrator performs when a key's durable journal is created.
    /// Signing refuses a journal that is not the key's.
    fn adopted(identity: KeyIdentity) -> Self {
        let mut journal = Self::default();
        adopt_key(&mut journal, identity).expect("adopt");
        journal
    }
}

impl LeafJournal for MemoryJournal {
    type Error = core::convert::Infallible;

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.committed.borrow_mut().push(leaf);
        Ok(())
    }

    fn next_leaf(&self) -> u32 {
        self.committed
            .borrow()
            .iter()
            .copied()
            .max()
            .map_or(0, |m| m + 1)
    }
    fn bound_key(&self) -> Option<KeyIdentity> {
        *self.bound.borrow()
    }

    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        *self.bound.borrow_mut() = Some(key);
        Ok(())
    }
}

#[test]
#[ignore = "about 49s of keygen; the smoke-128s-q18 job runs this with --ignored"]
fn keygen_matches_h5_fixture_and_stateful_leaf_1_is_reproducible() {
    let f = fixture::h5();
    let (mut sk, pk) = keygen::<H5>(&[0x50u8; 32], 4).expect("keygen");

    assert_eq!(
        pk.as_ref(),
        f.public_key.as_slice(),
        "keygen public key must match the pinned H5 fixture bytes"
    );

    let mut journal = MemoryJournal::adopted(sk.key_identity());
    let sig = H5::sign_stateful(&mut sk, &mut journal, &f.stateful_msg, &f.stateful_ctx)
        .expect("stateful leaf 1");

    assert_eq!(
        sig.as_slice(),
        f.stateful_signature.as_slice(),
        "stateful leaf-1 signature must match the pinned H5 fixture bytes"
    );

    assert!(
        H5::verify(&pk, &f.stateful_msg, &f.stateful_ctx, &sig),
        "stateful leaf-1 signature must verify against the keygen public key"
    );
}
