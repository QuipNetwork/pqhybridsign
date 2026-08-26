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
//! End-to-end round trips for EdSh (ed25519 + SHRINCS) and SrSh (sr25519 +
//! SHRINCS): keygen, stateful signing with a durable leaf journal, stateless
//! signing, and verification.

// Round trips call keygen and sign_stateless; the composition behaviour under
// test does not depend on the SHRINCS parameter set.
#![cfg(feature = "profile-256s")]

use pqhybridsign::shrincs::{keygen, EdSh, SrSh};
use pqhybridsign::stateful::{adopt_key, KeyIdentity, LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign_test_support::MemoryBudget;
use std::cell::RefCell;
use std::rc::Rc;

/// An in-memory `LeafJournal`. Not durable across a process restart, which
/// is fine for a test: the property under test is *ordering* (commit before
/// signature), not real persistence.
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

// 1. keygen -> sign_stateful -> verify, for both EdSh and SrSh.

#[test]
fn ed_sh_stateful_round_trip_verifies() {
    let (mut sk, pk) = keygen::<EdSh>(&[1u8; 32], 4).expect("keygen");
    let mut journal = MemoryJournal::adopted(sk.key_identity());

    let sig = EdSh::sign_stateful(&mut sk, &mut journal, b"hello EdSh", b"ctx").expect("sign");

    assert!(EdSh::verify_stateful(&pk, b"hello EdSh", b"ctx", &sig));
}

#[test]
fn sr_sh_stateful_round_trip_verifies() {
    let (mut sk, pk) = keygen::<SrSh>(&[1u8; 32], 4).expect("keygen");
    let mut journal = MemoryJournal::adopted(sk.key_identity());

    let sig = SrSh::sign_stateful(&mut sk, &mut journal, b"hello SrSh", b"ctx").expect("sign");

    assert!(SrSh::verify_stateful(&pk, b"hello SrSh", b"ctx", &sig));
}

// 2. Composite sizes live in `profile_conformance.rs` so they run under every
//    profile against the verify-only fixtures.

// 3. Two successive stateful signatures consume leaves 1 then 2, and both
//    verify.

#[test]
fn successive_stateful_signatures_advance_the_leaf_and_both_verify() {
    let (mut sk, pk) = keygen::<EdSh>(&[3u8; 32], 4).expect("keygen");
    let mut journal = MemoryJournal::adopted(sk.key_identity());

    let first =
        EdSh::sign_stateful(&mut sk, &mut journal, b"message one", b"").expect("first sign");
    assert_eq!(*journal.committed.borrow(), vec![0]);
    assert!(EdSh::verify_stateful(&pk, b"message one", b"", &first));

    let second =
        EdSh::sign_stateful(&mut sk, &mut journal, b"message two", b"").expect("second sign");
    assert_eq!(*journal.committed.borrow(), vec![0, 1]);
    assert!(EdSh::verify_stateful(&pk, b"message two", b"", &second));

    // Leaf-consuming: the two signatures over different messages must not
    // be interchangeable.
    assert!(!EdSh::verify_stateful(&pk, b"message two", b"", &first));
}

// 4. A signature made under EdSh does NOT verify under SrSh.

#[test]
fn ed_sh_signature_does_not_verify_under_sr_sh() {
    let (mut sk_ed_sh, _pk_ed_sh) = keygen::<EdSh>(&[4u8; 32], 4).expect("ed_sh keygen");
    let (_sk_sr_sh, pk_sr_sh) = keygen::<SrSh>(&[4u8; 32], 4).expect("sr_sh keygen");
    let mut journal = MemoryJournal::adopted(sk_ed_sh.key_identity());

    let sig = EdSh::sign_stateful(&mut sk_ed_sh, &mut journal, b"cross-suite", b"").expect("sign");

    assert!(!SrSh::verify_stateful(&pk_sr_sh, b"cross-suite", b"", &sig));
}

// 5. Tampering with the classical half alone fails verification; tampering
//    with the SHRINCS half alone fails verification.

#[test]
fn tampering_either_half_fails_verification() {
    let (mut sk, pk) = keygen::<EdSh>(&[5u8; 32], 4).expect("keygen");
    let mut journal = MemoryJournal::adopted(sk.key_identity());
    let sig = EdSh::sign_stateful(&mut sk, &mut journal, b"tamper me", b"").expect("sign");
    assert!(EdSh::verify_stateful(&pk, b"tamper me", b"", &sig));

    // Classical half: the first 64 bytes of the composite encoding
    // (specification section 6, `pqhybridsign::encoding_path`).
    let mut classical_tampered = sig.clone();
    classical_tampered[0] ^= 0x01;
    assert!(!EdSh::verify_stateful(
        &pk,
        b"tamper me",
        b"",
        &classical_tampered
    ));

    // SHRINCS half: anywhere past the classical signature and selector.
    let mut shrincs_tampered = sig.clone();
    let last = shrincs_tampered.len() - 1;
    shrincs_tampered[last] ^= 0x01;
    assert!(!EdSh::verify_stateful(
        &pk,
        b"tamper me",
        b"",
        &shrincs_tampered
    ));
}

// 6. The leaf-burning rule (every signing attempt spends its leaf, even one
//    the component refuses) is covered as a driver-level unit test in
//    `pqhybridsign::stateful_composite::tests::a_refused_message_still_burns_its_leaf`,
//    using a fake `PqStatefulScheme` rigged to refuse a sentinel message
//    after it has spent the leaf. A real message cannot make SHRINCS refuse
//    (`ShrincsScheme::precheck`, `crates/pqhybridsign-shrincs/src/scheme.rs`)
//    -- it maps to an `ActionContext` whose required fields are fixed
//    non-zero constants -- so the case is not reachable through this
//    crate's public API, and is proven once, generically, at the driver
//    level instead.

// 7. A stateless signature verifies, and resigning the same message gives
//    byte-identical output.

#[test]
fn stateless_signature_verifies_and_resigning_is_byte_identical() {
    let (sk, pk) = keygen::<EdSh>(&[7u8; 32], 4).expect("keygen");

    // One store across both calls: a resign draws a second unit of the same
    // budget, and the signature bytes must still match.
    let mut budget = MemoryBudget::default();
    let a = EdSh::sign_stateless(&sk, &mut budget, b"stateless message", b"ctx").expect("sign a");
    let b = EdSh::sign_stateless(&sk, &mut budget, b"stateless message", b"ctx").expect("sign b");

    assert_eq!(a, b, "resigning the same message must be byte-identical");
    assert!(EdSh::verify_stateless(
        &pk,
        b"stateless message",
        b"ctx",
        &a
    ));
}

#[test]
fn sr_sh_stateless_signature_verifies() {
    let (sk, pk) = keygen::<SrSh>(&[8u8; 32], 4).expect("keygen");

    let sig = SrSh::sign_stateless(&sk, &mut MemoryBudget::default(), b"sr_sh stateless", b"")
        .expect("sign");

    assert!(SrSh::verify_stateless(&pk, b"sr_sh stateless", b"", &sig));
}
