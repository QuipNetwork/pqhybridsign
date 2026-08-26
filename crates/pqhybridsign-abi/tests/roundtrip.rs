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
//! Cross-checks the type-erased dispatch layer against the generic API it
//! wraps, for all six suites, and proves the stateless/stateful split holds
//! at the boundary.

use pqhybridsign::shrincs::{EdSh, SrSh};
use pqhybridsign::stateful::StatefulHybridSignatureScheme;
use pqhybridsign::{
    composite, composite_delta,
    suite::{DeltaSuite, Suite as CoreSuite},
};
use pqhybridsign::{EdMl44, EdFn512, SrMl44, SrFn512};
use pqhybridsign_abi::{AbiError, KeyIdentity, LeafJournal, Suite};
use pqhybridsign_test_support::MemoryBudget;
use rand_core::OsRng;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default)]
struct JournalState {
    committed: Vec<u32>,
    bound: Option<KeyIdentity>,
}
struct MemoryJournal(Rc<RefCell<JournalState>>);
impl LeafJournal for MemoryJournal {
    type Error = std::convert::Infallible;
    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.0.borrow_mut().committed.push(leaf);
        Ok(())
    }
    fn next_leaf(&self) -> u32 {
        self.0
            .borrow()
            .committed
            .iter()
            .copied()
            .max()
            .map_or(0, |m| m + 1)
    }
    fn bound_key(&self) -> Option<KeyIdentity> {
        self.0.borrow().bound
    }
    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        self.0.borrow_mut().bound = Some(key);
        Ok(())
    }
}

/// A fresh journal, adopted by the key `pk` names. Signing refuses a journal
/// that has never been bound to the key, so every stateful test here does the
/// one-off adoption an integrator does when the key is provisioned.
fn adopted_journal(suite: Suite, pk: &[u8]) -> MemoryJournal {
    let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
    let identity = pqhybridsign_abi::key_identity(suite, pk).unwrap();
    pqhybridsign_abi::adopt_key(&mut journal, identity).unwrap();
    journal
}

const SEED: [u8; 32] = [42u8; 32];
const MSG: &[u8] = b"the message the abi layer signs";
const CTX: &[u8] = b"abi-roundtrip-test";

/// EdMl44: dispatch through the enum must match the generic API byte for byte,
/// for the same seed and message.
#[test]
fn ed_ml44_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::EdMl44)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::EdMl44)];
    pqhybridsign_abi::keygen_from_seed(Suite::EdMl44, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <EdMl44 as CoreSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <EdMl44 as CoreSuite>::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<EdMl44>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();

    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::EdMl44)];
    let n =
        pqhybridsign_abi::sign_deterministic(Suite::EdMl44, &abi_sk, MSG, CTX, b"nonce", &mut abi_sig)
            .unwrap();

    let mut generic_sig = vec![0u8; <EdMl44 as CoreSuite>::SIGNATURE_LEN];
    composite::sign_deterministic::<EdMl44>(&generic_sk, MSG, CTX, b"nonce", &mut generic_sig).unwrap();

    assert_eq!(&abi_sig[..n], &generic_sig[..]);
    assert!(pqhybridsign_abi::verify(
        Suite::EdMl44,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..n]
    ));
    assert!(composite::verify::<EdMl44>(&generic_pk, MSG, CTX, &generic_sig));
}

/// EdFn512: the delta-length suite. Round-trips through the enum and matches the
/// generic API, including the variable signature length.
#[test]
fn ed_fn512_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::EdFn512)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::EdFn512)];
    pqhybridsign_abi::keygen_from_seed(Suite::EdFn512, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <EdFn512 as DeltaSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <EdFn512 as DeltaSuite>::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<EdFn512>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();
    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::EdFn512)];
    let n = pqhybridsign_abi::sign(Suite::EdFn512, &abi_sk, MSG, CTX, &mut OsRng, &mut abi_sig).unwrap();
    assert!(n <= pqhybridsign_abi::signature_len(Suite::EdFn512));
    assert!(pqhybridsign_abi::verify(
        Suite::EdFn512,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..n]
    ));
}

/// A signature made under one suite must fail to verify under every other
/// suite, including within the same classical/post-quantum family (EdMl44 vs
/// SrMl44, EdFn512 vs SrFn512).
#[test]
fn a_signature_from_one_suite_fails_under_every_other() {
    let all = [
        Suite::EdMl44,
        Suite::EdFn512,
        Suite::SrMl44,
        Suite::SrFn512,
        Suite::EdSh,
        Suite::SrSh,
    ];

    let mut material = Vec::new();
    for (i, suite) in all.iter().enumerate() {
        let seed = [i as u8 + 1; 32];
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(*suite)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(*suite)];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(*suite)];

        let sig_len = if suite.is_stateful() {
            pqhybridsign_abi::keygen_stateful_from_seed(*suite, &seed, 4, &mut sk, &mut pk)
                .unwrap();
            let mut journal = adopted_journal(*suite, &pk);
            let mut sk_out = sk.clone();
            pqhybridsign_abi::sign_stateful(
                *suite,
                &sk,
                &mut journal,
                MSG,
                CTX,
                &mut sk_out,
                &mut sig,
            )
            .unwrap()
        } else {
            pqhybridsign_abi::keygen_from_seed(*suite, &seed, &mut sk, &mut pk).unwrap();
            pqhybridsign_abi::sign(*suite, &sk, MSG, CTX, &mut OsRng, &mut sig).unwrap()
        };

        assert!(pqhybridsign_abi::verify(
            *suite,
            &pk,
            MSG,
            CTX,
            &sig[..sig_len]
        ));
        material.push((*suite, pk, sig[..sig_len].to_vec()));
    }

    for (owner, pk, sig) in &material {
        for suite in &all {
            if suite == owner {
                continue;
            }
            assert!(
                !pqhybridsign_abi::verify(*suite, pk, MSG, CTX, sig),
                "{owner}'s signature verified under {suite}"
            );
        }
    }
}

/// EdSh: the stateful suite. Signing spends a leaf, advances the exported
/// key, and interoperates with the generic
/// `StatefulHybridSignatureScheme` for the same seed and message.
#[test]
fn ed_sh_stateful_signing_matches_the_generic_api_and_advances_the_leaf() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::EdSh)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::EdSh)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::EdSh, &SEED, 4, &mut abi_sk, &mut abi_pk)
        .unwrap();

    let (mut generic_sk, generic_pk) =
        pqhybridsign::stateful_composite::keygen::<EdSh>(&SEED, 4).unwrap();
    assert_eq!(abi_pk, generic_pk.as_ref());

    let mut journal_a = adopted_journal(Suite::EdSh, &abi_pk);
    let mut journal_b = adopted_journal(Suite::EdSh, generic_pk.as_ref());

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::EdSh)];
    let mut sk_out = abi_sk.clone();
    let n = pqhybridsign_abi::sign_stateful(
        Suite::EdSh,
        &abi_sk,
        &mut journal_a,
        MSG,
        CTX,
        &mut sk_out,
        &mut abi_sig,
    )
    .unwrap();

    let generic_sig = EdSh::sign_stateful(&mut generic_sk, &mut journal_b, MSG, CTX).unwrap();
    assert_eq!(&abi_sig[..n], generic_sig.as_slice());
    assert!(pqhybridsign_abi::verify(
        Suite::EdSh,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..n]
    ));

    // The exported key advanced past the spent leaf, and does not equal
    // the key it started from.
    assert_ne!(sk_out, abi_sk);

    // Signing again with the pre-advance key bytes but the now-advanced
    // journal must fail: the component counter and the journal have
    // drifted apart, which is exactly the drift `sign_stateful` exists to
    // catch rather than silently reissue a leaf.
    let mut sk_out2 = abi_sk.clone();
    let mut sig2 = vec![0u8; pqhybridsign_abi::signature_len(Suite::EdSh)];
    let err = pqhybridsign_abi::sign_stateful(
        Suite::EdSh,
        &abi_sk,
        &mut journal_a,
        MSG,
        CTX,
        &mut sk_out2,
        &mut sig2,
    )
    .unwrap_err();
    // Named, not the generic `SigningFailed`: a diverged key can never sign
    // again and must be rotated, while a signing failure may be worth a
    // retry. A caller that cannot tell them apart retries forever.
    assert_eq!(err, AbiError::CountersDiverged);
}

/// EdSh's stateless (few-time) path spends no leaf and can be called
/// repeatedly from the same key bytes.
#[test]
fn ed_sh_stateless_signing_spends_no_leaf() {
    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::EdSh)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::EdSh)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::EdSh, &SEED, 4, &mut sk, &mut pk).unwrap();

    let mut sig_a = vec![0u8; pqhybridsign_abi::signature_len(Suite::EdSh)];
    let mut sig_b = vec![0u8; pqhybridsign_abi::signature_len(Suite::EdSh)];
    // One store across both calls, as a deployment would have: the leaf
    // state must stay untouched even though the stateless budget advances.
    let mut budget = MemoryBudget::default();
    let n_a = pqhybridsign_abi::sign_stateless(Suite::EdSh, &sk, &mut budget, MSG, CTX, &mut sig_a)
        .unwrap();
    let n_b = pqhybridsign_abi::sign_stateless(Suite::EdSh, &sk, &mut budget, MSG, CTX, &mut sig_b)
        .unwrap();

    // Plain `verify` accepts only the stateful path for EdSh/SrSh
    // (specification section 20.2): a stateless-path signature verifies
    // only through `verify_stateless`.
    assert!(!pqhybridsign_abi::verify(
        Suite::EdSh,
        &pk,
        MSG,
        CTX,
        &sig_a[..n_a]
    ));
    assert!(pqhybridsign_abi::verify_stateless(Suite::EdSh, &pk, MSG, CTX, &sig_a[..n_a]).unwrap());
    assert!(pqhybridsign_abi::verify_stateless(Suite::EdSh, &pk, MSG, CTX, &sig_b[..n_b]).unwrap());
}

/// SrMl44/SrFn512/SrSh: the second suite in each family round-trips end to end
/// through the enum too, so no suite is left untested by the EdMl44/EdFn512/EdSh
/// checks above.
#[test]
fn sr_ml44_sr_fn512_sr_sh_round_trip_end_to_end() {
    for suite in [Suite::SrMl44, Suite::SrFn512] {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(suite)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(suite)];
        pqhybridsign_abi::keygen_from_seed(suite, &SEED, &mut sk, &mut pk).unwrap();
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];
        let n = pqhybridsign_abi::sign(suite, &sk, MSG, CTX, &mut OsRng, &mut sig).unwrap();
        assert!(pqhybridsign_abi::verify(suite, &pk, MSG, CTX, &sig[..n]));
    }

    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::SrSh)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::SrSh)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::SrSh, &SEED, 4, &mut sk, &mut pk).unwrap();
    let mut journal = adopted_journal(Suite::SrSh, &pk);
    let mut sk_out = sk.clone();
    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::SrSh)];
    let n = pqhybridsign_abi::sign_stateful(
        Suite::SrSh,
        &sk,
        &mut journal,
        MSG,
        CTX,
        &mut sk_out,
        &mut sig,
    )
    .unwrap();
    assert!(pqhybridsign_abi::verify(
        Suite::SrSh,
        &pk,
        MSG,
        CTX,
        &sig[..n]
    ));
}

// The three tests below close a gap the cross-suite rejection test cannot
// reach. That test proves a signature made under one suite fails under
// every other, which catches gross mis-wiring: dispatching `Suite::SrMl44` to
// EdMl44's implementation would make an "SrMl44" signature verify under EdMl44. It does
// not catch a consistent error. If the dispatch layer signed and verified
// SrMl44 under the wrong label, every assertion in this file about SrMl44 alone
// would still hold. Only comparing byte-for-byte against the generic API
// catches that, and it was previously done for EdMl44, EdFn512, and EdSh but not for
// their sr25519 siblings.

/// SrMl44 dispatch matches the generic API byte for byte.
#[test]
fn sr_ml44_dispatch_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::SrMl44)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::SrMl44)];
    pqhybridsign_abi::keygen_from_seed(Suite::SrMl44, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <SrMl44 as CoreSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <SrMl44 as CoreSuite>::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<SrMl44>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();
    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::SrMl44)];
    pqhybridsign_abi::sign_deterministic(Suite::SrMl44, &abi_sk, MSG, CTX, b"nonce", &mut abi_sig)
        .unwrap();
    let mut generic_sig = vec![0u8; <SrMl44 as CoreSuite>::SIGNATURE_LEN];
    composite::sign_deterministic::<SrMl44>(&generic_sk, MSG, CTX, b"nonce", &mut generic_sig).unwrap();
    assert_eq!(abi_sig, generic_sig);

    assert!(pqhybridsign_abi::verify(
        Suite::SrMl44,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig
    ));
    assert!(composite::verify::<SrMl44>(&generic_pk, MSG, CTX, &generic_sig));
}

/// SrFn512 dispatch matches the generic API byte for byte, over the
/// delta-length wire format.
#[test]
fn sr_fn512_dispatch_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::SrFn512)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::SrFn512)];
    pqhybridsign_abi::keygen_from_seed(Suite::SrFn512, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <SrFn512 as DeltaSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <SrFn512 as DeltaSuite>::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<SrFn512>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();
    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::SrFn512)];
    let abi_n =
        pqhybridsign_abi::sign_deterministic(Suite::SrFn512, &abi_sk, MSG, CTX, b"nonce", &mut abi_sig)
            .unwrap();
    let mut generic_sig = vec![0u8; <SrFn512 as DeltaSuite>::MAX_SIGNATURE_LEN];
    let generic_n = composite_delta::sign_deterministic::<SrFn512>(
        &generic_sk,
        MSG,
        CTX,
        b"nonce",
        &mut generic_sig,
    )
    .unwrap();
    assert_eq!(abi_n, generic_n);
    assert_eq!(abi_sig[..abi_n], generic_sig[..generic_n]);

    assert!(pqhybridsign_abi::verify(
        Suite::SrFn512,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..abi_n]
    ));
}

/// SrSh stateful dispatch matches the generic API byte for byte.
#[test]
fn sr_sh_stateful_dispatch_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::SrSh)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::SrSh)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::SrSh, &SEED, 4, &mut abi_sk, &mut abi_pk)
        .unwrap();

    let (mut generic_sk, generic_pk) =
        pqhybridsign::stateful_composite::keygen::<SrSh>(&SEED, 4).unwrap();
    assert_eq!(abi_pk, generic_pk.as_ref());

    let mut journal_a = adopted_journal(Suite::SrSh, &abi_pk);
    let mut journal_b = adopted_journal(Suite::SrSh, generic_pk.as_ref());

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::SrSh)];
    let mut sk_out = abi_sk.clone();
    let n = pqhybridsign_abi::sign_stateful(
        Suite::SrSh,
        &abi_sk,
        &mut journal_a,
        MSG,
        CTX,
        &mut sk_out,
        &mut abi_sig,
    )
    .unwrap();

    let generic_sig = SrSh::sign_stateful(&mut generic_sk, &mut journal_b, MSG, CTX).unwrap();
    assert_eq!(&abi_sig[..n], generic_sig.as_slice());
    assert!(pqhybridsign_abi::verify(
        Suite::SrSh,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..n]
    ));
}
