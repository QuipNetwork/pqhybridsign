// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-checks the type-erased dispatch layer against the generic API it
//! wraps, for all six suites, and proves the stateless/stateful split holds
//! at the boundary.

use pqhybridsign::{H1, H2, H3, H4};
use pqhybridsign_abi::{AbiError, LeafJournal, Suite};
use pqhybridsign_core::stateful::StatefulHybridSignatureScheme;
use pqhybridsign_core::{composite, composite_delta, DeltaSuite, Suite as CoreSuite};
use pqhybridsign_shrincs::{H5, H6};
use rand_core::OsRng;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default)]
struct JournalState {
    committed: Vec<u32>,
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
}

const SEED: [u8; 32] = [42u8; 32];
const MSG: &[u8] = b"the message the abi layer signs";
const CTX: &[u8] = b"abi-roundtrip-test";

/// H1: dispatch through the enum must match the generic API byte for byte,
/// for the same seed and message.
#[test]
fn h1_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H1)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H1)];
    pqhybridsign_abi::keygen_from_seed(Suite::H1, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <H1 as CoreSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <H1 as CoreSuite>::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<H1>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();

    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::H1)];
    let n =
        pqhybridsign_abi::sign_deterministic(Suite::H1, &abi_sk, MSG, CTX, b"nonce", &mut abi_sig)
            .unwrap();

    let mut generic_sig = vec![0u8; <H1 as CoreSuite>::SIGNATURE_LEN];
    composite::sign_deterministic::<H1>(&generic_sk, MSG, CTX, b"nonce", &mut generic_sig).unwrap();

    assert_eq!(&abi_sig[..n], &generic_sig[..]);
    assert!(pqhybridsign_abi::verify(
        Suite::H1,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..n]
    ));
    assert!(composite::verify::<H1>(&generic_pk, MSG, CTX, &generic_sig));
}

/// H2: the delta-length suite. Round-trips through the enum and matches the
/// generic API, including the variable signature length.
#[test]
fn h2_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H2)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H2)];
    pqhybridsign_abi::keygen_from_seed(Suite::H2, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <H2 as DeltaSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <H2 as DeltaSuite>::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<H2>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();
    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::H2)];
    let n = pqhybridsign_abi::sign(Suite::H2, &abi_sk, MSG, CTX, &mut OsRng, &mut abi_sig).unwrap();
    assert!(n <= pqhybridsign_abi::signature_len(Suite::H2));
    assert!(pqhybridsign_abi::verify(
        Suite::H2,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..n]
    ));
}

/// A signature made under one suite must fail to verify under every other
/// suite, including within the same classical/post-quantum family (H1 vs
/// H3, H2 vs H4).
#[test]
fn a_signature_from_one_suite_fails_under_every_other() {
    let all = [
        Suite::H1,
        Suite::H2,
        Suite::H3,
        Suite::H4,
        Suite::H5,
        Suite::H6,
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
            let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
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

/// H5: the stateful suite. Signing spends a leaf, advances the exported
/// key, and interoperates with the generic
/// `StatefulHybridSignatureScheme` for the same seed and message.
#[test]
fn h5_stateful_signing_matches_the_generic_api_and_advances_the_leaf() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H5)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H5)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::H5, &SEED, 4, &mut abi_sk, &mut abi_pk)
        .unwrap();

    let (mut generic_sk, generic_pk) =
        pqhybridsign_core::stateful_composite::keygen::<H5>(&SEED, 4).unwrap();
    assert_eq!(abi_pk, generic_pk.as_ref());

    let mut journal_a = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
    let mut journal_b = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::H5)];
    let mut sk_out = abi_sk.clone();
    let n = pqhybridsign_abi::sign_stateful(
        Suite::H5,
        &abi_sk,
        &mut journal_a,
        MSG,
        CTX,
        &mut sk_out,
        &mut abi_sig,
    )
    .unwrap();

    let generic_sig = H5::sign_stateful(&mut generic_sk, &mut journal_b, MSG, CTX).unwrap();
    assert_eq!(&abi_sig[..n], generic_sig.as_slice());
    assert!(pqhybridsign_abi::verify(
        Suite::H5,
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
    let mut sig2 = vec![0u8; pqhybridsign_abi::signature_len(Suite::H5)];
    let err = pqhybridsign_abi::sign_stateful(
        Suite::H5,
        &abi_sk,
        &mut journal_a,
        MSG,
        CTX,
        &mut sk_out2,
        &mut sig2,
    )
    .unwrap_err();
    assert_eq!(err, AbiError::SigningFailed);
}

/// H5's stateless (few-time) path spends no leaf and can be called
/// repeatedly from the same key bytes.
#[test]
fn h5_stateless_signing_spends_no_leaf() {
    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H5)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H5)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::H5, &SEED, 4, &mut sk, &mut pk).unwrap();

    let mut sig_a = vec![0u8; pqhybridsign_abi::signature_len(Suite::H5)];
    let mut sig_b = vec![0u8; pqhybridsign_abi::signature_len(Suite::H5)];
    let n_a = pqhybridsign_abi::sign_stateless(Suite::H5, &sk, MSG, CTX, &mut sig_a).unwrap();
    let n_b = pqhybridsign_abi::sign_stateless(Suite::H5, &sk, MSG, CTX, &mut sig_b).unwrap();

    assert!(pqhybridsign_abi::verify(
        Suite::H5,
        &pk,
        MSG,
        CTX,
        &sig_a[..n_a]
    ));
    assert!(pqhybridsign_abi::verify(
        Suite::H5,
        &pk,
        MSG,
        CTX,
        &sig_b[..n_b]
    ));
}

/// H3/H4/H6: the second suite in each family round-trips end to end
/// through the enum too, so no suite is left untested by the H1/H2/H5
/// checks above.
#[test]
fn h3_h4_h6_round_trip_end_to_end() {
    for suite in [Suite::H3, Suite::H4] {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(suite)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(suite)];
        pqhybridsign_abi::keygen_from_seed(suite, &SEED, &mut sk, &mut pk).unwrap();
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];
        let n = pqhybridsign_abi::sign(suite, &sk, MSG, CTX, &mut OsRng, &mut sig).unwrap();
        assert!(pqhybridsign_abi::verify(suite, &pk, MSG, CTX, &sig[..n]));
    }

    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H6)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H6)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::H6, &SEED, 4, &mut sk, &mut pk).unwrap();
    let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
    let mut sk_out = sk.clone();
    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::H6)];
    let n = pqhybridsign_abi::sign_stateful(
        Suite::H6,
        &sk,
        &mut journal,
        MSG,
        CTX,
        &mut sk_out,
        &mut sig,
    )
    .unwrap();
    assert!(pqhybridsign_abi::verify(
        Suite::H6,
        &pk,
        MSG,
        CTX,
        &sig[..n]
    ));
}

// The three tests below close a gap the cross-suite rejection test cannot
// reach. That test proves a signature made under one suite fails under
// every other, which catches gross mis-wiring: dispatching `Suite::H3` to
// H1's implementation would make an "H3" signature verify under H1. It does
// not catch a consistent error. If the dispatch layer signed and verified
// H3 under the wrong label, every assertion in this file about H3 alone
// would still hold. Only comparing byte-for-byte against the generic API
// catches that, and it was previously done for H1, H2, and H5 but not for
// their sr25519 siblings.

/// H3 dispatch matches the generic API byte for byte.
#[test]
fn h3_dispatch_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H3)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H3)];
    pqhybridsign_abi::keygen_from_seed(Suite::H3, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <H3 as CoreSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <H3 as CoreSuite>::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<H3>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();
    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::H3)];
    pqhybridsign_abi::sign_deterministic(Suite::H3, &abi_sk, MSG, CTX, b"nonce", &mut abi_sig)
        .unwrap();
    let mut generic_sig = vec![0u8; <H3 as CoreSuite>::SIGNATURE_LEN];
    composite::sign_deterministic::<H3>(&generic_sk, MSG, CTX, b"nonce", &mut generic_sig).unwrap();
    assert_eq!(abi_sig, generic_sig);

    assert!(pqhybridsign_abi::verify(
        Suite::H3,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig
    ));
    assert!(composite::verify::<H3>(&generic_pk, MSG, CTX, &generic_sig));
}

/// H4 dispatch matches the generic API byte for byte, over the
/// delta-length wire format.
#[test]
fn h4_dispatch_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H4)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H4)];
    pqhybridsign_abi::keygen_from_seed(Suite::H4, &SEED, &mut abi_sk, &mut abi_pk).unwrap();

    let mut generic_sk = vec![0u8; <H4 as DeltaSuite>::SECRET_KEY_LEN];
    let mut generic_pk = vec![0u8; <H4 as DeltaSuite>::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<H4>(&SEED, &mut generic_sk, &mut generic_pk).unwrap();
    assert_eq!(abi_sk, generic_sk);
    assert_eq!(abi_pk, generic_pk);

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::H4)];
    let abi_n =
        pqhybridsign_abi::sign_deterministic(Suite::H4, &abi_sk, MSG, CTX, b"nonce", &mut abi_sig)
            .unwrap();
    let mut generic_sig = vec![0u8; <H4 as DeltaSuite>::MAX_SIGNATURE_LEN];
    let generic_n = composite_delta::sign_deterministic::<H4>(
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
        Suite::H4,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..abi_n]
    ));
}

/// H6 stateful dispatch matches the generic API byte for byte.
#[test]
fn h6_stateful_dispatch_matches_the_generic_api() {
    let mut abi_sk = vec![0u8; pqhybridsign_abi::secret_key_len(Suite::H6)];
    let mut abi_pk = vec![0u8; pqhybridsign_abi::public_key_len(Suite::H6)];
    pqhybridsign_abi::keygen_stateful_from_seed(Suite::H6, &SEED, 4, &mut abi_sk, &mut abi_pk)
        .unwrap();

    let (mut generic_sk, generic_pk) =
        pqhybridsign_core::stateful_composite::keygen::<H6>(&SEED, 4).unwrap();
    assert_eq!(abi_pk, generic_pk.as_ref());

    let mut journal_a = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
    let mut journal_b = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));

    let mut abi_sig = vec![0u8; pqhybridsign_abi::signature_len(Suite::H6)];
    let mut sk_out = abi_sk.clone();
    let n = pqhybridsign_abi::sign_stateful(
        Suite::H6,
        &abi_sk,
        &mut journal_a,
        MSG,
        CTX,
        &mut sk_out,
        &mut abi_sig,
    )
    .unwrap();

    let generic_sig = H6::sign_stateful(&mut generic_sk, &mut journal_b, MSG, CTX).unwrap();
    assert_eq!(&abi_sig[..n], generic_sig.as_slice());
    assert!(pqhybridsign_abi::verify(
        Suite::H6,
        &abi_pk,
        MSG,
        CTX,
        &abi_sig[..n]
    ));
}
