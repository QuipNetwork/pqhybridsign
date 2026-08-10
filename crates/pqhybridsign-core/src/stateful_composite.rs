// SPDX-License-Identifier: AGPL-3.0-or-later
//! Generic composite signing, verification and keygen for any
//! [`StatefulSuite`].
//!
//! This module is where a stateful hybrid suite (H5, H6, ...) becomes a real
//! [`StatefulHybridSignatureScheme`]: a blanket implementation over every
//! `S: StatefulSuite` at the bottom of this file. A concrete suite crate
//! only has to declare its labels with [`crate::hybrid_stateful_suite!`] and
//! implement [`PqStatefulScheme`] for its post-quantum component; this
//! module supplies the keys, the encoding, and the ordering.
//!
//! # Layering
//!
//! Nothing here knows what "SHRINCS" is. [`PqStatefulScheme`] is the only
//! seam: everything scheme-specific (commitment bundles, action contexts,
//! wire geometry of a single component signature) lives behind it, in the
//! suite crate. This module only ever sees opaque `vk`/`sk`/`msg`/`sig`
//! byte buffers and the two component-supplied path-length constants
//! ([`PqStatefulScheme::FIXED_STATEFUL_SIG_LEN`],
//! [`PqStatefulScheme::STATELESS_SIG_LEN`]) needed to drive
//! [`crate::encoding_path`].

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use zeroize::Zeroize;

use crate::encoding_path::{self, PathBody, PathProfile, PathSelectedSig, TrustedMaxSignatures};
use crate::stateful::{
    sign_after_commit, LeafJournal, StatefulHybridSignatureScheme, StatefulSignError,
};
use crate::{
    derive_component_seeds, m_prime, ClassicalScheme, Error, PqStatefulScheme, Result,
    StatefulSuite,
};

/// The verify-key-sized composite public key: `ClassicalPK ||
/// PqVerifyKey`, length [`StatefulSuite::VERIFY_PUBLIC_KEY_LEN`].
///
/// This is the form [`StatefulHybridSignatureScheme::verify`] needs. The
/// smaller on-storage form (`ClassicalPK || PqStoredKey`, length
/// [`StatefulSuite::STORED_PUBLIC_KEY_LEN`]) is a storage concern the
/// integrator owns; nothing here assumes how -- or whether -- a caller
/// shrinks this type down for storage.
pub struct PublicKey<S: StatefulSuite> {
    bytes: Vec<u8>,
    _suite: PhantomData<S>,
}

impl<S: StatefulSuite> Clone for PublicKey<S> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _suite: PhantomData,
        }
    }
}

impl<S: StatefulSuite> AsRef<[u8]> for PublicKey<S> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<S: StatefulSuite> PublicKey<S> {
    /// The classical component's public key.
    pub fn classical(&self) -> &[u8] {
        &self.bytes[..<S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN]
    }

    /// The post-quantum component's verify key.
    pub fn pq_verify_key(&self) -> &[u8] {
        &self.bytes[<S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN..]
    }
}

/// The composite secret key: `ClassicalSK || PqSecretKey`, length
/// [`StatefulSuite::SECRET_KEY_LEN`].
///
/// Deliberately **not** `Clone`: a cloned copy would be a second holder of
/// the same one-time leaf budget (see
/// [`StatefulHybridSignatureScheme::SecretKey`]).
pub struct SecretKey<S: StatefulSuite> {
    classical: Vec<u8>,
    pq: <S::Pq as PqStatefulScheme>::SecretKey,
    /// The post-quantum verify key, cached from keygen. Public data --
    /// needed on every `sign_stateful`/`sign_stateless` call because
    /// `PqStatefulScheme::sign_stateful`/`sign_stateless` take it as an
    /// argument -- so caching it here avoids re-deriving it from `pq` on
    /// every call.
    pq_verify_key: Vec<u8>,
}

impl<S: StatefulSuite> Zeroize for SecretKey<S> {
    fn zeroize(&mut self) {
        self.classical.zeroize();
        self.pq.zeroize();
        // `pq_verify_key` is public data; no need to wipe it.
    }
}

/// Derive a composite keypair from a 32-byte master seed.
///
/// The suite label is bound into the key derivation (specification section
/// 9), so two suites from one master seed produce independent keys.
///
/// # Errors
///
/// [`Error::ComponentFailure`] if `max_stateful_signatures` is `0` or
/// exceeds [`PqStatefulScheme::LEAF_CAPACITY_LIMIT`], or if either
/// component's derivation fails.
pub fn keygen<S: StatefulSuite>(
    master: &[u8; 32],
    max_stateful_signatures: u32,
) -> Result<(SecretKey<S>, PublicKey<S>)> {
    if max_stateful_signatures == 0
        || max_stateful_signatures > <S::Pq as PqStatefulScheme>::LEAF_CAPACITY_LIMIT
    {
        return Err(Error::ComponentFailure);
    }

    let pq_seed_len = <S::Pq as PqStatefulScheme>::SEED_LEN;
    let mut classical_seed = [0u8; 32];
    let mut pq_seed = alloc::vec![0u8; pq_seed_len];
    let derive_result = derive_component_seeds(master, S::LABEL, &mut classical_seed, &mut pq_seed);
    if let Err(e) = derive_result {
        classical_seed.zeroize();
        pq_seed.zeroize();
        return Err(e);
    }

    let mut classical = alloc::vec![0u8; <S::Classical as ClassicalScheme>::SECRET_KEY_LEN];
    let mut classical_pk = alloc::vec![0u8; <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN];
    let classical_result = <S::Classical as ClassicalScheme>::derive(
        &classical_seed,
        &mut classical,
        &mut classical_pk,
    );
    classical_seed.zeroize();
    if let Err(e) = classical_result {
        pq_seed.zeroize();
        classical.zeroize();
        return Err(e);
    }

    let mut pq_verify_key = alloc::vec![0u8; <S::Pq as PqStatefulScheme>::VERIFY_KEY_LEN];
    let pq_result = <S::Pq as PqStatefulScheme>::keygen_from_seed(
        &pq_seed,
        max_stateful_signatures,
        &mut pq_verify_key,
    );
    pq_seed.zeroize();
    let pq = match pq_result {
        Ok(pq) => pq,
        Err(e) => {
            classical.zeroize();
            return Err(e);
        }
    };

    let mut bytes = Vec::with_capacity(classical_pk.len() + pq_verify_key.len());
    bytes.extend_from_slice(&classical_pk);
    bytes.extend_from_slice(&pq_verify_key);

    Ok((
        SecretKey {
            classical,
            pq,
            pq_verify_key,
        },
        PublicKey {
            bytes,
            _suite: PhantomData,
        },
    ))
}

fn path_profile<S: StatefulSuite>() -> PathProfile {
    PathProfile {
        fixed_stateful_len: <S::Pq as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN,
        stateless_len: <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN,
    }
}

fn classical_sign<S: StatefulSuite>(
    sk: &SecretKey<S>,
    m_prime: &[u8],
    ctx: &[u8],
) -> core::result::Result<Vec<u8>, StatefulSignError> {
    let mut sig = alloc::vec![0u8; <S::Classical as ClassicalScheme>::SIGNATURE_LEN];
    <S::Classical as ClassicalScheme>::sign_deterministic(
        &sk.classical,
        m_prime,
        ctx,
        S::LABEL,
        &mut sig,
    )
    .map_err(|_| StatefulSignError::SigningFailed)?;
    Ok(sig)
}

fn encode_signature<S: StatefulSuite>(
    classical_sig: &[u8],
    body: PathBody<'_>,
) -> core::result::Result<Vec<u8>, StatefulSignError> {
    // `classical_sig` is exactly `Classical::SIGNATURE_LEN` bytes (built
    // just above), and `encoding_path::CLASSICAL_SIG_LEN` is a fixed 64 --
    // true for every classical component this crate ships.
    let classical: &[u8; encoding_path::CLASSICAL_SIG_LEN] = classical_sig
        .try_into()
        .map_err(|_| StatefulSignError::SigningFailed)?;
    let sig = PathSelectedSig { classical, body };
    encoding_path::encode_path_selected(&sig, &path_profile::<S>())
        .map_err(|_| StatefulSignError::SigningFailed)
}

impl<S: StatefulSuite> StatefulHybridSignatureScheme for S {
    type PublicKey = PublicKey<S>;
    type SecretKey = SecretKey<S>;
    type Signature = Vec<u8>;

    fn sign_stateful(
        sk: &mut Self::SecretKey,
        journal: &mut impl LeafJournal,
        msg: &[u8],
        ctx: &[u8],
    ) -> core::result::Result<Self::Signature, StatefulSignError> {
        let m_prime = m_prime(S::LABEL, ctx, msg).map_err(|_| StatefulSignError::SigningFailed)?;

        // Step 1 of the ordering contract: validate before any leaf is
        // touched.
        if !<S::Pq as PqStatefulScheme>::precheck(&m_prime) {
            return Err(StatefulSignError::SigningFailed);
        }

        let leaf_capacity = <S::Pq as PqStatefulScheme>::leaf_capacity(&sk.pq);
        let pq_next = <S::Pq as PqStatefulScheme>::next_leaf(&sk.pq);
        // The component's own leaf counter and the caller's durable
        // `LeafJournal` are two independent counters that must stay in
        // lockstep: both only ever advance together, through this
        // function. Any drift means the journal and the in-memory key came
        // from different sessions, and signing must not proceed.
        if pq_next != journal.next_leaf() {
            return Err(StatefulSignError::SigningFailed);
        }

        let classical_sig = classical_sign(sk, &m_prime, ctx)?;

        let pq_verify_key = sk.pq_verify_key.clone();
        let max_sig_len = <S::Pq as PqStatefulScheme>::max_stateful_sig_len(leaf_capacity);
        let pq = &mut sk.pq;
        let flat = sign_after_commit(journal, u64::from(leaf_capacity), move |_leaf| {
            let mut sig_out = alloc::vec![0u8; max_sig_len];
            let written = <S::Pq as PqStatefulScheme>::sign_stateful(
                pq,
                &pq_verify_key,
                &m_prime,
                &mut sig_out,
            )
            // After the exhaustion pre-check above, any remaining
            // failure here is provably a grind abort (or equivalent
            // component-internal failure past the exhaustion boundary):
            // see the component's own documentation for the exact
            // upstream failure modes this collapses.
            .map_err(|_| StatefulSignError::GrindAbort)?;
            sig_out.truncate(written);
            Ok(sig_out)
        })?;

        let fixed = <S::Pq as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN;
        let leaf_count = u32::try_from((flat.len() - fixed) / encoding_path::AUTH_PATH_NODE_LEN)
            .map_err(|_| StatefulSignError::SigningFailed)?;
        encode_signature::<S>(
            &classical_sig,
            PathBody::Stateful {
                leaf_count,
                signature: &flat,
            },
        )
    }

    fn sign_stateless(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
    ) -> core::result::Result<Self::Signature, StatefulSignError> {
        let m_prime = m_prime(S::LABEL, ctx, msg).map_err(|_| StatefulSignError::SigningFailed)?;
        if !<S::Pq as PqStatefulScheme>::precheck(&m_prime) {
            return Err(StatefulSignError::SigningFailed);
        }

        let mut sig_out = alloc::vec![0u8; <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN];
        let written = <S::Pq as PqStatefulScheme>::sign_stateless(&sk.pq, &m_prime, &mut sig_out)
            // Every failure cause on the stateless path is
            // indistinguishable from the component's `Result`; mapped
            // to `GrindAbort` as the closest-fitting variant. See the
            // component's own documentation for the ambiguity this
            // collapses.
            .map_err(|_| StatefulSignError::GrindAbort)?;
        sig_out.truncate(written);

        let classical_sig = classical_sign(sk, &m_prime, ctx)?;
        encode_signature::<S>(
            &classical_sig,
            PathBody::Stateless {
                signature: &sig_out,
            },
        )
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool {
        let Ok(m_prime) = m_prime(S::LABEL, ctx, msg) else {
            return false;
        };
        if !<S::Pq as PqStatefulScheme>::precheck(&m_prime) {
            return false;
        }

        // The verify key does not carry `maxSignatures` generically (only
        // the SHRINCS component knows where it lives inside `vk`), so the
        // decode-time leaf-count bound comes from the leaf-dependent
        // signature length arithmetic alone: any `LeafCount` whose implied
        // length does not fit the remaining bytes is rejected regardless.
        // `TrustedMaxSignatures` is set to `u32::MAX`, the widest bound any
        // key can have; the component's own `verify_stateful` still
        // enforces the real per-key bound when it recomputes state from
        // `vk`.
        let trusted_max = TrustedMaxSignatures::from_verified_bundle(u32::MAX);
        let Ok(decoded) =
            encoding_path::decode_path_selected(sig, trusted_max, &path_profile::<S>())
        else {
            return false;
        };

        let classical_ok = <S::Classical as ClassicalScheme>::verify(
            pk.classical(),
            &m_prime,
            S::LABEL,
            &decoded.classical[..],
        );

        let pq_ok = match decoded.body {
            PathBody::Stateful { signature, .. } => <S::Pq as PqStatefulScheme>::verify_stateful(
                pk.pq_verify_key(),
                &m_prime,
                signature,
            ),
            PathBody::Stateless { signature } => <S::Pq as PqStatefulScheme>::verify_stateless(
                pk.pq_verify_key(),
                &m_prime,
                signature,
            ),
        };

        // Bitwise AND, never `&&`: no short circuit, so neither the result
        // nor the running time reveals which component rejected. Mirrors
        // `composite::verify`.
        bool::from(classical_ok & pq_ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::LeafJournal;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::cell::RefCell;
    use std::rc::Rc;
    use subtle::Choice;

    /// Counts calls into `FakePq::verify_stateful`, so a test can prove the
    /// post-quantum half is evaluated even when the classical half already
    /// failed (no short circuit). Global rather than per-instance because
    /// `FakePq` is a unit struct; other tests in this module also drive it,
    /// so assertions against this counter only ever check for an increase
    /// across a call, never an exact value.
    static VERIFY_STATEFUL_CALLS: AtomicUsize = AtomicUsize::new(0);

    // A minimal fake `PqStatefulScheme` + `StatefulSuite`, to prove the
    // generic driver's ordering (precheck before `sign_after_commit`, so a
    // rejected message burns no leaf) without any real cryptography. This
    // is the "leaf-burning guard" test: it cannot be exercised through a
    // real component's public API, because a real component's `precheck`
    // is built to accept every message an honest caller can construct.
    #[derive(Default, zeroize::Zeroize)]
    pub struct FakeSecretKey {
        leaf: u32,
    }

    pub struct FakePq;

    impl crate::PqStatefulScheme for FakePq {
        const NAME: &'static str = "fake";
        const SEED_LEN: usize = 1;
        const PUBLIC_KEY_LEN: usize = 1;
        const VERIFY_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 1;
        const LEAF_CAPACITY_LIMIT: u32 = 8;
        const FIXED_STATEFUL_SIG_LEN: usize = 0;
        const STATELESS_SIG_LEN: usize = 1;

        type SecretKey = FakeSecretKey;

        fn keygen_from_seed(
            _seed: &[u8],
            _max_signatures: u32,
            vk_out: &mut [u8],
        ) -> Result<Self::SecretKey> {
            vk_out.fill(0);
            Ok(FakeSecretKey { leaf: 0 })
        }
        fn leaf_capacity(_sk: &Self::SecretKey) -> u32 {
            4
        }
        fn next_leaf(sk: &Self::SecretKey) -> u32 {
            sk.leaf
        }
        fn precheck(msg: &[u8]) -> bool {
            // `msg` here is the built `M'`, not the raw application message;
            // the rigged sentinel is checked anywhere in it so the test can
            // still trigger it by passing `[0xFF]` as the raw message.
            !msg.contains(&0xFF)
        }
        fn max_stateful_sig_len(max_signatures: u32) -> usize {
            max_signatures as usize * encoding_path::AUTH_PATH_NODE_LEN
        }
        fn sign_stateful(
            sk: &mut Self::SecretKey,
            _vk: &[u8],
            _msg: &[u8],
            sig_out: &mut [u8],
        ) -> Result<usize> {
            sk.leaf += 1;
            // `FIXED_STATEFUL_SIG_LEN` is 0, so a signature carrying exactly
            // one authentication-path node (32 bytes, `leaf_count = 1`) is
            // the smallest one `encoding_path` accepts (leaf count >= 1).
            sig_out[..encoding_path::AUTH_PATH_NODE_LEN].fill(0);
            Ok(encoding_path::AUTH_PATH_NODE_LEN)
        }
        fn sign_stateless(_sk: &Self::SecretKey, _msg: &[u8], sig_out: &mut [u8]) -> Result<usize> {
            sig_out.fill(0);
            Ok(1)
        }
        fn verify_stateful(_vk: &[u8], _msg: &[u8], _sig: &[u8]) -> Choice {
            VERIFY_STATEFUL_CALLS.fetch_add(1, Ordering::SeqCst);
            Choice::from(1u8)
        }
        fn verify_stateless(_vk: &[u8], _msg: &[u8], _sig: &[u8]) -> Choice {
            Choice::from(1u8)
        }
    }

    /// Minimal stand-in `ClassicalScheme`, local to this test module: the
    /// real `Ed25519`/`Sr25519` live in a downstream crate this crate does
    /// not depend on, and `component::tests::Stub` is private to its own
    /// module.
    #[derive(Clone, Copy, Debug)]
    pub struct FakeClassical;

    impl crate::ClassicalScheme for FakeClassical {
        const NAME: &'static str = "stub";
        const PUBLIC_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 1;
        const SIGNATURE_LEN: usize = encoding_path::CLASSICAL_SIG_LEN;

        fn derive(_seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
            sk_out.fill(1);
            pk_out.fill(2);
            Ok(())
        }
        fn sign(
            _sk: &[u8],
            _msg: &[u8],
            _label: &'static [u8],
            _rng: &mut impl rand_core::CryptoRngCore,
            sig_out: &mut [u8],
        ) -> Result<()> {
            sig_out.fill(3);
            Ok(())
        }
        fn sign_deterministic(
            _sk: &[u8],
            _msg: &[u8],
            _nonce: &[u8],
            _label: &'static [u8],
            sig_out: &mut [u8],
        ) -> Result<()> {
            sig_out.fill(3);
            Ok(())
        }
        fn verify(_pk: &[u8], _msg: &[u8], _label: &'static [u8], sig: &[u8]) -> Choice {
            // `sign`/`sign_deterministic` above always fill the signature
            // with `3`; accept only that, so a tampered byte is actually
            // detectable (needed by
            // `verify_evaluates_the_post_quantum_half_even_when_the_classical_half_fails`).
            Choice::from(u8::from(sig.iter().all(|&b| b == 3)))
        }
    }

    crate::hybrid_stateful_suite! {
        FakeH,
        classical = FakeClassical as "stub",
        pq = FakePq as "fake",
        label = "hybrid-stub-fake-v1",
        label_len = 20,
    }

    #[derive(Default)]
    struct JournalState {
        committed: Vec<u32>,
    }
    struct MemoryJournal(Rc<RefCell<JournalState>>);
    impl LeafJournal for MemoryJournal {
        type Error = core::convert::Infallible;
        fn commit(&mut self, leaf: u32) -> core::result::Result<(), Self::Error> {
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

    #[test]
    fn precheck_failure_burns_no_leaf() {
        let (mut sk, _pk) = keygen::<FakeH>(&[1u8; 32], 4).expect("keygen");
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = MemoryJournal(Rc::clone(&state));

        // `0xFF` as the first message byte is rigged, in `FakePq::precheck`
        // above, to fail. A real message can never trigger this class of
        // failure (see the module doc on why), but the driver's ordering
        // guarantee does not care why `precheck` failed -- only that it
        // runs first.
        let outcome = FakeH::sign_stateful(&mut sk, &mut journal, &[0xFFu8], b"");

        assert_eq!(outcome, Err(StatefulSignError::SigningFailed));
        assert!(state.borrow().committed.is_empty(), "no leaf was committed");
        assert_eq!(journal.next_leaf(), 0, "no leaf was consumed");
    }

    #[test]
    fn successful_signing_advances_both_counters_together() {
        let (mut sk, _pk) = keygen::<FakeH>(&[2u8; 32], 4).expect("keygen");
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = MemoryJournal(Rc::clone(&state));

        FakeH::sign_stateful(&mut sk, &mut journal, b"ok", b"").expect("sign");
        assert_eq!(state.borrow().committed, alloc::vec![0]);
        assert_eq!(<FakePq as crate::PqStatefulScheme>::next_leaf(&sk.pq), 1);
    }

    /// The two halves must combine without a short circuit: a failed
    /// classical half must not skip evaluating the post-quantum half,
    /// because that timing difference would tell an attacker which
    /// component rejected.
    #[test]
    fn verify_evaluates_the_post_quantum_half_even_when_the_classical_half_fails() {
        let (mut sk, pk) = keygen::<FakeH>(&[9u8; 32], 4).expect("keygen");
        let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
        let sig = FakeH::sign_stateful(&mut sk, &mut journal, b"ok", b"").expect("sign");

        let mut tampered = sig.clone();
        tampered[0] ^= 0x01; // corrupt the classical half only

        let before = VERIFY_STATEFUL_CALLS.load(Ordering::SeqCst);
        let outcome = FakeH::verify(&pk, b"ok", b"", &tampered);
        let after = VERIFY_STATEFUL_CALLS.load(Ordering::SeqCst);

        assert!(!outcome, "a tampered classical half must fail verification");
        assert!(
            after > before,
            "verify_stateful must run even though the classical half already failed"
        );
    }
}
