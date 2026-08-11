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
///
/// [`keygen`] and [`SecretKey::import`] are the only two ways to obtain one.
/// [`SecretKey::export`] is the persistence path a stateful signer needs:
/// restoring a signer by re-running [`keygen`] on the master seed resets the
/// leaf counter and reissues leaves the key already spent.
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

/// Width of the leaf-counter field inside an exported [`SecretKey`].
const COUNTER_FIELD_LEN: usize = 4;

impl<S: StatefulSuite> SecretKey<S> {
    /// Length of the blob [`SecretKey::export`] produces and
    /// [`SecretKey::import`] accepts.
    ///
    /// The layout is
    ///
    /// ```text
    /// ClassicalSK || PqSecretKey || nextLeaf(4, big-endian) || PqVerifyKey
    /// ```
    ///
    /// The first two fields are the composite secret key itself
    /// ([`StatefulSuite::SECRET_KEY_LEN`] bytes); the trailer carries the
    /// state and the cached public verify key that [`keygen`] would
    /// otherwise be the only source of.
    pub fn exported_len() -> usize {
        <S::Classical as ClassicalScheme>::SECRET_KEY_LEN
            + <S::Pq as PqStatefulScheme>::SECRET_KEY_LEN
            + COUNTER_FIELD_LEN
            + <S::Pq as PqStatefulScheme>::VERIFY_KEY_LEN
    }

    /// Serialize this key, its post-quantum half, and the leaf counter as one
    /// blob, so the parts cannot be restored out of step with each other.
    ///
    /// The result is secret material. It carries the classical secret key and
    /// the post-quantum secret key in the clear; the caller owns wiping it
    /// (`zeroize`) and protecting it at rest.
    ///
    /// Persisting this blob is the **only** correct way to restore a stateful
    /// signer. Re-running [`keygen`] from the master seed rebuilds the same
    /// key with the counter back at the first leaf, and every leaf the
    /// original spent would then be issued a second time.
    ///
    /// # Errors
    ///
    /// [`Error::ComponentFailure`] if the component's own export fails. That
    /// is what a wiped key ([`Zeroize::zeroize`]) reports:
    /// [`PqStatefulScheme::export_secret_key`] is required to fail on wiped
    /// material rather than hand back zeros, and this function has no other
    /// way to tell wiped material from live material.
    pub fn export(&self) -> Result<Vec<u8>> {
        let classical_len = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
        let pq_len = <S::Pq as PqStatefulScheme>::SECRET_KEY_LEN;
        // Defensive: both fields are fixed-width by construction (`keygen`
        // and `import` are the only two ways to build this type), so a
        // mismatch means the invariant is already broken. Refuse rather than
        // index past the end.
        if self.classical.len() != classical_len
            || self.pq_verify_key.len() != <S::Pq as PqStatefulScheme>::VERIFY_KEY_LEN
        {
            return Err(Error::ComponentFailure);
        }

        let mut out = alloc::vec![0u8; Self::exported_len()];
        out[..classical_len].copy_from_slice(&self.classical);
        if let Err(e) = <S::Pq as PqStatefulScheme>::export_secret_key(
            &self.pq,
            &mut out[classical_len..][..pq_len],
        ) {
            out.zeroize();
            return Err(e);
        }
        let counter_at = classical_len + pq_len;
        let next_leaf = <S::Pq as PqStatefulScheme>::next_leaf(&self.pq);
        out[counter_at..counter_at + COUNTER_FIELD_LEN].copy_from_slice(&next_leaf.to_be_bytes());
        out[counter_at + COUNTER_FIELD_LEN..].copy_from_slice(&self.pq_verify_key);
        Ok(out)
    }

    /// Rebuild a key from [`SecretKey::export`] output, rejecting a blob whose
    /// parts do not belong together.
    ///
    /// This is the only way to reconstruct a [`SecretKey`] other than
    /// [`keygen`], because the type is deliberately not `Clone`.
    ///
    /// **An export followed by two imports is a forked leaf budget.** Two
    /// restored keys hold the same counter and will spend the same one-time
    /// leaves on different messages, which is the exact failure that makes a
    /// stateful hash-based key insecure. Treat the exported blob as a
    /// single-holder token: import it once, and destroy the blob (or keep it
    /// only as a backup that is never imported while another holder is live).
    ///
    /// Validation has two layers. The component validates its own half (see
    /// [`PqStatefulScheme::import_secret_key`]: for a real component this
    /// re-derives the public part from the private part, so a tampered or
    /// spliced blob and an out-of-range counter are rejected). This function
    /// then checks the counter field against the counter the imported
    /// component key actually holds, so a blob whose recorded state disagrees
    /// with its key material is refused rather than restored.
    ///
    /// The cached verify key is public data and is taken as given: pairing a
    /// valid secret key with a different key's verify key produces a signer
    /// whose signatures do not verify, but it cannot cause leaf reuse.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if `bytes` is not [`SecretKey::exported_len`]
    /// bytes. [`Error::ComponentFailure`] if the component rejects its half,
    /// or if the counter field disagrees with it.
    pub fn import(bytes: &[u8]) -> Result<Self> {
        let expected = Self::exported_len();
        if bytes.len() != expected {
            return Err(Error::BadLength {
                expected,
                actual: bytes.len(),
            });
        }
        let classical_len = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
        let pq_len = <S::Pq as PqStatefulScheme>::SECRET_KEY_LEN;
        let counter_at = classical_len + pq_len;

        let mut pq =
            <S::Pq as PqStatefulScheme>::import_secret_key(&bytes[classical_len..][..pq_len])?;

        let recorded = u32::from_be_bytes(
            bytes[counter_at..counter_at + COUNTER_FIELD_LEN]
                .try_into()
                .map_err(|_| Error::ComponentFailure)?,
        );
        if recorded != <S::Pq as PqStatefulScheme>::next_leaf(&pq) {
            pq.zeroize();
            return Err(Error::ComponentFailure);
        }

        Ok(Self {
            classical: bytes[..classical_len].to_vec(),
            pq,
            pq_verify_key: bytes[counter_at + COUNTER_FIELD_LEN..].to_vec(),
        })
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
    /// Mirrors the real component's shape: the material lives in an
    /// `Option` so that `zeroize` can take it, and every accessor fails
    /// closed once it is gone. Without that, a wiped fake would be
    /// indistinguishable from a fresh one and could not stand in for a wiped
    /// key in the export test.
    #[derive(Default)]
    pub struct FakeSecretKey {
        leaf: Option<u32>,
    }

    impl zeroize::Zeroize for FakeSecretKey {
        fn zeroize(&mut self) {
            if let Some(leaf) = self.leaf.as_mut() {
                leaf.zeroize();
            }
            self.leaf = None;
        }
    }

    pub struct FakePq;

    impl crate::PqStatefulScheme for FakePq {
        const NAME: &'static str = "fake";
        const SEED_LEN: usize = 1;
        const PUBLIC_KEY_LEN: usize = 1;
        const VERIFY_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 4;
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
            Ok(FakeSecretKey { leaf: Some(0) })
        }
        fn leaf_capacity(sk: &Self::SecretKey) -> u32 {
            // A wiped key has no budget left, matching the real component.
            sk.leaf.map_or(0, |_| 4)
        }
        fn next_leaf(sk: &Self::SecretKey) -> u32 {
            sk.leaf.unwrap_or(0)
        }
        fn export_secret_key(sk: &Self::SecretKey, out: &mut [u8]) -> Result<()> {
            if out.len() != Self::SECRET_KEY_LEN {
                return Err(Error::BadLength {
                    expected: Self::SECRET_KEY_LEN,
                    actual: out.len(),
                });
            }
            let leaf = sk.leaf.ok_or(Error::ComponentFailure)?;
            out.copy_from_slice(&leaf.to_be_bytes());
            Ok(())
        }
        fn import_secret_key(bytes: &[u8]) -> Result<Self::SecretKey> {
            let raw: [u8; 4] = bytes.try_into().map_err(|_| Error::BadLength {
                expected: Self::SECRET_KEY_LEN,
                actual: bytes.len(),
            })?;
            let leaf = u32::from_be_bytes(raw);
            // Stand-in for a real component's re-derivation check. The fake
            // budget is a fixed 4, so 4 (exhausted) is the largest counter a
            // signer can reach and anything above it is out of range.
            if leaf > 4 {
                return Err(Error::ComponentFailure);
            }
            Ok(FakeSecretKey { leaf: Some(leaf) })
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
            sk.leaf = Some(sk.leaf.ok_or(Error::ComponentFailure)? + 1);
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

    /// Offset of the 4-byte leaf-counter field inside an exported
    /// `SecretKey<FakeH>`, per the layout documented on
    /// `SecretKey::exported_len`.
    const FAKE_COUNTER_AT: usize = <FakeClassical as crate::ClassicalScheme>::SECRET_KEY_LEN
        + <FakePq as crate::PqStatefulScheme>::SECRET_KEY_LEN;

    #[test]
    fn export_import_round_trip_carries_every_part_of_the_key() {
        let (mut sk, pk) = keygen::<FakeH>(&[3u8; 32], 4).expect("keygen");
        let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
        FakeH::sign_stateful(&mut sk, &mut journal, b"one", b"").expect("sign");
        FakeH::sign_stateful(&mut sk, &mut journal, b"two", b"").expect("sign");

        let blob = sk.export().expect("export");
        assert_eq!(blob.len(), SecretKey::<FakeH>::exported_len());

        let mut restored = SecretKey::<FakeH>::import(&blob).expect("import");
        assert_eq!(
            <FakePq as crate::PqStatefulScheme>::next_leaf(&restored.pq),
            2,
            "the restored key resumes at the leaf the original stopped at"
        );
        assert_eq!(restored.classical, sk.classical);
        assert_eq!(restored.pq_verify_key, sk.pq_verify_key);

        // Import then export is byte-identical, so the blob is a stable
        // record of the state and not a re-encoding that drifts.
        assert_eq!(restored.export().expect("export"), blob);

        // The restored key is a working signer: it continues the journal it
        // left off with, rather than starting the budget over.
        let sig = FakeH::sign_stateful(&mut restored, &mut journal, b"three", b"").expect("sign");
        assert!(FakeH::verify(&pk, b"three", b"", &sig));
        assert_eq!(journal.next_leaf(), 3);
    }

    /// The exhausted counter is the one value a restore must not round down:
    /// a key that reports a fresh budget is a key that reissues every leaf.
    #[test]
    fn export_import_preserves_the_exhausted_counter() {
        let (mut sk, _pk) = keygen::<FakeH>(&[4u8; 32], 4).expect("keygen");
        let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
        for msg in [b"a".as_slice(), b"b", b"c", b"d"] {
            FakeH::sign_stateful(&mut sk, &mut journal, msg, b"").expect("sign");
        }
        let capacity = <FakePq as crate::PqStatefulScheme>::leaf_capacity(&sk.pq);
        assert_eq!(
            <FakePq as crate::PqStatefulScheme>::next_leaf(&sk.pq),
            capacity,
            "the budget is spent"
        );

        let restored = SecretKey::<FakeH>::import(&sk.export().expect("export")).expect("import");
        assert_eq!(
            <FakePq as crate::PqStatefulScheme>::next_leaf(&restored.pq),
            capacity
        );

        // And the restored key stays exhausted: the driver refuses to sign.
        let mut restored = restored;
        assert!(FakeH::sign_stateful(&mut restored, &mut journal, b"e", b"").is_err());
    }

    /// The counter field and the component key are two records of the same
    /// state. If they disagree, the blob was edited, and importing it would
    /// restore a signer whose state nobody vouches for.
    #[test]
    fn import_rejects_a_counter_field_that_disagrees_with_the_component_key() {
        let (mut sk, _pk) = keygen::<FakeH>(&[5u8; 32], 4).expect("keygen");
        let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
        FakeH::sign_stateful(&mut sk, &mut journal, b"one", b"").expect("sign");
        let blob = sk.export().expect("export");

        for rewritten in [0u32, 2, u32::MAX] {
            let mut tampered = blob.clone();
            tampered[FAKE_COUNTER_AT..FAKE_COUNTER_AT + 4]
                .copy_from_slice(&rewritten.to_be_bytes());
            assert_eq!(
                SecretKey::<FakeH>::import(&tampered).err(),
                Some(Error::ComponentFailure),
                "counter field rewritten to {rewritten} must be rejected"
            );
        }
    }

    /// The component's own validation must be reachable through the composite
    /// import, not bypassed by it.
    #[test]
    fn import_propagates_the_components_rejection_of_its_own_half() {
        let (sk, _pk) = keygen::<FakeH>(&[6u8; 32], 4).expect("keygen");
        let mut blob = sk.export().expect("export");

        // Out of range for the fake component's fixed budget of 4. Written to
        // both the component half and the counter field, so the only check
        // that can reject it is the component's.
        let out_of_range = 5u32.to_be_bytes();
        blob[FAKE_COUNTER_AT - 4..FAKE_COUNTER_AT].copy_from_slice(&out_of_range);
        blob[FAKE_COUNTER_AT..FAKE_COUNTER_AT + 4].copy_from_slice(&out_of_range);

        assert_eq!(
            SecretKey::<FakeH>::import(&blob).err(),
            Some(Error::ComponentFailure)
        );
    }

    #[test]
    fn import_rejects_a_blob_of_the_wrong_length() {
        let (sk, _pk) = keygen::<FakeH>(&[7u8; 32], 4).expect("keygen");
        let blob = sk.export().expect("export");
        let expected = SecretKey::<FakeH>::exported_len();

        assert_eq!(
            SecretKey::<FakeH>::import(&blob[..blob.len() - 1]).err(),
            Some(Error::BadLength {
                expected,
                actual: expected - 1
            })
        );

        let mut long = blob.clone();
        long.push(0);
        assert_eq!(
            SecretKey::<FakeH>::import(&long).err(),
            Some(Error::BadLength {
                expected,
                actual: expected + 1
            })
        );
        assert_eq!(
            SecretKey::<FakeH>::import(&[]).err(),
            Some(Error::BadLength {
                expected,
                actual: 0
            })
        );
    }

    /// A wiped key must fail to export rather than export a well-formed blob
    /// of zeros, which would import as a key with a counter no signer reached.
    #[test]
    fn a_wiped_key_fails_to_export() {
        let (mut sk, _pk) = keygen::<FakeH>(&[8u8; 32], 4).expect("keygen");
        assert!(sk.export().is_ok());
        sk.zeroize();
        assert_eq!(sk.export().err(), Some(Error::ComponentFailure));
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
