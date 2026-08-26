// SPDX-License-Identifier: AGPL-3.0-or-later
//! Generic composite signing, verification and keygen for any
//! [`StatefulSuite`].
//!
//! This module is where a stateful hybrid suite (EdSh, SrSh, ...) becomes a real
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

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::budget::{spend_stateless_budget, StatelessBudgetStore};
use crate::encoding_path::{self, PathBody, PathProfile, PathSelectedSig, TrustedMaxSignatures};
use crate::stateful::{
    sign_after_commit, KeyIdentity, LeafJournal, StatefulHybridSignatureScheme, StatefulSignError,
};
use crate::{
    component::{ClassicalScheme, PqStatefulScheme},
    derive::derive_component_seeds,
    error::{Error, Result},
    message::m_prime,
    suite::StatefulSuite,
};

/// The verify-key-sized composite public key: `ClassicalPK ||
/// PqVerifyKey`, length [`StatefulSuite::VERIFY_PUBLIC_KEY_LEN`].
///
/// This is the form [`StatefulHybridSignatureScheme::verify_stateful`] and
/// [`StatefulHybridSignatureScheme::verify_stateless`] need. The
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

    /// Reconstruct a public key from its wire bytes (`ClassicalPK ||
    /// PqVerifyKey`, [`StatefulSuite::VERIFY_PUBLIC_KEY_LEN`] bytes),
    /// **checking nothing but the length**.
    ///
    /// This function performs no commitment validation. It cannot: the only
    /// thing it is given is the key itself, and a key cannot vouch for
    /// itself. Whatever `PqVerifyKey` the caller passes becomes the key the
    /// signature is verified against, so a caller who takes those bytes from
    /// the wire verifies against whichever key the sender chose. For a
    /// component whose stored form is a commitment -- SHRINCS for EdSh and SrSh
    /// -- that is the whole of the post-quantum guarantee, and the composite
    /// then reduces to its classical half alone.
    ///
    /// Use [`from_stored_commitment_and_bundle`](Self::from_stored_commitment_and_bundle)
    /// instead wherever the verify key arrives from an untrusted source. It
    /// is the documented constructor for verification. This one is correct
    /// only for bytes the caller already trusts: the value [`keygen`] handed
    /// back, or a verify key read from the caller's own storage.
    ///
    /// The length check is the only validation, matching
    /// [`crate::composite::verify`] and [`crate::composite_delta::verify`]:
    /// a garbled public key produces a value that fails verification, rather
    /// than an error that would need its own channel.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if `bytes` is not
    /// [`StatefulSuite::VERIFY_PUBLIC_KEY_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != S::VERIFY_PUBLIC_KEY_LEN {
            return Err(Error::BadLength {
                expected: S::VERIFY_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _suite: PhantomData,
        })
    }

    /// The identity a [`crate::stateful::LeafJournal`] records for this key.
    ///
    /// The same value [`SecretKey::key_identity`] returns for the matching
    /// secret key, derived from this key's own public material alone. A
    /// verifier, an operator or a provisioning tool can compute it without
    /// ever holding the secret key, which is what makes it usable as a name:
    /// an identity only the signer could compute would be a secret, not an
    /// identity.
    #[must_use]
    pub fn key_identity(&self) -> KeyIdentity {
        KeyIdentity::derive(S::LABEL, self.pq_verify_key())
    }
}

/// A post-quantum component whose small stored public key
/// ([`PqStatefulScheme::PUBLIC_KEY_LEN`]) is a commitment to its larger
/// verify key ([`PqStatefulScheme::VERIFY_KEY_LEN`]), and which can prove
/// that one belongs to the other.
///
/// Separate from [`PqStatefulScheme`] because it describes the shape of a
/// component's key material, not its signing: a component whose stored and
/// verify forms are the same bytes has nothing to prove and does not
/// implement this. Implementing it is what makes
/// [`PublicKey::from_stored_commitment_and_bundle`] available for a suite.
pub trait CommittedVerifyKey: PqStatefulScheme {
    /// Prove that `verify_key` is the key `stored_public_key` commits to.
    ///
    /// `stored_public_key` is the trusted side of this comparison and the
    /// only trusted side: it is what a verifier installed and holds, of
    /// length [`PqStatefulScheme::PUBLIC_KEY_LEN`]. `verify_key` is
    /// untrusted, of length [`PqStatefulScheme::VERIFY_KEY_LEN`].
    ///
    /// An implementation must recompute the commitment from `verify_key`'s
    /// own key material and compare the result against `stored_public_key`.
    /// A commitment that `verify_key` carries inside itself proves only that
    /// the key is internally consistent, which every self-generated key is,
    /// including one an attacker generated; it must never stand in for
    /// `stored_public_key`.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if either argument is not its component's
    /// declared length. [`Error::ComponentFailure`] if `verify_key` is not
    /// the key `stored_public_key` commits to, which includes an
    /// uninstalled (for example all-zero) `stored_public_key` that no key
    /// may ever match.
    fn verify_committed_key(stored_public_key: &[u8], verify_key: &[u8]) -> Result<()>;

    /// Compute the stored form `verify_key` commits to.
    ///
    /// The inverse of [`verify_committed_key`](Self::verify_committed_key):
    /// what this writes is exactly what that accepts for the same key. It
    /// exists so a caller who holds only the verify form can produce the
    /// stored form to install, without knowing where a component keeps its
    /// commitment. Slicing at a hard-coded offset is the alternative, and
    /// it puts component layout into application code.
    ///
    /// `out` receives [`PqStatefulScheme::PUBLIC_KEY_LEN`] bytes.
    ///
    /// This computes; it does not verify. The result is trustworthy only
    /// insofar as `verify_key` is: a caller who computes a stored form from
    /// an attacker-supplied verify key and then installs it has installed
    /// the attacker's key. Install a stored form obtained out of band, and
    /// use [`verify_committed_key`](Self::verify_committed_key) to check a
    /// verify key against it.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if `verify_key` is not
    /// [`PqStatefulScheme::VERIFY_KEY_LEN`] bytes or `out` is not
    /// [`PqStatefulScheme::PUBLIC_KEY_LEN`] bytes.
    /// [`Error::ComponentFailure`] if `verify_key` is malformed.
    fn compute_committed_key(verify_key: &[u8], out: &mut [u8]) -> Result<()>;
}

impl<S: StatefulSuite> PublicKey<S>
where
    S::Pq: CommittedVerifyKey,
{
    /// Build a verify-form public key from the stored key a verifier holds
    /// and an untrusted post-quantum verify key, failing closed unless the
    /// second is the key the first commits to.
    ///
    /// This is the constructor to use at verification time. It is the one
    /// place the trust boundary is crossed, and it is crossed in one
    /// direction only:
    ///
    /// * `stored_public_key` is trusted. It is the small on-storage form,
    ///   `ClassicalPK || PqStoredKey` ([`StatefulSuite::STORED_PUBLIC_KEY_LEN`]
    ///   bytes), read from the verifier's own storage -- an account record, a
    ///   registry entry, a pinned configuration file.
    /// * `pq_verify_key` is untrusted. It is the larger post-quantum verify
    ///   key ([`PqStatefulScheme::VERIFY_KEY_LEN`] bytes) that the signer
    ///   supplies alongside the signature, because it is too large to store.
    ///
    /// The commitment is recomputed from `pq_verify_key` and matched against
    /// the stored one ([`CommittedVerifyKey::verify_committed_key`]) before
    /// this returns. The classical half of the result is copied from
    /// `stored_public_key`, never from anything the signer supplied, so a
    /// caller cannot substitute a classical key either.
    ///
    /// Contrast [`from_bytes`](Self::from_bytes), which takes a whole
    /// verify-form key and checks only its length. Given an attacker's own
    /// freshly generated key, `from_bytes` produces a public key that
    /// verifies the attacker's own signatures perfectly well, because
    /// nothing in it refers to what the verifier installed. This constructor
    /// is what ties the key on the wire to the key on the account.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if `stored_public_key` is not
    /// [`StatefulSuite::STORED_PUBLIC_KEY_LEN`] bytes or `pq_verify_key` is
    /// not [`PqStatefulScheme::VERIFY_KEY_LEN`] bytes.
    /// [`Error::ComponentFailure`] if `pq_verify_key` is not the key
    /// `stored_public_key` commits to.
    pub fn from_stored_commitment_and_bundle(
        stored_public_key: &[u8],
        pq_verify_key: &[u8],
    ) -> Result<Self> {
        if stored_public_key.len() != S::STORED_PUBLIC_KEY_LEN {
            return Err(Error::BadLength {
                expected: S::STORED_PUBLIC_KEY_LEN,
                actual: stored_public_key.len(),
            });
        }
        let verify_key_len = <S::Pq as PqStatefulScheme>::VERIFY_KEY_LEN;
        if pq_verify_key.len() != verify_key_len {
            return Err(Error::BadLength {
                expected: verify_key_len,
                actual: pq_verify_key.len(),
            });
        }

        // Split rather than index: `PqStatefulScheme` is a public trait, so
        // the two lengths this offset is composed from come from an
        // implementation this module does not control.
        let classical_len = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
        let (classical_pk, stored_pq) = stored_public_key
            .split_at_checked(classical_len)
            .ok_or(Error::ComponentFailure)?;

        <S::Pq as CommittedVerifyKey>::verify_committed_key(stored_pq, pq_verify_key)?;

        let mut bytes = Vec::with_capacity(classical_len + verify_key_len);
        bytes.extend_from_slice(classical_pk);
        bytes.extend_from_slice(pq_verify_key);
        Ok(Self {
            bytes,
            _suite: PhantomData,
        })
    }

    /// The stored form of this key: the classical public key followed by the
    /// component's commitment.
    ///
    /// This is the form a verifier installs, and the form
    /// [`from_stored_commitment_and_bundle`](Self::from_stored_commitment_and_bundle)
    /// takes as its trusted side. Computing it here is what keeps component
    /// layout out of application code: the alternative is slicing the
    /// classical prefix and the commitment at an offset the caller has to
    /// know.
    ///
    /// This computes; it does not verify. `self` is whatever verify key its
    /// caller built it from, and this method trusts that key completely: it
    /// is not this method's job to ask whether `self` is the key a verifier
    /// should be installing. A caller who computes a stored form from an
    /// attacker-supplied verify key and then installs it has installed the
    /// attacker's key. Call this only on a key you already trust -- one
    /// [`keygen`] handed back, or one read from your own storage -- and
    /// never on a verify key that arrived from the wire or from an
    /// untrusted peer.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] or [`Error::ComponentFailure`] as
    /// [`CommittedVerifyKey::compute_committed_key`] reports them.
    pub fn stored_form(&self) -> Result<Vec<u8>> {
        let classical = self.classical();
        let mut out =
            alloc::vec![0u8; classical.len() + <S::Pq as PqStatefulScheme>::PUBLIC_KEY_LEN];
        out[..classical.len()].copy_from_slice(classical);
        <S::Pq as CommittedVerifyKey>::compute_committed_key(
            self.pq_verify_key(),
            &mut out[classical.len()..],
        )?;
        Ok(out)
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

/// Wipe the key when it goes out of scope.
///
/// `zeroize::Zeroize` generates no destructor, so without this impl every
/// drop left `classical` -- the 32-byte ed25519 seed for EdSh, the 64-byte
/// sr25519 secret for SrSh -- in freed heap verbatim. The post-quantum half
/// survived only by accident, because the component's own key halves are
/// `ZeroizeOnDrop` upstream.
///
/// Wiping on drop rather than asking callers to remember is the only form
/// that holds: a `SecretKey` is dropped on every early return, every `?`,
/// and every panic unwind, and none of those paths can be made to call
/// `zeroize` by hand.
impl<S: StatefulSuite> Drop for SecretKey<S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Asserts the guarantee [`Drop`] above provides, so a caller can rely on it
/// through the bound rather than by reading this module.
impl<S: StatefulSuite> ZeroizeOnDrop for SecretKey<S> {}

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

    /// The classical secret key bytes.
    ///
    /// `pub(crate)`, not `pub`: the only caller outside this module is
    /// `crate::rotation`, which needs both component secret keys directly to
    /// sign a rotation's two component signatures over `M'_rotation` rather
    /// than the ordinary `M'` this type's other methods build.
    pub(crate) fn classical_bytes(&self) -> &[u8] {
        &self.classical
    }

    /// The cached post-quantum verify key.
    ///
    /// Public material, and the bytes
    /// [`PqStatefulScheme::stateless_key_material`] reads the few-time
    /// budget's key out of. `pub(crate)` on the same grounds as
    /// [`Self::classical_bytes`]: `crate::rotation` needs it to charge a
    /// rotation authorization against the pre-rotation material, and letting
    /// a caller supply that material instead is precisely how the charge
    /// would end up aimed at the wrong key.
    pub(crate) fn pq_verify_key(&self) -> &[u8] {
        &self.pq_verify_key
    }

    /// The post-quantum component secret key. See [`Self::classical_bytes`]
    /// for why this is exposed and to whom.
    pub(crate) fn pq_secret_key(&self) -> &<S::Pq as PqStatefulScheme>::SecretKey {
        &self.pq
    }

    /// The next unused leaf this key will spend.
    ///
    /// Read this after [`Self::import`] and compare it against the journal
    /// the key will sign with. The two must agree: a key restored from an
    /// older blob than the journal has already recorded will try to reissue
    /// leaves the journal says are spent.
    ///
    /// The driver also checks this at signing time, but only as an opaque
    /// failure. Reconciling at restore time fails loudly, while there is
    /// still an operator watching.
    pub fn next_leaf(&self) -> u32 {
        <S::Pq as PqStatefulScheme>::next_leaf(&self.pq)
    }

    /// The identity of the journal that belongs to this key.
    ///
    /// Derived from the cached post-quantum verify key and the suite label --
    /// public material only, so this discloses nothing about the secret half
    /// and is the same value [`PublicKey::key_identity`] returns for the
    /// matching public key.
    ///
    /// Pass it to [`crate::stateful::adopt_key`] once, when the key's durable
    /// journal is first created. Every later signature checks it, and a
    /// journal that does not carry it is refused with
    /// [`StatefulSignError::JournalKeyMismatch`].
    #[must_use]
    pub fn key_identity(&self) -> KeyIdentity {
        KeyIdentity::derive(S::LABEL, &self.pq_verify_key)
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

        // No message validation runs here, deliberately. Every attempt to
        // sign burns a leaf, including an attempt that the component will
        // refuse. A signing path that can return without advancing the
        // counter is a leaf-reuse hazard, and reuse is total security
        // failure for the key, while a burned leaf is only availability
        // loss. `precheck` therefore belongs on the stateless path and in
        // `verify`, never in front of this commit.

        // Identity before counters. The lockstep check below compares two
        // numbers, and two numbers can only be compared once it is settled
        // that they count the same thing: a journal bound to another key -- or
        // to none -- reports a counter for some other budget, and `0 == 0`
        // between a fresh journal and an unspent key is precisely the
        // agreement that used to let one key's leaves be spent twice.
        //
        // `sign_after_commit` runs the same check again, and deliberately: it
        // is the reference flow an out-of-tree scheme drives, and the
        // guarantee has to hold there without this driver's cooperation. The
        // repeated `bound_key` read is the price of checking it here too,
        // where the error can still be reported as the mismatch it is rather
        // than as the counter divergence the next few lines would call it.
        let identity = sk.key_identity();
        crate::stateful::require_bound_key(journal, identity)?;

        let leaf_capacity = <S::Pq as PqStatefulScheme>::leaf_capacity(&sk.pq);
        let pq_next = <S::Pq as PqStatefulScheme>::next_leaf(&sk.pq);
        // The component's own leaf counter and the caller's durable
        // `LeafJournal` are two independent counters that must stay in
        // lockstep: both only ever advance together, through this
        // function. Any drift means the journal and the in-memory key came
        // from different sessions, or that a component failure landed after
        // the journal had already committed the leaf below -- in which case
        // the journal is one ahead and stays there. Either way signing must
        // not proceed.
        //
        // Named rather than folded into `SigningFailed`: the divergence is
        // permanent and the only remedy is rotating the key, so an operator
        // who sees the generic "signing failed" would keep retrying a key
        // that can never sign again.
        if pq_next != journal.next_leaf() {
            return Err(StatefulSignError::CountersDiverged);
        }

        let classical_sig = classical_sign(sk, &m_prime, ctx)?;

        let pq_verify_key = sk.pq_verify_key.clone();
        let max_sig_len = <S::Pq as PqStatefulScheme>::max_stateful_sig_len(leaf_capacity);
        let pq = &mut sk.pq;
        let flat = sign_after_commit(journal, identity, u64::from(leaf_capacity), move |_leaf| {
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

        // `PqStatefulScheme` is a public trait, so the component is an
        // extension point an out-of-tree implementation can occupy. Neither
        // arithmetic below may assume it reported a well-formed length: a
        // bare subtraction panics in debug and wraps in release when the
        // component returns fewer bytes than its own fixed prefix, and a
        // remainder that is not a whole number of nodes would silently round
        // the leaf count down to a signature nobody can verify.
        let fixed = <S::Pq as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN;
        let path_bytes = flat
            .len()
            .checked_sub(fixed)
            .ok_or(StatefulSignError::SigningFailed)?;
        if path_bytes % encoding_path::AUTH_PATH_NODE_LEN != 0 {
            return Err(StatefulSignError::SigningFailed);
        }
        let leaf_count = u32::try_from(path_bytes / encoding_path::AUTH_PATH_NODE_LEN)
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
        budget: &mut impl StatelessBudgetStore,
        msg: &[u8],
        ctx: &[u8],
    ) -> core::result::Result<Self::Signature, StatefulSignError> {
        let m_prime = m_prime(S::LABEL, ctx, msg).map_err(|_| StatefulSignError::SigningFailed)?;
        if !<S::Pq as PqStatefulScheme>::precheck(&m_prime) {
            return Err(StatefulSignError::SigningFailed);
        }

        // The spend goes here, after validation and before the component
        // signer runs. Validation first, because a unit of this budget never
        // comes back while the stateless material survives, so an input the
        // component was always going to reject must not cost one. The
        // component signer second, because a stateless signature released
        // before its spend is durable is a signature a restart can reissue --
        // the same reason `sign_stateful` commits its leaf before it builds.
        let material = <S::Pq as PqStatefulScheme>::stateless_key_material(&sk.pq_verify_key)
            .map_err(|_| StatefulSignError::SigningFailed)?;
        spend_stateless_budget(
            budget,
            material,
            <S::Pq as PqStatefulScheme>::STATELESS_BUDGET,
        )?;

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

    fn verify_stateful(
        pk: &Self::PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &Self::Signature,
    ) -> bool {
        let Some((m_prime, decoded)) = decode_for_verify::<S>(pk, msg, ctx, sig) else {
            return false;
        };
        // Step 3 of `encoding_path`'s decode order, seen from the caller
        // that has already committed to one path: a selector naming the
        // other path is refused here, before either component signature is
        // checked, and the refusal does not depend on whether `signature`
        // below would itself have verified. This is what keeps the
        // stateless path out of reach of a caller who asked for the
        // stateful one, as specification section 20.2 requires for ordinary
        // application messages.
        let PathBody::Stateful { signature, .. } = decoded.body else {
            return false;
        };
        verify_components::<S>(
            pk,
            &m_prime,
            &decoded,
            signature,
            <S::Pq as PqStatefulScheme>::verify_stateful,
        )
    }

    fn verify_stateless(
        pk: &Self::PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &Self::Signature,
    ) -> bool {
        let Some((m_prime, decoded)) = decode_for_verify::<S>(pk, msg, ctx, sig) else {
            return false;
        };
        // The mirror image of the check in `verify_stateful`: a selector
        // naming the stateful path is refused before any cryptography runs.
        let PathBody::Stateless { signature } = decoded.body else {
            return false;
        };
        verify_components::<S>(
            pk,
            &m_prime,
            &decoded,
            signature,
            <S::Pq as PqStatefulScheme>::verify_stateless,
        )
    }
}

/// Shared preamble for [`StatefulHybridSignatureScheme::verify_stateful`]
/// and [`verify_stateless`](StatefulHybridSignatureScheme::verify_stateless):
/// build `M'`, run the component precheck, and decode the wire signature far
/// enough to read its `PathSelector`.
///
/// Returns `None` for anything that fails before a path is even known -- a
/// malformed `ctx`/`msg` pairing, a precheck rejection, or an undecodable
/// signature -- so both callers treat that the same as "reject", without
/// needing to know why.
fn decode_for_verify<'a, S: StatefulSuite>(
    pk: &PublicKey<S>,
    msg: &[u8],
    ctx: &[u8],
    sig: &'a [u8],
) -> Option<(Vec<u8>, PathSelectedSig<'a>)> {
    let m_prime = m_prime(S::LABEL, ctx, msg).ok()?;
    if !<S::Pq as PqStatefulScheme>::precheck(&m_prime) {
        return None;
    }

    // Step 2 of `encoding_path`'s decode order. The bound is read out of
    // the verify key the *verifier* holds, which is the only
    // `maxSignatures` in reach that the signature under test cannot
    // choose. The component knows where the field lives inside `vk`; the
    // generic layer only names which key to ask.
    //
    // `pk` is what a caller installed. When that caller built it with
    // `PublicKey::from_stored_commitment_and_bundle`, the stored
    // commitment binds every byte of the bundle, this field included.
    // When they built it with `from_bytes`, the whole key is theirs to
    // choose and the signature verifies against it either way, so
    // reading the bound from it concedes nothing new.
    //
    // The value is the wire `LeafCount` bound: one-based, so `1..=max`
    // is the accepted range.
    let max_signatures =
        <S::Pq as PqStatefulScheme>::max_signatures_from_vk(pk.pq_verify_key()).ok()?;
    let trusted_max = TrustedMaxSignatures::from_verified_bundle(max_signatures);
    let decoded =
        encoding_path::decode_path_selected(sig, trusted_max, &path_profile::<S>()).ok()?;
    Some((m_prime, decoded))
}

/// Verify the classical half of `decoded` against `m_prime`, and the
/// post-quantum half of `component_signature` against `m_prime` through
/// `verify_pq`, combining the two by bitwise AND.
///
/// Called only once the caller has already matched `decoded.body` against
/// the path it asked for, so by this point both halves are always checked:
/// no short circuit stands between them, and neither the result nor the
/// running time reveals which one rejected. Mirrors `composite::verify`.
fn verify_components<S: StatefulSuite>(
    pk: &PublicKey<S>,
    m_prime: &[u8],
    decoded: &PathSelectedSig<'_>,
    component_signature: &[u8],
    verify_pq: impl FnOnce(&[u8], &[u8], &[u8]) -> subtle::Choice,
) -> bool {
    let classical_ok = <S::Classical as ClassicalScheme>::verify(
        pk.classical(),
        m_prime,
        S::LABEL,
        &decoded.classical[..],
    );
    let pq_ok = verify_pq(pk.pq_verify_key(), m_prime, component_signature);
    bool::from(classical_ok & pq_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::test_store::MemoryStore;
    use crate::budget::BudgetKey;
    use crate::stateful::LeafJournal;
    use alloc::rc::Rc;
    use core::cell::{Cell, RefCell};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use subtle::Choice;

    // Both counters below are thread-local, not global, and that is the whole
    // point of them. `FakePq` and `FakeSecretKey` are unit structs with no
    // instance to hang state off, and many tests in this module drive them.
    // A process-global counter therefore mixes calls from tests that cargo is
    // running in parallel on other threads, which makes any assertion about
    // an exact value or an absence of calls fail for reasons unrelated to
    // what it tests. A `#[test]` body runs on one thread and drives these
    // fakes synchronously, so a thread-local counter observes that test's own
    // calls and nothing else.
    std::thread_local! {
        /// Counts calls into `FakePq::verify_stateful` made by the current
        /// test, so a test can prove the post-quantum half is evaluated even
        /// when the classical half already failed (no short circuit), or that
        /// it is never reached at all.
        static VERIFY_STATEFUL_CALLS: Cell<usize> = const { Cell::new(0) };

        /// Counts calls into `FakeSecretKey::zeroize` made by the current
        /// test. Dropping a `SecretKey` is the only way a test can observe
        /// that the wipe ran, because reading the freed buffer afterwards is
        /// undefined behaviour.
        static COMPONENT_WIPES: Cell<usize> = const { Cell::new(0) };
    }

    /// Read a thread-local call counter.
    fn counter(slot: &'static std::thread::LocalKey<Cell<usize>>) -> usize {
        slot.with(Cell::get)
    }

    /// Add one to a thread-local call counter.
    fn bump(slot: &'static std::thread::LocalKey<Cell<usize>>) {
        slot.with(|n| n.set(n.get() + 1));
    }

    // A minimal fake `PqStatefulScheme` + `StatefulSuite`, to prove the
    // generic driver's ordering (commit the leaf, then attempt the
    // component signature, so a refused message still burns its leaf)
    // without any real cryptography. A real component cannot be driven
    // into this state through its public API, because a real component
    // accepts every message an honest caller can construct.
    /// Mirrors the real component's shape: the material lives in an
    /// `Option` so that `zeroize` can take it, and every accessor fails
    /// closed once it is gone. Without that, a wiped fake would be
    /// indistinguishable from a fresh one and could not stand in for a wiped
    /// key in the export test.
    #[derive(Default)]
    pub struct FakeSecretKey {
        leaf: Option<u32>,
    }

    impl Zeroize for FakeSecretKey {
        fn zeroize(&mut self) {
            bump(&COMPONENT_WIPES);
            if let Some(leaf) = self.leaf.as_mut() {
                leaf.zeroize();
            }
            self.leaf = None;
        }
    }

    pub struct FakePq;

    impl PqStatefulScheme for FakePq {
        const NAME: &'static str = "fake";
        const SEED_LEN: usize = 1;
        const PUBLIC_KEY_LEN: usize = 1;
        const VERIFY_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 4;
        const LEAF_CAPACITY_LIMIT: u32 = 8;
        const FIXED_STATEFUL_SIG_LEN: usize = 0;
        const STATELESS_SIG_LEN: usize = 1;
        const STATELESS_BUDGET: u64 = 4;

        type SecretKey = FakeSecretKey;

        fn keygen_from_seed(
            seed: &[u8],
            _max_signatures: u32,
            vk_out: &mut [u8],
        ) -> Result<Self::SecretKey> {
            // Seed-dependent, as a real component's verify key is: two master
            // seeds must not produce the same verify key, or every key would
            // share one `KeyIdentity` and the identity tests would pass
            // vacuously. One byte is all `VERIFY_KEY_LEN` allows, so the
            // seeds the tests use are chosen not to collide in it.
            vk_out.fill(seed.first().copied().unwrap_or(0));
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
        fn max_signatures_from_vk(verify_key: &[u8]) -> Result<u32> {
            if verify_key.len() != Self::VERIFY_KEY_LEN {
                return Err(Error::BadLength {
                    expected: Self::VERIFY_KEY_LEN,
                    actual: verify_key.len(),
                });
            }
            // The fake's leaf budget is a fixed 4 (see `leaf_capacity`), and
            // its one-byte verify key carries no `maxSignatures` field to
            // read it out of. A real bound, deliberately not `u32::MAX`: a
            // fake that returned the widest value would reproduce the very
            // defect this method removes, inside the test suite, and make
            // `verify_rejects_a_leaf_count_beyond_the_key_declared_bound`
            // vacuous.
            Ok(4)
        }
        fn sign_stateful(
            sk: &mut Self::SecretKey,
            _vk: &[u8],
            msg: &[u8],
            sig_out: &mut [u8],
        ) -> Result<usize> {
            let leaf = sk.leaf.ok_or(Error::ComponentFailure)?;
            if !Self::precheck(msg) {
                return Err(Error::ComponentFailure);
            }
            // The counter advances only on success, mirroring upstream's
            // `sign_stateful_raw`. A fake that advanced unconditionally
            // would hide the counter divergence a post-commit component
            // failure actually causes.
            sk.leaf = Some(leaf + 1);
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
            bump(&VERIFY_STATEFUL_CALLS);
            Choice::from(1u8)
        }
        fn verify_stateless(_vk: &[u8], _msg: &[u8], _sig: &[u8]) -> Choice {
            Choice::from(1u8)
        }
        // This module's tests never exercise the rotation gate (see
        // `rotation.rs` for that); these two are here only to satisfy the
        // trait.
        fn sign_stateless_rotation(
            _sk: &Self::SecretKey,
            _payload: &crate::rotation::RotationPayload,
            _m_prime_rotation: &[u8],
            sig_out: &mut [u8],
        ) -> Result<usize> {
            sig_out.fill(0);
            Ok(1)
        }
        fn verify_stateless_rotation(
            _vk: &[u8],
            _payload: &crate::rotation::RotationPayload,
            _m_prime_rotation: &[u8],
            _sig: &[u8],
        ) -> Choice {
            Choice::from(1u8)
        }
        fn stateless_key_material(vk: &[u8]) -> Result<&[u8]> {
            Ok(vk)
        }
    }

    /// A stand-in commitment: one byte, and deliberately not the identity,
    /// so a test cannot pass by handing the verify key back as its own
    /// commitment -- the exact confusion the real defect was.
    fn fake_commitment(verify_key: &[u8]) -> Result<u8> {
        match verify_key {
            [byte] => Ok(byte.wrapping_add(1)),
            _ => Err(Error::BadLength {
                expected: <FakePq as PqStatefulScheme>::VERIFY_KEY_LEN,
                actual: verify_key.len(),
            }),
        }
    }

    impl CommittedVerifyKey for FakePq {
        fn verify_committed_key(stored_public_key: &[u8], verify_key: &[u8]) -> Result<()> {
            let recomputed = fake_commitment(verify_key)?;
            match stored_public_key {
                [stored] if *stored == recomputed => Ok(()),
                [_] => Err(Error::ComponentFailure),
                _ => Err(Error::BadLength {
                    expected: Self::PUBLIC_KEY_LEN,
                    actual: stored_public_key.len(),
                }),
            }
        }

        // Mirrors `fake_commitment` exactly, so whatever this writes is what
        // `verify_committed_key` above accepts. A fake that computed
        // something else would make the accessor's round-trip tests pass for
        // the wrong reason.
        fn compute_committed_key(verify_key: &[u8], out: &mut [u8]) -> Result<()> {
            if out.len() != Self::PUBLIC_KEY_LEN {
                return Err(Error::BadLength {
                    expected: Self::PUBLIC_KEY_LEN,
                    actual: out.len(),
                });
            }
            out[0] = fake_commitment(verify_key)?;
            Ok(())
        }
    }

    /// Minimal stand-in `ClassicalScheme`, local to this test module: the
    /// real `Ed25519`/`Sr25519` live in a downstream crate this crate does
    /// not depend on, and `component::tests::Stub` is private to its own
    /// module.
    #[derive(Clone, Copy, Debug)]
    pub struct FakeClassical;

    impl ClassicalScheme for FakeClassical {
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
        rotate_label = "hybrid-stub-fake-rotate-v1",
        rotate_label_len = 27,
    }

    /// How many bytes `RaggedPq::sign_stateful` claims to have written.
    ///
    /// `PqStatefulScheme` is public, so an out-of-tree component can report
    /// any length at all -- including one shorter than its own declared
    /// fixed prefix, or one whose remainder is not a whole number of
    /// authentication-path nodes. The driver has to survive both, and this
    /// is the only way to produce them: no honest component does.
    static RAGGED_REPORTED_LEN: AtomicUsize = AtomicUsize::new(0);

    /// A `PqStatefulScheme` that misreports its own signature length. Every
    /// method other than `sign_stateful` is a stub; only the reported length
    /// matters here.
    pub struct RaggedPq;

    impl PqStatefulScheme for RaggedPq {
        const NAME: &'static str = "ragged";
        const SEED_LEN: usize = 1;
        const PUBLIC_KEY_LEN: usize = 1;
        const VERIFY_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 4;
        const LEAF_CAPACITY_LIMIT: u32 = 8;
        /// Non-zero, unlike `FakePq`'s, so a reported length below it
        /// underflows the driver's `len - fixed` unless the driver checks.
        const FIXED_STATEFUL_SIG_LEN: usize = 64;
        const STATELESS_SIG_LEN: usize = 1;
        const STATELESS_BUDGET: u64 = 4;

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
            sk.leaf.map_or(0, |_| 4)
        }
        fn next_leaf(sk: &Self::SecretKey) -> u32 {
            sk.leaf.unwrap_or(0)
        }
        fn export_secret_key(_sk: &Self::SecretKey, _out: &mut [u8]) -> Result<()> {
            Err(Error::ComponentFailure)
        }
        fn import_secret_key(_bytes: &[u8]) -> Result<Self::SecretKey> {
            Err(Error::ComponentFailure)
        }
        fn precheck(_msg: &[u8]) -> bool {
            true
        }
        fn max_stateful_sig_len(max_signatures: u32) -> usize {
            Self::FIXED_STATEFUL_SIG_LEN
                + max_signatures as usize * encoding_path::AUTH_PATH_NODE_LEN
        }
        fn max_signatures_from_vk(_verify_key: &[u8]) -> Result<u32> {
            // A real bound, for the same reason `FakePq`'s is one: never
            // `u32::MAX`. This fake's tests only reach the signing path, so
            // the exact value does not matter beyond that.
            Ok(4)
        }
        fn sign_stateful(
            sk: &mut Self::SecretKey,
            _vk: &[u8],
            _msg: &[u8],
            sig_out: &mut [u8],
        ) -> Result<usize> {
            sk.leaf = Some(sk.leaf.ok_or(Error::ComponentFailure)? + 1);
            let written = RAGGED_REPORTED_LEN.load(Ordering::SeqCst);
            sig_out.fill(0);
            Ok(written)
        }
        fn sign_stateless(_sk: &Self::SecretKey, _msg: &[u8], sig_out: &mut [u8]) -> Result<usize> {
            sig_out.fill(0);
            Ok(1)
        }
        fn verify_stateful(_vk: &[u8], _msg: &[u8], _sig: &[u8]) -> Choice {
            Choice::from(1u8)
        }
        fn verify_stateless(_vk: &[u8], _msg: &[u8], _sig: &[u8]) -> Choice {
            Choice::from(1u8)
        }
        fn sign_stateless_rotation(
            _sk: &Self::SecretKey,
            _payload: &crate::rotation::RotationPayload,
            _m_prime_rotation: &[u8],
            sig_out: &mut [u8],
        ) -> Result<usize> {
            sig_out.fill(0);
            Ok(1)
        }
        fn verify_stateless_rotation(
            _vk: &[u8],
            _payload: &crate::rotation::RotationPayload,
            _m_prime_rotation: &[u8],
            _sig: &[u8],
        ) -> Choice {
            Choice::from(1u8)
        }
        fn stateless_key_material(vk: &[u8]) -> Result<&[u8]> {
            Ok(vk)
        }
    }

    crate::hybrid_stateful_suite! {
        RaggedH,
        classical = FakeClassical as "stub",
        pq = RaggedPq as "ragged",
        label = "hybrid-stub-ragged-v1",
        label_len = 22,
        rotate_label = "hybrid-stub-ragged-rotate-v1",
        rotate_label_len = 29,
    }

    #[derive(Default)]
    struct JournalState {
        committed: Vec<u32>,
        bound: Option<KeyIdentity>,
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
        fn bound_key(&self) -> Option<KeyIdentity> {
            self.0.borrow().bound
        }
        fn bind_key(&mut self, key: KeyIdentity) -> core::result::Result<(), Self::Error> {
            self.0.borrow_mut().bound = Some(key);
            Ok(())
        }
    }

    /// A fresh journal, already adopted by `sk`: what an integrator does once,
    /// when the key's durable journal is created. Every test below that is
    /// not about identity starts here, so the identity check is satisfied and
    /// the behaviour under test is the only thing that can fail.
    fn adopted_journal<S: StatefulSuite>(
        state: &Rc<RefCell<JournalState>>,
        sk: &SecretKey<S>,
    ) -> MemoryJournal {
        let mut journal = MemoryJournal(Rc::clone(state));
        crate::stateful::adopt_key(&mut journal, sk.key_identity()).expect("adopt");
        journal
    }

    #[test]
    fn a_refused_message_still_burns_its_leaf() {
        let (mut sk, _pk) = keygen::<FakeH>(&[1u8; 32], 4).expect("keygen");
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = adopted_journal(&state, &sk);

        // `0xFF` anywhere in the message is rigged, in `FakePq`, to be
        // refused by the component after it has already spent the leaf. A
        // real message cannot trigger this class of failure (see the module
        // comment on why), but the property under test does not care why
        // the attempt failed -- only that the leaf is gone either way.
        let outcome = FakeH::sign_stateful(&mut sk, &mut journal, &[0xFFu8], b"");

        assert_eq!(outcome, Err(StatefulSignError::GrindAbort));
        assert_eq!(
            state.borrow().committed,
            alloc::vec![0],
            "the leaf was committed before the attempt, so it is spent"
        );
        assert_eq!(journal.next_leaf(), 1, "the journal advanced");

        // The component, like the real one, advances only on success, so a
        // failure after the commit leaves the journal one ahead. That is
        // fail-closed but permanent, and the operator has to be told which
        // of the two it is: every later call names the divergence rather
        // than reporting an opaque `SigningFailed` forever.
        assert_eq!(
            <FakePq as PqStatefulScheme>::next_leaf(&sk.pq),
            0,
            "the component did not spend the leaf the journal committed"
        );
        assert_eq!(
            FakeH::sign_stateful(&mut sk, &mut journal, b"next", b""),
            Err(StatefulSignError::CountersDiverged),
            "the key is finished, and says so by name"
        );
    }

    /// A component that misreports its own signature length must produce an
    /// error, never a debug panic and never a release wraparound.
    ///
    /// Both cases run through the same key, one after the other, because
    /// each attempt spends a leaf and the point is only what the driver
    /// returns.
    #[test]
    fn a_component_that_misreports_its_signature_length_is_refused() {
        let fixed = <RaggedPq as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN;
        let node = encoding_path::AUTH_PATH_NODE_LEN;

        let (mut sk, _pk) = keygen::<RaggedH>(&[12u8; 32], 4).expect("keygen");
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);

        // Shorter than the component's own fixed prefix: the subtraction
        // that derives the leaf count would underflow.
        RAGGED_REPORTED_LEN.store(fixed - 1, Ordering::SeqCst);
        assert_eq!(
            RaggedH::sign_stateful(&mut sk, &mut journal, b"short", b""),
            Err(StatefulSignError::SigningFailed)
        );

        // Long enough, but the authentication path is a ragged number of
        // nodes: rounding it down would encode a leaf count that describes
        // fewer bytes than the signature actually carries.
        RAGGED_REPORTED_LEN.store(fixed + node + 1, Ordering::SeqCst);
        assert_eq!(
            RaggedH::sign_stateful(&mut sk, &mut journal, b"ragged", b""),
            Err(StatefulSignError::SigningFailed)
        );

        // The same driver accepts a whole number of nodes, so the two
        // refusals above are the length checks firing and not the path
        // being unusable for some other reason.
        RAGGED_REPORTED_LEN.store(fixed + node, Ordering::SeqCst);
        assert!(RaggedH::sign_stateful(&mut sk, &mut journal, b"whole", b"").is_ok());
    }

    /// The pqhs-aww reproduction at the generic layer: one key, two journals
    /// that have each recorded nothing, two different messages. Both journals
    /// truthfully report that leaf `0` is next, so no counter comparison can
    /// separate them -- only the binding can.
    ///
    /// Every leaf index here is signer-side and zero-based
    /// (`LeafJournal::next_leaf`), not the one-based wire `LeafCount`.
    #[test]
    fn a_journal_that_never_adopted_this_key_cannot_spend_its_leaves() {
        let (mut sk, _pk) = keygen::<FakeH>(&[21u8; 32], 4).expect("keygen");

        // The key's own journal, adopted once when it was provisioned.
        let owned_state = Rc::new(RefCell::new(JournalState::default()));
        let mut owned = adopted_journal(&owned_state, &sk);
        FakeH::sign_stateful(&mut sk, &mut owned, b"message one", b"").expect("sign");
        assert_eq!(owned_state.borrow().committed, alloc::vec![0]);

        // A second, independent journal. It has committed nothing, so its
        // counter says leaf 0 -- and so did the key's, one signature ago.
        let fresh_state = Rc::new(RefCell::new(JournalState::default()));
        let mut fresh = MemoryJournal(Rc::clone(&fresh_state));
        assert_eq!(
            fresh.next_leaf(),
            0,
            "the fresh journal agrees with a fresh key"
        );
        assert_eq!(fresh.bound_key(), None, "and it belongs to no key");

        let restored = SecretKey::<FakeH>::import(&sk.export().expect("export")).expect("import");
        let mut restored = restored;
        assert_eq!(
            FakeH::sign_stateful(&mut restored, &mut fresh, b"message two", b""),
            Err(StatefulSignError::JournalKeyMismatch)
        );
        assert!(
            fresh_state.borrow().committed.is_empty(),
            "the refusal lands before any leaf is committed"
        );
    }

    /// A journal adopted by one key must refuse the other, both ways round.
    #[test]
    fn a_journal_bound_to_one_key_refuses_the_other() {
        let (mut a_key, _a_pk) = keygen::<FakeH>(&[22u8; 32], 4).expect("keygen");
        let (mut b_key, _b_pk) = keygen::<FakeH>(&[23u8; 32], 4).expect("keygen");
        assert_ne!(a_key.key_identity(), b_key.key_identity());

        let a_state = Rc::new(RefCell::new(JournalState::default()));
        let b_state = Rc::new(RefCell::new(JournalState::default()));
        let mut a_journal = adopted_journal(&a_state, &a_key);
        let mut b_journal = adopted_journal(&b_state, &b_key);

        assert_eq!(
            FakeH::sign_stateful(&mut a_key, &mut b_journal, b"msg", b""),
            Err(StatefulSignError::JournalKeyMismatch)
        );
        assert_eq!(
            FakeH::sign_stateful(&mut b_key, &mut a_journal, b"msg", b""),
            Err(StatefulSignError::JournalKeyMismatch)
        );
        assert!(a_state.borrow().committed.is_empty());
        assert!(b_state.borrow().committed.is_empty());

        // Each key signs through its own journal, so the two refusals above
        // are the binding and not something else refusing every call.
        assert!(FakeH::sign_stateful(&mut a_key, &mut a_journal, b"msg", b"").is_ok());
        assert!(FakeH::sign_stateful(&mut b_key, &mut b_journal, b"msg", b"").is_ok());
    }

    /// The identity is derived from public material, so the public key alone
    /// yields it. An integrator provisioning a journal record therefore never
    /// has to handle the secret key to do it.
    #[test]
    fn the_public_key_names_the_same_identity_as_the_secret_key() {
        let (sk, pk) = keygen::<FakeH>(&[24u8; 32], 4).expect("keygen");
        assert_eq!(sk.key_identity(), pk.key_identity());

        // And it survives export/import, so a restarted signer names the same
        // journal it named before.
        let restored = SecretKey::<FakeH>::import(&sk.export().expect("export")).expect("import");
        assert_eq!(restored.key_identity(), sk.key_identity());
    }

    /// Identity binding is layered on top of the counter check, not in place
    /// of it: an adopted journal whose counter has drifted still reports the
    /// divergence.
    #[test]
    fn the_lockstep_counter_check_still_fires_on_an_adopted_journal() {
        let (mut sk, _pk) = keygen::<FakeH>(&[25u8; 32], 4).expect("keygen");
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = adopted_journal(&state, &sk);

        // `0xFF` is rigged in `FakePq` to fail after the leaf is committed,
        // which leaves the journal one ahead of the key.
        assert_eq!(
            FakeH::sign_stateful(&mut sk, &mut journal, &[0xFFu8], b""),
            Err(StatefulSignError::GrindAbort)
        );
        assert_eq!(journal.next_leaf(), 1);
        assert_eq!(<FakePq as PqStatefulScheme>::next_leaf(&sk.pq), 0);

        assert_eq!(
            FakeH::sign_stateful(&mut sk, &mut journal, b"next", b""),
            Err(StatefulSignError::CountersDiverged),
            "the right journal with the wrong counter is still a divergence"
        );
    }

    #[test]
    fn successful_signing_advances_both_counters_together() {
        let (mut sk, _pk) = keygen::<FakeH>(&[2u8; 32], 4).expect("keygen");
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = adopted_journal(&state, &sk);

        FakeH::sign_stateful(&mut sk, &mut journal, b"ok", b"").expect("sign");
        assert_eq!(state.borrow().committed, alloc::vec![0]);
        assert_eq!(<FakePq as PqStatefulScheme>::next_leaf(&sk.pq), 1);
    }

    /// Offset of the 4-byte leaf-counter field inside an exported
    /// `SecretKey<FakeH>`, per the layout documented on
    /// `SecretKey::exported_len`.
    const FAKE_COUNTER_AT: usize = <FakeClassical as ClassicalScheme>::SECRET_KEY_LEN
        + <FakePq as PqStatefulScheme>::SECRET_KEY_LEN;

    #[test]
    fn export_import_round_trip_carries_every_part_of_the_key() {
        let (mut sk, pk) = keygen::<FakeH>(&[3u8; 32], 4).expect("keygen");
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);
        FakeH::sign_stateful(&mut sk, &mut journal, b"one", b"").expect("sign");
        FakeH::sign_stateful(&mut sk, &mut journal, b"two", b"").expect("sign");

        let blob = sk.export().expect("export");
        assert_eq!(blob.len(), SecretKey::<FakeH>::exported_len());

        let mut restored = SecretKey::<FakeH>::import(&blob).expect("import");
        assert_eq!(
            <FakePq as PqStatefulScheme>::next_leaf(&restored.pq),
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
        assert!(FakeH::verify_stateful(&pk, b"three", b"", &sig));
        assert_eq!(journal.next_leaf(), 3);
    }

    /// The exhausted counter is the one value a restore must not round down:
    /// a key that reports a fresh budget is a key that reissues every leaf.
    #[test]
    fn export_import_preserves_the_exhausted_counter() {
        let (mut sk, _pk) = keygen::<FakeH>(&[4u8; 32], 4).expect("keygen");
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);
        for msg in [b"a".as_slice(), b"b", b"c", b"d"] {
            FakeH::sign_stateful(&mut sk, &mut journal, msg, b"").expect("sign");
        }
        let capacity = <FakePq as PqStatefulScheme>::leaf_capacity(&sk.pq);
        assert_eq!(
            <FakePq as PqStatefulScheme>::next_leaf(&sk.pq),
            capacity,
            "the budget is spent"
        );

        let restored = SecretKey::<FakeH>::import(&sk.export().expect("export")).expect("import");
        assert_eq!(
            <FakePq as PqStatefulScheme>::next_leaf(&restored.pq),
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
    fn next_leaf_lets_an_integrator_reconcile_a_restored_key() {
        let (mut sk, _pk) = keygen::<FakeH>(&[7u8; 32], 4).expect("keygen");
        assert_eq!(sk.next_leaf(), 0, "a fresh key has spent nothing");

        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = adopted_journal(&state, &sk);
        FakeH::sign_stateful(&mut sk, &mut journal, b"one", b"").expect("sign");
        FakeH::sign_stateful(&mut sk, &mut journal, b"two", b"").expect("sign");
        assert_eq!(sk.next_leaf(), 2);
        assert_eq!(
            sk.next_leaf(),
            journal.next_leaf(),
            "the restored key and its journal must agree, which is what an \
             integrator checks at restore time"
        );

        let blob = sk.export().expect("export");
        let restored = SecretKey::<FakeH>::import(&blob).expect("import");
        assert_eq!(
            restored.next_leaf(),
            2,
            "the counter survives the round trip"
        );
    }

    #[test]
    fn import_rejects_a_counter_field_that_disagrees_with_the_component_key() {
        let (mut sk, _pk) = keygen::<FakeH>(&[5u8; 32], 4).expect("keygen");
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);
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

    /// `from_bytes` round-trips a public key's wire bytes and rejects the
    /// wrong length, mirroring `SecretKey::import`'s length check.
    #[test]
    fn public_key_from_bytes_round_trips_and_rejects_bad_length() {
        let (_sk, pk) = keygen::<FakeH>(&[10u8; 32], 4).expect("keygen");

        let rebuilt = PublicKey::<FakeH>::from_bytes(pk.as_ref()).expect("from_bytes");
        assert_eq!(rebuilt.as_ref(), pk.as_ref());

        let expected = <FakeH as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN;
        assert_eq!(
            PublicKey::<FakeH>::from_bytes(&pk.as_ref()[..pk.as_ref().len() - 1]).err(),
            Some(Error::BadLength {
                expected,
                actual: expected - 1
            })
        );
    }

    /// The stored-commitment constructor must refuse a verify key that the
    /// stored key does not name, and `from_bytes` must be shown taking the
    /// same key without complaint -- the difference between the two is the
    /// whole of the guarantee.
    #[test]
    fn from_stored_commitment_and_bundle_refuses_a_key_the_stored_key_does_not_name() {
        let classical_len = <FakeClassical as ClassicalScheme>::PUBLIC_KEY_LEN;
        let (_sk, pk) = keygen::<FakeH>(&[13u8; 32], 4).expect("keygen");
        let verify_key = &pk.as_ref()[classical_len..];

        // What a verifier installs: the classical public key and a
        // commitment to the post-quantum verify key, never the verify key
        // itself.
        let mut stored = alloc::vec![0u8; <FakeH as StatefulSuite>::STORED_PUBLIC_KEY_LEN];
        stored[..classical_len].copy_from_slice(&pk.as_ref()[..classical_len]);
        stored[classical_len] = fake_commitment(verify_key).expect("commitment");

        let rebuilt = PublicKey::<FakeH>::from_stored_commitment_and_bundle(&stored, verify_key)
            .expect("the installed key's own verify key must be accepted");
        assert_eq!(rebuilt.as_ref(), pk.as_ref());
        assert_eq!(
            rebuilt.classical(),
            &stored[..classical_len],
            "the classical half comes from the stored key"
        );

        // A key an attacker generated: internally consistent, and accepted
        // against its own stored key, because there is nothing wrong with it
        // except whose it is.
        let attacker_verify_key = [0xAAu8];
        let attacker_stored = alloc::vec![
            stored[0],
            fake_commitment(&attacker_verify_key).expect("commitment"),
        ];
        assert!(PublicKey::<FakeH>::from_stored_commitment_and_bundle(
            &attacker_stored,
            &attacker_verify_key
        )
        .is_ok());

        // Against the victim's stored key it fails closed.
        assert_eq!(
            PublicKey::<FakeH>::from_stored_commitment_and_bundle(&stored, &attacker_verify_key)
                .err(),
            Some(Error::ComponentFailure),
        );

        // `from_bytes` accepts the attacker's key as a whole verify-form
        // public key, because a key cannot vouch for itself and `from_bytes`
        // has nothing else to compare it against.
        let mut attacker_bytes = alloc::vec![0u8; <FakeH as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN];
        attacker_bytes[..classical_len].copy_from_slice(&pk.as_ref()[..classical_len]);
        attacker_bytes[classical_len..].copy_from_slice(&attacker_verify_key);
        assert!(PublicKey::<FakeH>::from_bytes(&attacker_bytes).is_ok());
    }

    #[test]
    fn from_stored_commitment_and_bundle_rejects_either_wrong_length() {
        let stored_len = <FakeH as StatefulSuite>::STORED_PUBLIC_KEY_LEN;
        let verify_key_len = <FakePq as PqStatefulScheme>::VERIFY_KEY_LEN;
        let stored = alloc::vec![0u8; stored_len];
        let verify_key = alloc::vec![0u8; verify_key_len];

        assert_eq!(
            PublicKey::<FakeH>::from_stored_commitment_and_bundle(
                &stored[..stored_len - 1],
                &verify_key
            )
            .err(),
            Some(Error::BadLength {
                expected: stored_len,
                actual: stored_len - 1
            })
        );
        assert_eq!(
            PublicKey::<FakeH>::from_stored_commitment_and_bundle(&stored, &[]).err(),
            Some(Error::BadLength {
                expected: verify_key_len,
                actual: 0
            })
        );
    }

    /// The computed stored form must be exactly what the checking side
    /// accepts. These two are inverses, and a commitment that
    /// `verify_committed_key` rejects would make the accessor worse than the
    /// manual slicing it replaces -- callers would install a value that
    /// never verifies.
    #[test]
    fn the_computed_stored_form_is_the_one_verification_accepts() {
        let (_sk, pk) = keygen::<FakeH>(&[7u8; 32], 4).expect("keygen");

        let stored = pk
            .stored_form()
            .expect("a committed suite computes its stored form");

        assert_eq!(
            stored.len(),
            <FakeH as StatefulSuite>::STORED_PUBLIC_KEY_LEN
        );
        <FakePq as CommittedVerifyKey>::verify_committed_key(
            &stored[pk.classical().len()..],
            pk.pq_verify_key(),
        )
        .expect("the computed commitment must verify against the key it came from");
    }

    /// A commitment computed from one key must not verify another. Without
    /// this the test above would still pass for a function that returns a
    /// constant.
    #[test]
    fn a_computed_stored_form_does_not_verify_another_key() {
        let (_sk_a, pk_a) = keygen::<FakeH>(&[7u8; 32], 4).expect("keygen a");
        let (_sk_b, pk_b) = keygen::<FakeH>(&[8u8; 32], 4).expect("keygen b");

        let stored_a = pk_a.stored_form().expect("stored form a");
        let stored_b = pk_b.stored_form().expect("stored form b");

        // Pins that `stored_form` is a function of its receiver: without
        // this, a `stored_form` that always returned the same constant bytes
        // would still pass the check below, since a constant does not
        // verify key B either.
        assert_ne!(
            stored_a, stored_b,
            "two different keys must not compute the same stored form"
        );

        assert!(
            <FakePq as CommittedVerifyKey>::verify_committed_key(
                &stored_a[pk_a.classical().len()..],
                pk_b.pq_verify_key(),
            )
            .is_err(),
            "one key's commitment must not accept another key"
        );
    }

    /// Dropping a key wipes it, without anybody remembering to ask.
    ///
    /// The classical half rides the same `self.zeroize()` call as the
    /// component half, so the component's wipe counter stands in for both:
    /// reading the freed `Vec<u8>` back to check it directly would be
    /// undefined behaviour.
    #[test]
    fn dropping_a_key_wipes_it() {
        let before = counter(&COMPONENT_WIPES);
        {
            let (_sk, _pk) = keygen::<FakeH>(&[11u8; 32], 4).expect("keygen");
        }
        assert!(
            counter(&COMPONENT_WIPES) > before,
            "the composite key's Drop must wipe the component half"
        );
    }

    /// The guarantee is visible in the type system, so a caller can rely on
    /// the bound instead of reading this module.
    #[test]
    fn the_secret_key_advertises_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretKey<FakeH>>();
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
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);
        let sig = FakeH::sign_stateful(&mut sk, &mut journal, b"ok", b"").expect("sign");

        let mut tampered = sig.clone();
        tampered[0] ^= 0x01; // corrupt the classical half only

        let before = counter(&VERIFY_STATEFUL_CALLS);
        let outcome = FakeH::verify_stateful(&pk, b"ok", b"", &tampered);
        let after = counter(&VERIFY_STATEFUL_CALLS);

        assert!(!outcome, "a tampered classical half must fail verification");
        assert!(
            after > before,
            "verify_stateful must run even though the classical half already failed"
        );
    }

    /// The decoder's range check must use the bound the verify key actually
    /// declares. Passing `u32::MAX` makes step 4 a no-op and leaves
    /// `TrustedMaxSignatures`' stated guarantee unbacked at its only real
    /// call site.
    ///
    /// Every leaf value here is the wire `LeafCount`: one-based, and the same
    /// space `max_signatures_from_vk` returns. The authentication path holds
    /// one node per leaf, so the node count and the leaf index are the same
    /// number. It is not the zero-based `LeafJournal` index, which is one
    /// less.
    ///
    /// The in-bound control matters as much as the rejection: without it,
    /// this test would still pass if the encoding were malformed for some
    /// reason having nothing to do with the bound.
    #[test]
    fn verify_rejects_a_leaf_count_beyond_the_key_declared_bound() {
        /// A well-formed stateful encoding declaring `leaf_count` path
        /// nodes, with a classical half `FakeClassical::verify` accepts. Only
        /// `LeafCount` varies between the two calls below.
        fn signature_declaring(leaf_count: u32) -> Vec<u8> {
            let classical = [3u8; encoding_path::CLASSICAL_SIG_LEN];
            let path = alloc::vec![0u8; leaf_count as usize * encoding_path::AUTH_PATH_NODE_LEN];
            encoding_path::encode_path_selected(
                &PathSelectedSig {
                    classical: &classical,
                    body: PathBody::Stateful {
                        leaf_count,
                        signature: &path,
                    },
                },
                &path_profile::<FakeH>(),
            )
            .expect("the encoder accepts any leaf count whose length fits")
        }

        let (_sk, pk) = keygen::<FakeH>(&[26u8; 32], 4).expect("keygen");
        let bound = <FakePq as PqStatefulScheme>::max_signatures_from_vk(pk.pq_verify_key())
            .expect("the fake declares a bound");
        assert!(
            bound < u32::MAX,
            "the fake must declare a real bound, otherwise this test proves nothing"
        );

        assert!(
            FakeH::verify_stateful(&pk, b"ok", b"", &signature_declaring(bound)),
            "a LeafCount at the key's declared bound must still be accepted"
        );
        assert!(
            !FakeH::verify_stateful(&pk, b"ok", b"", &signature_declaring(bound + 1)),
            "a LeafCount above the key's declared bound must be refused"
        );
    }

    // ------------------------------------------------------------------
    // `verify_stateful` and `verify_stateless` each accept only their own
    // wire path, rejected by `PathSelector` before any signature check.
    // ------------------------------------------------------------------

    /// A message signed on the stateful path verifies under
    /// `verify_stateful`, and is refused by `verify_stateless` even though
    /// the classical half is identical between the two calls.
    #[test]
    fn a_stateful_signed_message_verifies_only_under_verify_stateful() {
        let (mut sk, pk) = keygen::<FakeH>(&[30u8; 32], 4).expect("keygen");
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);
        let sig = FakeH::sign_stateful(&mut sk, &mut journal, b"ok", b"").expect("sign");

        assert!(
            FakeH::verify_stateful(&pk, b"ok", b"", &sig),
            "a stateful signature must verify through its own entry point"
        );
        assert!(
            !FakeH::verify_stateless(&pk, b"ok", b"", &sig),
            "a stateful signature must be refused by the stateless entry point"
        );
    }

    /// The mirror image: a message signed on the stateless path verifies
    /// under `verify_stateless` and is refused by `verify_stateful`.
    #[test]
    fn a_stateless_signed_message_verifies_only_under_verify_stateless() {
        let (sk, pk) = keygen::<FakeH>(&[31u8; 32], 4).expect("keygen");
        let mut budget = MemoryStore::default();
        let sig = FakeH::sign_stateless(&sk, &mut budget, b"ok", b"").expect("sign");

        assert!(
            FakeH::verify_stateless(&pk, b"ok", b"", &sig),
            "a stateless signature must verify through its own entry point"
        );
        assert!(
            !FakeH::verify_stateful(&pk, b"ok", b"", &sig),
            "a stateless signature must be refused by the stateful entry point"
        );
    }

    /// Flipping the wire `PathSelector` byte of an otherwise-valid stateful
    /// signature must make both entry points refuse it: `verify_stateful`
    /// because the selector no longer names its path, and `verify_stateless`
    /// because the relabeled body does not decode as one (the length a
    /// stateful body carries almost never matches the fixed length a
    /// stateless one requires).
    #[test]
    fn flipping_the_path_selector_byte_is_refused_by_both_entry_points() {
        let (mut sk, pk) = keygen::<FakeH>(&[32u8; 32], 4).expect("keygen");
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);
        let mut sig = FakeH::sign_stateful(&mut sk, &mut journal, b"ok", b"").expect("sign");
        assert!(
            FakeH::verify_stateful(&pk, b"ok", b"", &sig),
            "sanity: signs and verifies before tampering"
        );

        sig[encoding_path::CLASSICAL_SIG_LEN] = encoding_path::SELECTOR_STATELESS;

        assert!(
            !FakeH::verify_stateful(&pk, b"ok", b"", &sig),
            "a relabeled selector must not still name the stateful path"
        );
        assert!(
            !FakeH::verify_stateless(&pk, b"ok", b"", &sig),
            "a relabeled selector must not decode as a valid stateless body either"
        );
    }

    /// `verify_stateful`'s refusal of a stateless-path signature must not
    /// depend on whether that stateless signature was itself cryptographically
    /// valid: a garbled stateless signature and a genuine one are refused the
    /// same way, and neither reaches `PqStatefulScheme::verify_stateful` at
    /// all. If the selector check depended on the component result, a
    /// carefully crafted invalid signature could take a different path
    /// through this function than a valid one, which is exactly the timing
    /// side channel the selector-first ordering exists to close.
    #[test]
    fn verify_stateful_refuses_a_stateless_signature_without_running_the_stateful_component_check()
    {
        let (sk, pk) = keygen::<FakeH>(&[33u8; 32], 4).expect("keygen");
        let mut budget = MemoryStore::default();
        let valid = FakeH::sign_stateless(&sk, &mut budget, b"ok", b"").expect("sign");
        let mut invalid = valid.clone();
        // Corrupt the stateless component signature itself. `FakePq::verify_stateless`
        // always returns `Choice::from(1u8)` regardless of content, so this
        // byte flip cannot be what makes `invalid` fail -- the selector check
        // must be why both are refused.
        *invalid
            .last_mut()
            .expect("a stateless signature is non-empty") ^= 0xFF;

        let before = counter(&VERIFY_STATEFUL_CALLS);
        assert!(!FakeH::verify_stateful(&pk, b"ok", b"", &valid));
        assert!(!FakeH::verify_stateful(&pk, b"ok", b"", &invalid));
        let after = counter(&VERIFY_STATEFUL_CALLS);

        assert_eq!(
            before, after,
            "verify_stateful must reject a stateless-path signature by its selector alone, \
             never by running the stateful component check"
        );
    }

    /// The assertion above is an exact one: it reads the counter, makes two
    /// calls, and requires the count not to have moved. That only means
    /// anything if no other test can move the counter while it runs, and
    /// cargo runs tests in parallel. This pins the isolation the assertion
    /// rests on, so a later change back to a process-global counter fails
    /// here rather than as an intermittent failure somewhere else.
    #[test]
    fn a_fake_call_counter_is_private_to_the_thread_that_drove_it() {
        let before = counter(&VERIFY_STATEFUL_CALLS);

        let counted_elsewhere = std::thread::spawn(|| {
            bump(&VERIFY_STATEFUL_CALLS);
            counter(&VERIFY_STATEFUL_CALLS)
        })
        .join()
        .expect("the probe thread must not panic");

        assert_eq!(
            counted_elsewhere, 1,
            "the probe thread must see its own call, starting from its own zero"
        );
        assert_eq!(
            counter(&VERIFY_STATEFUL_CALLS),
            before,
            "a call counted on another thread must not be visible on this one"
        );
    }

    // ------------------------------------------------------------------
    // The few-time stateless budget (specification section 21).
    //
    // `FakePq::STATELESS_BUDGET` is 4 and `stateless_key_material` hands
    // back the whole (one-byte) verify key, so a whole budget is walkable
    // here in a way it never is against a real 2^20 component.
    // ------------------------------------------------------------------

    /// The budget key a given composite key's stateless material resolves
    /// to, so a test can read a store without repeating the derivation.
    fn budget_key_of(pk: &PublicKey<FakeH>) -> BudgetKey {
        BudgetKey::from_material(pk.pq_verify_key())
    }

    /// Every stateless signature must decrement the budget, and the count
    /// must be durable before the signature exists -- the stateless
    /// counterpart of committing the leaf before building.
    #[test]
    fn every_stateless_signature_decrements_the_budget() {
        let (sk, pk) = keygen::<FakeH>(&[20u8; 32], 4).expect("keygen");
        let mut budget = MemoryStore::default();
        let key = budget_key_of(&pk);

        assert_eq!(budget.consumed(&key), None, "a fresh key has spent nothing");

        for expected in 1..=3u64 {
            FakeH::sign_stateless(&sk, &mut budget, b"m", b"").expect("below the bound");
            assert_eq!(budget.consumed(&key), Some(expected));
        }
    }

    /// Ordinary application signing must never draw on this budget: the two
    /// bounds are separate, and a stateful signature that quietly charged
    /// the stateless one would exhaust a security assumption through the
    /// fast path it is meant to leave alone.
    #[test]
    fn stateful_signing_does_not_draw_on_the_stateless_budget() {
        let (mut sk, pk) = keygen::<FakeH>(&[21u8; 32], 4).expect("keygen");
        let mut journal = adopted_journal(&Rc::new(RefCell::new(JournalState::default())), &sk);
        // Never handed to anything: `sign_stateful` takes no budget store at
        // all, which is the strongest form the guarantee can take. This
        // store exists only to be read afterwards.
        let budget = MemoryStore::default();

        for _ in 0..3 {
            FakeH::sign_stateful(&mut sk, &mut journal, b"ok", b"").expect("stateful sign");
        }

        assert_eq!(
            budget.consumed(&budget_key_of(&pk)),
            None,
            "stateful signing must leave the stateless budget untouched"
        );
    }

    /// At the bound the signature is refused with the typed error, and the
    /// refused attempt records nothing: a bound that charged for the calls
    /// it rejected would be a bound that shrinks under retries.
    #[test]
    fn exceeding_the_budget_is_refused_and_the_refused_attempt_spends_nothing() {
        let (sk, pk) = keygen::<FakeH>(&[22u8; 32], 4).expect("keygen");
        let mut budget = MemoryStore::default();
        let key = budget_key_of(&pk);

        for _ in 0..4 {
            FakeH::sign_stateless(&sk, &mut budget, b"m", b"").expect("within the bound");
        }
        assert_eq!(budget.consumed(&key), Some(4));

        for _ in 0..3 {
            assert_eq!(
                FakeH::sign_stateless(&sk, &mut budget, b"m", b""),
                Err(StatefulSignError::StatelessBudgetExhausted)
            );
            assert_eq!(
                budget.consumed(&key),
                Some(4),
                "a refused attempt must record nothing"
            );
        }
    }

    /// A store that cannot make the spend durable must refuse the signature
    /// rather than release one whose spend a restart would forget, and the
    /// same unit must still be there once the fault is repaired.
    #[test]
    fn a_budget_store_failure_refuses_the_signature_and_records_nothing() {
        let (sk, pk) = keygen::<FakeH>(&[23u8; 32], 4).expect("keygen");
        let mut budget = MemoryStore::default();
        budget.fail = true;
        let key = budget_key_of(&pk);

        assert_eq!(
            FakeH::sign_stateless(&sk, &mut budget, b"m", b""),
            Err(StatefulSignError::BudgetStoreFailed)
        );
        assert_eq!(budget.consumed(&key), None);

        budget.fail = false;
        assert!(FakeH::sign_stateless(&sk, &mut budget, b"m", b"").is_ok());
        assert_eq!(budget.consumed(&key), Some(1));
    }

    /// Two keys with different stateless material must hold independent
    /// counts: one key's spending must never be charged to another's bound.
    #[test]
    fn two_keys_hold_independent_budgets() {
        let (sk_a, pk_a) = keygen::<FakeH>(&[24u8; 32], 4).expect("keygen a");
        let (sk_b, pk_b) = keygen::<FakeH>(&[25u8; 32], 4).expect("keygen b");
        assert_ne!(
            pk_a.pq_verify_key(),
            pk_b.pq_verify_key(),
            "the fake component must derive seed-dependent verify keys"
        );

        let mut budget = MemoryStore::default();
        FakeH::sign_stateless(&sk_a, &mut budget, b"m", b"").expect("a signs");
        FakeH::sign_stateless(&sk_a, &mut budget, b"m", b"").expect("a signs again");
        FakeH::sign_stateless(&sk_b, &mut budget, b"m", b"").expect("b signs");

        assert_eq!(budget.consumed(&budget_key_of(&pk_a)), Some(2));
        assert_eq!(budget.consumed(&budget_key_of(&pk_b)), Some(1));
    }
}
