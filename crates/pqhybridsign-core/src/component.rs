// SPDX-License-Identifier: AGPL-3.0-or-later
//! The classical and post-quantum component traits every hybrid suite
//! composes, and their stateful variant.

use crate::rotation::RotationPayload;
use crate::Result;
use subtle::Choice;

/// A classical signature component, for example ed25519 or sr25519.
///
/// Corresponds to the DH functions abstraction in the Noise Protocol
/// Framework: a named primitive with fixed sizes that the generic
/// composite layer never needs to look inside.
pub trait ClassicalScheme {
    /// Name token used to compose the suite label, for example `"ed25519"`.
    const NAME: &'static str;
    /// Length in bytes of this component's public key.
    const PUBLIC_KEY_LEN: usize;
    /// Length in bytes of this component's secret key.
    const SECRET_KEY_LEN: usize;
    /// Length in bytes of this component's signature. Fixed: unlike
    /// [`PqScheme::SIGNATURE_LEN`], a classical component's signature never
    /// varies in length.
    const SIGNATURE_LEN: usize;

    /// Derive the component keypair from a 32-byte seed.
    ///
    /// Writes `SECRET_KEY_LEN` bytes into `sk_out` and `PUBLIC_KEY_LEN`
    /// bytes into `pk_out`.
    fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()>;

    /// Hedged signing. `label` is the suite label, used as the schnorrkel
    /// signing context where the component needs one.
    fn sign(
        sk: &[u8],
        msg: &[u8],
        label: &'static [u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()>;

    /// Deterministic signing. The nonce is mixed with the secret key as
    /// `k = H(sk || nonce || msg)`. The secret key must always take part,
    /// or the signing key becomes trivially recoverable.
    fn sign_deterministic(
        sk: &[u8],
        msg: &[u8],
        nonce: &[u8],
        label: &'static [u8],
        sig_out: &mut [u8],
    ) -> Result<()>;

    /// Verify. Returns a `Choice`, never a `bool`, so the composite layer
    /// can combine components without a short-circuiting branch.
    fn verify(pk: &[u8], msg: &[u8], label: &'static [u8], sig: &[u8]) -> Choice;
}

/// A post-quantum signature component, for example ML-DSA-44.
///
/// Corresponds to the cipher functions abstraction in the Noise Protocol
/// Framework.
pub trait PqScheme {
    /// Name token used to compose the suite label, for example `"mldsa44"`.
    const NAME: &'static str;
    /// Length in bytes of this component's public key.
    const PUBLIC_KEY_LEN: usize;
    /// Length in bytes of this component's secret key.
    const SECRET_KEY_LEN: usize;
    /// Length in bytes of this component's signature. Unlike
    /// [`ClassicalScheme::SIGNATURE_LEN`], a post-quantum component's
    /// encoded signature length is fixed per algorithm but need not equal
    /// the classical half's.
    const SIGNATURE_LEN: usize;
    /// Seed length this component consumes from HKDF. 32 for ML-DSA-44.
    const SEED_LEN: usize;
    /// True when the algorithm is message-deterministic by specification.
    const IS_DETERMINISTIC: bool;

    /// Derive the component keypair from `seed`.
    ///
    /// Writes `SECRET_KEY_LEN` bytes into `sk_out` and `PUBLIC_KEY_LEN`
    /// bytes into `pk_out`.
    fn derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()>;

    /// Hedged signing.
    fn sign(
        sk: &[u8],
        msg: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()>;

    /// Deterministic signing. A component that is deterministic by
    /// specification ignores the nonce.
    fn sign_deterministic(sk: &[u8], msg: &[u8], nonce: &[u8], sig_out: &mut [u8]) -> Result<()>;

    /// Verify. Returns a `Choice`, never a `bool`, for the same reason as
    /// [`ClassicalScheme::verify`].
    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Choice;
}

/// A post-quantum component whose stateful signing spends one-time state.
///
/// Sibling of [`PqScheme`], for components like SHRINCS that pair a
/// stateful fast path (a signature spends a one-time leaf) with a stateless
/// recovery path. The borrow shapes differ from [`PqScheme`] precisely
/// because of that: stateless signing takes `&sk` (spends no state),
/// stateful signing takes `&mut sk` (spends one leaf and must advance the
/// component's own counter on success).
///
/// A stateful signature's encoded length grows with the leaf index (its
/// authentication path), so unlike [`PqScheme::SIGNATURE_LEN`] there is no
/// single fixed signature length here. [`FIXED_STATEFUL_SIG_LEN`] is the
/// part that does not vary; [`STATELESS_SIG_LEN`] is fixed because the
/// stateless path carries no leaf-dependent path at all.
///
/// [`FIXED_STATEFUL_SIG_LEN`]: PqStatefulScheme::FIXED_STATEFUL_SIG_LEN
/// [`STATELESS_SIG_LEN`]: PqStatefulScheme::STATELESS_SIG_LEN
pub trait PqStatefulScheme {
    /// Name token used to compose the suite label. Profile-qualified, for
    /// example `"shrincs-256s"`, since a stateful component's wire geometry
    /// is a compile-time profile choice.
    const NAME: &'static str;
    /// Seed length this component consumes for key derivation.
    const SEED_LEN: usize;
    /// Stored public-key form: a commitment, not the full verify key.
    const PUBLIC_KEY_LEN: usize;
    /// Verify-key form supplied at verification time (larger than
    /// `PUBLIC_KEY_LEN`: a commitment alone is not enough to verify
    /// against).
    const VERIFY_KEY_LEN: usize;
    /// Length of the component secret key in its exported form (see
    /// [`export_secret_key`]).
    ///
    /// [`export_secret_key`]: PqStatefulScheme::export_secret_key
    const SECRET_KEY_LEN: usize;
    /// Upper bound on the one-time leaf budget a key can be given.
    const LEAF_CAPACITY_LIMIT: u32;
    /// Few-time budget for the stateless path (specification section 21):
    /// `2^20`, except `2^18` under the component's low-budget profile (for
    /// this component, `profile-128s-q18`). A caller reads this constant
    /// rather than hardcoding the figure at the call site, so the budget
    /// used to guard signing can never drift from the one the spec assigns
    /// to the active profile.
    const STATELESS_BUDGET: u64;
    /// Bytes of a stateful signature excluding its leaf-dependent
    /// authentication path.
    const FIXED_STATEFUL_SIG_LEN: usize;
    /// Bytes of a stateless signature. Fixed: the stateless path carries no
    /// leaf-dependent authentication path.
    const STATELESS_SIG_LEN: usize;

    /// MUST NOT implement `Clone`: a clone forks the one-time leaf budget,
    /// and both copies would then be able to reissue the same leaf.
    type SecretKey: zeroize::Zeroize;

    /// Derive a secret key from `seed`, giving it a budget of
    /// `max_signatures` one-time leaves, and write the verify key
    /// (`VERIFY_KEY_LEN` bytes) into `vk_out`.
    fn keygen_from_seed(
        seed: &[u8],
        max_signatures: u32,
        vk_out: &mut [u8],
    ) -> Result<Self::SecretKey>;

    /// The leaf budget this key was given.
    fn leaf_capacity(sk: &Self::SecretKey) -> u32;
    /// The next unspent leaf.
    fn next_leaf(sk: &Self::SecretKey) -> u32;

    /// Write the component secret key into `out` in its exported form.
    ///
    /// The component owns this layout: the generic composite layer only
    /// concatenates the result and never looks inside it. Two obligations
    /// bind every implementation.
    ///
    /// The exported form MUST carry the leaf counter exactly as it stands,
    /// including the exhausted value that a fully spent key holds. A form
    /// that loses the counter turns restore into re-keygen, which reissues
    /// every leaf already spent.
    ///
    /// A key whose material has been wiped MUST export as an error, never as
    /// zeros. A blob of zeros is a blob that looks importable, and importing
    /// it would produce a key with a counter no signer ever reached.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if `out` is not exactly [`SECRET_KEY_LEN`] bytes,
    /// [`Error::ComponentFailure`] if the key has been wiped.
    ///
    /// [`Error::BadLength`]: crate::Error::BadLength
    /// [`Error::ComponentFailure`]: crate::Error::ComponentFailure
    /// [`SECRET_KEY_LEN`]: PqStatefulScheme::SECRET_KEY_LEN
    fn export_secret_key(sk: &Self::SecretKey, out: &mut [u8]) -> Result<()>;

    /// Rebuild a component secret key from [`export_secret_key`] output.
    ///
    /// This is a *validating* import, not a parse. An implementation MUST
    /// reject a blob whose public part disagrees with its private part
    /// (re-deriving the public part is the usual way to check this), and
    /// MUST reject a leaf counter outside the range a signer for this key
    /// can actually reach. Splicing a field from one key into another, or
    /// editing the counter to point at a leaf outside the tree, must fail
    /// here rather than produce a key that signs.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if `bytes` is not exactly [`SECRET_KEY_LEN`]
    /// bytes, [`Error::ComponentFailure`] if validation rejects the blob.
    ///
    /// [`export_secret_key`]: PqStatefulScheme::export_secret_key
    /// [`Error::BadLength`]: crate::Error::BadLength
    /// [`Error::ComponentFailure`]: crate::Error::ComponentFailure
    /// [`SECRET_KEY_LEN`]: PqStatefulScheme::SECRET_KEY_LEN
    fn import_secret_key(bytes: &[u8]) -> Result<Self::SecretKey>;

    /// Scheme-specific precondition on the message to be signed.
    ///
    /// This is **not** a guard that saves a leaf. The stateful signing path
    /// never calls it: every attempt to sign burns a leaf, including an
    /// attempt the component goes on to refuse. A signing path that can
    /// return without advancing the counter is a leaf-reuse hazard, and
    /// reuse is total security failure for the key, while a burned leaf is
    /// only availability loss.
    ///
    /// The composite calls this on the stateless path, where no leaf
    /// exists, and in `verify`, so that a message no honest signer could
    /// have produced is refused before any cryptography runs.
    fn precheck(msg: &[u8]) -> bool;

    /// Upper bound on the stateful signature length for a key with this
    /// leaf budget. The leaf that will actually be used is not known before
    /// signing, so a caller sizing `sig_out` ahead of time must size for the
    /// worst case.
    fn max_stateful_sig_len(max_signatures: u32) -> usize;

    /// Sign `msg` with the next unused leaf, advancing this component's own
    /// leaf counter on success. Returns the number of bytes written into
    /// `sig_out`.
    fn sign_stateful(
        sk: &mut Self::SecretKey,
        vk: &[u8],
        msg: &[u8],
        sig_out: &mut [u8],
    ) -> Result<usize>;

    /// Sign `msg` without spending any leaf state. Returns the number of
    /// bytes written into `sig_out`.
    fn sign_stateless(sk: &Self::SecretKey, msg: &[u8], sig_out: &mut [u8]) -> Result<usize>;

    /// Verify a stateful signature against the verify key `vk`.
    fn verify_stateful(vk: &[u8], msg: &[u8], sig: &[u8]) -> Choice;
    /// Verify a stateless signature against the verify key `vk`.
    fn verify_stateless(vk: &[u8], msg: &[u8], sig: &[u8]) -> Choice;

    /// Sign `m_prime_rotation` on the stateless path, for a key-rotation or
    /// -recovery authorization (specification section 19.2). Spends no leaf,
    /// like [`sign_stateless`](Self::sign_stateless). Returns the number of
    /// bytes written into `sig_out`.
    ///
    /// `payload` is the same [`RotationPayload`] `m_prime_rotation` was built
    /// from; both are supplied so the implementation can derive a domain
    /// separator that binds `payload.next_classical_pk` and `payload.kind`
    /// into the signature itself, not only into `m_prime_rotation`'s bytes.
    /// **This binding is the whole point of a separate method rather than
    /// reusing [`sign_stateless`](Self::sign_stateless):** without it, a
    /// stateless rotation signature produced for one `NextClassicalPK`
    /// verifies just as well paired with a classical co-signature over a
    /// different one, letting a holder of a compromised current classical
    /// key front-run an honest recovery by splicing their own key in
    /// alongside the honest new stateful tree. See section 19.2 for the
    /// full attack.
    fn sign_stateless_rotation(
        sk: &Self::SecretKey,
        payload: &RotationPayload,
        m_prime_rotation: &[u8],
        sig_out: &mut [u8],
    ) -> Result<usize>;

    /// Verify a
    /// [`sign_stateless_rotation`](Self::sign_stateless_rotation) signature
    /// against the verify key `vk`.
    ///
    /// Returns a `Choice`, never a `bool`, for the same reason as every
    /// other verify method here: the composite rotation gate
    /// (`crate::rotation::verify_rotation`) combines this with the classical
    /// half's result by bitwise `&`, never `&&`, so neither the result nor
    /// the running time reveals which half rejected.
    fn verify_stateless_rotation(
        vk: &[u8],
        payload: &RotationPayload,
        m_prime_rotation: &[u8],
        sig: &[u8],
    ) -> Choice;

    /// The stateless key material inside a verify key -- `pkSeed ||
    /// hypertreeRoot` (specification section 3), 64 bytes -- the bytes the
    /// few-time stateless budget (specification section 21) is keyed to.
    ///
    /// This is distinct from `vk` as a whole and from any commitment or
    /// stored public key derived from it: a rotation changes the
    /// commitment on every install, but the stateless budget MUST reset
    /// only when this material itself changes (specification section
    /// 19.3). A component that keyed the budget to the commitment instead
    /// would let a rotation silently refill a hard security bound -- the
    /// exact finding this method exists to prevent.
    ///
    /// # Errors
    ///
    /// Whatever the component reports for a `vk` it cannot parse (for
    /// example, the wrong length).
    fn stateless_key_material(vk: &[u8]) -> Result<&[u8]>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::Choice;

    struct Stub;

    impl ClassicalScheme for Stub {
        const NAME: &'static str = "stub";
        const PUBLIC_KEY_LEN: usize = 2;
        const SECRET_KEY_LEN: usize = 4;
        const SIGNATURE_LEN: usize = 8;

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
            sig_out.fill(4);
            Ok(())
        }
        fn verify(_pk: &[u8], _msg: &[u8], _label: &'static [u8], _sig: &[u8]) -> Choice {
            Choice::from(1u8)
        }
    }

    #[test]
    fn trait_constants_are_reachable() {
        assert_eq!(Stub::NAME, "stub");
        assert_eq!(Stub::SIGNATURE_LEN, 8);
    }

    #[test]
    fn derive_fills_both_buffers() {
        let mut sk = [0u8; 4];
        let mut pk = [0u8; 2];
        Stub::derive(&[0u8; 32], &mut sk, &mut pk).expect("stub derive");
        assert_eq!(sk, [1u8; 4]);
        assert_eq!(pk, [2u8; 2]);
    }
}
