// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key rotation and recovery payload, specification section 19.2.
//!
//! ```text
//! RotationPayload = RotationKind(1) || CurrentCommitment(32) || NextCommitment(32) || NextClassicalPK(32)   // 97 bytes fixed
//! M'_rotation     = Prefix(0x01) || RotationLabel || len(ctx) || ctx || RotationPayload
//! ```
//!
//! `RotationKind` shares its two numeric values (`0x01`, `0x02`) with
//! `encoding_path::PathSelector`, but the two are deliberately unrelated
//! types with independent decoders: a rotation authorization and a
//! signature-path tag answer different questions, and coercing one into the
//! other would let a byte that was never meant as a rotation vote get read
//! as one (or vice versa). `RotationLabel` (`StatefulSuite::ROTATE_LABEL`)
//! is the domain separator that keeps an ordinary signature from ever being
//! read back as a rotation co-signature; see `crate::suite`.

use crate::{message, ClassicalScheme, Error, PqStatefulScheme, Result, StatefulSuite};

#[cfg(feature = "alloc")]
use crate::{encoding_path, stateful_composite};

/// Width of one commitment or public-key field inside [`RotationPayload`].
const FIELD_LEN: usize = 32;

/// Total encoded width of [`RotationPayload`]: the 1-byte kind plus three
/// 32-byte fields.
pub const ROTATION_PAYLOAD_LEN: usize = 1 + 3 * FIELD_LEN;

/// What a rotation authorizes: a stateful-only graft (fresh stateful tree
/// onto the unchanged classical/stateless-verify half) or a full swap
/// (stateless material and, possibly, the classical key both change).
///
/// **Not** `encoding_path::PathSelector`, despite sharing numeric values.
/// Specification section 19.2 requires the two stay separate types with
/// separate decoders, so a `PathSelector` byte from a signature encoding can
/// never be misread as a rotation vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RotationKind {
    /// Fresh stateful tree grafted onto the unchanged stateless-verify half.
    StatefulGraft = 0x01,
    /// Full bundle swap: stateless material (and possibly the classical key)
    /// both change.
    FullSwap = 0x02,
}

impl RotationKind {
    /// The wire value for this kind.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for RotationKind {
    type Error = Error;

    /// Any byte other than `0x01` or `0x02` is rejected. There is no
    /// fallback interpretation: an unrecognized kind must fail decoding
    /// rather than default to either variant.
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::StatefulGraft),
            0x02 => Ok(Self::FullSwap),
            kind => Err(Error::BadRotationKind { kind }),
        }
    }
}

/// The fixed-length rotation authorization payload, specification section
/// 19.2.
///
/// Both component signatures over `M'_rotation` commit to every field here,
/// including `next_classical_pk`: binding the next classical key into the
/// stateless signature's domain separator (not just the classical
/// co-signature) is what stops a holder of a compromised current classical
/// key from splicing their own key in alongside an honest recovery. See
/// section 19.2 for the attack this closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPayload {
    pub kind: RotationKind,
    pub current_commitment: [u8; FIELD_LEN],
    pub next_commitment: [u8; FIELD_LEN],
    pub next_classical_pk: [u8; FIELD_LEN],
}

impl RotationPayload {
    /// Write the encoded payload into `out`.
    ///
    /// # Errors
    ///
    /// [`Error::OutputBufferTooSmall`] if `out` is shorter than
    /// [`ROTATION_PAYLOAD_LEN`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < ROTATION_PAYLOAD_LEN {
            return Err(Error::OutputBufferTooSmall {
                needed: ROTATION_PAYLOAD_LEN,
                actual: out.len(),
            });
        }
        out[0] = self.kind.to_u8();
        out[1..1 + FIELD_LEN].copy_from_slice(&self.current_commitment);
        out[1 + FIELD_LEN..1 + 2 * FIELD_LEN].copy_from_slice(&self.next_commitment);
        out[1 + 2 * FIELD_LEN..ROTATION_PAYLOAD_LEN].copy_from_slice(&self.next_classical_pk);
        Ok(ROTATION_PAYLOAD_LEN)
    }

    /// Decode a payload, rejecting any length but [`ROTATION_PAYLOAD_LEN`]
    /// and any byte value but `0x01`/`0x02` for the kind.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if `bytes.len() != ROTATION_PAYLOAD_LEN`.
    /// [`Error::BadRotationKind`] if the first byte is not `0x01` or `0x02`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ROTATION_PAYLOAD_LEN {
            return Err(Error::BadLength {
                expected: ROTATION_PAYLOAD_LEN,
                actual: bytes.len(),
            });
        }
        let kind = RotationKind::try_from(bytes[0])?;
        // Exact-width slices, checked above; the `try_into` cannot fail.
        let current_commitment: [u8; FIELD_LEN] = bytes[1..1 + FIELD_LEN]
            .try_into()
            .map_err(|_| Error::ComponentFailure)?;
        let next_commitment: [u8; FIELD_LEN] = bytes[1 + FIELD_LEN..1 + 2 * FIELD_LEN]
            .try_into()
            .map_err(|_| Error::ComponentFailure)?;
        let next_classical_pk: [u8; FIELD_LEN] = bytes[1 + 2 * FIELD_LEN..ROTATION_PAYLOAD_LEN]
            .try_into()
            .map_err(|_| Error::ComponentFailure)?;
        Ok(Self {
            kind,
            current_commitment,
            next_commitment,
            next_classical_pk,
        })
    }
}

/// Length of `M'_rotation` for a payload under this suite and `ctx`.
///
/// # Errors
///
/// [`Error::ContextTooLong`] if `ctx` exceeds 255 bytes.
pub fn m_prime_rotation_len<S: StatefulSuite>(ctx: &[u8]) -> Result<usize> {
    // Only the length of the (fixed-width) payload matters here, so a
    // zeroed placeholder stands in rather than requiring a real payload.
    message::m_prime_len(S::ROTATE_LABEL, ctx, &[0u8; ROTATION_PAYLOAD_LEN])
}

/// Write `M'_rotation = Prefix(0x01) || S::ROTATE_LABEL || len(ctx) || ctx
/// || RotationPayload` into `out`.
///
/// Built entirely from [`RotationPayload::encode`] and
/// [`message::write_m_prime`]: the payload goes into a stack buffer first,
/// then the existing prefix/length-prefixed-context framing runs unchanged
/// with [`StatefulSuite::ROTATE_LABEL`] in place of
/// [`StatefulSuite::LABEL`](StatefulSuite::LABEL). No allocation, so this
/// works without the `alloc` feature.
///
/// # Errors
///
/// [`Error::ContextTooLong`] if `ctx` exceeds 255 bytes.
/// [`Error::OutputBufferTooSmall`] if `out` is too small for the result.
pub fn write_m_prime_rotation<S: StatefulSuite>(
    out: &mut [u8],
    payload: &RotationPayload,
    ctx: &[u8],
) -> Result<usize> {
    let mut payload_bytes = [0u8; ROTATION_PAYLOAD_LEN];
    payload.encode(&mut payload_bytes)?;
    message::write_m_prime(out, S::ROTATE_LABEL, ctx, &payload_bytes)
}

/// Allocating convenience wrapper around [`write_m_prime_rotation`].
#[cfg(feature = "alloc")]
pub fn m_prime_rotation<S: StatefulSuite>(
    payload: &RotationPayload,
    ctx: &[u8],
) -> Result<alloc::vec::Vec<u8>> {
    let needed = m_prime_rotation_len::<S>(ctx)?;
    let mut out = alloc::vec![0u8; needed];
    write_m_prime_rotation::<S>(&mut out, payload, ctx)?;
    Ok(out)
}

/// The next stored composite public key a valid rotation authorizes:
/// `NextClassicalPK || NextCommitment`, specification section 19.3's install
/// target.
///
/// Built and returned as one value, never in two steps, so a caller cannot
/// install `next_classical_pk` without `next_commitment` or vice versa: the
/// two fields are always populated together, by the one function that
/// produces this type ([`verify_rotation`]). Registry state this task does
/// not own (nonce, keyVersion, policy reset, stateless-budget reset) is
/// deliberately absent; the caller still owns applying those alongside this
/// value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextStoredPublicKey {
    pub next_classical_pk: [u8; FIELD_LEN],
    pub next_commitment: [u8; FIELD_LEN],
}

/// Encoded length of a [`sign_rotation`]/[`verify_rotation`] signature for
/// suite `S`: `classical(64) || stateless(S::Pq::STATELESS_SIG_LEN)`.
///
/// Fixed length, with no `PathSelector` byte. A rotation is not a
/// path-selected signature: `encoding_path::PathSelector` exists to tell a
/// stateful component signature apart from a stateless one on the ordinary
/// signing path, but a rotation authorization is stateless-only by
/// specification section 19.2 (the composite driver never grinds a stateful
/// rotation signature). Giving rotation a selector byte of its own would
/// create a second place in the wire format where the two paths are told
/// apart, for a distinction that does not exist here.
#[cfg(feature = "alloc")]
pub fn rotation_signature_len<S: StatefulSuite>() -> usize {
    encoding_path::CLASSICAL_SIG_LEN + <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN
}

/// Sign only the classical half of a rotation authorization: `M'_rotation`
/// under the current classical secret key, specification section 19.2.
///
/// [`sign_rotation`] uses this for its own classical half. It is also
/// exposed on its own: proving that [`verify_rotation`] rejects a spliced
/// co-signature (specification section 19.2's front-running attack, and the
/// sibling property that changing `RotationKind` alone must invalidate the
/// stateless half) needs a *valid* classical signature over an *arbitrary*
/// rotation payload, without re-running the stateless half -- which, for a
/// real `PqStatefulScheme` like SHRINCS, costs seconds per call. This
/// function grants no capability [`sign_rotation`] itself does not already
/// grant: a classical co-signature alone never authorizes a rotation, only
/// [`verify_rotation`]'s AND gate does.
///
/// Writes [`encoding_path::CLASSICAL_SIG_LEN`] bytes into `sig_out` and
/// returns that count.
///
/// # Errors
///
/// [`Error::OutputBufferTooSmall`] if `sig_out` is too small.
/// [`Error::ContextTooLong`] if `ctx` exceeds 255 bytes. Any error the
/// classical component reports while signing.
#[cfg(feature = "alloc")]
pub fn sign_rotation_classical_half<S: StatefulSuite>(
    sk: &stateful_composite::SecretKey<S>,
    ctx: &[u8],
    payload: &RotationPayload,
    sig_out: &mut [u8],
) -> Result<usize> {
    let m_prime_rotation = m_prime_rotation::<S>(payload, ctx)?;
    write_classical_half::<S>(sk, ctx, &m_prime_rotation, sig_out)
}

/// Shared by [`sign_rotation_classical_half`] and [`sign_rotation`], so the
/// latter builds `m_prime_rotation` exactly once instead of once per half.
#[cfg(feature = "alloc")]
fn write_classical_half<S: StatefulSuite>(
    sk: &stateful_composite::SecretKey<S>,
    ctx: &[u8],
    m_prime_rotation: &[u8],
    sig_out: &mut [u8],
) -> Result<usize> {
    if sig_out.len() < encoding_path::CLASSICAL_SIG_LEN {
        return Err(Error::OutputBufferTooSmall {
            needed: encoding_path::CLASSICAL_SIG_LEN,
            actual: sig_out.len(),
        });
    }
    <S::Classical as ClassicalScheme>::sign_deterministic(
        sk.classical_bytes(),
        m_prime_rotation,
        ctx,
        S::LABEL,
        &mut sig_out[..encoding_path::CLASSICAL_SIG_LEN],
    )?;
    Ok(encoding_path::CLASSICAL_SIG_LEN)
}

/// Sign a rotation authorization: `M'_rotation`, signed under both
/// components, specification section 19.2.
///
/// The classical half signs `M'_rotation` directly (the same shape as an
/// ordinary composite signature, but over the rotation message and always
/// deterministic: a rotation authorization has no hedged form) -- see
/// [`sign_rotation_classical_half`]. The stateless half goes through
/// [`PqStatefulScheme::sign_stateless_rotation`], not
/// [`PqStatefulScheme::sign_stateless`], so the component can bind
/// `payload.next_classical_pk` and `payload.kind` into its own domain
/// separator rather than relying on the classical co-signature alone to
/// carry that binding. See [`RotationPayload`]'s documentation for why that
/// binding is required.
///
/// Writes [`rotation_signature_len::<S>`] bytes into `sig_out` and returns
/// that count.
///
/// # Errors
///
/// [`Error::OutputBufferTooSmall`] if `sig_out` is too small.
/// [`Error::ContextTooLong`] if `ctx` exceeds 255 bytes. Any error either
/// component reports while signing.
#[cfg(feature = "alloc")]
pub fn sign_rotation<S: StatefulSuite>(
    sk: &stateful_composite::SecretKey<S>,
    ctx: &[u8],
    payload: &RotationPayload,
    sig_out: &mut [u8],
) -> Result<usize> {
    let stateless_len = <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN;
    let needed = encoding_path::CLASSICAL_SIG_LEN + stateless_len;
    if sig_out.len() < needed {
        return Err(Error::OutputBufferTooSmall {
            needed,
            actual: sig_out.len(),
        });
    }

    let m_prime_rotation = m_prime_rotation::<S>(payload, ctx)?;

    write_classical_half::<S>(
        sk,
        ctx,
        &m_prime_rotation,
        &mut sig_out[..encoding_path::CLASSICAL_SIG_LEN],
    )?;

    let written = <S::Pq as PqStatefulScheme>::sign_stateless_rotation(
        sk.pq_secret_key(),
        payload,
        &m_prime_rotation,
        &mut sig_out[encoding_path::CLASSICAL_SIG_LEN..needed],
    )?;
    // The component contract is to fill exactly `STATELESS_SIG_LEN` bytes,
    // same as `sign_stateless`; a short write here would leave stale
    // `sig_out` bytes inside a signature this function reports as complete.
    if written != stateless_len {
        return Err(Error::ComponentFailure);
    }

    Ok(needed)
}

/// Verify a rotation authorization and, on success, hand back the complete
/// next stored public key ([`NextStoredPublicKey`]) atomically.
///
/// Both halves are required: `classical_ok` and `stateless_ok` are computed
/// unconditionally, both evaluated regardless of what the other decided, and
/// combined with a bitwise `&` on `subtle::Choice` -- never `&&` -- so
/// neither the result nor the running time reveals which half rejected.
/// Mirrors `stateful_composite::verify`.
///
/// Returns `None` on any rejection: a bad signature length, a `ctx` over 255
/// bytes, or a failed gate. Returns `Some(next)` only when both halves
/// verify, with `next` built directly from `payload`'s already-checked
/// fields -- there is no path that returns a partially built
/// `NextStoredPublicKey`, and no separate "then install" step that a caller
/// could invoke without having verified anything.
#[cfg(feature = "alloc")]
pub fn verify_rotation<S: StatefulSuite>(
    current_pk: &stateful_composite::PublicKey<S>,
    ctx: &[u8],
    payload: &RotationPayload,
    sig: &[u8],
) -> Option<NextStoredPublicKey> {
    let needed = rotation_signature_len::<S>();
    if sig.len() != needed {
        return None;
    }
    let m_prime_rotation = m_prime_rotation::<S>(payload, ctx).ok()?;
    let (classical_sig, stateless_sig) = sig.split_at(encoding_path::CLASSICAL_SIG_LEN);

    let classical_ok = <S::Classical as ClassicalScheme>::verify(
        current_pk.classical(),
        &m_prime_rotation,
        S::LABEL,
        classical_sig,
    );
    let stateless_ok = <S::Pq as PqStatefulScheme>::verify_stateless_rotation(
        current_pk.pq_verify_key(),
        payload,
        &m_prime_rotation,
        stateless_sig,
    );

    if bool::from(classical_ok & stateless_ok) {
        Some(NextStoredPublicKey {
            next_classical_pk: payload.next_classical_pk,
            next_commitment: payload.next_commitment,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::Choice;

    // Minimal stand-in components, local to this test module: rotation.rs
    // has no dependency on a real classical or SHRINCS component, and
    // `StatefulSuite` requires full trait implementations regardless of
    // which methods a given test actually exercises.
    //
    // The classical and stateless-rotation halves below are not
    // cryptographic, but they are *functional*: each signature is a
    // deterministic function of the secret key and the exact bytes signed,
    // and verification recomputes and compares. That is what lets the
    // rotation-gate tests below exercise real properties (front-running,
    // single-byte tamper detection, kind-binding) against a fake component,
    // cheaply -- the expensive equivalents against the real SHRINCS
    // component live in `pqhybridsign-shrincs/tests/rotation.rs`.
    #[derive(Clone, Copy, Debug)]
    pub struct FakeClassical;

    /// XOR-fold of `bytes`, used by both fakes below as a cheap stand-in for
    /// "a hash of the whole signed message affects the signature."
    fn fold(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |acc, &b| acc ^ b)
    }

    impl crate::ClassicalScheme for FakeClassical {
        const NAME: &'static str = "stub";
        const PUBLIC_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 1;
        const SIGNATURE_LEN: usize = 1;

        fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
            sk_out.fill(seed[0]);
            pk_out.fill(seed[0]);
            Ok(())
        }
        fn sign(
            sk: &[u8],
            msg: &[u8],
            label: &'static [u8],
            _rng: &mut impl rand_core::CryptoRngCore,
            sig_out: &mut [u8],
        ) -> Result<()> {
            Self::sign_deterministic(sk, msg, b"", label, sig_out)
        }
        /// Every byte of `sig_out` is filled with `sk[0] ^ fold(msg)`, so a
        /// single flipped byte anywhere in the signature is detectable by
        /// [`Self::verify`] (needed by the "valid stateless, tampered
        /// classical half" test case).
        fn sign_deterministic(
            sk: &[u8],
            msg: &[u8],
            _nonce: &[u8],
            _label: &'static [u8],
            sig_out: &mut [u8],
        ) -> Result<()> {
            let byte = sk.first().copied().unwrap_or(0) ^ fold(msg);
            sig_out.fill(byte);
            Ok(())
        }
        fn verify(pk: &[u8], msg: &[u8], _label: &'static [u8], sig: &[u8]) -> Choice {
            let Some(&pk0) = pk.first() else {
                return Choice::from(0u8);
            };
            let expected = pk0 ^ fold(msg);
            Choice::from(u8::from(
                !sig.is_empty() && sig.iter().all(|&b| b == expected),
            ))
        }
    }

    #[derive(Default)]
    pub struct FakeSecretKey {
        key: u8,
    }

    impl zeroize::Zeroize for FakeSecretKey {
        fn zeroize(&mut self) {
            self.key.zeroize();
        }
    }

    /// Stand-in for a rotation domain separator: a real (non-linear) hash
    /// over `payload.kind`, `payload.next_classical_pk`, and the exact
    /// `m_prime_rotation` bytes actually signed. A linear fold (XOR/wrapping
    /// sum) is not safe here: `payload.kind` and `payload.next_classical_pk`
    /// already appear a second time inside `m_prime_rotation`, and a linear
    /// combination of the two can cancel a change in one against the
    /// matching change in the other -- which is exactly why the real domain
    /// separator (specification section 19.2) is a cryptographic hash, not
    /// an XOR fold. Using `sha2::Sha256` here (already a dependency of this
    /// crate) keeps this fake honest about that property instead of hiding
    /// it behind toy arithmetic.
    fn mix(payload: &RotationPayload, m_prime_rotation: &[u8]) -> u8 {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([payload.kind.to_u8()]);
        hasher.update(payload.next_classical_pk);
        hasher.update(m_prime_rotation);
        hasher.finalize()[0]
    }

    pub struct FakePq;

    impl crate::PqStatefulScheme for FakePq {
        const NAME: &'static str = "fake";
        const SEED_LEN: usize = 1;
        const PUBLIC_KEY_LEN: usize = 1;
        const VERIFY_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 1;
        const LEAF_CAPACITY_LIMIT: u32 = 1;
        const FIXED_STATEFUL_SIG_LEN: usize = 0;
        const STATELESS_SIG_LEN: usize = 1;
        const STATELESS_BUDGET: u64 = 1;

        type SecretKey = FakeSecretKey;

        fn keygen_from_seed(
            seed: &[u8],
            _max_signatures: u32,
            vk_out: &mut [u8],
        ) -> Result<Self::SecretKey> {
            let key = seed.first().copied().unwrap_or(0);
            vk_out.fill(key);
            Ok(FakeSecretKey { key })
        }
        fn leaf_capacity(_sk: &Self::SecretKey) -> u32 {
            0
        }
        fn next_leaf(_sk: &Self::SecretKey) -> u32 {
            0
        }
        fn export_secret_key(_sk: &Self::SecretKey, _out: &mut [u8]) -> Result<()> {
            Ok(())
        }
        fn import_secret_key(_bytes: &[u8]) -> Result<Self::SecretKey> {
            Ok(FakeSecretKey::default())
        }
        fn precheck(_msg: &[u8]) -> bool {
            true
        }
        fn max_stateful_sig_len(_max_signatures: u32) -> usize {
            0
        }
        fn sign_stateful(
            _sk: &mut Self::SecretKey,
            _vk: &[u8],
            _msg: &[u8],
            _sig_out: &mut [u8],
        ) -> Result<usize> {
            Ok(0)
        }
        fn sign_stateless(
            _sk: &Self::SecretKey,
            _msg: &[u8],
            _sig_out: &mut [u8],
        ) -> Result<usize> {
            Ok(0)
        }
        fn verify_stateful(_vk: &[u8], _msg: &[u8], _sig: &[u8]) -> Choice {
            Choice::from(0u8)
        }
        fn verify_stateless(_vk: &[u8], _msg: &[u8], _sig: &[u8]) -> Choice {
            Choice::from(0u8)
        }
        fn sign_stateless_rotation(
            sk: &Self::SecretKey,
            payload: &RotationPayload,
            m_prime_rotation: &[u8],
            sig_out: &mut [u8],
        ) -> Result<usize> {
            sig_out[0] = sk.key ^ mix(payload, m_prime_rotation);
            Ok(1)
        }
        fn verify_stateless_rotation(
            vk: &[u8],
            payload: &RotationPayload,
            m_prime_rotation: &[u8],
            sig: &[u8],
        ) -> Choice {
            let (Some(&vk0), Some(&sig0)) = (vk.first(), sig.first()) else {
                return Choice::from(0u8);
            };
            Choice::from(u8::from(
                sig.len() == 1 && sig0 == (vk0 ^ mix(payload, m_prime_rotation)),
            ))
        }
        fn stateless_key_material(vk: &[u8]) -> Result<&[u8]> {
            Ok(vk)
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

    fn payload() -> RotationPayload {
        RotationPayload {
            kind: RotationKind::StatefulGraft,
            current_commitment: [1u8; 32],
            next_commitment: [2u8; 32],
            next_classical_pk: [3u8; 32],
        }
    }

    #[test]
    fn a_payload_round_trips_through_encode_and_decode() {
        let p = payload();
        let mut buf = [0u8; ROTATION_PAYLOAD_LEN];
        let written = p.encode(&mut buf).expect("encode");
        assert_eq!(written, ROTATION_PAYLOAD_LEN);

        let decoded = RotationPayload::decode(&buf).expect("decode");
        assert_eq!(decoded, p);
    }

    #[test]
    fn every_byte_but_the_two_valid_kinds_fails_to_decode() {
        for kind in 0u8..=u8::MAX {
            if kind == 0x01 || kind == 0x02 {
                continue;
            }
            let mut buf = [0u8; ROTATION_PAYLOAD_LEN];
            buf[0] = kind;
            assert_eq!(
                RotationPayload::decode(&buf).err(),
                Some(Error::BadRotationKind { kind }),
                "kind {kind:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn a_short_or_long_buffer_fails_to_decode() {
        let mut buf = [0u8; ROTATION_PAYLOAD_LEN];
        buf[0] = 0x01;

        assert_eq!(
            RotationPayload::decode(&buf[..ROTATION_PAYLOAD_LEN - 1]).err(),
            Some(Error::BadLength {
                expected: ROTATION_PAYLOAD_LEN,
                actual: ROTATION_PAYLOAD_LEN - 1
            })
        );

        let mut long = [0u8; ROTATION_PAYLOAD_LEN + 1];
        long[..ROTATION_PAYLOAD_LEN].copy_from_slice(&buf);
        assert_eq!(
            RotationPayload::decode(&long).err(),
            Some(Error::BadLength {
                expected: ROTATION_PAYLOAD_LEN,
                actual: ROTATION_PAYLOAD_LEN + 1
            })
        );
    }

    #[test]
    fn rotate_label_ends_in_a_null_byte_with_the_declared_length() {
        assert_eq!(FakeH::ROTATE_LABEL, b"hybrid-stub-fake-rotate-v1\0");
        assert_eq!(FakeH::ROTATE_LABEL.len(), 27);
        assert_eq!(*FakeH::ROTATE_LABEL.last().unwrap(), 0u8);
    }

    // Uses the allocating `m_prime_rotation` wrapper.
    #[cfg(feature = "alloc")]
    #[test]
    fn m_prime_rotation_differs_from_m_prime_over_the_same_bytes() {
        let p = payload();
        let ctx = b"chain";

        let rotation = m_prime_rotation::<FakeH>(&p, ctx).expect("m_prime_rotation");

        let mut payload_bytes = [0u8; ROTATION_PAYLOAD_LEN];
        p.encode(&mut payload_bytes).expect("encode");

        let mut expected = alloc::vec![0x01u8];
        expected.extend_from_slice(FakeH::ROTATE_LABEL);
        expected.push(ctx.len() as u8);
        expected.extend_from_slice(ctx);
        expected.extend_from_slice(&payload_bytes);
        assert_eq!(
            rotation, expected,
            "M'_rotation must match the specified layout"
        );

        let ordinary = message::m_prime(FakeH::LABEL, ctx, &payload_bytes).expect("m_prime");
        assert_ne!(
            rotation, ordinary,
            "the rotate and ordinary labels differ, so the two M' encodings must differ too"
        );
    }

    // ------------------------------------------------------------------
    // `sign_rotation` / `verify_rotation`: the AND gate.
    // ------------------------------------------------------------------

    #[cfg(feature = "alloc")]
    #[test]
    fn a_valid_rotation_verifies() {
        let (sk, pk) = stateful_composite::keygen::<FakeH>(&[1u8; 32], 1).expect("keygen");
        let p = payload();
        let ctx = b"chain";

        let mut sig = alloc::vec![0u8; rotation_signature_len::<FakeH>()];
        let written = sign_rotation::<FakeH>(&sk, ctx, &p, &mut sig).expect("sign_rotation");
        assert_eq!(written, sig.len());

        assert_eq!(
            verify_rotation::<FakeH>(&pk, ctx, &p, &sig),
            Some(NextStoredPublicKey {
                next_classical_pk: p.next_classical_pk,
                next_commitment: p.next_commitment,
            })
        );
    }

    /// Specification section 19.2's central property, and the reason
    /// `sign_stateless_rotation`/`verify_stateless_rotation` exist as
    /// separate methods rather than reusing the ordinary stateless path: a
    /// stateless rotation signature must not be reusable against a
    /// different `NextClassicalPK`.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_front_running_attack_fails() {
        // An honest rotation authorizing NextClassicalPK = A.
        let (sk, pk) = stateful_composite::keygen::<FakeH>(&[2u8; 32], 1).expect("keygen");
        let ctx = b"chain";
        let mut payload_a = payload();
        payload_a.next_classical_pk = [0xAAu8; 32];

        let mut honest_sig = alloc::vec![0u8; rotation_signature_len::<FakeH>()];
        sign_rotation::<FakeH>(&sk, ctx, &payload_a, &mut honest_sig).expect("sign_rotation");

        // The attacker keeps the honest stateless half unchanged, and pairs
        // it with a fresh, valid classical co-signature over a payload
        // naming NextClassicalPK = B.
        let mut payload_b = payload_a;
        payload_b.next_classical_pk = [0xBBu8; 32];
        let classical_len = encoding_path::CLASSICAL_SIG_LEN;
        let mut forged = honest_sig.clone();
        sign_rotation_classical_half::<FakeH>(&sk, ctx, &payload_b, &mut forged[..classical_len])
            .expect("classical sign");

        assert!(
            verify_rotation::<FakeH>(&pk, ctx, &payload_b, &forged).is_none(),
            "a stateless signature bound to NextClassicalPK = A must not \
             verify once paired with a classical co-signature naming \
             NextClassicalPK = B"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn an_invalid_stateless_half_is_rejected_even_with_a_valid_classical_half() {
        let (sk, pk) = stateful_composite::keygen::<FakeH>(&[3u8; 32], 1).expect("keygen");
        let p = payload();
        let ctx = b"chain";
        let mut sig = alloc::vec![0u8; rotation_signature_len::<FakeH>()];
        sign_rotation::<FakeH>(&sk, ctx, &p, &mut sig).expect("sign_rotation");

        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert!(verify_rotation::<FakeH>(&pk, ctx, &p, &sig).is_none());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn an_invalid_classical_half_is_rejected_even_with_a_valid_stateless_half() {
        let (sk, pk) = stateful_composite::keygen::<FakeH>(&[4u8; 32], 1).expect("keygen");
        let p = payload();
        let ctx = b"chain";
        let mut sig = alloc::vec![0u8; rotation_signature_len::<FakeH>()];
        sign_rotation::<FakeH>(&sk, ctx, &p, &mut sig).expect("sign_rotation");

        sig[0] ^= 0x01;
        assert!(verify_rotation::<FakeH>(&pk, ctx, &p, &sig).is_none());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn an_ordinary_classical_signature_cannot_be_spliced_in_as_the_rotation_co_signature() {
        let (sk, pk) = stateful_composite::keygen::<FakeH>(&[5u8; 32], 1).expect("keygen");
        let p = payload();
        let ctx = b"chain";
        let mut sig = alloc::vec![0u8; rotation_signature_len::<FakeH>()];
        sign_rotation::<FakeH>(&sk, ctx, &p, &mut sig).expect("sign_rotation");

        // An ordinary (non-rotation) M' over the payload's own bytes as an
        // application message, signed under the ordinary label.
        let mut payload_bytes = [0u8; ROTATION_PAYLOAD_LEN];
        p.encode(&mut payload_bytes).expect("encode");
        let ordinary_m_prime =
            message::m_prime(FakeH::LABEL, ctx, &payload_bytes).expect("m_prime");
        let classical_len = encoding_path::CLASSICAL_SIG_LEN;
        FakeClassical::sign_deterministic(
            sk.classical_bytes(),
            &ordinary_m_prime,
            ctx,
            FakeH::LABEL,
            &mut sig[..classical_len],
        )
        .expect("classical sign");
        // (This one signs the ordinary M' directly, not through
        // `sign_rotation_classical_half`, which only ever builds
        // `M'_rotation`: the whole point of this test is a signature over
        // the *ordinary* framing.)

        assert!(
            verify_rotation::<FakeH>(&pk, ctx, &p, &sig).is_none(),
            "an ordinary classical signature must not verify as a rotation \
             co-signature, because LABEL and ROTATE_LABEL differ"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn changing_rotation_kind_alone_invalidates_the_stateless_half() {
        let (sk, pk) = stateful_composite::keygen::<FakeH>(&[6u8; 32], 1).expect("keygen");
        let ctx = b"chain";
        let mut original = payload();
        original.kind = RotationKind::StatefulGraft;

        let mut sig = alloc::vec![0u8; rotation_signature_len::<FakeH>()];
        sign_rotation::<FakeH>(&sk, ctx, &original, &mut sig).expect("sign_rotation");

        let mut flipped = original;
        flipped.kind = RotationKind::FullSwap;

        // A fresh, valid classical co-signature over the flipped-kind
        // payload, paired with the original (unmodified) stateless half.
        let classical_len = encoding_path::CLASSICAL_SIG_LEN;
        let mut forged = sig.clone();
        sign_rotation_classical_half::<FakeH>(&sk, ctx, &flipped, &mut forged[..classical_len])
            .expect("classical sign");

        assert!(
            verify_rotation::<FakeH>(&pk, ctx, &flipped, &forged).is_none(),
            "the stateless half was bound to RotationKind::StatefulGraft and \
             must not verify once the kind changes to RotationKind::FullSwap"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn install_returns_the_next_stored_key_differing_from_current_in_both_halves() {
        let (sk, pk) = stateful_composite::keygen::<FakeH>(&[7u8; 32], 1).expect("keygen");
        let ctx = b"chain";
        let mut p = payload();
        p.kind = RotationKind::FullSwap;
        p.next_classical_pk = [0x42u8; 32];
        p.next_commitment = [0x99u8; 32];

        let mut sig = alloc::vec![0u8; rotation_signature_len::<FakeH>()];
        sign_rotation::<FakeH>(&sk, ctx, &p, &mut sig).expect("sign_rotation");

        let next = verify_rotation::<FakeH>(&pk, ctx, &p, &sig).expect("valid rotation");
        assert_ne!(
            &next.next_classical_pk[..1],
            pk.classical(),
            "the classical half must differ from the current stored key"
        );
        assert_ne!(
            next.next_commitment, p.current_commitment,
            "the commitment half must differ from the current stored key"
        );
    }
}
