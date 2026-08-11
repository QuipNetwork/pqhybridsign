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

use crate::{message, Error, Result, StatefulSuite};

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

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::Choice;

    // Minimal stand-in components, local to this test module: rotation.rs
    // has no dependency on a real classical or SHRINCS component, and
    // `StatefulSuite` requires full trait implementations regardless of
    // which methods a given test actually exercises.
    #[derive(Clone, Copy, Debug)]
    pub struct FakeClassical;

    impl crate::ClassicalScheme for FakeClassical {
        const NAME: &'static str = "stub";
        const PUBLIC_KEY_LEN: usize = 1;
        const SECRET_KEY_LEN: usize = 1;
        const SIGNATURE_LEN: usize = 1;

        fn derive(_seed: &[u8; 32], _sk_out: &mut [u8], _pk_out: &mut [u8]) -> Result<()> {
            Ok(())
        }
        fn sign(
            _sk: &[u8],
            _msg: &[u8],
            _label: &'static [u8],
            _rng: &mut impl rand_core::CryptoRngCore,
            _sig_out: &mut [u8],
        ) -> Result<()> {
            Ok(())
        }
        fn sign_deterministic(
            _sk: &[u8],
            _msg: &[u8],
            _nonce: &[u8],
            _label: &'static [u8],
            _sig_out: &mut [u8],
        ) -> Result<()> {
            Ok(())
        }
        fn verify(_pk: &[u8], _msg: &[u8], _label: &'static [u8], _sig: &[u8]) -> Choice {
            Choice::from(0u8)
        }
    }

    #[derive(Default)]
    pub struct FakeSecretKey;

    impl zeroize::Zeroize for FakeSecretKey {
        fn zeroize(&mut self) {}
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

        type SecretKey = FakeSecretKey;

        fn keygen_from_seed(
            _seed: &[u8],
            _max_signatures: u32,
            _vk_out: &mut [u8],
        ) -> Result<Self::SecretKey> {
            Ok(FakeSecretKey)
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
            Ok(FakeSecretKey)
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
}
