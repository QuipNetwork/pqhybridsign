// SPDX-License-Identifier: AGPL-3.0-or-later
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
    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
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
    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    /// Seed length this component consumes from HKDF. 32 for ML-DSA-44.
    const SEED_LEN: usize;
    /// True when the algorithm is message-deterministic by specification.
    const IS_DETERMINISTIC: bool;

    fn derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()>;

    fn sign(
        sk: &[u8],
        msg: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()>;

    /// Deterministic signing. A component that is deterministic by
    /// specification ignores the nonce.
    fn sign_deterministic(sk: &[u8], msg: &[u8], nonce: &[u8], sig_out: &mut [u8]) -> Result<()>;

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Choice;
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
