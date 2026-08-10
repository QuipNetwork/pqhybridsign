// SPDX-License-Identifier: AGPL-3.0-or-later
use ed25519_zebra::{SigningKey, VerificationKey};
use pqhybridsign_core::{ClassicalScheme, Error, Result};
use subtle::Choice;
use zeroize::Zeroize;

/// ed25519 classical component, per RFC 8032.
#[derive(Clone, Copy, Debug)]
pub struct Ed25519;

impl ClassicalScheme for Ed25519 {
    const NAME: &'static str = "ed25519";
    const PUBLIC_KEY_LEN: usize = 32;
    const SECRET_KEY_LEN: usize = 64;
    const SIGNATURE_LEN: usize = 64;

    fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
        check_len(sk_out, Self::SECRET_KEY_LEN)?;
        check_len(pk_out, Self::PUBLIC_KEY_LEN)?;
        let mut signing = SigningKey::from(*seed);
        let public: [u8; 32] = VerificationKey::from(&signing).into();
        // `SigningKey` is `Copy`, so it has no drop glue and its copy of the
        // seed would otherwise stay on the stack.
        signing.zeroize();
        sk_out[..32].copy_from_slice(seed);
        sk_out[32..].copy_from_slice(&public);
        pk_out.copy_from_slice(&public);
        Ok(())
    }

    fn sign(
        sk: &[u8],
        msg: &[u8],
        _label: &'static [u8],
        _rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()> {
        // ed25519 is deterministic by specification, so hedged signing and
        // deterministic signing coincide when no nonce is supplied.
        raw_sign(sk, msg, sig_out)
    }

    /// Ignores `_nonce`: ed25519 is deterministic per RFC 8032, and its
    /// built-in nonce `r = H(prefix || msg)` already includes the secret
    /// key and the message, which gives nonce secrecy and per-message
    /// uniqueness -- exactly the property the caller-supplied nonce exists
    /// to guarantee. `ed25519-zebra` exposes no hook to inject a
    /// caller-chosen `r`; supplying one would mean hand-rolling RFC 8032
    /// signing, which this component declines to do. Contrast with the
    /// sr25519 component, which does bind the caller nonce because
    /// schnorrkel supports it directly.
    fn sign_deterministic(
        sk: &[u8],
        msg: &[u8],
        _nonce: &[u8],
        _label: &'static [u8],
        sig_out: &mut [u8],
    ) -> Result<()> {
        raw_sign(sk, msg, sig_out)
    }

    fn verify(pk: &[u8], msg: &[u8], _label: &'static [u8], sig: &[u8]) -> Choice {
        let Ok(pk): core::result::Result<[u8; 32], _> = pk.try_into() else {
            return Choice::from(0u8);
        };
        let Ok(sig): core::result::Result<[u8; 64], _> = sig.try_into() else {
            return Choice::from(0u8);
        };
        let Ok(vk) = VerificationKey::try_from(pk) else {
            return Choice::from(0u8);
        };
        Choice::from(u8::from(vk.verify(&sig.into(), msg).is_ok()))
    }
}

fn check_len(buf: &[u8], want: usize) -> Result<()> {
    if buf.len() == want {
        Ok(())
    } else {
        Err(Error::BadLength {
            expected: want,
            actual: buf.len(),
        })
    }
}

fn raw_sign(sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<()> {
    check_len(sk, 64)?;
    check_len(sig_out, 64)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk[..32]);
    let mut signing = SigningKey::from(seed);
    seed.zeroize();
    let sig: [u8; 64] = signing.sign(msg).into();
    // `SigningKey` is `Copy`, so it has no drop glue: wipe it explicitly.
    signing.zeroize();
    sig_out.copy_from_slice(&sig);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::ClassicalScheme;

    const LABEL: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

    fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
        let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
        Ed25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn secret_key_holds_seed_then_public_key() {
        let (sk, pk) = keypair(1);
        assert_eq!(&sk[..32], &[1u8; 32], "first half is the seed");
        assert_eq!(&sk[32..], &pk[..], "second half is the public key");
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(2);
        let mut sig = [0u8; 64];
        Ed25519::sign_deterministic(&sk, b"msg", b"nonce", LABEL, &mut sig).expect("sign");
        assert!(bool::from(Ed25519::verify(&pk, b"msg", LABEL, &sig)));
    }

    #[test]
    fn a_wrong_message_fails() {
        let (sk, pk) = keypair(3);
        let mut sig = [0u8; 64];
        Ed25519::sign_deterministic(&sk, b"msg", b"nonce", LABEL, &mut sig).expect("sign");
        assert!(!bool::from(Ed25519::verify(&pk, b"other", LABEL, &sig)));
    }

    #[test]
    fn deterministic_signing_is_canonical() {
        let (sk, _) = keypair(4);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        Ed25519::sign_deterministic(&sk, b"m", b"n", LABEL, &mut a).expect("sign");
        Ed25519::sign_deterministic(&sk, b"m", b"n", LABEL, &mut b).expect("sign");
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_ignores_the_nonce() {
        let (sk, _) = keypair(5);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        Ed25519::sign_deterministic(&sk, b"m", b"n1", LABEL, &mut a).expect("sign");
        Ed25519::sign_deterministic(&sk, b"m", b"n2", LABEL, &mut b).expect("sign");
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_matches_hedged() {
        let (sk, _) = keypair(6);
        let (mut deterministic, mut hedged) = ([0u8; 64], [0u8; 64]);
        Ed25519::sign_deterministic(&sk, b"m", b"n", LABEL, &mut deterministic).expect("sign");
        let mut rng = rand_core::OsRng;
        Ed25519::sign(&sk, b"m", LABEL, &mut rng, &mut hedged).expect("sign");
        assert_eq!(deterministic, hedged);
    }
}
