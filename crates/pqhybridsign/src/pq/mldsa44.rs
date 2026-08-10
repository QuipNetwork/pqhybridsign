// SPDX-License-Identifier: AGPL-3.0-or-later
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use pqhybridsign_core::{Error, PqScheme, Result};
use subtle::Choice;

/// ML-DSA-44 post-quantum component, FIPS 204.
#[derive(Clone, Copy, Debug)]
pub struct MlDsa44;

/// The `ctx` argument to `fips204`. Always empty: the hybrid layer already
/// binds every suite through its own message construction (`M'`), and using
/// the fips204 ctx as well would add a second, unspecified separation layer
/// and break interoperability with other conforming implementations.
const EMPTY_CTX: &[u8] = &[];

/// The FIPS 204 deterministic variant supplies an all-zero `rnd` value in
/// place of the random bit generator output (section 5.5, step 5).
const ZERO_SEED: [u8; 32] = [0u8; 32];

impl PqScheme for MlDsa44 {
    const NAME: &'static str = "mldsa44";
    const PUBLIC_KEY_LEN: usize = ml_dsa_44::PK_LEN;
    const SECRET_KEY_LEN: usize = ml_dsa_44::SK_LEN;
    const SIGNATURE_LEN: usize = ml_dsa_44::SIG_LEN;
    const SEED_LEN: usize = 32;
    const IS_DETERMINISTIC: bool = true;

    fn derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
        let seed: &[u8; 32] = seed.try_into().map_err(|_| Error::BadLength {
            expected: 32,
            actual: seed.len(),
        })?;
        check_len(sk_out, Self::SECRET_KEY_LEN)?;
        check_len(pk_out, Self::PUBLIC_KEY_LEN)?;
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(seed);
        sk_out.copy_from_slice(&sk.into_bytes());
        pk_out.copy_from_slice(&pk.into_bytes());
        Ok(())
    }

    fn sign(
        sk: &[u8],
        msg: &[u8],
        _rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()> {
        // ML-DSA-44 is deterministic by specification, so hedged and
        // deterministic signing coincide here.
        Self::sign_deterministic(sk, msg, &[], sig_out)
    }

    fn sign_deterministic(sk: &[u8], msg: &[u8], _nonce: &[u8], sig_out: &mut [u8]) -> Result<()> {
        check_len(sig_out, Self::SIGNATURE_LEN)?;
        let bytes: [u8; ml_dsa_44::SK_LEN] = sk.try_into().map_err(|_| Error::BadLength {
            expected: Self::SECRET_KEY_LEN,
            actual: sk.len(),
        })?;
        let private =
            ml_dsa_44::PrivateKey::try_from_bytes(bytes).map_err(|_| Error::ComponentFailure)?;
        let sig = private
            .try_sign_with_seed(&ZERO_SEED, msg, EMPTY_CTX)
            .map_err(|_| Error::ComponentFailure)?;
        sig_out.copy_from_slice(&sig);
        Ok(())
    }

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Choice {
        let Ok(pk_bytes): core::result::Result<[u8; ml_dsa_44::PK_LEN], _> = pk.try_into() else {
            return Choice::from(0u8);
        };
        let Ok(sig_bytes): core::result::Result<[u8; ml_dsa_44::SIG_LEN], _> = sig.try_into()
        else {
            return Choice::from(0u8);
        };
        let Ok(public) = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes) else {
            return Choice::from(0u8);
        };
        Choice::from(u8::from(public.verify(msg, &sig_bytes, EMPTY_CTX)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::PqScheme;

    fn keypair(seed: u8) -> ([u8; MlDsa44::SECRET_KEY_LEN], [u8; MlDsa44::PUBLIC_KEY_LEN]) {
        let mut sk = [0u8; MlDsa44::SECRET_KEY_LEN];
        let mut pk = [0u8; MlDsa44::PUBLIC_KEY_LEN];
        MlDsa44::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn sizes_match_the_specification() {
        assert_eq!(MlDsa44::PUBLIC_KEY_LEN, 1312);
        assert_eq!(MlDsa44::SECRET_KEY_LEN, 2560);
        assert_eq!(MlDsa44::SIGNATURE_LEN, 2420);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(keypair(1), keypair(1));
        assert_ne!(keypair(1), keypair(2));
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(3);
        let mut sig = [0u8; MlDsa44::SIGNATURE_LEN];
        MlDsa44::sign_deterministic(&sk, b"msg", b"ignored", &mut sig).expect("sign");
        assert!(bool::from(MlDsa44::verify(&pk, b"msg", &sig)));
        assert!(!bool::from(MlDsa44::verify(&pk, b"other", &sig)));
    }

    #[test]
    fn deterministic_signing_is_canonical() {
        let (sk, _) = keypair(4);
        let mut a = [0u8; MlDsa44::SIGNATURE_LEN];
        let mut b = [0u8; MlDsa44::SIGNATURE_LEN];
        MlDsa44::sign_deterministic(&sk, b"m", b"n1", &mut a).expect("sign");
        MlDsa44::sign_deterministic(&sk, b"m", b"n2", &mut b).expect("sign");
        assert_eq!(a, b, "the nonce is ignored: ML-DSA is deterministic by specification");
    }
}
