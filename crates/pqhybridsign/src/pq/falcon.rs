// SPDX-License-Identifier: AGPL-3.0-or-later
use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, DomainContext, KeyPairGenerator,
    KeyPairGenerator512, SigningKey, SigningKey512, VerifyingKey, VerifyingKey512, DOMAIN_NONE,
    FN_DSA_LOGN_512, HASH_ID_RAW,
};
use pqhybridsign_core::{Error, PqScheme, Result};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use subtle::Choice;
use zeroize::Zeroize;

/// FN-DSA-512 post-quantum component (Falcon), `fn-dsa` crate 0.4.0.
///
/// Specification section 6 pins `MIN_FALCON512_SIG_LEN` for the
/// delta-length wire encoding this component's H2 and H4 suites use; that
/// constant lives with the suites (`pqhybridsign::suites`), not here, since
/// it is a wire-format property, not a component property.
#[derive(Clone, Copy, Debug)]
pub struct Falcon512;

/// FN-DSA's domain-separation context. Empty: `M'` already binds the suite
/// label, and using the FN-DSA context as well would add a second,
/// unspecified separation layer, mirroring `MlDsa44::EMPTY_CTX`.
const EMPTY_DOMAIN: DomainContext<'static> = DOMAIN_NONE;

impl PqScheme for Falcon512 {
    const NAME: &'static str = "falcon512";
    const PUBLIC_KEY_LEN: usize = vrfy_key_size(FN_DSA_LOGN_512);
    const SECRET_KEY_LEN: usize = sign_key_size(FN_DSA_LOGN_512);
    const SIGNATURE_LEN: usize = signature_size(FN_DSA_LOGN_512);
    const SEED_LEN: usize = 32;
    /// FN-DSA's Gaussian sampler consumes randomness for every signature by
    /// construction; unlike ML-DSA-44 there is no all-zero `rnd` fixed by
    /// specification, so this is `false` and `sign_deterministic` below
    /// derives its own seed instead.
    const IS_DETERMINISTIC: bool = false;

    fn derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
        let seed: &[u8; 32] = seed.try_into().map_err(|_| Error::BadLength {
            expected: 32,
            actual: seed.len(),
        })?;
        check_len(sk_out, Self::SECRET_KEY_LEN)?;
        check_len(pk_out, Self::PUBLIC_KEY_LEN)?;
        let mut rng = SeededRng::new(*seed);
        let mut kg = KeyPairGenerator512::default();
        kg.keygen(FN_DSA_LOGN_512, &mut rng, sk_out, pk_out);
        Ok(())
    }

    /// Hedged signing: `rng` seeds the internal deterministic expander that
    /// drives FN-DSA's Gaussian sampler for this one signature.
    fn sign(
        sk: &[u8],
        msg: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let result = sign_with_seed(sk, msg, &seed, sig_out);
        seed.zeroize();
        result
    }

    /// `k = H(sk || nonce || msg)`, the same construction `Sr25519` uses:
    /// the secret key always takes part, so the nonce seed cannot be
    /// recovered from public data alone.
    fn sign_deterministic(sk: &[u8], msg: &[u8], nonce: &[u8], sig_out: &mut [u8]) -> Result<()> {
        let mut hasher = Sha512::new();
        hasher.update(sk);
        hasher.update(nonce);
        hasher.update(msg);
        let mut digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        digest.zeroize();
        let result = sign_with_seed(sk, msg, &seed, sig_out);
        seed.zeroize();
        result
    }

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Choice {
        let Some(vk) = VerifyingKey512::decode(pk) else {
            return Choice::from(0u8);
        };
        Choice::from(u8::from(vk.verify(sig, &EMPTY_DOMAIN, &HASH_ID_RAW, msg)))
    }
}

fn sign_with_seed(sk: &[u8], msg: &[u8], seed: &[u8; 32], sig_out: &mut [u8]) -> Result<()> {
    check_len(sig_out, Falcon512::SIGNATURE_LEN)?;
    let mut signing_key = SigningKey512::decode(sk).ok_or(Error::ComponentFailure)?;
    let mut rng = SeededRng::new(*seed);
    signing_key
        .sign(&mut rng, &EMPTY_DOMAIN, &HASH_ID_RAW, msg, sig_out)
        .ok_or(Error::ComponentFailure)
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

/// A deterministic RNG seeded from a 32-byte value, expanded by repeated
/// SHA-512 hashing over a counter.
///
/// FN-DSA has no all-zero deterministic mode the way ML-DSA-44's `rnd` does:
/// its key generation and signing both draw an RNG-sized, unbounded amount
/// of randomness. Seeding this expander from a value derived from the
/// secret key (see `sign_deterministic`) or, for `derive`, from the
/// HKDF-expanded component seed, reproduces the same output for the same
/// input while keeping the seed itself secret. Mirrors `Sr25519`'s
/// `SeededRng`, duplicated here rather than shared because it is private to
/// each component module.
struct SeededRng {
    state: [u8; 32],
    counter: u64,
    buffer: [u8; 64],
    used: usize,
}

impl SeededRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            state: seed,
            counter: 0,
            buffer: [0u8; 64],
            used: 64,
        }
    }
    fn refill(&mut self) {
        let mut hasher = Sha512::new();
        hasher.update(self.state);
        hasher.update(self.counter.to_be_bytes());
        self.buffer.copy_from_slice(&hasher.finalize());
        self.counter += 1;
        self.used = 0;
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.used == self.buffer.len() {
                self.refill();
            }
            *byte = self.buffer[self.used];
            self.used += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

impl Drop for SeededRng {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::PqScheme;

    fn keypair(
        seed: u8,
    ) -> (
        [u8; Falcon512::SECRET_KEY_LEN],
        [u8; Falcon512::PUBLIC_KEY_LEN],
    ) {
        let mut sk = [0u8; Falcon512::SECRET_KEY_LEN];
        let mut pk = [0u8; Falcon512::PUBLIC_KEY_LEN];
        Falcon512::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn sizes_match_the_measured_fn_dsa_0_4_0_values() {
        assert_eq!(Falcon512::PUBLIC_KEY_LEN, 897);
        assert_eq!(Falcon512::SECRET_KEY_LEN, 1345);
        assert_eq!(Falcon512::SIGNATURE_LEN, 666);
    }

    #[test]
    fn derivation_is_deterministic() {
        let (sk1, pk1) = keypair(1);
        let (sk2, pk2) = keypair(1);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
        let (sk3, _) = keypair(2);
        assert_ne!(sk1, sk3);
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(3);
        let mut sig = [0u8; Falcon512::SIGNATURE_LEN];
        Falcon512::sign_deterministic(&sk, b"msg", b"ignored", &mut sig).expect("sign");
        assert!(bool::from(Falcon512::verify(&pk, b"msg", &sig)));
        assert!(!bool::from(Falcon512::verify(&pk, b"other", &sig)));
    }

    #[test]
    fn hedged_signing_draws_from_the_caller_rng() {
        let (sk, pk) = keypair(7);
        let mut a = [0u8; Falcon512::SIGNATURE_LEN];
        let mut b = [0u8; Falcon512::SIGNATURE_LEN];
        let mut rng = rand_core::OsRng;
        Falcon512::sign(&sk, b"m", &mut rng, &mut a).expect("sign");
        Falcon512::sign(&sk, b"m", &mut rng, &mut b).expect("sign");
        assert_ne!(a, b, "hedged signing must not repeat a signature");
        assert!(bool::from(Falcon512::verify(&pk, b"m", &a)));
        assert!(bool::from(Falcon512::verify(&pk, b"m", &b)));
    }

    #[test]
    fn deterministic_signing_is_canonical_and_varies_with_the_nonce() {
        let (sk, _) = keypair(4);
        let mut a = [0u8; Falcon512::SIGNATURE_LEN];
        let mut b = [0u8; Falcon512::SIGNATURE_LEN];
        Falcon512::sign_deterministic(&sk, b"m", b"n1", &mut a).expect("sign");
        Falcon512::sign_deterministic(&sk, b"m", b"n1", &mut b).expect("sign");
        assert_eq!(a, b, "same nonce must reproduce the same signature");

        let mut c = [0u8; Falcon512::SIGNATURE_LEN];
        Falcon512::sign_deterministic(&sk, b"m", b"n2", &mut c).expect("sign");
        assert_ne!(a, c, "a different nonce must change the signature");
    }
}
