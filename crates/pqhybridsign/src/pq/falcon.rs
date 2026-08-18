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

/// Domain separator for the deterministic nonce seed. Distinct from the
/// sr25519 one so a seed derived for one component can never be mistaken
/// for the other's. Trailing NUL follows the suite-label convention
/// (`hybrid-<classical>-<pq>-v1\0`), matching `sr25519`'s domain constant.
const NONCE_SEED_DOMAIN: &[u8] = b"pqhybridsign/nonce-seed/fn-dsa-512/v1\0";

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

    /// See `nonce_seed` for the seed construction: the same length-prefixed
    /// layout `Sr25519` uses, with a domain constant distinct to this
    /// component.
    fn sign_deterministic(sk: &[u8], msg: &[u8], nonce: &[u8], sig_out: &mut [u8]) -> Result<()> {
        let mut seed = nonce_seed(sk, nonce, msg);
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

/// The deterministic nonce seed:
/// `SHA-512(NONCE_SEED_DOMAIN || u64_be(len(sk)) || sk || u64_be(len(nonce))
/// || nonce || u64_be(len(msg)) || msg)`, truncated to 32 bytes.
///
/// Each variable-length field is length-prefixed so that no pair of
/// (nonce, msg) values can be re-cut into another pair with the same
/// concatenation; the same discipline `KeyIdentity::derive` and `M'`
/// already use. Lengths are `u64` big-endian, not `usize`: `usize` is
/// 4 bytes on a 32-bit target and 8 on a 64-bit one, and a nonce seed
/// that depended on the pointer width of the machine that computed it
/// would not survive being written down.
fn nonce_seed(sk: &[u8], nonce: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(NONCE_SEED_DOMAIN);
    hasher.update((sk.len() as u64).to_be_bytes());
    hasher.update(sk);
    hasher.update((nonce.len() as u64).to_be_bytes());
    hasher.update(nonce);
    hasher.update((msg.len() as u64).to_be_bytes());
    hasher.update(msg);
    let mut digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    digest.zeroize();
    seed
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

    /// `(nonce, msg)` pairs that concatenate to the same bytes must not
    /// derive the same nonce seed. Without a length prefix
    /// ("ab", "c") and ("a", "bc") both hash sk || "abc".
    #[test]
    fn split_ambiguous_nonce_and_message_produce_different_signatures() {
        let (sk, _) = keypair(5);
        let mut left = [0u8; Falcon512::SIGNATURE_LEN];
        let mut right = [0u8; Falcon512::SIGNATURE_LEN];

        Falcon512::sign_deterministic(&sk, b"c", b"ab", &mut left).expect("sign left");
        Falcon512::sign_deterministic(&sk, b"bc", b"a", &mut right).expect("sign right");

        assert_ne!(
            left.as_slice(),
            right.as_slice(),
            "a re-cut of the same concatenation must not reach the same nonce seed"
        );
    }

    /// The defect this construction fixes is only observable in the seed:
    /// `fn-dsa` hedges the salt with the message representative, so a
    /// signature comparison cannot see it either. Without the length
    /// prefixes, ("ab", "c") and ("a", "bc") both hash sk || "abc" and reach
    /// one seed.
    #[test]
    fn a_re_cut_of_the_same_concatenation_gives_a_different_nonce_seed() {
        let sk = [7u8; Falcon512::SECRET_KEY_LEN];
        assert_ne!(
            nonce_seed(&sk, b"ab", b"c"),
            nonce_seed(&sk, b"a", b"bc"),
            "the length prefixes must separate the nonce from the message"
        );
    }

    /// Known answers computed independently of this code. They pin the
    /// domain string, the field order and the 8-byte big-endian widths, so
    /// a 32-bit target that silently used `usize` would fail here too.
    #[test]
    fn the_nonce_seed_layout_is_pinned() {
        let sk = [7u8; Falcon512::SECRET_KEY_LEN];
        assert_eq!(
            hex::encode(nonce_seed(&sk, b"ab", b"c")),
            "544ae45d91fdb54d9e3eba31c5430579a7e73604ed3326e77110ecf836cc5524"
        );
        assert_eq!(
            hex::encode(nonce_seed(&sk, b"a", b"bc")),
            "2cfa34a60d0ca4a1e7c22135e83dd1ec6532609c07b02c699766ab05da9a7aeb"
        );
    }
}
