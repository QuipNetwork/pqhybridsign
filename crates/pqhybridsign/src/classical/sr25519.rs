// SPDX-License-Identifier: AGPL-3.0-or-later
use pqhybridsign_core::{ClassicalScheme, Error, Result};
use rand_core::{CryptoRng, RngCore};
use schnorrkel::context::attach_rng;
use schnorrkel::{signing_context, ExpansionMode, MiniSecretKey, PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha512};
use subtle::Choice;
use zeroize::Zeroize;

/// sr25519 classical component, Schnorr over Ristretto.
#[derive(Clone, Copy, Debug)]
pub struct Sr25519;

/// Holds a schnorrkel key so that its wipe happens on drop.
///
/// schnorrkel 0.11.5 implements `Drop` only for `Keypair` (`src/keys.rs`);
/// `MiniSecretKey` and `SecretKey` derive `Zeroize` but have no destructor,
/// so a plain local leaves its bytes in the stack frame verbatim. Both
/// key types below are short-lived copies of real key material -- the
/// HKDF-expanded component seed in `derive`, the full 64-byte secret on
/// every signature in `sign_with_rng` -- and both were previously dropped
/// unwiped.
///
/// A bare `zeroize()` call at the end of each function would fix today's
/// code and quietly stop working the moment somebody adds an early return
/// or a `?` above it. Holding the value here makes the wipe structural
/// instead: it runs on every exit path, including a panic unwind.
struct Wiped<T: Zeroize>(T);

impl<T: Zeroize> Drop for Wiped<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A deterministic RNG seeded from `H(sk || nonce || msg)`.
///
/// schnorrkel draws its Schnorr nonce from this RNG. Seeding it from the
/// secret key keeps the nonce secret, which specification section 14
/// requires: a public nonce makes the signing key trivially recoverable.
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

impl ClassicalScheme for Sr25519 {
    const NAME: &'static str = "sr25519";
    const PUBLIC_KEY_LEN: usize = 32;
    const SECRET_KEY_LEN: usize = 64;
    const SIGNATURE_LEN: usize = 64;

    fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
        check_len(sk_out, Self::SECRET_KEY_LEN)?;
        check_len(pk_out, Self::PUBLIC_KEY_LEN)?;
        let mini = Wiped(MiniSecretKey::from_bytes(seed).map_err(|_| Error::ComponentFailure)?);
        let keypair = mini.0.expand_to_keypair(ExpansionMode::Ed25519);
        // `to_bytes` returns an owned array with no drop glue, so wipe the
        // temporary once it has been copied into the caller's buffer.
        let mut secret_bytes = keypair.secret.to_bytes();
        sk_out.copy_from_slice(&secret_bytes);
        secret_bytes.zeroize();
        pk_out.copy_from_slice(&keypair.public.to_bytes());
        Ok(())
    }

    fn sign(
        sk: &[u8],
        msg: &[u8],
        label: &'static [u8],
        rng: &mut impl rand_core::CryptoRngCore,
        sig_out: &mut [u8],
    ) -> Result<()> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let result = sign_with_rng(sk, msg, label, &mut SeededRng::new(seed), sig_out);
        seed.zeroize();
        result
    }

    fn sign_deterministic(
        sk: &[u8],
        msg: &[u8],
        nonce: &[u8],
        label: &'static [u8],
        sig_out: &mut [u8],
    ) -> Result<()> {
        check_len(sk, Self::SECRET_KEY_LEN)?;
        // k = H(sk || nonce || msg). The secret key always takes part.
        let mut hasher = Sha512::new();
        hasher.update(sk);
        hasher.update(nonce);
        hasher.update(msg);
        let mut digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        // The digest is secret: its first half is the nonce seed and it is
        // derived from the secret key.
        digest.zeroize();
        let result = sign_with_rng(sk, msg, label, &mut SeededRng::new(seed), sig_out);
        seed.zeroize();
        result
    }

    fn verify(pk: &[u8], msg: &[u8], label: &'static [u8], sig: &[u8]) -> Choice {
        let Ok(public) = PublicKey::from_bytes(pk) else {
            return Choice::from(0u8);
        };
        let Ok(signature) = Signature::from_bytes(sig) else {
            return Choice::from(0u8);
        };
        let ctx = signing_context(label);
        Choice::from(u8::from(public.verify(ctx.bytes(msg), &signature).is_ok()))
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

fn sign_with_rng(
    sk: &[u8],
    msg: &[u8],
    label: &'static [u8],
    rng: &mut SeededRng,
    sig_out: &mut [u8],
) -> Result<()> {
    check_len(sk, 64)?;
    check_len(sig_out, 64)?;
    let secret = Wiped(SecretKey::from_bytes(sk).map_err(|_| Error::ComponentFailure)?);
    let public = secret.0.to_public();
    let ctx = signing_context(label);
    // schnorrkel 0.11.5 has no `SigningTranscript::with_rng`; the caller-
    // supplied RNG is attached via `schnorrkel::context::attach_rng`, which
    // wraps the transcript so `witness_bytes_rng` draws from it instead of
    // the OS RNG (`getrandom_or_panic`). The nonce derived here is seeded
    // from `H(sk || nonce || msg)`, so it never depends on public data alone.
    let sig = secret.0.sign(attach_rng(ctx.bytes(msg), rng), &public);
    sig_out.copy_from_slice(&sig.to_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::ClassicalScheme;

    const H1: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";
    const H3: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";

    fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
        let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
        Sr25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(1);
        let mut sig = [0u8; 64];
        Sr25519::sign_deterministic(&sk, b"msg", b"nonce", H3, &mut sig).expect("sign");
        assert!(bool::from(Sr25519::verify(&pk, b"msg", H3, &sig)));
    }

    #[test]
    fn a_signature_does_not_verify_under_another_suite_context() {
        // The signing context is the suite label. This is the second
        // separation layer below M-prime, per beads pqhs-8ep.9.
        let (sk, pk) = keypair(2);
        let mut sig = [0u8; 64];
        Sr25519::sign_deterministic(&sk, b"msg", b"nonce", H3, &mut sig).expect("sign");
        assert!(!bool::from(Sr25519::verify(&pk, b"msg", H1, &sig)));
    }

    #[test]
    fn deterministic_signing_is_canonical() {
        let (sk, _) = keypair(3);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        Sr25519::sign_deterministic(&sk, b"m", b"n", H3, &mut a).expect("sign");
        Sr25519::sign_deterministic(&sk, b"m", b"n", H3, &mut b).expect("sign");
        assert_eq!(a, b);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(keypair(4), keypair(4));
    }
}
