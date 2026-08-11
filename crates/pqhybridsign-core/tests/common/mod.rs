// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stub component implementations shared across integration tests.
#![allow(dead_code)]

use pqhybridsign_core::{ClassicalScheme, PqScheme, Result};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

pub struct Ed25519Stub;
pub struct MlDsaStub;

impl ClassicalScheme for Ed25519Stub {
    const NAME: &'static str = "ed25519";
    const PUBLIC_KEY_LEN: usize = 32;
    const SECRET_KEY_LEN: usize = 64;
    const SIGNATURE_LEN: usize = 64;
    fn derive(_s: &[u8; 32], _sk: &mut [u8], _pk: &mut [u8]) -> Result<()> {
        Ok(())
    }
    fn sign(
        _a: &[u8],
        _b: &[u8],
        _c: &'static [u8],
        _r: &mut impl rand_core::CryptoRngCore,
        _o: &mut [u8],
    ) -> Result<()> {
        Ok(())
    }
    fn sign_deterministic(
        _a: &[u8],
        _b: &[u8],
        _n: &[u8],
        _c: &'static [u8],
        _o: &mut [u8],
    ) -> Result<()> {
        Ok(())
    }
    fn verify(_a: &[u8], _b: &[u8], _c: &'static [u8], _d: &[u8]) -> Choice {
        Choice::from(1u8)
    }
}

impl PqScheme for MlDsaStub {
    const NAME: &'static str = "mldsa44";
    const PUBLIC_KEY_LEN: usize = 1312;
    const SECRET_KEY_LEN: usize = 2560;
    const SIGNATURE_LEN: usize = 2420;
    const SEED_LEN: usize = 32;
    const IS_DETERMINISTIC: bool = true;
    fn derive(_s: &[u8], _sk: &mut [u8], _pk: &mut [u8]) -> Result<()> {
        Ok(())
    }
    fn sign(
        _a: &[u8],
        _b: &[u8],
        _r: &mut impl rand_core::CryptoRngCore,
        _o: &mut [u8],
    ) -> Result<()> {
        Ok(())
    }
    fn sign_deterministic(_a: &[u8], _b: &[u8], _n: &[u8], _o: &mut [u8]) -> Result<()> {
        Ok(())
    }
    fn verify(_a: &[u8], _b: &[u8], _c: &[u8]) -> Choice {
        Choice::from(1u8)
    }
}

/// Hash-based stubs that actually reject a modified signature.
///
/// The stubs above accept everything, which is enough for size and layout
/// checks but cannot show that a flipped byte fails. These stubs bind the
/// signature to the key, the label and the message, so a single changed bit
/// in either half makes verification fail. They are not signatures: the
/// "public key" is enough to forge one. Only the composite plumbing is
/// under test here.
pub struct HashClassical;
pub struct HashClassicalSr;
pub struct HashPq;

/// Fill `out` with counter-indexed SHA-256 blocks over `parts`.
fn kdf(out: &mut [u8], domain: &[u8], parts: &[&[u8]]) {
    for (counter, chunk) in out.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(domain);
        h.update((counter as u32).to_le_bytes());
        for p in parts {
            h.update(p);
        }
        let block = h.finalize();
        let n = chunk.len();
        chunk.copy_from_slice(&block[..n]);
    }
}

fn classical_public(sk: &[u8]) -> [u8; 32] {
    let mut pk = [0u8; 32];
    kdf(&mut pk, b"stub-classical-pk", &[sk]);
    pk
}

fn classical_derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
    kdf(sk_out, b"stub-classical-sk", &[seed]);
    pk_out.copy_from_slice(&classical_public(sk_out));
    Ok(())
}

fn classical_sign(sk: &[u8], msg: &[u8], label: &[u8], sig_out: &mut [u8]) -> Result<()> {
    kdf(
        sig_out,
        b"stub-classical-sig",
        &[&classical_public(sk), label, msg],
    );
    Ok(())
}

fn classical_verify(pk: &[u8], msg: &[u8], label: &[u8], sig: &[u8]) -> Choice {
    let mut expected = [0u8; 64];
    kdf(&mut expected, b"stub-classical-sig", &[pk, label, msg]);
    sig.ct_eq(&expected)
}

macro_rules! hash_classical_impl {
    ($ty:ty, $name:literal) => {
        impl ClassicalScheme for $ty {
            const NAME: &'static str = $name;
            const PUBLIC_KEY_LEN: usize = 32;
            const SECRET_KEY_LEN: usize = 32;
            const SIGNATURE_LEN: usize = 64;
            fn derive(seed: &[u8; 32], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
                classical_derive(seed, sk_out, pk_out)
            }
            fn sign(
                sk: &[u8],
                msg: &[u8],
                label: &'static [u8],
                _rng: &mut impl rand_core::CryptoRngCore,
                sig_out: &mut [u8],
            ) -> Result<()> {
                classical_sign(sk, msg, label, sig_out)
            }
            fn sign_deterministic(
                sk: &[u8],
                msg: &[u8],
                _nonce: &[u8],
                label: &'static [u8],
                sig_out: &mut [u8],
            ) -> Result<()> {
                classical_sign(sk, msg, label, sig_out)
            }
            fn verify(pk: &[u8], msg: &[u8], label: &'static [u8], sig: &[u8]) -> Choice {
                classical_verify(pk, msg, label, sig)
            }
        }
    };
}

hash_classical_impl!(HashClassical, "ed25519");
hash_classical_impl!(HashClassicalSr, "sr25519");

fn pq_public(sk: &[u8]) -> [u8; 32] {
    let mut pk = [0u8; 32];
    kdf(&mut pk, b"stub-pq-pk", &[sk]);
    pk
}

fn pq_sign(sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<()> {
    kdf(sig_out, b"stub-pq-sig", &[&pq_public(sk), msg]);
    Ok(())
}

macro_rules! hash_pq_impl {
    ($ty:ty, $name:literal, $siglen:literal) => {
        impl PqScheme for $ty {
            const NAME: &'static str = $name;
            const PUBLIC_KEY_LEN: usize = 32;
            const SECRET_KEY_LEN: usize = 32;
            const SIGNATURE_LEN: usize = $siglen;
            const SEED_LEN: usize = 32;
            const IS_DETERMINISTIC: bool = true;
            fn derive(seed: &[u8], sk_out: &mut [u8], pk_out: &mut [u8]) -> Result<()> {
                kdf(sk_out, b"stub-pq-sk", &[seed]);
                pk_out.copy_from_slice(&pq_public(sk_out));
                Ok(())
            }
            fn sign(
                sk: &[u8],
                msg: &[u8],
                _rng: &mut impl rand_core::CryptoRngCore,
                sig_out: &mut [u8],
            ) -> Result<()> {
                pq_sign(sk, msg, sig_out)
            }
            fn sign_deterministic(
                sk: &[u8],
                msg: &[u8],
                _nonce: &[u8],
                sig_out: &mut [u8],
            ) -> Result<()> {
                pq_sign(sk, msg, sig_out)
            }
            fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Choice {
                let mut expected = [0u8; $siglen];
                kdf(&mut expected, b"stub-pq-sig", &[pk, msg]);
                sig.ct_eq(&expected)
            }
        }
    };
}

hash_pq_impl!(HashPq, "mldsa44", 128);

/// A fixed-signature-length post-quantum stub for `DeltaSuite` tests. Real
/// FN-DSA-512 signatures under `fn-dsa` 0.4.0 are fixed-length too (see
/// `pqhybridsign::pq::Falcon512`); the delta-length wire encoding still
/// carries a real length field, so these tests exercise it against a
/// component whose signature length is deliberately not the classical
/// component's, rather than assume the two happen to line up.
pub struct HashPqDelta;
hash_pq_impl!(HashPqDelta, "falcon512", 96);
