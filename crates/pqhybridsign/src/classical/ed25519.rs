// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    component::ClassicalScheme,
    error::{Error, Result},
};
use ed25519_zebra::{SigningKey, VerificationKey};
use subtle::Choice;
use zeroize::Zeroize;

/// ed25519 classical component of suites H1, H2, H5.
///
/// Signing follows RFC 8032. Verification follows [ZIP-215], which
/// `ed25519-zebra` implements, and the two sides are deliberately
/// asymmetric:
///
/// * What this component **produces** is valid under both ZIP-215 and
///   strict RFC 8032, so any verifier accepts it. [`derive`] emits a
///   canonical, torsion-free public key and [`sign`] emits a signature
///   that satisfies the exact equation `[s]B = R + [k]A`, not only the
///   cofactored `[8][s]B = [8]R + [8][k]A`. `tests/ed25519_strict.rs`
///   pins both, with hard-failing tests: this half of the contract is fully
///   under this crate's control and a regression here is a real bug.
/// * What this component **accepts** is a strict superset of RFC 8032.
///   ZIP-215 requires accepting non-canonical encodings of `A` and `R`,
///   which RFC 8032 section 5.1.3 rejects, and requires the cofactored
///   equation. A verifier that instead takes the alternative equation
///   RFC 8032 section 5.1.7 permits -- `ed25519-dalek`'s `verify_strict`,
///   Go's `crypto/ed25519`, the common Solidity ports -- rejects
///   signatures this component accepts.
///
/// The second bullet is a consensus hazard, not a malleability one:
/// malleability is closed, because `s` must be canonical and `R_bytes` is
/// hashed into `k`. The hazard is that two conforming implementations can
/// disagree about whether one attacker-chosen signature is valid.
/// `tests/vectors/ed25519_zip215_negative.json` pins triples that show the
/// disagreement, and `tests/ed25519_strict.rs` prints a detailed warning for
/// each one, visible on a plain `cargo test` with no extra flag, rather than
/// failing the build, because the exact set of accepted triples is a
/// property of `ed25519-zebra`/`curve25519-dalek`, not something this
/// crate's own specification can bind a second implementation to.
///
/// # Reproducing this in a second implementation
///
/// This crate's specification states ZIP-215 acceptance as this
/// implementation's behavior, and recommends (does not require) that a
/// second, independent implementation reproduce it. A second implementation
/// that instead verifies with a stock strict library -- `ed25519-dalek`'s
/// `verify_strict`, Go's `crypto/ed25519`, or a common Solidity ed25519
/// port -- stays specification-conformant, but takes on the following
/// disadvantages:
///
/// * **Which peers it can disagree with.** The three verifiers named above
///   all reject the triples `tests/vectors/ed25519_zip215_negative.json`
///   pins; this crate's own `verify` accepts them. Two otherwise-conformant
///   parties running one implementation each can reach opposite verdicts on
///   the identical wire bytes.
/// * **Who can trigger the disagreement, and at what cost.** The attacker
///   needs no secret key at all for the classical half: an ed25519 public
///   key of order 8 (or 4, or 2) makes the cofactored check pass for
///   essentially any message, with `R` and `s` fixed constants. There is no
///   private key to steal or brute-force, because none is used --
///   `weak_classical_forgery` in `tests/support/mod.rs` builds one from
///   public curve constants alone.
/// * **What that means for a consensus system.** For an on-chain registry
///   or any protocol where independent parties must agree on validity, this
///   is not "a malformed transaction gets rejected" -- both verifiers
///   reject genuinely malformed input identically. It is "a well-formed,
///   attacker-supplied input is accepted by one honest verifier and
///   rejected by another," which is the shape of a chain split.
///   `tests/ed25519_strict.rs`'s `a_low_order_ed25519_half_splits_h1_verification`
///   shows this survives into the H1 composite signature, not only the bare
///   ed25519 component: an H1 signature with this classical forgery spliced
///   in and an honest ML-DSA-44 half still verifies under this crate,
///   because composite verification is `classical_ok & pq_ok`.
///
/// This crate's own outputs never trigger the hazard (see the first bullet
/// above), so the disadvantage is specific to a second implementation that
/// deliberately chooses a stricter verifier than this specification
/// recommends -- not to any signature this crate itself produces.
///
/// [ZIP-215]: https://zips.z.cash/zip-0215
/// [`derive`]: ClassicalScheme::derive
/// [`sign`]: ClassicalScheme::sign
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
    use crate::component::ClassicalScheme;

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
