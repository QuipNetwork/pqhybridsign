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

/// The ed25519 verifiable random function: RFC 9381
/// `ECVRF-EDWARDS25519-SHA512-TAI`, suite string `0x03`.
///
/// # Why TAI and not ELL2
///
/// RFC 9381 section 5.5 defines two ciphersuites over edwards25519. They
/// differ only in `ECVRF_encode_to_curve`: TAI hashes with try-and-increment,
/// ELL2 with Elligator 2. ELL2 is constant time and TAI is not, so RFC 9381
/// section 7.5 prefers ELL2 wherever the VRF input has to stay secret. This
/// crate pins **TAI**, for two reasons that both have to hold:
///
/// * **Nothing secret reaches the variable-time loop.** TAI's running time is
///   a function of its hash input alone, and that input is
///   `suite || 0x01 || PK_string || alpha_string || ctr || 0x00`. The public
///   key is public by definition and `alpha_string` here is the suite label
///   and the caller's VRF input, which in a consensus deployment is chain
///   state every validator already holds. The iteration count is therefore
///   computable by anybody who can see the proof, so leaking it through timing
///   leaks nothing. RFC 9381 section 5.4.1.1 states the same condition. **A
///   caller who evaluates this VRF over a secret input does not get that
///   guarantee** and should treat the evaluation as leaking the input's
///   iteration count; the construction in [`crate::vrf`] has no secret input.
/// * **ELL2 cannot be reached without writing new field arithmetic.**
///   `curve25519-dalek` 4.1 keeps `elligator_encode` and `FieldElement`
///   crate-private, so an ELL2 suite here would mean hand-rolling square roots
///   in GF(2^255-19). New, unreviewed field code carrying the whole VRF is a
///   worse risk than a loop whose timing depends on public data, and it is the
///   kind of risk that does not show up in a test suite.
///
/// # What is pinned, and where the RFC's bytes go
///
/// [`vrf_evaluate`](crate::vrf::ClassicalVrf::vrf_evaluate) writes the RFC's
/// proof in two pieces, and the split is the one [`crate::vrf`] needs rather
/// than the RFC's:
/// `point_to_string(Gamma)` is the **pre-output**, the sole source of every
/// consensus-decisive byte, and `int_to_string(c, 16) || int_to_string(s, 32)`
/// is the **proof**. Concatenated in that order they are exactly RFC 9381's
/// 80-byte `pi_string`, so the first `PRE_OUTPUT_LEN + PROOF_LEN` bytes of a
/// hybrid VRF proof can be handed to any other RFC 9381 implementation
/// unaltered. `the_rfc_9381_appendix_b3_vectors_pass` holds that claim against
/// the RFC's own vectors.
///
/// `alpha_string` is **not** the caller's `input` on its own. It is
/// `u64_be(len(label)) || label || u64_be(len(input)) || input`, so two suites
/// over one classical key evaluate to different pre-outputs, which is the
/// separation the sr25519 component gets from its signing context. The length
/// prefixes stop a `(label, input)` pair from being re-cut into another pair
/// with the same concatenation. The RFC does not constrain `alpha_string`, so
/// this stays conformant; an integration that wants the bare RFC input has to
/// pass it as `input` under a label it does not otherwise use.
///
/// # Key validation is on
///
/// RFC 9381 section 5.3 makes `validate_key` optional and this implementation
/// supports only `validate_key = TRUE`: `vrf_verify` and `vrf_make_bytes`
/// both reject a public key of small order.
/// Without it the VRF has trial uniqueness but not *full* uniqueness (RFC 9381
/// section 3.1), meaning a prover holding a chosen, malformed key could show
/// two different outputs on one input -- and this crate's whole reason to have
/// a VRF is that exactly one output exists per key and input. The same
/// low-order structure is what
/// `tests/ed25519_strict.rs::a_low_order_ed25519_half_splits_h1_verification`
/// exercises against the signature path, where ZIP-215 acceptance leaves it
/// open; here it is closed.
///
/// Point decoding is likewise strict, unlike [`ClassicalScheme::verify`]:
/// `string_to_point` requires the encoding to round-trip through
/// `point_to_string`, which is RFC 8032 section 5.1.3's rule that `y < p`, and
/// rejects the non-canonical encodings ZIP-215 accepts. A VRF that two honest
/// verifiers can read differently is a chain split, and here nothing forces
/// the looser rule.
#[cfg(feature = "vrf")]
mod vrf_impl {
    use super::{check_len, Ed25519, Error, Result};
    use crate::classical::Wiped;
    use crate::component::ClassicalScheme;
    use crate::vrf::{ClassicalVrf, PRE_OUTPUT_LEN};
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity;
    use hkdf::Hkdf;
    use sha2::{Digest, Sha512};
    use subtle::{Choice, ConstantTimeEq};
    use zeroize::Zeroize;

    /// RFC 9381 section 5.5, `suite_string` for ECVRF-EDWARDS25519-SHA512-TAI.
    const SUITE_STRING: u8 = 0x03;
    /// `cLen`: the challenge is the first 16 octets of a SHA-512 digest.
    const C_LEN: usize = 16;
    /// `qLen`: `s` is a 32-octet little-endian scalar.
    const S_LEN: usize = 32;
    /// `hLen`: the width of `beta_string`.
    const BETA_LEN: usize = 64;
    /// `encode_to_curve_domain_separator_front`, RFC 9381 section 5.4.1.1.
    const ENCODE_TO_CURVE_FRONT: u8 = 0x01;
    /// `challenge_generation_domain_separator_front`, section 5.4.3.
    const CHALLENGE_FRONT: u8 = 0x02;
    /// `proof_to_hash_domain_separator_front`, section 5.2.
    const PROOF_TO_HASH_FRONT: u8 = 0x03;
    /// The `..._domain_separator_back` every one of the three shares.
    const DOMAIN_BACK: u8 = 0x00;

    /// HKDF salt for [`make_bytes`]. RFC 9381 stops at `beta_string`, a fixed
    /// 64 octets with no notion of an output context, so the expansion below
    /// is this crate's and is separated from every other use of HKDF here.
    const MAKE_BYTES_SALT: &[u8] = b"pqhybridsign/ecvrf-ed25519/make-bytes/v1\0";

    /// RFC 9381 `string_to_point`, which for this suite is RFC 8032
    /// section 5.1.3.
    ///
    /// `CompressedEdwardsY::decompress` alone is not that function: it masks
    /// the sign bit and reduces `y` modulo `p`, so it silently accepts the 19
    /// non-canonical encodings with `y >= p` and an `x = 0` point whose sign
    /// bit is set. Requiring the encoding to survive a round trip through
    /// `point_to_string` rejects both, because `compress` emits only the
    /// canonical form. The cost is one extra field inversion per decode; the
    /// alternative is two honest verifiers disagreeing on one wire value.
    fn string_to_point(bytes: &[u8]) -> Option<EdwardsPoint> {
        let encoded: [u8; 32] = bytes.try_into().ok()?;
        let point = CompressedEdwardsY(encoded).decompress()?;
        (point.compress().to_bytes() == encoded).then_some(point)
    }

    /// RFC 9381 section 5.4.1.1, `ECVRF_encode_to_curve_try_and_increment`,
    /// with `interpret_hash_value_as_a_point(s) = string_to_point(s[0..32])`.
    ///
    /// `alpha` arrives as its pieces rather than as one slice because this
    /// crate's `alpha_string` is a length-prefixed pair and the crate is
    /// `no_std` with no allocator by default. The pieces are only ever fed to
    /// a hash, so concatenating them would buy nothing.
    ///
    /// Returns `None` if all 256 counter values fail, which the RFC puts at
    /// probability about 2^-256. It returns rather than panicking because
    /// `panic` is denied in this crate and an unreachable branch that aborts
    /// is still an abort.
    fn encode_to_curve(pk: &[u8; 32], alpha: &[&[u8]]) -> Option<EdwardsPoint> {
        for ctr in 0..=u8::MAX {
            let mut hasher = Sha512::new();
            hasher.update([SUITE_STRING, ENCODE_TO_CURVE_FRONT]);
            hasher.update(pk);
            for part in alpha {
                hasher.update(part);
            }
            hasher.update([ctr, DOMAIN_BACK]);
            let digest = hasher.finalize();
            if let Some(candidate) = string_to_point(&digest[..32]) {
                // The RFC clears the cofactor first and tests for the identity
                // afterwards, in that order: a point of order 8 maps to the
                // identity here and must be rejected, not returned.
                let h = candidate.mul_by_cofactor();
                if !h.is_identity() {
                    return Some(h);
                }
            }
        }
        None
    }

    /// RFC 9381 section 5.4.3, `ECVRF_challenge_generation`, returning
    /// `truncated_c_string` rather than an integer: `string_to_int` is
    /// little-endian for this suite, so the 16 octets *are* the challenge and
    /// converting them to an integer and back is a no-op.
    fn challenge(points: [&EdwardsPoint; 5]) -> [u8; C_LEN] {
        let mut hasher = Sha512::new();
        hasher.update([SUITE_STRING, CHALLENGE_FRONT]);
        for point in points {
            hasher.update(point.compress().to_bytes());
        }
        hasher.update([DOMAIN_BACK]);
        let digest = hasher.finalize();
        let mut c = [0u8; C_LEN];
        c.copy_from_slice(&digest[..C_LEN]);
        c
    }

    /// The challenge as a scalar. Zero-extending 16 little-endian octets gives
    /// a value below 2^128 and so far below the group order that
    /// `from_bytes_mod_order` never reduces.
    fn challenge_scalar(c: &[u8; C_LEN]) -> Scalar {
        let mut wide = [0u8; 32];
        wide[..C_LEN].copy_from_slice(c);
        Scalar::from_bytes_mod_order(wide)
    }

    /// The RFC 8032 expansion of a secret seed: the clamped secret scalar and
    /// the 32-octet prefix RFC 9381 section 5.4.2.2 hashes into the nonce.
    struct Expanded {
        /// `x`, the secret scalar, reduced modulo the group order.
        x: Scalar,
        /// `truncated_hashed_sk_string`.
        prefix: [u8; 32],
    }

    impl Zeroize for Expanded {
        fn zeroize(&mut self) {
            self.x.zeroize();
            self.prefix.zeroize();
        }
    }

    /// RFC 8032 section 5.1.5 steps 1 to 3.
    ///
    /// The clamped integer is reduced modulo the group order, which RFC 8032
    /// does not do. It is safe here and everywhere this crate uses `x`: the
    /// base point has order exactly `l`, and `H` is a cofactor multiple and so
    /// also has order dividing `l`, so `x` and `x mod l` are the same
    /// multiplier on both. `s` is computed modulo `l` by definition. The
    /// alternative, `Scalar::from_bits`, is deprecated in `curve25519-dalek`
    /// 4 precisely because an unreduced scalar is unsafe in general.
    fn expand_secret(seed: &[u8; 32]) -> Expanded {
        let mut hashed = Sha512::digest(seed);
        let mut clamped = [0u8; 32];
        clamped.copy_from_slice(&hashed[..32]);
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&hashed[32..]);
        let x = Scalar::from_bytes_mod_order(clamped);
        clamped.zeroize();
        hashed.zeroize();
        Expanded { x, prefix }
    }

    /// RFC 9381 section 5.4.2.2, `ECVRF_nonce_generation_RFC8032`.
    ///
    /// This is why [`ClassicalVrf::vrf_evaluate`] ignores its RNG on this
    /// component: the nonce is a function of the secret key and `H`, so there
    /// is no witness to draw and nothing that could reach `getrandom` and
    /// panic on a target that has none.
    fn nonce(prefix: &[u8; 32], h_string: &[u8; 32]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(prefix);
        hasher.update(h_string);
        let mut k_string = hasher.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&k_string);
        let k = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        k_string.zeroize();
        k
    }

    /// RFC 9381 section 5.2, `ECVRF_proof_to_hash`, starting from a decoded
    /// `Gamma` because the caller has already split the proof.
    ///
    /// `cofactor * Gamma` is not decoration. It is what makes the output
    /// insensitive to the torsion component of a `Gamma` an adversary chose,
    /// and so half of what gives the VRF full uniqueness; the other half is
    /// the key validation in `vrf_verify`.
    fn proof_to_hash(gamma: &EdwardsPoint) -> [u8; BETA_LEN] {
        let mut hasher = Sha512::new();
        hasher.update([SUITE_STRING, PROOF_TO_HASH_FRONT]);
        hasher.update(gamma.mul_by_cofactor().compress().to_bytes());
        hasher.update([DOMAIN_BACK]);
        let mut beta = [0u8; BETA_LEN];
        beta.copy_from_slice(&hasher.finalize());
        beta
    }

    /// The two big-endian length prefixes of this crate's `alpha_string`.
    ///
    /// Returned rather than written into a buffer so the caller can keep them
    /// on its own stack frame and borrow them into an `alpha` piece list.
    fn alpha_lengths(label: &[u8], input: &[u8]) -> ([u8; 8], [u8; 8]) {
        (
            (label.len() as u64).to_be_bytes(),
            (input.len() as u64).to_be_bytes(),
        )
    }

    /// RFC 9381 section 5.1, `ECVRF_prove`, writing `Gamma` and `c || s` into
    /// separate buffers.
    fn prove(
        sk: &[u8],
        alpha: &[&[u8]],
        pre_output_out: &mut [u8],
        proof_out: &mut [u8],
    ) -> Result<()> {
        check_len(sk, Ed25519::SECRET_KEY_LEN)?;
        check_len(pre_output_out, PRE_OUTPUT_LEN)?;
        check_len(proof_out, Ed25519::PROOF_LEN)?;

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&sk[..32]);
        let secret = Wiped(expand_secret(&seed));
        seed.zeroize();

        // `Y` is recomputed rather than read from the second half of `sk`, the
        // same choice `sr25519::sign_with_rng` makes. `Y` is hashed into both
        // `H` and `c`, so a secret key whose two halves disagree would emit a
        // proof that verifies under neither of them; recomputing removes that
        // failure mode instead of documenting it.
        let y_point = EdwardsPoint::mul_base(&secret.0.x);
        let y_string = y_point.compress().to_bytes();

        let h_point = encode_to_curve(&y_string, alpha).ok_or(Error::ComponentFailure)?;
        let h_string = h_point.compress().to_bytes();
        let gamma = h_point * secret.0.x;

        let k = Wiped(nonce(&secret.0.prefix, &h_string));
        let u_point = EdwardsPoint::mul_base(&k.0);
        let v_point = h_point * k.0;

        let c = challenge([&y_point, &h_point, &gamma, &u_point, &v_point]);
        let s = k.0 + challenge_scalar(&c) * secret.0.x;

        pre_output_out.copy_from_slice(&gamma.compress().to_bytes());
        proof_out[..C_LEN].copy_from_slice(&c);
        proof_out[C_LEN..].copy_from_slice(&s.to_bytes());
        Ok(())
    }

    /// RFC 9381 section 5.3, `ECVRF_verify`, with `validate_key = TRUE`, over
    /// a proof the caller has already split into `Gamma` and `c || s`.
    ///
    /// Returns a `Choice` rather than a `bool` so the composite layer can
    /// combine it with the post-quantum binding's verdict without a
    /// short-circuiting branch. Every value read here is public, so the early
    /// returns on a malformed encoding leak nothing an attacker who wrote the
    /// encoding does not already know.
    fn verify_proof(pk: &[u8], alpha: &[&[u8]], pre_output: &[u8], proof: &[u8]) -> Choice {
        let reject = Choice::from(0u8);
        if proof.len() != Ed25519::PROOF_LEN {
            return reject;
        }
        let Ok(y_string): core::result::Result<[u8; 32], _> = pk.try_into() else {
            return reject;
        };
        let Some(y_point) = string_to_point(&y_string) else {
            return reject;
        };
        if y_point.mul_by_cofactor().is_identity() {
            return reject;
        }
        let Some(gamma) = string_to_point(pre_output) else {
            return reject;
        };

        let mut c_bytes = [0u8; C_LEN];
        c_bytes.copy_from_slice(&proof[..C_LEN]);
        let mut s_bytes = [0u8; S_LEN];
        s_bytes.copy_from_slice(&proof[C_LEN..]);
        // RFC 9381 section 5.4.4 step 8: a non-canonical `s` is INVALID. Two
        // encodings of one scalar would otherwise both verify, which is
        // malleability of the proof even though the output cannot move.
        let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
            return reject;
        };
        let Some(h_point) = encode_to_curve(&y_string, alpha) else {
            return reject;
        };

        let c = challenge_scalar(&c_bytes);
        let u_point = EdwardsPoint::mul_base(&s) - y_point * c;
        let v_point = h_point * s - gamma * c;
        challenge([&y_point, &h_point, &gamma, &u_point, &v_point]).ct_eq(&c_bytes)
    }

    impl ClassicalVrf for Ed25519 {
        const PROOF_LEN: usize = C_LEN + S_LEN;

        /// Ignores `_rng`. RFC 9381 section 5.4.2.2 derives the ECVRF nonce
        /// from the secret key and `H`, so this component has no witness to
        /// hedge and the hedged and reproducible paths coincide -- the same
        /// relationship [`ClassicalScheme::sign`] and
        /// [`ClassicalScheme::sign_deterministic`] already have here. The
        /// uniqueness argument in [`crate::vrf`] is unaffected: it needs the
        /// pre-output to be independent of the randomness, and independence
        /// from randomness that is never read is the strongest form of that.
        fn vrf_evaluate(
            sk: &[u8],
            label: &'static [u8],
            input: &[u8],
            _rng: &mut impl rand_core::CryptoRngCore,
            pre_output_out: &mut [u8],
            proof_out: &mut [u8],
        ) -> Result<()> {
            Self::vrf_evaluate_deterministic(sk, label, input, pre_output_out, proof_out)
        }

        fn vrf_evaluate_deterministic(
            sk: &[u8],
            label: &'static [u8],
            input: &[u8],
            pre_output_out: &mut [u8],
            proof_out: &mut [u8],
        ) -> Result<()> {
            let (label_len, input_len) = alpha_lengths(label, input);
            let alpha: [&[u8]; 4] = [&label_len, label, &input_len, input];
            prove(sk, &alpha, pre_output_out, proof_out)
        }

        fn vrf_verify(
            pk: &[u8],
            label: &'static [u8],
            input: &[u8],
            pre_output: &[u8],
            proof: &[u8],
        ) -> Choice {
            let (label_len, input_len) = alpha_lengths(label, input);
            let alpha: [&[u8]; 4] = [&label_len, label, &input_len, input];
            verify_proof(pk, &alpha, pre_output, proof)
        }

        /// Expands RFC 9381's `beta_string` to the caller's width with
        /// HKDF-SHA512.
        ///
        /// The RFC's output is a fixed 64 octets and has no output context, so
        /// something has to bridge it to `B` and to `context`. HKDF is that
        /// bridge because it is already this crate's expansion function
        /// ([`crate::derive`]) and its extract step tolerates a `beta_string`
        /// that is not uniformly random.
        ///
        /// `label` and `input` go into the info string even though
        /// `beta_string` already commits to both through `alpha_string`. It
        /// costs a fixed 24 bytes of hashing and makes the separation hold
        /// even if a future ciphersuite change loosened what `alpha_string`
        /// binds -- the same second-layer reasoning
        /// [`crate::vrf::binding_message`] records for its own label field.
        fn vrf_make_bytes<B: Default + AsMut<[u8]>>(
            pk: &[u8],
            label: &'static [u8],
            input: &[u8],
            pre_output: &[u8],
            context: &[u8],
        ) -> Result<B> {
            // Key validation runs here too, not only in `vrf_verify`. A caller
            // that respects the "verify first" rule has already paid for it,
            // but one that did not would otherwise derive consensus bytes
            // under a key the VRF's uniqueness argument excludes.
            let y_point = string_to_point(pk).ok_or(Error::ComponentFailure)?;
            if y_point.mul_by_cofactor().is_identity() {
                return Err(Error::ComponentFailure);
            }
            let gamma = string_to_point(pre_output).ok_or(Error::ComponentFailure)?;
            let beta = proof_to_hash(&gamma);

            let (label_len, input_len) = alpha_lengths(label, input);
            let context_len = (context.len() as u64).to_be_bytes();
            let info: [&[u8]; 6] = [&label_len, label, &input_len, input, &context_len, context];
            let mut out = B::default();
            Hkdf::<Sha512>::new(Some(MAKE_BYTES_SALT), &beta)
                .expand_multi_info(&info, out.as_mut())
                // The only way this fails is `B` wider than 255 * 64 bytes.
                .map_err(|_| Error::ComponentFailure)?;
            Ok(out)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            challenge_scalar, encode_to_curve, proof_to_hash, prove, string_to_point, verify_proof,
            Ed25519,
        };
        use crate::component::ClassicalScheme;
        use crate::vrf::{ClassicalVrf, PRE_OUTPUT_LEN};
        use alloc::vec::Vec;

        const LABEL: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

        /// The width of `c || s`, spelled out so the test arrays can be sized
        /// in a const position.
        const PROOF_LEN: usize = <Ed25519 as ClassicalVrf>::PROOF_LEN;

        /// One RFC 9381 Appendix B.3 example. The field names are the RFC's.
        struct Vector {
            /// `SK`, the 32-octet secret seed.
            sk: &'static str,
            /// `PK`, the expected public key.
            pk: &'static str,
            /// `alpha`, the VRF input, passed to the RFC's algorithms raw.
            alpha: &'static str,
            /// `H`, the output of `ECVRF_encode_to_curve`.
            h: &'static str,
            /// `pi`, the 80-octet proof.
            pi: &'static str,
            /// `beta`, the 64-octet VRF hash output.
            beta: &'static str,
        }

        /// RFC 9381 Appendix B.3, Examples 16, 17 and 18, transcribed from
        /// the RFC with the line wrapping removed.
        const VECTORS: [Vector; 3] = [
            Vector {
                sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                alpha: "",
                h: "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
                pi: "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
                     26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268\
                     a1b0db10836d9826a528ca76567805",
                beta: "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff\
                       66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
            },
            Vector {
                sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                alpha: "72",
                h: "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
                pi: "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593\
                     3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3\
                     ef39226bbc355bdc9850112c8f4b02",
                beta: "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb\
                       5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
            },
            Vector {
                sk: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                pk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                alpha: "af82",
                h: "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
                pi: "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf809\
                     6bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d4\
                     1b00b05081ed0f58ee5e31b3a970e",
                beta: "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45\
                       2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
            },
        ];

        fn unhex(s: &str) -> Vec<u8> {
            hex::decode(s).expect("test vector is valid hex")
        }

        /// The known-answer test the whole implementation stands or falls on.
        /// A VRF that only agrees with itself is worthless for
        /// interoperability, and nothing else here would catch a wrong domain
        /// separator, a big-endian `s`, or a challenge taken from the wrong
        /// end of the digest.
        ///
        /// The RFC's algorithms take `alpha_string` directly, so these call
        /// [`prove`] and [`verify_proof`] rather than the [`ClassicalVrf`]
        /// methods, which wrap the suite label around the input.
        #[test]
        fn the_rfc_9381_appendix_b3_vectors_pass() {
            for (index, vector) in VECTORS.iter().enumerate() {
                let seed: [u8; 32] = unhex(vector.sk).try_into().expect("32-byte seed");
                let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
                Ed25519::derive(&seed, &mut sk, &mut pk).expect("derive");
                assert_eq!(
                    hex::encode(pk),
                    vector.pk,
                    "example {index}: RFC 8032 key generation"
                );

                let alpha = unhex(vector.alpha);
                let alpha_parts: [&[u8]; 1] = [&alpha];

                let mut pre_output = [0u8; PRE_OUTPUT_LEN];
                let mut proof = [0u8; PROOF_LEN];
                prove(&sk, &alpha_parts, &mut pre_output, &mut proof).expect("prove");

                let mut pi = [0u8; PRE_OUTPUT_LEN + PROOF_LEN];
                pi[..PRE_OUTPUT_LEN].copy_from_slice(&pre_output);
                pi[PRE_OUTPUT_LEN..].copy_from_slice(&proof);
                assert_eq!(hex::encode(pi), vector.pi, "example {index}: pi_string");

                assert!(
                    bool::from(verify_proof(&pk, &alpha_parts, &pre_output, &proof)),
                    "example {index}: the RFC's own proof must verify"
                );

                let gamma = string_to_point(&pre_output).expect("Gamma decodes");
                assert_eq!(
                    hex::encode(proof_to_hash(&gamma)),
                    vector.beta,
                    "example {index}: beta_string"
                );
            }
        }

        /// Pins the try-and-increment loop on its own. `pi` would fail for any
        /// wrong `H` too, but not in a way that says which of the four hash
        /// inputs moved; these vectors also cover both `ctr = 0` and `ctr = 1`.
        #[test]
        fn the_rfc_9381_encode_to_curve_vectors_pass() {
            for (index, vector) in VECTORS.iter().enumerate() {
                let pk: [u8; 32] = unhex(vector.pk).try_into().expect("32-byte key");
                let alpha = unhex(vector.alpha);
                let h = encode_to_curve(&pk, &[&alpha]).expect("encode_to_curve");
                assert_eq!(
                    hex::encode(h.compress().to_bytes()),
                    vector.h,
                    "example {index}"
                );
            }
        }

        fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
            let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
            Ed25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
            (sk, pk)
        }

        fn evaluate(sk: &[u8], input: &[u8]) -> ([u8; PRE_OUTPUT_LEN], [u8; PROOF_LEN]) {
            let (mut pre_output, mut proof) = ([0u8; PRE_OUTPUT_LEN], [0u8; PROOF_LEN]);
            Ed25519::vrf_evaluate_deterministic(sk, LABEL, input, &mut pre_output, &mut proof)
                .expect("evaluate");
            (pre_output, proof)
        }

        #[test]
        fn an_evaluation_round_trips() {
            let (sk, pk) = keypair(1);
            let (pre_output, proof) = evaluate(&sk, b"input");
            assert!(bool::from(Ed25519::vrf_verify(
                &pk,
                LABEL,
                b"input",
                &pre_output,
                &proof
            )));
        }

        #[test]
        fn another_input_does_not_verify() {
            let (sk, pk) = keypair(2);
            let (pre_output, proof) = evaluate(&sk, b"input");
            assert!(!bool::from(Ed25519::vrf_verify(
                &pk,
                LABEL,
                b"other",
                &pre_output,
                &proof
            )));
        }

        #[test]
        fn a_tampered_proof_does_not_verify() {
            let (sk, pk) = keypair(3);
            let (pre_output, mut proof) = evaluate(&sk, b"input");
            proof[0] ^= 0x01;
            assert!(!bool::from(Ed25519::vrf_verify(
                &pk,
                LABEL,
                b"input",
                &pre_output,
                &proof
            )));
        }

        /// The hedged entry point takes an RNG it cannot use, so it must land
        /// on the identical proof, not merely the identical pre-output.
        #[test]
        fn the_hedged_path_matches_the_reproducible_one() {
            let (sk, _) = keypair(4);
            let (mut pre_output, mut proof) = ([0u8; PRE_OUTPUT_LEN], [0u8; PROOF_LEN]);
            Ed25519::vrf_evaluate(
                &sk,
                LABEL,
                b"input",
                &mut rand_core::OsRng,
                &mut pre_output,
                &mut proof,
            )
            .expect("evaluate");
            assert_eq!(evaluate(&sk, b"input"), (pre_output, proof));
        }

        /// RFC 9381 section 5.4.5. Without this a prover holding a chosen,
        /// malformed key could exhibit more than one output on one input,
        /// which is exactly the uniqueness the hybrid VRF is built to have.
        /// `01 00...00` is the encoding of the identity, whose order is 1.
        #[test]
        fn a_small_order_public_key_is_rejected() {
            let mut identity = [0u8; 32];
            identity[0] = 1;
            let (sk, _) = keypair(5);
            let (pre_output, proof) = evaluate(&sk, b"input");
            assert!(!bool::from(Ed25519::vrf_verify(
                &identity,
                LABEL,
                b"input",
                &pre_output,
                &proof
            )));
            assert!(Ed25519::vrf_make_bytes::<[u8; 32]>(
                &identity,
                LABEL,
                b"input",
                &pre_output,
                b"ctx"
            )
            .is_err());
        }

        /// RFC 8032 section 5.1.3 rejects `y >= p`; ZIP-215, which this
        /// component's *signature* verifier follows, accepts it. The VRF takes
        /// the strict rule, so the two honest verifiers of one wire value
        /// cannot disagree. `p` itself is the smallest such encoding, and it
        /// decodes under a lax decoder to the same point as `0`.
        #[test]
        fn a_non_canonical_point_encoding_is_rejected() {
            let mut p = [0xffu8; 32];
            p[0] = 0xed;
            p[31] = 0x7f;
            assert!(string_to_point(&p).is_none());
        }

        /// The output context is the only thing separating two draws from one
        /// evaluation, so it has to reach the expansion.
        #[test]
        fn different_output_contexts_give_different_bytes() {
            let (sk, pk) = keypair(6);
            let (pre_output, _) = evaluate(&sk, b"input");
            let score: [u8; 32] =
                Ed25519::vrf_make_bytes(&pk, LABEL, b"input", &pre_output, b"leadership-score")
                    .expect("bytes");
            let randomness: [u8; 32] =
                Ed25519::vrf_make_bytes(&pk, LABEL, b"input", &pre_output, b"randomness")
                    .expect("bytes");
            assert_ne!(score, randomness);
        }

        /// Zero-extending the 16-octet challenge must not reduce, or the
        /// verifier would compute a different `c` than the prover on the
        /// values where reduction would bite.
        #[test]
        fn the_challenge_scalar_is_the_challenge_bytes_zero_extended() {
            let c = [0xffu8; 16];
            let mut expected = [0u8; 32];
            expected[..16].copy_from_slice(&c);
            assert_eq!(challenge_scalar(&c).to_bytes(), expected);
        }
    }
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
