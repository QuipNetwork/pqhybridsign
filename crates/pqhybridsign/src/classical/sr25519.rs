// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    classical::Wiped,
    component::ClassicalScheme,
    error::{Error, Result},
};
use rand_core::{CryptoRng, RngCore};
use schnorrkel::context::attach_rng;
use schnorrkel::{signing_context, ExpansionMode, MiniSecretKey, PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha512};
use subtle::Choice;
use zeroize::Zeroize;

/// sr25519 classical component, Schnorr over Ristretto.
#[derive(Clone, Copy, Debug)]
pub struct Sr25519;

/// Domain separator for the deterministic nonce seed. Distinct from the
/// FN-DSA one so a seed derived for one component can never be mistaken
/// for the other's. Trailing NUL follows the suite-label convention
/// (`hybrid-<classical>-<pq>-v1\0`), not `KeyIdentity::derive`'s domain,
/// which omits it; harmless either way since a fixed-length domain is
/// always followed by an explicit 8-byte length.
const NONCE_SEED_DOMAIN: &[u8] = b"pqhybridsign/nonce-seed/sr25519/v1\0";

/// A deterministic RNG seeded from [`nonce_seed`].
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
        let mut seed = nonce_seed(sk, nonce, msg);
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
    nonce_seed_in(NONCE_SEED_DOMAIN, sk, nonce, msg)
}

/// [`nonce_seed`] with the domain separator as a parameter, so the VRF path
/// below can reach the same layout under a domain of its own.
fn nonce_seed_in(domain: &[u8], sk: &[u8], nonce: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update((sk.len() as u64).to_be_bytes());
    hasher.update(sk);
    hasher.update((nonce.len() as u64).to_be_bytes());
    hasher.update(nonce);
    hasher.update((msg.len() as u64).to_be_bytes());
    hasher.update(msg);
    let mut digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    // The digest is secret: its first half is the nonce seed and it is
    // derived from the secret key.
    digest.zeroize();
    seed
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
    // from `nonce_seed`, so it never depends on public data alone.
    let sig = secret.0.sign(attach_rng(ctx.bytes(msg), rng), &public);
    sig_out.copy_from_slice(&sig.to_bytes());
    Ok(())
}

/// The sr25519 verifiable random function, specification section 15.
///
/// The VRF itself is schnorrkel's own, called unmodified: `vrf_create_hash`
/// for the pre-output and `dleq_proove` under `KUSAMA_VRF` for the proof, with
/// the same `b"VRF"` extra transcript `Keypair::vrf_sign` uses. So the wire
/// values are schnorrkel's, and `PublicKey::vrf_verify` -- the same function
/// `sp_core::sr25519` calls -- is what verifies them below.
///
/// Be precise about what that buys, because section 15 calls the hybrid VRF a
/// drop-in replacement for BABE's and it is only half of one. The **proof
/// format and the DLEQ transcript** are schnorrkel's, so no private variant is
/// introduced. The **input transcript** is this crate's:
/// `signing_context(suite_label).bytes(input)`, which binds the suite the way
/// every other signature here is bound. BABE builds its input transcript its
/// own way, so an integration has to feed the same bytes through this
/// `input` parameter rather than assume the two transcripts already agree.
#[cfg(feature = "vrf")]
mod vrf_impl {
    use super::{
        check_len, nonce_seed_in, SeededRng, Sr25519, Wiped, {Error, Result},
    };
    use crate::component::ClassicalScheme;
    use crate::vrf::{ClassicalVrf, PRE_OUTPUT_LEN};
    use merlin::Transcript;
    use schnorrkel::context::attach_rng;
    use schnorrkel::vrf::{VRFPreOut, VRFProof, KUSAMA_VRF};
    use schnorrkel::{signing_context, PublicKey, SecretKey};
    use subtle::Choice;
    use zeroize::Zeroize;

    /// Domain separator for the VRF proof's deterministic nonce seed.
    ///
    /// Distinct from the signing path's `NONCE_SEED_DOMAIN` so that a caller
    /// who signs a message deterministically and evaluates the VRF over the
    /// same bytes cannot reach one seed by two routes. schnorrkel mixes the
    /// transcript into the nonce as well as this seed, and a signature
    /// transcript and a DLEQ transcript never agree, so the separation here is
    /// a second layer rather than the only one.
    const VRF_NONCE_SEED_DOMAIN: &[u8] = b"pqhybridsign/nonce-seed/sr25519-vrf/v1\0";

    /// The extra-transcript label schnorrkel's own `vrf_sign` and `vrf_verify`
    /// use. Matching it is what keeps proofs interoperable.
    const EXTRA_TRANSCRIPT_LABEL: &[u8] = b"VRF";

    impl ClassicalVrf for Sr25519 {
        const PROOF_LEN: usize = 64;

        fn vrf_evaluate(
            sk: &[u8],
            label: &'static [u8],
            input: &[u8],
            rng: &mut impl rand_core::CryptoRngCore,
            pre_output_out: &mut [u8],
            proof_out: &mut [u8],
        ) -> Result<()> {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let result = evaluate_with_rng(
                sk,
                label,
                input,
                &mut SeededRng::new(seed),
                pre_output_out,
                proof_out,
            );
            seed.zeroize();
            result
        }

        fn vrf_evaluate_deterministic(
            sk: &[u8],
            label: &'static [u8],
            input: &[u8],
            pre_output_out: &mut [u8],
            proof_out: &mut [u8],
        ) -> Result<()> {
            check_len(sk, Self::SECRET_KEY_LEN)?;
            let mut seed = nonce_seed_in(VRF_NONCE_SEED_DOMAIN, sk, label, input);
            let result = evaluate_with_rng(
                sk,
                label,
                input,
                &mut SeededRng::new(seed),
                pre_output_out,
                proof_out,
            );
            seed.zeroize();
            result
        }

        fn vrf_verify(
            pk: &[u8],
            label: &'static [u8],
            input: &[u8],
            pre_output: &[u8],
            proof: &[u8],
        ) -> Choice {
            let Ok(public) = PublicKey::from_bytes(pk) else {
                return Choice::from(0u8);
            };
            let Ok(pre_out) = VRFPreOut::from_bytes(pre_output) else {
                return Choice::from(0u8);
            };
            let Ok(vrf_proof) = VRFProof::from_bytes(proof) else {
                return Choice::from(0u8);
            };
            let ctx = signing_context(label);
            Choice::from(u8::from(
                public
                    .vrf_verify(ctx.bytes(input), &pre_out, &vrf_proof)
                    .is_ok(),
            ))
        }

        fn vrf_make_bytes<B: Default + AsMut<[u8]>>(
            pk: &[u8],
            label: &'static [u8],
            input: &[u8],
            pre_output: &[u8],
            context: &[u8],
        ) -> Result<B> {
            let public = PublicKey::from_bytes(pk).map_err(|_| Error::ComponentFailure)?;
            let pre_out = VRFPreOut::from_bytes(pre_output).map_err(|_| Error::ComponentFailure)?;
            let ctx = signing_context(label);
            let inout = pre_out
                .attach_input_hash(&public, ctx.bytes(input))
                .map_err(|_| Error::ComponentFailure)?;
            Ok(inout.make_bytes(context))
        }
    }

    /// Evaluate the VRF, drawing the DLEQ proof's Schnorr nonce from `rng`.
    ///
    /// The pre-output is `sk * H(input)` and does not read `rng` at all, so
    /// every caller reaches the same pre-output over one `(key, input)` pair
    /// no matter what `rng` yields. That is the uniqueness the construction
    /// rests on: a prover who re-runs this a million times moves the proof and
    /// never the output.
    fn evaluate_with_rng(
        sk: &[u8],
        label: &'static [u8],
        input: &[u8],
        rng: &mut SeededRng,
        pre_output_out: &mut [u8],
        proof_out: &mut [u8],
    ) -> Result<()> {
        check_len(sk, Sr25519::SECRET_KEY_LEN)?;
        check_len(pre_output_out, PRE_OUTPUT_LEN)?;
        check_len(proof_out, Sr25519::PROOF_LEN)?;

        // `to_keypair` consumes the `SecretKey`, and `Keypair` is the one
        // schnorrkel type with a `Drop` that wipes, so the expanded secret
        // leaves no unwiped copy behind. `Wiped` still guards the pre-expansion
        // value for the window before the move.
        let secret = Wiped(SecretKey::from_bytes(sk).map_err(|_| Error::ComponentFailure)?);
        let keypair = secret.0.clone().to_keypair();
        let ctx = signing_context(label);
        let inout = keypair.vrf_create_hash(ctx.bytes(input));

        // schnorrkel's own `vrf_sign` passes a bare `Transcript` here, whose
        // `witness_scalar` draws through `getrandom_or_panic`. That panics on a
        // `no_std` target without `getrandom`, so the caller's RNG is attached
        // instead, exactly as `sign_with_rng` does for ordinary signatures.
        // `attach_rng` only redirects witness generation: the committed
        // transcript is unchanged, so the proof still verifies against the bare
        // `Transcript` that `vrf_verify` builds.
        let (proof, _batchable) = keypair.dleq_proove(
            attach_rng(Transcript::new(EXTRA_TRANSCRIPT_LABEL), rng),
            &inout,
            KUSAMA_VRF,
        );

        pre_output_out.copy_from_slice(&inout.to_preout().to_bytes());
        proof_out.copy_from_slice(&proof.to_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::ClassicalScheme;

    const ED_ML44: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";
    const SR_ML44: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";

    fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
        let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
        Sr25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
        (sk, pk)
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, pk) = keypair(1);
        let mut sig = [0u8; 64];
        Sr25519::sign_deterministic(&sk, b"msg", b"nonce", SR_ML44, &mut sig).expect("sign");
        assert!(bool::from(Sr25519::verify(&pk, b"msg", SR_ML44, &sig)));
    }

    #[test]
    fn a_signature_does_not_verify_under_another_suite_context() {
        // The signing context is the suite label. This is the second
        // separation layer below M-prime, per beads pqhs-8ep.9.
        let (sk, pk) = keypair(2);
        let mut sig = [0u8; 64];
        Sr25519::sign_deterministic(&sk, b"msg", b"nonce", SR_ML44, &mut sig).expect("sign");
        assert!(!bool::from(Sr25519::verify(&pk, b"msg", ED_ML44, &sig)));
    }

    #[test]
    fn deterministic_signing_is_canonical() {
        let (sk, _) = keypair(3);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        Sr25519::sign_deterministic(&sk, b"m", b"n", SR_ML44, &mut a).expect("sign");
        Sr25519::sign_deterministic(&sk, b"m", b"n", SR_ML44, &mut b).expect("sign");
        assert_eq!(a, b);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(keypair(4), keypair(4));
    }

    /// `(nonce, msg)` pairs that concatenate to the same bytes must not
    /// derive the same nonce seed. Without a length prefix
    /// ("ab", "c") and ("a", "bc") both hash sk || "abc".
    #[test]
    fn split_ambiguous_nonce_and_message_produce_different_signatures() {
        let sk = [7u8; Sr25519::SECRET_KEY_LEN];
        let mut left = [0u8; Sr25519::SIGNATURE_LEN];
        let mut right = [0u8; Sr25519::SIGNATURE_LEN];

        Sr25519::sign_deterministic(&sk, b"c", b"ab", SR_ML44, &mut left).expect("sign left");
        Sr25519::sign_deterministic(&sk, b"bc", b"a", SR_ML44, &mut right).expect("sign right");

        assert_ne!(
            left.as_slice(),
            right.as_slice(),
            "a re-cut of the same concatenation must not reach the same nonce seed"
        );
    }

    /// The defect this construction fixes is only observable in the seed:
    /// both signature paths bind the message independently, so a signature
    /// comparison cannot see it. Without the length prefixes, ("ab", "c")
    /// and ("a", "bc") both hash sk || "abc" and reach one seed.
    #[test]
    fn a_re_cut_of_the_same_concatenation_gives_a_different_nonce_seed() {
        let sk = [7u8; Sr25519::SECRET_KEY_LEN];
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
        let sk = [7u8; Sr25519::SECRET_KEY_LEN];
        assert_eq!(
            hex::encode(nonce_seed(&sk, b"ab", b"c")),
            "f22b809490ccc6639029676bbd806543ce6cf4d429aa2116aacf584c5de2fa93"
        );
        assert_eq!(
            hex::encode(nonce_seed(&sk, b"a", b"bc")),
            "01d700df27aa70c24c7837b74eceeed5eae156b6c26a1444ff6ecc0b969ac999"
        );
    }
}
