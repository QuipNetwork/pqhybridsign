// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid VRF, specification section 15.
//!
//! A verifiable random function maps `(secret key, input)` to an output that
//! is pseudorandom to everyone else and to a proof anyone can check. Consensus
//! uses one for leader election, so the output must be **unique**: for a fixed
//! key and input there must be exactly one value the prover can present.
//!
//! No post-quantum VRF is mature enough to deploy, and a post-quantum
//! signature cannot stand in for one. ML-DSA rejection sampling and the
//! stateless SHRINCS counter grind both admit many valid signatures over one
//! message, and the verifier holds only a public key, so it cannot tell a
//! deterministic signature from a chosen one. So this construction takes the
//! VRF itself from the classical half and adds a post-quantum **binding**
//! signature that proves post-quantum key possession over the same input.
//!
//! ```text
//! evaluate:
//!     (pre_output, classical_proof) = classical_vrf(sk_classical, input)
//!     binding = pq_sign(sk_pq, binding_message(label, input, pre_output))
//!     proof   = pre_output || classical_proof || binding
//!
//! verify:
//!     the classical VRF proof against the classical public key and input,
//!     AND the binding against the post-quantum public key
//!
//! derive bytes:
//!     from pre_output ALONE. The binding is verified and never read here.
//! ```
//!
//! # The uniqueness rule
//!
//! **Every consensus-decisive byte comes from the classical pre-output, and
//! the post-quantum binding MUST NOT enter that derivation.** The pre-output
//! is `sk * H(input)`, one value per `(public key, input)` pair, and the proof
//! is what convinces a verifier of that. The binding carries authentication,
//! not entropy.
//!
//! Two things that look like they would fix grindability and do not:
//!
//! - **Fixing the input from chain state does not.** It closes the other
//!   vector, where a producer picks a favourable input, and BABE already
//!   closes it. For one fixed input the post-quantum signature is still not
//!   unique, so a producer who can read the signature into the output grinds
//!   the signature instead.
//! - **Signing the binding deterministically does not.** Determinism is a
//!   property of the signer, and the signer is the one party with a reason to
//!   deviate. [`sign_deterministic`] exists here to make a proof reproducible
//!   and cheap to re-derive, not to carry uniqueness.
//!
//! This is not hypothetical. The deployed testnet build sets
//! `hybrid_output = SHA256(pre_output || binding)` and is grindable at about
//! 11 signatures per slot (QUI-925).
//!
//! # Randomness does not move the output
//!
//! [`sign`] takes an RNG and [`sign_deterministic`] does not, and both reach
//! the same pre-output. The randomness reaches only the Schnorr nonce inside
//! the classical proof, and on the ed25519 component not even that: RFC 9381
//! derives the nonce from the secret key and the input, so the whole ed25519
//! proof is already reproducible and [`sign`] ignores its RNG there, exactly
//! as [`ClassicalScheme::sign`] does for an ordinary ed25519 signature. A
//! prover who re-runs [`sign`] a million times gets at most a million distinct
//! proofs that all carry one pre-output and therefore one output.
//! `randomness_cannot_move_the_output` and
//! `a_second_valid_binding_gives_the_same_output` hold both halves of that,
//! for both components.
//!
//! # Suite coverage
//!
//! Every suite has a hybrid VRF. The classical VRF is schnorrkel's own for the
//! sr25519 component and an RFC 9381 `ECVRF-EDWARDS25519-SHA512-TAI` for the
//! ed25519 component; both are reached through [`ClassicalVrf`], and the
//! construction above is identical on either side.
//!
//! | Suite | Entry points | Classical VRF | Binding |
//! |---|---|---|---|
//! | H1 | [`sign`], [`verify`], [`make_bytes`] | ECVRF-EDWARDS25519-SHA512-TAI | ML-DSA-44, deterministic |
//! | H2 | [`sign_delta`], [`verify_delta`], [`make_bytes_delta`] | ECVRF-EDWARDS25519-SHA512-TAI | FN-DSA-512, deterministic |
//! | H3 | [`sign`], [`verify`], [`make_bytes`] | schnorrkel, Ristretto | ML-DSA-44, deterministic |
//! | H4 | [`sign_delta`], [`verify_delta`], [`make_bytes_delta`] | schnorrkel, Ristretto | FN-DSA-512, deterministic |
//! | H5 | [`sign_stateless`], [`verify_stateless`], [`make_bytes_stateless`] | ECVRF-EDWARDS25519-SHA512-TAI | SHRINCS, stateless path |
//! | H6 | [`sign_stateless`], [`verify_stateless`], [`make_bytes_stateless`] | schnorrkel, Ristretto | SHRINCS, stateless path |
//!
//! The two classical VRFs do not share a proof width, so the proof header is
//! sized by [`header_len`] rather than by a constant: an sr25519 proof is
//! schnorrkel's 64-byte DLEQ proof and an ed25519 proof is RFC 9381's
//! `c || s`, 48 bytes. Size a buffer from [`proof_len`],
//! [`max_proof_len_delta`] or [`proof_len_stateless`] rather than from an
//! arithmetic expression of your own.
//!
//! # H5 and H6 spend budget, never a leaf
//!
//! Both stateful suites bind through the SHRINCS **stateless** path, and
//! everything below applies to each of them; they differ only in the classical
//! half. The stateful path would spend one one-time leaf per evaluation and
//! exhaust a 4,096-leaf tree in about 6.8 hours at 6-second slots, which is
//! why specification section 15
//! excludes H6 from BABE outright. The stateless path spends the few-time
//! budget instead, so the exhaustion argument does not apply, but two limits
//! replace it and neither is small:
//!
//! - **Latency rules out per-slot use below 256s.** A stateless signature
//!   costs about 1.15 s under `profile-256s` and about 0.33 s under
//!   `profile-256s-sha2`, against about 176 s under the 128s profiles. Only
//!   the 256s profiles fit a 6-second slot at all.
//! - **The few-time budget becomes the block-production budget.** The bound is
//!   `2^20` evaluations, or `2^18` under `profile-128s-q18`, and it is shared
//!   with rotation and recovery. At one authored block a minute that is about
//!   two years before a mandatory rotation.
//!
//! So use H5 or H6 for a low-frequency VRF, such as epoch randomness. Per-slot
//! leader election belongs on H1 through H4.
//!
//! # A failed evaluation may leave bytes in the buffer
//!
//! Every evaluation entry point writes the pre-output and the classical proof
//! before the post-quantum binding exists, so an error raised after that point
//! leaves those bytes in `proof_out` with no binding after them. **Discard the
//! buffer on `Err`.** Nothing secret is exposed by it -- a pre-output and its
//! proof are public, and no post-quantum signature was produced -- but the
//! partial contents are not a proof and no verifier will accept them. For H5
//! and H6 in particular, a budget spend that did not land means no SHRINCS
//! signature was released, which is the property that matters there.

use crate::component::{ClassicalScheme, PqScheme};
use crate::encoding_delta;
use crate::error::{Error, Result};
use crate::suite::{DeltaSuite, Suite};
use sha2::{Digest, Sha256};
use subtle::Choice;

/// Length in bytes of a VRF pre-output, the unique value every
/// consensus-decisive byte is derived from.
///
/// A constant, not an associated item, because both classical components make
/// their pre-output one compressed curve point over a 255-bit field: a
/// Ristretto point for sr25519, an Edwards point for ed25519. A third
/// component with a wider point would have to move this onto [`ClassicalVrf`]
/// the way [`ClassicalVrf::PROOF_LEN`] already is.
pub const PRE_OUTPUT_LEN: usize = 32;

/// Length in bytes of the header every hybrid VRF proof opens with: the
/// pre-output followed by the classical proof.
///
/// Not a constant, because the two classical components do not agree on
/// [`ClassicalVrf::PROOF_LEN`].
#[must_use]
pub const fn header_len<C: ClassicalVrf>() -> usize {
    PRE_OUTPUT_LEN + C::PROOF_LEN
}

/// Length in bytes of a [`binding_message`] digest.
pub const BINDING_MESSAGE_LEN: usize = 32;

/// Domain separator for the binding message.
///
/// Specification section 15 writes the binding message as
/// `H("hybrid-vrf" || input || vrf_pre_output)` and stops there: it names
/// neither the hash nor an unambiguous encoding, and a bare concatenation of
/// a variable-length input with anything else can be re-cut. The exact layout
/// this crate signs is pinned in [`binding_message`] and by the
/// `the_binding_message_layout_is_pinned` known-answer test. The trailing null
/// byte follows the suite-label convention.
const BINDING_DOMAIN: &[u8] = b"pqhybridsign/hybrid-vrf/v1\0";

/// A classical component that provides a verifiable random function.
///
/// Sibling of [`ClassicalScheme`], and still a separate trait now that both
/// components implement it: the VRF is compiled only under the `vrf` feature,
/// and folding these five items into [`ClassicalScheme`] would put a feature
/// gate inside the trait every suite already depends on.
///
/// The `label` argument is the suite label, and it separates suites that share
/// one classical key: on sr25519 it is the schnorrkel signing context, exactly
/// as [`ClassicalScheme::sign`] uses it, and on ed25519 it is length-prefixed
/// ahead of `input` to form the RFC 9381 `alpha_string`. Either way two suites
/// over one classical key reach different pre-outputs on one input.
pub trait ClassicalVrf: ClassicalScheme {
    /// Length in bytes of this component's classical VRF proof, the value
    /// written into `proof_out` by [`Self::vrf_evaluate`].
    ///
    /// 64 for sr25519, schnorrkel's DLEQ proof. 48 for ed25519, RFC 9381's
    /// `c || s` with `cLen = 16` and `qLen = 32`; the RFC's third proof field,
    /// `Gamma`, is this construction's pre-output and is carried ahead of it.
    const PROOF_LEN: usize;

    /// Evaluate the VRF, drawing the proof's Schnorr nonce from `rng`.
    ///
    /// Writes [`PRE_OUTPUT_LEN`] bytes into `pre_output_out` and
    /// [`Self::PROOF_LEN`] bytes into `proof_out`.
    ///
    /// `rng` reaches the proof and nothing else, and a component whose proof
    /// is deterministic by specification -- the ed25519 ECVRF, whose nonce
    /// RFC 9381 derives from the secret key and the input -- ignores it
    /// entirely. The pre-output is a deterministic function of the secret key
    /// and the input either way, so it is identical to what
    /// [`Self::vrf_evaluate_deterministic`] produces.
    ///
    /// # Errors
    ///
    /// [`Error::BadLength`] if any buffer is the wrong size,
    /// [`Error::ComponentFailure`] if the secret key does not decode.
    fn vrf_evaluate(
        sk: &[u8],
        label: &'static [u8],
        input: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
        pre_output_out: &mut [u8],
        proof_out: &mut [u8],
    ) -> Result<()>;

    /// Evaluate the VRF with the proof's Schnorr nonce derived from the
    /// secret key and the input, so the whole proof is reproducible.
    ///
    /// # Errors
    ///
    /// The same as [`Self::vrf_evaluate`].
    fn vrf_evaluate_deterministic(
        sk: &[u8],
        label: &'static [u8],
        input: &[u8],
        pre_output_out: &mut [u8],
        proof_out: &mut [u8],
    ) -> Result<()>;

    /// Check a pre-output and proof against a public key and input.
    ///
    /// Returns a `Choice`, never a `bool`, so the composite layer can combine
    /// it with the binding's result without a short-circuiting branch.
    fn vrf_verify(
        pk: &[u8],
        label: &'static [u8],
        input: &[u8],
        pre_output: &[u8],
        proof: &[u8],
    ) -> Choice;

    /// Derive output bytes from a verified pre-output.
    ///
    /// `context` separates independent outputs drawn from one evaluation, the
    /// way BABE draws a leadership score and a randomness contribution from a
    /// single VRF.
    ///
    /// **Verify first.** This reads the pre-output without checking the proof,
    /// because a verifier that has already checked it should not pay for a
    /// second check and a prover has nothing to check. Deriving bytes from an
    /// unverified pre-output derives them from a value nobody vouched for.
    ///
    /// # Errors
    ///
    /// [`Error::ComponentFailure`] if the public key or the pre-output does
    /// not decode to a valid group element.
    fn vrf_make_bytes<B: Default + AsMut<[u8]>>(
        pk: &[u8],
        label: &'static [u8],
        input: &[u8],
        pre_output: &[u8],
        context: &[u8],
    ) -> Result<B>;
}

/// The message the post-quantum binding signs.
///
/// ```text
/// SHA-256(BINDING_DOMAIN || u64_be(len(label)) || label
///                        || u64_be(len(input)) || input || pre_output)
/// ```
///
/// Every variable-length field carries an 8-byte big-endian length, so no two
/// distinct `(label, input)` pairs can be re-cut into the same byte string.
/// The pre-output is fixed at [`PRE_OUTPUT_LEN`] bytes and closes the message,
/// so it needs no prefix of its own. Lengths are `u64`, not `usize`, because a
/// `usize` is 4 bytes on a 32-bit target and 8 on a 64-bit one, and a binding
/// that depended on the pointer width of the machine that produced it would
/// not verify across hosts.
///
/// The label is included even though specification section 15 omits it. Suite
/// separation is already carried by key derivation, so this is a second layer
/// rather than the only one, and it costs a fixed 34 bytes of hashing.
#[must_use]
pub fn binding_message(label: &[u8], input: &[u8], pre_output: &[u8]) -> [u8; BINDING_MESSAGE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((input.len() as u64).to_be_bytes());
    hasher.update(input);
    hasher.update(pre_output);
    let mut out = [0u8; BINDING_MESSAGE_LEN];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Split a composite secret key into its classical and post-quantum halves.
fn split_sk(sk: &[u8], total: usize, classical_len: usize) -> Result<(&[u8], &[u8])> {
    if sk.len() != total {
        return Err(Error::BadLength {
            expected: total,
            actual: sk.len(),
        });
    }
    Ok(sk.split_at(classical_len))
}

/// Split a proof buffer into its pre-output, classical proof and binding
/// slots, rejecting a buffer that cannot hold all three.
fn split_proof_out<C: ClassicalVrf>(
    proof_out: &mut [u8],
    binding_len: usize,
) -> Result<(&mut [u8], &mut [u8], &mut [u8])> {
    let header = header_len::<C>();
    let needed = header + binding_len;
    if proof_out.len() < needed {
        return Err(Error::OutputBufferTooSmall {
            needed,
            actual: proof_out.len(),
        });
    }
    let (head, rest) = proof_out.split_at_mut(header);
    let (pre_output, classical) = head.split_at_mut(PRE_OUTPUT_LEN);
    Ok((pre_output, classical, &mut rest[..binding_len]))
}

/// Split a received proof into its pre-output, classical proof and binding.
fn split_proof<C: ClassicalVrf>(proof: &[u8], binding_len: usize) -> Result<(&[u8], &[u8], &[u8])> {
    let header = header_len::<C>();
    let needed = header + binding_len;
    if proof.len() != needed {
        return Err(Error::BadLength {
            expected: needed,
            actual: proof.len(),
        });
    }
    Ok((
        &proof[..PRE_OUTPUT_LEN],
        &proof[PRE_OUTPUT_LEN..header],
        &proof[header..],
    ))
}

/// Derive output bytes given the classical half of a composite public key.
///
/// Shared by the three families' `make_bytes` entry points, which differ only
/// in how they bound the suite: the classical public key always opens a
/// composite public key, and the pre-output always opens a hybrid VRF proof.
fn make_bytes_inner<C: ClassicalVrf, B: Default + AsMut<[u8]>>(
    label: &'static [u8],
    composite_pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<B> {
    // Two checks rather than one disjunction, so the error names the field
    // that was actually wrong. A caller who passed a short public key and read
    // back a complaint about the proof length would go looking in the wrong
    // place.
    if composite_pk.len() < C::PUBLIC_KEY_LEN {
        return Err(Error::BadLength {
            expected: C::PUBLIC_KEY_LEN,
            actual: composite_pk.len(),
        });
    }
    if proof.len() < header_len::<C>() {
        return Err(Error::BadLength {
            expected: header_len::<C>(),
            actual: proof.len(),
        });
    }
    C::vrf_make_bytes(
        &composite_pk[..C::PUBLIC_KEY_LEN],
        label,
        input,
        &proof[..PRE_OUTPUT_LEN],
        context,
    )
}

// ---------------------------------------------------------------------------
// H1 and H3: fixed-length post-quantum binding.
// ---------------------------------------------------------------------------

/// Length in bytes of a hybrid VRF proof for a fixed-length suite.
#[must_use]
pub fn proof_len<S: Suite>() -> usize
where
    S::Classical: ClassicalVrf,
{
    header_len::<S::Classical>() + <S::Pq as PqScheme>::SIGNATURE_LEN
}

/// Evaluate the hybrid VRF, drawing the classical proof's nonce from `rng`.
///
/// Returns the number of bytes written into `proof_out`, which is
/// [`proof_len`] for this suite. A larger buffer is accepted and only that
/// prefix is written.
///
/// `rng` cannot move the output. See the module documentation.
///
/// # Errors
///
/// [`Error::OutputBufferTooSmall`] if `proof_out` is shorter than
/// [`proof_len`], [`Error::BadLength`] if `sk` is not the suite's secret-key
/// length, [`Error::ComponentFailure`] if either component rejects its key.
pub fn sign<S: Suite>(
    sk: &[u8],
    input: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    proof_out: &mut [u8],
) -> Result<usize>
where
    S::Classical: ClassicalVrf,
{
    let binding_len = <S::Pq as PqScheme>::SIGNATURE_LEN;
    let (sk_classical, sk_pq) = split_sk(
        sk,
        S::SECRET_KEY_LEN,
        <S::Classical as ClassicalScheme>::SECRET_KEY_LEN,
    )?;
    let (pre_output, classical, binding) = split_proof_out::<S::Classical>(proof_out, binding_len)?;

    <S::Classical as ClassicalVrf>::vrf_evaluate(
        sk_classical,
        S::LABEL,
        input,
        rng,
        pre_output,
        classical,
    )?;
    let message = binding_message(S::LABEL, input, pre_output);
    // The binding is signed deterministically so a re-evaluation reproduces
    // the whole proof byte for byte. This is not what makes the construction
    // non-grindable; the exclusion of `binding` from `make_bytes` is. The
    // nonce is empty because the deterministic seed each component derives is
    // already keyed to its own secret key and to this message.
    <S::Pq as PqScheme>::sign_deterministic(sk_pq, &message, &[], binding)?;
    Ok(header_len::<S::Classical>() + binding_len)
}

/// Evaluate the hybrid VRF with a reproducible classical proof.
///
/// # Errors
///
/// The same as [`sign`].
pub fn sign_deterministic<S: Suite>(sk: &[u8], input: &[u8], proof_out: &mut [u8]) -> Result<usize>
where
    S::Classical: ClassicalVrf,
{
    let binding_len = <S::Pq as PqScheme>::SIGNATURE_LEN;
    let (sk_classical, sk_pq) = split_sk(
        sk,
        S::SECRET_KEY_LEN,
        <S::Classical as ClassicalScheme>::SECRET_KEY_LEN,
    )?;
    let (pre_output, classical, binding) = split_proof_out::<S::Classical>(proof_out, binding_len)?;

    <S::Classical as ClassicalVrf>::vrf_evaluate_deterministic(
        sk_classical,
        S::LABEL,
        input,
        pre_output,
        classical,
    )?;
    let message = binding_message(S::LABEL, input, pre_output);
    <S::Pq as PqScheme>::sign_deterministic(sk_pq, &message, &[], binding)?;
    Ok(header_len::<S::Classical>() + binding_len)
}

/// Verify a hybrid VRF proof. Both halves must accept.
///
/// The two results combine with a bitwise `Choice` conjunction, never `&&`,
/// mirroring [`crate::composite::verify`]: no short circuit, so neither the
/// result nor the running time reveals which half failed.
#[must_use]
pub fn verify<S: Suite>(pk: &[u8], input: &[u8], proof: &[u8]) -> bool
where
    S::Classical: ClassicalVrf,
{
    if pk.len() != S::PUBLIC_KEY_LEN {
        return false;
    }
    let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
    let Ok((pre_output, classical, binding)) =
        split_proof::<S::Classical>(proof, <S::Pq as PqScheme>::SIGNATURE_LEN)
    else {
        return false;
    };

    let classical_ok = <S::Classical as ClassicalVrf>::vrf_verify(
        &pk[..c_pk],
        S::LABEL,
        input,
        pre_output,
        classical,
    );
    let message = binding_message(S::LABEL, input, pre_output);
    let binding_ok = <S::Pq as PqScheme>::verify(&pk[c_pk..], &message, binding);
    // The only conversion to `bool`, at the API boundary.
    bool::from(classical_ok & binding_ok)
}

/// Derive output bytes from a verified proof's pre-output.
///
/// **Verify first**, for the reason given on [`ClassicalVrf::vrf_make_bytes`].
///
/// # Errors
///
/// [`Error::BadLength`] if `proof` is shorter than [`header_len`] or `pk`
/// shorter than the classical public key, [`Error::ComponentFailure`] if the
/// public key or the pre-output does not decode.
pub fn make_bytes<S: Suite, B: Default + AsMut<[u8]>>(
    pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<B>
where
    S::Classical: ClassicalVrf,
{
    make_bytes_inner::<S::Classical, B>(S::LABEL, pk, input, proof, context)
}

// ---------------------------------------------------------------------------
// H4: delta-length post-quantum binding.
// ---------------------------------------------------------------------------

/// Largest hybrid VRF proof a delta-length suite can produce.
///
/// The binding carries the same one-byte `DeltaLen` field as this suite's
/// ordinary signatures ([`crate::encoding_delta`]), so a shorter FN-DSA-512
/// binding stays representable.
#[must_use]
pub fn max_proof_len_delta<S: DeltaSuite>() -> usize
where
    S::Classical: ClassicalVrf,
{
    header_len::<S::Classical>() + encoding_delta::DELTA_LEN + <S::Pq as PqScheme>::SIGNATURE_LEN
}

/// Evaluate the hybrid VRF under a delta-length suite.
///
/// Returns the number of bytes written, which is at most
/// [`max_proof_len_delta`].
///
/// # Errors
///
/// The same as [`sign`], plus [`Error::DeltaLengthOutOfRange`] if the
/// post-quantum binding's length falls outside
/// `S::MIN_PQ_SIG_LEN..=S::MIN_PQ_SIG_LEN + 255`.
pub fn sign_delta<S: DeltaSuite>(
    sk: &[u8],
    input: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    proof_out: &mut [u8],
) -> Result<usize>
where
    S::Classical: ClassicalVrf,
{
    let (sk_classical, sk_pq) = split_sk(
        sk,
        S::SECRET_KEY_LEN,
        <S::Classical as ClassicalScheme>::SECRET_KEY_LEN,
    )?;
    let slots = split_proof_out_delta::<S>(proof_out)?;

    <S::Classical as ClassicalVrf>::vrf_evaluate(
        sk_classical,
        S::LABEL,
        input,
        rng,
        slots.pre_output,
        slots.classical,
    )?;
    delta_bind::<S>(sk_pq, input, slots.pre_output, slots.delta, slots.binding)
}

/// Evaluate the hybrid VRF under a delta-length suite with a reproducible
/// classical proof.
///
/// # Errors
///
/// The same as [`sign_delta`].
pub fn sign_delta_deterministic<S: DeltaSuite>(
    sk: &[u8],
    input: &[u8],
    proof_out: &mut [u8],
) -> Result<usize>
where
    S::Classical: ClassicalVrf,
{
    let (sk_classical, sk_pq) = split_sk(
        sk,
        S::SECRET_KEY_LEN,
        <S::Classical as ClassicalScheme>::SECRET_KEY_LEN,
    )?;
    let slots = split_proof_out_delta::<S>(proof_out)?;

    <S::Classical as ClassicalVrf>::vrf_evaluate_deterministic(
        sk_classical,
        S::LABEL,
        input,
        slots.pre_output,
        slots.classical,
    )?;
    delta_bind::<S>(sk_pq, input, slots.pre_output, slots.delta, slots.binding)
}

/// The four slots a delta-length proof buffer carves into.
///
/// A struct rather than a tuple: four same-typed mutable slices in a row are
/// trivial to hand to a caller in the wrong order, and the compiler would not
/// notice.
struct DeltaSlots<'a> {
    /// Where the VRF pre-output is written.
    pre_output: &'a mut [u8],
    /// Where the classical VRF proof is written.
    classical: &'a mut [u8],
    /// The one-byte `DeltaLen` field.
    delta: &'a mut [u8],
    /// Where the post-quantum binding is written.
    binding: &'a mut [u8],
}

/// Carve a delta-length proof buffer into its four slots.
fn split_proof_out_delta<S: DeltaSuite>(proof_out: &mut [u8]) -> Result<DeltaSlots<'_>>
where
    S::Classical: ClassicalVrf,
{
    let binding_len = <S::Pq as PqScheme>::SIGNATURE_LEN;
    let (pre_output, classical, tail) =
        split_proof_out::<S::Classical>(proof_out, encoding_delta::DELTA_LEN + binding_len)?;
    let (delta, binding) = tail.split_at_mut(encoding_delta::DELTA_LEN);
    Ok(DeltaSlots {
        pre_output,
        classical,
        delta,
        binding,
    })
}

/// Sign the binding and fill the `DeltaLen` field. Shared tail of the two
/// delta-length evaluation entry points, which differ only in how the
/// classical proof was produced.
fn delta_bind<S: DeltaSuite>(
    sk_pq: &[u8],
    input: &[u8],
    pre_output: &[u8],
    delta_slot: &mut [u8],
    binding: &mut [u8],
) -> Result<usize>
where
    S::Classical: ClassicalVrf,
{
    let message = binding_message(S::LABEL, input, pre_output);
    <S::Pq as PqScheme>::sign_deterministic(sk_pq, &message, &[], binding)?;
    delta_slot[0] = encoding_delta::encode_delta_byte(binding.len(), S::MIN_PQ_SIG_LEN)?;
    Ok(header_len::<S::Classical>() + encoding_delta::DELTA_LEN + binding.len())
}

/// Verify a hybrid VRF proof under a delta-length suite.
#[must_use]
pub fn verify_delta<S: DeltaSuite>(pk: &[u8], input: &[u8], proof: &[u8]) -> bool
where
    S::Classical: ClassicalVrf,
{
    if pk.len() != S::PUBLIC_KEY_LEN || proof.len() < PRE_OUTPUT_LEN {
        return false;
    }
    let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
    let (pre_output, body) = proof.split_at(PRE_OUTPUT_LEN);

    let Ok((classical, binding)) = decode_delta_body::<S>(body) else {
        return false;
    };

    let classical_ok = <S::Classical as ClassicalVrf>::vrf_verify(
        &pk[..c_pk],
        S::LABEL,
        input,
        pre_output,
        classical,
    );
    let message = binding_message(S::LABEL, input, pre_output);
    let binding_ok = <S::Pq as PqScheme>::verify(&pk[c_pk..], &message, binding);
    bool::from(classical_ok & binding_ok)
}

/// Split `classical_proof || DeltaLen || binding` into its two payloads.
///
/// This does not call [`encoding_delta::decode_delta`], which fixes the
/// classical field at [`encoding_delta::CLASSICAL_SIG_LEN`]. That width is
/// right for a signature and wrong here: the field holds a classical VRF
/// proof, which is 64 bytes on sr25519 and 48 on ed25519. The checks run in
/// `decode_delta`'s order, and the order is the security property -- reject a
/// body too short to hold the header before any length arithmetic, then
/// recover `pq_len` from the one declared byte, then require the body to be
/// exactly that long, so neither a truncated binding nor trailing bytes gets
/// past the split.
fn decode_delta_body<S: DeltaSuite>(body: &[u8]) -> Result<(&[u8], &[u8])>
where
    S::Classical: ClassicalVrf,
{
    let head = <S::Classical as ClassicalVrf>::PROOF_LEN + encoding_delta::DELTA_LEN;
    if body.len() < head {
        return Err(Error::BadLength {
            expected: head,
            actual: body.len(),
        });
    }
    let (classical, tail) = body.split_at(<S::Classical as ClassicalVrf>::PROOF_LEN);
    // `tail[0]` is the `DeltaLen` byte; the addition cannot overflow for any
    // `MIN_PQ_SIG_LEN` this crate ships, but it is checked so a future, larger
    // one fails closed rather than wrapping.
    let pq_len = S::MIN_PQ_SIG_LEN.checked_add(usize::from(tail[0])).ok_or(
        Error::DeltaLengthOutOfRange {
            actual_len: body.len(),
            min_len: S::MIN_PQ_SIG_LEN,
        },
    )?;
    let binding = &tail[encoding_delta::DELTA_LEN..];
    if binding.len() != pq_len {
        return Err(Error::BadLength {
            expected: pq_len,
            actual: binding.len(),
        });
    }
    Ok((classical, binding))
}

/// Derive output bytes from a verified delta-length proof's pre-output.
///
/// # Errors
///
/// The same as [`make_bytes`].
pub fn make_bytes_delta<S: DeltaSuite, B: Default + AsMut<[u8]>>(
    pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<B>
where
    S::Classical: ClassicalVrf,
{
    make_bytes_inner::<S::Classical, B>(S::LABEL, pk, input, proof, context)
}

// ---------------------------------------------------------------------------
// H5 and H6: stateless post-quantum binding, charged to the few-time budget.
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
mod stateless {
    use super::{
        binding_message, header_len, make_bytes_inner, split_proof, split_proof_out, ClassicalVrf,
        Error, Result,
    };
    use crate::budget::{spend_stateless_budget, StatelessBudgetStore};
    use crate::component::{ClassicalScheme, PqStatefulScheme};
    use crate::stateful_composite::SecretKey;
    use crate::suite::StatefulSuite;

    /// Length in bytes of a hybrid VRF proof for a stateful suite.
    ///
    /// Fixed, because the binding takes the stateless path: a stateless
    /// SHRINCS signature carries no leaf-dependent authentication path, so
    /// unlike a stateful signature its length does not grow with the leaf
    /// index.
    #[must_use]
    pub fn proof_len_stateless<S: StatefulSuite>() -> usize
    where
        S::Classical: ClassicalVrf,
    {
        header_len::<S::Classical>() + <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN
    }

    /// Evaluate the hybrid VRF under a stateful suite, binding through the
    /// SHRINCS stateless path.
    ///
    /// **This spends one unit of the few-time stateless budget and no leaf.**
    /// The key's leaf counter is untouched, so a caller needs no journal here,
    /// but the budget is shared with rotation and recovery and is the reason
    /// H6 belongs on a low-frequency VRF. See the module documentation.
    ///
    /// The order of operations matters and matches
    /// `crate::stateful::StatefulHybridSignatureScheme::sign_stateless`. The
    /// classical VRF runs first because it spends nothing and the binding
    /// message cannot be built without its pre-output. The budget is charged
    /// next, before the component signer runs, because a stateless signature
    /// released before its spend is durable is a signature a restart can
    /// reissue.
    ///
    /// # Errors
    ///
    /// [`Error::StatelessBudgetExhausted`] if this key's few-time budget is
    /// spent, [`Error::BudgetStoreFailed`] if the store could not durably
    /// record the spend, [`Error::OutputBufferTooSmall`] if `proof_out` is
    /// shorter than [`proof_len_stateless`], [`Error::ComponentFailure`] if a
    /// component rejects its key or the message.
    pub fn sign_stateless<S: StatefulSuite>(
        sk: &SecretKey<S>,
        budget: &mut impl StatelessBudgetStore,
        input: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
        proof_out: &mut [u8],
    ) -> Result<usize>
    where
        S::Classical: ClassicalVrf,
    {
        let binding_len = <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN;
        let (pre_output, classical, binding) =
            split_proof_out::<S::Classical>(proof_out, binding_len)?;

        <S::Classical as ClassicalVrf>::vrf_evaluate(
            sk.classical_bytes(),
            S::LABEL,
            input,
            rng,
            pre_output,
            classical,
        )?;
        let message = binding_message(S::LABEL, input, pre_output);
        if !<S::Pq as PqStatefulScheme>::precheck(&message) {
            return Err(Error::ComponentFailure);
        }

        let material = <S::Pq as PqStatefulScheme>::stateless_key_material(sk.pq_verify_key())?;
        spend_stateless_budget(
            budget,
            material,
            <S::Pq as PqStatefulScheme>::STATELESS_BUDGET,
        )?;

        let written =
            <S::Pq as PqStatefulScheme>::sign_stateless(sk.pq_secret_key(), &message, binding)?;
        if written != binding_len {
            return Err(Error::BadLength {
                expected: binding_len,
                actual: written,
            });
        }
        Ok(header_len::<S::Classical>() + binding_len)
    }

    /// Verify a hybrid VRF proof under a stateful suite.
    ///
    /// `pk` is the verify-form composite public key
    /// ([`StatefulSuite::VERIFY_PUBLIC_KEY_LEN`] bytes), not the smaller
    /// stored form: a commitment alone cannot check a SHRINCS signature.
    #[must_use]
    pub fn verify_stateless<S: StatefulSuite>(pk: &[u8], input: &[u8], proof: &[u8]) -> bool
    where
        S::Classical: ClassicalVrf,
    {
        if pk.len() != S::VERIFY_PUBLIC_KEY_LEN {
            return false;
        }
        let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
        let Ok((pre_output, classical, binding)) =
            split_proof::<S::Classical>(proof, <S::Pq as PqStatefulScheme>::STATELESS_SIG_LEN)
        else {
            return false;
        };

        let classical_ok = <S::Classical as ClassicalVrf>::vrf_verify(
            &pk[..c_pk],
            S::LABEL,
            input,
            pre_output,
            classical,
        );
        let message = binding_message(S::LABEL, input, pre_output);
        let binding_ok =
            <S::Pq as PqStatefulScheme>::verify_stateless(&pk[c_pk..], &message, binding);
        bool::from(classical_ok & binding_ok)
    }

    /// Derive output bytes from a verified stateful-suite proof's pre-output.
    ///
    /// # Errors
    ///
    /// The same as [`super::make_bytes`].
    pub fn make_bytes_stateless<S: StatefulSuite, B: Default + AsMut<[u8]>>(
        pk: &[u8],
        input: &[u8],
        proof: &[u8],
        context: &[u8],
    ) -> Result<B>
    where
        S::Classical: ClassicalVrf,
    {
        make_bytes_inner::<S::Classical, B>(S::LABEL, pk, input, proof, context)
    }
}

#[cfg(feature = "alloc")]
pub use stateless::{make_bytes_stateless, proof_len_stateless, sign_stateless, verify_stateless};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classical::{Ed25519, Sr25519};
    use crate::composite;
    use crate::composite_delta;
    use crate::{H1, H2, H3, H4};
    use rand_core::OsRng;

    const INPUT: &[u8] = b"epoch-7/slot-42/randomness";
    const OTHER_INPUT: &[u8] = b"epoch-7/slot-43/randomness";
    const OUT_CTX: &[u8] = b"leadership-score";

    /// The two proof-header widths, spelled out once. They differ, which is
    /// the whole reason [`header_len`] is a function.
    const SR_HEADER: usize = header_len::<Sr25519>();
    const ED_HEADER: usize = header_len::<Ed25519>();

    const H3_SK_LEN: usize = <H3 as Suite>::SECRET_KEY_LEN;
    const H3_PK_LEN: usize = <H3 as Suite>::PUBLIC_KEY_LEN;
    const H3_BINDING_LEN: usize = <<H3 as Suite>::Pq as PqScheme>::SIGNATURE_LEN;
    const H3_PROOF_LEN: usize = SR_HEADER + H3_BINDING_LEN;
    const H3_CLASSICAL_SK_LEN: usize =
        <<H3 as Suite>::Classical as ClassicalScheme>::SECRET_KEY_LEN;
    const H3_CLASSICAL_PK_LEN: usize =
        <<H3 as Suite>::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;

    fn h3_keypair(seed: u8) -> ([u8; H3_SK_LEN], [u8; H3_PK_LEN]) {
        let mut sk = [0u8; H3_SK_LEN];
        let mut pk = [0u8; H3_PK_LEN];
        composite::keypair_from_seed::<H3>(&[seed; 32], &mut sk, &mut pk).expect("keygen");
        (sk, pk)
    }

    fn h3_proof(sk: &[u8]) -> [u8; H3_PROOF_LEN] {
        let mut proof = [0u8; H3_PROOF_LEN];
        let written = sign_deterministic::<H3>(sk, INPUT, &mut proof).expect("evaluate");
        assert_eq!(written, H3_PROOF_LEN);
        proof
    }

    fn h3_output(pk: &[u8], proof: &[u8]) -> [u8; 32] {
        make_bytes::<H3, [u8; 32]>(pk, INPUT, proof, OUT_CTX).expect("derive bytes")
    }

    #[test]
    fn a_proof_round_trips() {
        let (sk, pk) = h3_keypair(1);
        let proof = h3_proof(&sk);
        assert!(verify::<H3>(&pk, INPUT, &proof));
    }

    #[test]
    fn proof_len_matches_what_evaluation_writes() {
        assert_eq!(proof_len::<H3>(), H3_PROOF_LEN);
    }

    #[test]
    fn a_proof_does_not_verify_over_another_input() {
        let (sk, pk) = h3_keypair(2);
        let proof = h3_proof(&sk);
        assert!(!verify::<H3>(&pk, OTHER_INPUT, &proof));
    }

    #[test]
    fn a_proof_does_not_verify_under_another_key() {
        let (sk, _) = h3_keypair(3);
        let (_, other_pk) = h3_keypair(4);
        let proof = h3_proof(&sk);
        assert!(!verify::<H3>(&other_pk, INPUT, &proof));
    }

    #[test]
    fn deterministic_evaluation_is_reproducible() {
        let (sk, _) = h3_keypair(5);
        assert_eq!(h3_proof(&sk), h3_proof(&sk));
    }

    /// The uniqueness property, from the prover's side. A prover who re-runs
    /// the hedged path is grinding the only randomness the construction gives
    /// it, and the output must not move.
    #[test]
    fn randomness_cannot_move_the_output() {
        let (sk, pk) = h3_keypair(6);
        let mut first = [0u8; H3_PROOF_LEN];
        let mut second = [0u8; H3_PROOF_LEN];
        sign::<H3>(&sk, INPUT, &mut OsRng, &mut first).expect("first");
        sign::<H3>(&sk, INPUT, &mut OsRng, &mut second).expect("second");

        assert!(verify::<H3>(&pk, INPUT, &first));
        assert!(verify::<H3>(&pk, INPUT, &second));
        assert_ne!(
            first[PRE_OUTPUT_LEN..SR_HEADER],
            second[PRE_OUTPUT_LEN..SR_HEADER],
            "the classical proof is hedged, so two runs must differ"
        );
        assert_eq!(
            first[..PRE_OUTPUT_LEN],
            second[..PRE_OUTPUT_LEN],
            "the pre-output is a deterministic function of the key and the input"
        );
        assert_eq!(h3_output(&pk, &first), h3_output(&pk, &second));
    }

    /// The uniqueness property, from the attacker's side, and the reason the
    /// deployed testnet VRF is defective (QUI-925).
    ///
    /// A block producer holds its own post-quantum key, so it can mint as many
    /// valid bindings over one message as it likes: ML-DSA-44's hedged mode
    /// gives a different signature every call and the verifier accepts each
    /// one. The construction survives that only because the binding never
    /// reaches the output. Hash the binding into the output, as the deployed
    /// build does, and this test is the grind.
    #[test]
    fn a_second_valid_binding_gives_the_same_output() {
        let (sk, pk) = h3_keypair(7);
        let honest = h3_proof(&sk);
        assert!(verify::<H3>(&pk, INPUT, &honest));

        let message = binding_message(H3::LABEL, INPUT, &honest[..PRE_OUTPUT_LEN]);
        let mut ground = honest;
        <<H3 as Suite>::Pq as PqScheme>::sign(
            &sk[H3_CLASSICAL_SK_LEN..],
            &message,
            &mut OsRng,
            &mut ground[SR_HEADER..],
        )
        .expect("a second binding over the same message");

        assert_ne!(
            honest[SR_HEADER..],
            ground[SR_HEADER..],
            "the grind must actually reach a different binding"
        );
        assert!(
            verify::<H3>(&pk, INPUT, &ground),
            "the second binding is equally valid, which is the whole problem"
        );
        assert_eq!(
            h3_output(&pk, &honest),
            h3_output(&pk, &ground),
            "a chosen binding must not move a consensus-decisive byte"
        );
    }

    #[test]
    fn different_inputs_give_different_outputs() {
        let (sk, pk) = h3_keypair(8);
        let mut other = [0u8; H3_PROOF_LEN];
        sign_deterministic::<H3>(&sk, OTHER_INPUT, &mut other).expect("evaluate");
        let first = h3_output(&pk, &h3_proof(&sk));
        let second =
            make_bytes::<H3, [u8; 32]>(&pk, OTHER_INPUT, &other, OUT_CTX).expect("derive bytes");
        assert_ne!(first, second);
    }

    #[test]
    fn different_output_contexts_give_different_outputs() {
        let (sk, pk) = h3_keypair(9);
        let proof = h3_proof(&sk);
        let score = h3_output(&pk, &proof);
        let randomness =
            make_bytes::<H3, [u8; 32]>(&pk, INPUT, &proof, b"randomness").expect("derive bytes");
        assert_ne!(score, randomness);
    }

    #[test]
    fn a_tampered_pre_output_is_rejected() {
        let (sk, pk) = h3_keypair(10);
        let mut proof = h3_proof(&sk);
        proof[0] ^= 0x01;
        assert!(!verify::<H3>(&pk, INPUT, &proof));
    }

    #[test]
    fn a_tampered_binding_is_rejected() {
        let (sk, pk) = h3_keypair(11);
        let mut proof = h3_proof(&sk);
        proof[SR_HEADER] ^= 0x01;
        assert!(!verify::<H3>(&pk, INPUT, &proof));
    }

    #[test]
    fn a_proof_of_the_wrong_length_is_rejected() {
        let (sk, pk) = h3_keypair(12);
        let proof = h3_proof(&sk);
        assert!(!verify::<H3>(&pk, INPUT, &proof[..H3_PROOF_LEN - 1]));
        assert!(!verify::<H3>(&pk, INPUT, &[]));
    }

    #[test]
    fn an_output_buffer_that_is_too_small_is_rejected() {
        let (sk, _) = h3_keypair(13);
        let mut proof = [0u8; H3_PROOF_LEN - 1];
        assert!(sign_deterministic::<H3>(&sk, INPUT, &mut proof).is_err());
    }

    /// Two suites over one classical key must not evaluate to one pre-output.
    /// The suite label is the schnorrkel signing context, which is what
    /// separates them.
    #[test]
    fn the_suite_label_separates_pre_outputs() {
        let sk = [7u8; H3_CLASSICAL_SK_LEN];
        let (mut left, mut right) = ([0u8; PRE_OUTPUT_LEN], [0u8; PRE_OUTPUT_LEN]);
        let (mut lp, mut rp) = (
            [0u8; <Sr25519 as ClassicalVrf>::PROOF_LEN],
            [0u8; <Sr25519 as ClassicalVrf>::PROOF_LEN],
        );
        Sr25519::vrf_evaluate_deterministic(&sk, H3::LABEL, INPUT, &mut left, &mut lp).expect("h3");
        Sr25519::vrf_evaluate_deterministic(&sk, H4::LABEL, INPUT, &mut right, &mut rp)
            .expect("h4");
        assert_ne!(left, right);
    }

    /// Known answers computed independently of this code. They pin the domain
    /// string, the field order and the 8-byte big-endian length widths, so a
    /// 32-bit target that silently used `usize` would fail here too.
    #[test]
    fn the_binding_message_layout_is_pinned() {
        let pre = [7u8; PRE_OUTPUT_LEN];
        assert_eq!(
            hex::encode(binding_message(H3::LABEL, b"vrf-input", &pre)),
            "34d8fc0e2773f377aa5662459005b44b434a0132bf84a5d7566b28d4dd303a90"
        );
        assert_eq!(
            hex::encode(binding_message(H3::LABEL, b"ab", &pre)),
            "3b2197d33db8c621f38f0c85a6c345d14d6235770337d6a45d8ae08491aa179d"
        );
    }

    /// Without the length prefix, a one-byte input and the label's last byte
    /// could be re-cut into each other. The prefixes are what stop that.
    #[test]
    fn a_re_cut_of_the_same_concatenation_gives_a_different_binding_message() {
        let pre = [7u8; PRE_OUTPUT_LEN];
        assert_ne!(
            binding_message(b"ab", b"c", &pre),
            binding_message(b"a", b"bc", &pre)
        );
    }

    #[test]
    fn a_delta_length_proof_round_trips() {
        let mut sk = [0u8; <H4 as DeltaSuite>::SECRET_KEY_LEN];
        let mut pk = [0u8; <H4 as DeltaSuite>::PUBLIC_KEY_LEN];
        composite_delta::keypair_from_seed::<H4>(&[14u8; 32], &mut sk, &mut pk).expect("keygen");

        let mut proof = [0u8; SR_HEADER + 1 + <<H4 as DeltaSuite>::Pq as PqScheme>::SIGNATURE_LEN];
        let written = sign_delta_deterministic::<H4>(&sk, INPUT, &mut proof).expect("evaluate");
        assert_eq!(written, max_proof_len_delta::<H4>());
        assert!(verify_delta::<H4>(&pk, INPUT, &proof[..written]));
        assert!(!verify_delta::<H4>(&pk, OTHER_INPUT, &proof[..written]));

        let hedged_written = sign_delta::<H4>(&sk, INPUT, &mut OsRng, &mut proof).expect("hedged");
        assert!(verify_delta::<H4>(&pk, INPUT, &proof[..hedged_written]));
    }

    /// The same uniqueness check as the H3 case, over FN-DSA-512, which is not
    /// deterministic by specification and so has an even larger space of valid
    /// bindings to grind.
    #[test]
    fn a_delta_length_proof_survives_a_reground_binding() {
        let mut sk = [0u8; <H4 as DeltaSuite>::SECRET_KEY_LEN];
        let mut pk = [0u8; <H4 as DeltaSuite>::PUBLIC_KEY_LEN];
        composite_delta::keypair_from_seed::<H4>(&[15u8; 32], &mut sk, &mut pk).expect("keygen");

        let len = max_proof_len_delta::<H4>();
        let mut honest = [0u8; SR_HEADER + 1 + <<H4 as DeltaSuite>::Pq as PqScheme>::SIGNATURE_LEN];
        sign_delta_deterministic::<H4>(&sk, INPUT, &mut honest).expect("evaluate");

        let classical_sk = <<H4 as DeltaSuite>::Classical as ClassicalScheme>::SECRET_KEY_LEN;
        let message = binding_message(H4::LABEL, INPUT, &honest[..PRE_OUTPUT_LEN]);
        let mut ground = honest;
        <<H4 as DeltaSuite>::Pq as PqScheme>::sign(
            &sk[classical_sk..],
            &message,
            &mut OsRng,
            &mut ground[SR_HEADER + 1..],
        )
        .expect("a second binding");

        assert_ne!(honest[SR_HEADER + 1..], ground[SR_HEADER + 1..]);
        assert!(verify_delta::<H4>(&pk, INPUT, &ground[..len]));
        let first: [u8; 32] =
            make_bytes_delta::<H4, [u8; 32]>(&pk, INPUT, &honest[..len], OUT_CTX).expect("bytes");
        let second: [u8; 32] =
            make_bytes_delta::<H4, [u8; 32]>(&pk, INPUT, &ground[..len], OUT_CTX).expect("bytes");
        assert_eq!(first, second);
    }

    #[test]
    fn the_classical_public_key_is_all_make_bytes_reads() {
        // A verifier that holds only the classical half can still derive the
        // output, which is the structural statement that the post-quantum
        // binding contributes no entropy.
        let (sk, pk) = h3_keypair(16);
        let proof = h3_proof(&sk);
        let from_composite = h3_output(&pk, &proof);
        let from_classical: [u8; 32] = <<H3 as Suite>::Classical as ClassicalVrf>::vrf_make_bytes(
            &pk[..H3_CLASSICAL_PK_LEN],
            H3::LABEL,
            INPUT,
            &proof[..PRE_OUTPUT_LEN],
            OUT_CTX,
        )
        .expect("derive bytes");
        assert_eq!(from_composite, from_classical);
    }

    // -----------------------------------------------------------------------
    // The ed25519 suites. The construction is identical, so these repeat the
    // two tests that carry the security property rather than the whole H3
    // battery: the output must not move when a second, equally valid binding
    // is minted, and it must not move when the hedged path is re-run.
    // -----------------------------------------------------------------------

    const H1_SK_LEN: usize = <H1 as Suite>::SECRET_KEY_LEN;
    const H1_PK_LEN: usize = <H1 as Suite>::PUBLIC_KEY_LEN;
    const H1_BINDING_LEN: usize = <<H1 as Suite>::Pq as PqScheme>::SIGNATURE_LEN;
    const H1_PROOF_LEN: usize = ED_HEADER + H1_BINDING_LEN;
    const H1_CLASSICAL_SK_LEN: usize =
        <<H1 as Suite>::Classical as ClassicalScheme>::SECRET_KEY_LEN;

    fn h1_keypair(seed: u8) -> ([u8; H1_SK_LEN], [u8; H1_PK_LEN]) {
        let mut sk = [0u8; H1_SK_LEN];
        let mut pk = [0u8; H1_PK_LEN];
        composite::keypair_from_seed::<H1>(&[seed; 32], &mut sk, &mut pk).expect("keygen");
        (sk, pk)
    }

    fn h1_proof(sk: &[u8]) -> [u8; H1_PROOF_LEN] {
        let mut proof = [0u8; H1_PROOF_LEN];
        let written = sign_deterministic::<H1>(sk, INPUT, &mut proof).expect("evaluate");
        assert_eq!(written, H1_PROOF_LEN);
        proof
    }

    fn h1_output(pk: &[u8], proof: &[u8]) -> [u8; 32] {
        make_bytes::<H1, [u8; 32]>(pk, INPUT, proof, OUT_CTX).expect("derive bytes")
    }

    #[test]
    fn an_ed25519_proof_round_trips() {
        let (sk, pk) = h1_keypair(20);
        let proof = h1_proof(&sk);
        assert!(verify::<H1>(&pk, INPUT, &proof));
        assert!(!verify::<H1>(&pk, OTHER_INPUT, &proof));
    }

    #[test]
    fn the_two_classical_components_do_not_share_a_proof_length() {
        // If they ever did, `header_len` could go back to being a constant --
        // and until then, a caller who assumed 96 bytes for every suite would
        // be writing past the end of an H1 header.
        assert_eq!(SR_HEADER, PRE_OUTPUT_LEN + 64);
        assert_eq!(ED_HEADER, PRE_OUTPUT_LEN + 48);
        assert_eq!(proof_len::<H1>(), H1_PROOF_LEN);
        assert_eq!(proof_len::<H3>(), H3_PROOF_LEN);
    }

    /// The uniqueness property from the prover's side, for H1. The ed25519
    /// ECVRF has no witness to hedge at all -- RFC 9381 derives its nonce
    /// from the secret key and the input -- so unlike H3 the *whole* proof
    /// has to repeat, not merely the pre-output.
    #[test]
    fn randomness_cannot_move_the_output_on_ed25519() {
        let (sk, pk) = h1_keypair(21);
        let mut first = [0u8; H1_PROOF_LEN];
        let mut second = [0u8; H1_PROOF_LEN];
        sign::<H1>(&sk, INPUT, &mut OsRng, &mut first).expect("first");
        sign::<H1>(&sk, INPUT, &mut OsRng, &mut second).expect("second");

        assert!(verify::<H1>(&pk, INPUT, &first));
        assert!(verify::<H1>(&pk, INPUT, &second));
        assert_eq!(
            first, second,
            "the ed25519 ECVRF reads no randomness, so two hedged runs coincide"
        );
        assert_eq!(h1_output(&pk, &first), h1_output(&pk, &second));
    }

    /// The uniqueness property from the attacker's side, for H1. The grind is
    /// the same one QUI-925 describes: the block producer holds its own
    /// ML-DSA-44 key and can mint as many valid bindings over one message as
    /// it likes.
    #[test]
    fn a_second_valid_binding_gives_the_same_output_on_ed25519() {
        let (sk, pk) = h1_keypair(22);
        let honest = h1_proof(&sk);
        assert!(verify::<H1>(&pk, INPUT, &honest));

        let message = binding_message(H1::LABEL, INPUT, &honest[..PRE_OUTPUT_LEN]);
        let mut ground = honest;
        <<H1 as Suite>::Pq as PqScheme>::sign(
            &sk[H1_CLASSICAL_SK_LEN..],
            &message,
            &mut OsRng,
            &mut ground[ED_HEADER..],
        )
        .expect("a second binding over the same message");

        assert_ne!(
            honest[ED_HEADER..],
            ground[ED_HEADER..],
            "the grind must actually reach a different binding"
        );
        assert!(
            verify::<H1>(&pk, INPUT, &ground),
            "the second binding is equally valid, which is the whole problem"
        );
        assert_eq!(
            h1_output(&pk, &honest),
            h1_output(&pk, &ground),
            "a chosen binding must not move a consensus-decisive byte"
        );
    }

    /// Two suites over one ed25519 key must not evaluate to one pre-output.
    /// The suite label is length-prefixed into `alpha_string`, which is what
    /// separates them; the sr25519 half of this is
    /// `the_suite_label_separates_pre_outputs`.
    #[test]
    fn the_suite_label_separates_ed25519_pre_outputs() {
        let sk = [7u8; H1_CLASSICAL_SK_LEN];
        let (mut left, mut right) = ([0u8; PRE_OUTPUT_LEN], [0u8; PRE_OUTPUT_LEN]);
        let (mut lp, mut rp) = (
            [0u8; <Ed25519 as ClassicalVrf>::PROOF_LEN],
            [0u8; <Ed25519 as ClassicalVrf>::PROOF_LEN],
        );
        Ed25519::vrf_evaluate_deterministic(&sk, H1::LABEL, INPUT, &mut left, &mut lp).expect("h1");
        Ed25519::vrf_evaluate_deterministic(&sk, H2::LABEL, INPUT, &mut right, &mut rp)
            .expect("h2");
        assert_ne!(left, right);
    }

    /// H2 puts the ed25519 ECVRF behind the delta-length encoding, where the
    /// classical field is 48 bytes rather than the 64 the signature encoder
    /// assumes. That is the case `decode_delta_body` exists for, and a wrong
    /// width here would put the `DeltaLen` byte inside the ECVRF proof.
    #[test]
    fn a_delta_length_ed25519_proof_round_trips() {
        let mut sk = [0u8; <H2 as DeltaSuite>::SECRET_KEY_LEN];
        let mut pk = [0u8; <H2 as DeltaSuite>::PUBLIC_KEY_LEN];
        composite_delta::keypair_from_seed::<H2>(&[23u8; 32], &mut sk, &mut pk).expect("keygen");

        let mut proof = [0u8; ED_HEADER + 1 + <<H2 as DeltaSuite>::Pq as PqScheme>::SIGNATURE_LEN];
        let written = sign_delta_deterministic::<H2>(&sk, INPUT, &mut proof).expect("evaluate");
        assert_eq!(written, max_proof_len_delta::<H2>());
        assert!(verify_delta::<H2>(&pk, INPUT, &proof[..written]));
        assert!(!verify_delta::<H2>(&pk, OTHER_INPUT, &proof[..written]));
        assert!(
            !verify_delta::<H2>(&pk, INPUT, &proof[..written - 1]),
            "a truncated binding must not be accepted"
        );

        let hedged = sign_delta::<H2>(&sk, INPUT, &mut OsRng, &mut proof).expect("hedged");
        assert!(verify_delta::<H2>(&pk, INPUT, &proof[..hedged]));
    }

    /// The H2 case of the grind, over FN-DSA-512, whose signatures are not
    /// deterministic by specification and so give an even larger space of
    /// valid bindings to search.
    #[test]
    fn a_delta_length_ed25519_proof_survives_a_reground_binding() {
        let mut sk = [0u8; <H2 as DeltaSuite>::SECRET_KEY_LEN];
        let mut pk = [0u8; <H2 as DeltaSuite>::PUBLIC_KEY_LEN];
        composite_delta::keypair_from_seed::<H2>(&[24u8; 32], &mut sk, &mut pk).expect("keygen");

        let len = max_proof_len_delta::<H2>();
        let mut honest = [0u8; ED_HEADER + 1 + <<H2 as DeltaSuite>::Pq as PqScheme>::SIGNATURE_LEN];
        sign_delta_deterministic::<H2>(&sk, INPUT, &mut honest).expect("evaluate");

        let classical_sk = <<H2 as DeltaSuite>::Classical as ClassicalScheme>::SECRET_KEY_LEN;
        let message = binding_message(H2::LABEL, INPUT, &honest[..PRE_OUTPUT_LEN]);
        let mut ground = honest;
        <<H2 as DeltaSuite>::Pq as PqScheme>::sign(
            &sk[classical_sk..],
            &message,
            &mut OsRng,
            &mut ground[ED_HEADER + 1..],
        )
        .expect("a second binding");

        assert_ne!(honest[ED_HEADER + 1..], ground[ED_HEADER + 1..]);
        assert!(verify_delta::<H2>(&pk, INPUT, &ground[..len]));
        let first: [u8; 32] =
            make_bytes_delta::<H2, [u8; 32]>(&pk, INPUT, &honest[..len], OUT_CTX).expect("bytes");
        let second: [u8; 32] =
            make_bytes_delta::<H2, [u8; 32]>(&pk, INPUT, &ground[..len], OUT_CTX).expect("bytes");
        assert_eq!(first, second);
    }

    /// The structural statement that the post-quantum binding carries no
    /// entropy, for the ed25519 component: a verifier holding only the
    /// classical half derives the identical bytes.
    #[test]
    fn the_ed25519_public_key_is_all_make_bytes_reads() {
        let (sk, pk) = h1_keypair(25);
        let proof = h1_proof(&sk);
        let from_classical: [u8; 32] = <<H1 as Suite>::Classical as ClassicalVrf>::vrf_make_bytes(
            &pk[..<<H1 as Suite>::Classical as ClassicalScheme>::PUBLIC_KEY_LEN],
            H1::LABEL,
            INPUT,
            &proof[..PRE_OUTPUT_LEN],
            OUT_CTX,
        )
        .expect("derive bytes");
        assert_eq!(h1_output(&pk, &proof), from_classical);
    }
}

/// H5 and H6 evaluate through the SHRINCS stateless path, so these tests check
/// the two properties that path adds: the few-time budget is charged, and the
/// key's one-time leaf counter is not. The budget arithmetic is identical on
/// either suite, so it is exercised on H6 alone; H5 gets the round trip and
/// the uniqueness check, which are the two that depend on the classical half.
#[cfg(all(
    test,
    feature = "alloc",
    any(
        feature = "profile-256s",
        feature = "profile-256s-sha2",
        feature = "profile-128s-q18",
        feature = "profile-128s-q20"
    )
))]
mod stateful_tests {
    use super::*;
    use crate::budget::{BudgetKey, StatelessBudgetStore};
    use crate::classical::Ed25519;
    use crate::component::PqStatefulScheme;
    use crate::shrincs::{H5, H6};
    use crate::stateful_composite::{keygen, SecretKey};
    use crate::suite::StatefulSuite;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand_core::OsRng;

    const INPUT: &[u8] = b"epoch-7/randomness";
    const OUT_CTX: &[u8] = b"epoch-randomness";

    /// The H6 proof header. H5's is 16 bytes shorter, because the ed25519
    /// ECVRF proof is `c || s` rather than schnorrkel's 64-byte DLEQ proof.
    const SR_HEADER: usize = header_len::<crate::classical::Sr25519>();

    /// A budget store held in memory. `Infallible` because a test that wants
    /// to see a store fault sets `fail` instead of relying on a real fault.
    #[derive(Default)]
    struct MemoryBudget {
        entries: Vec<(BudgetKey, u64)>,
        fail: bool,
    }

    impl MemoryBudget {
        /// Every unit recorded across every key, which is what the tests
        /// assert against.
        fn total(&self) -> u64 {
            self.entries.iter().map(|(_, count)| *count).sum()
        }
    }

    impl StatelessBudgetStore for MemoryBudget {
        type Error = ();

        fn consumed(&self, key: &BudgetKey) -> Option<u64> {
            self.entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, count)| *count)
        }

        fn record(&mut self, key: &BudgetKey, count: u64) -> core::result::Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            match self.entries.iter_mut().find(|(k, _)| k == key) {
                Some(entry) => entry.1 = count,
                None => self.entries.push((*key, count)),
            }
            Ok(())
        }
    }

    fn h6_key(seed: u8) -> (SecretKey<H6>, Vec<u8>) {
        let (sk, pk) = keygen::<H6>(&[seed; 32], 8).expect("keygen");
        // The verify-form composite public key: classical public key followed
        // by the post-quantum verify key, the layout `verify_stateless` reads.
        let mut verify_pk = Vec::with_capacity(<H6 as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN);
        verify_pk.extend_from_slice(pk.classical());
        verify_pk.extend_from_slice(pk.pq_verify_key());
        (sk, verify_pk)
    }

    fn evaluate(sk: &SecretKey<H6>, budget: &mut MemoryBudget) -> Vec<u8> {
        let mut proof = vec![0u8; proof_len_stateless::<H6>()];
        let written =
            sign_stateless::<H6>(sk, budget, INPUT, &mut OsRng, &mut proof).expect("evaluate");
        assert_eq!(written, proof.len());
        proof
    }

    #[test]
    fn a_stateless_proof_round_trips() {
        let (sk, pk) = h6_key(1);
        let mut budget = MemoryBudget::default();
        let proof = evaluate(&sk, &mut budget);
        assert!(verify_stateless::<H6>(&pk, INPUT, &proof));
        assert!(!verify_stateless::<H6>(&pk, b"another input", &proof));
    }

    /// The point of binding H6 through the stateless path rather than the
    /// stateful one: a per-evaluation leaf spend would exhaust the tree.
    #[test]
    fn evaluation_spends_budget_and_never_a_leaf() {
        let (sk, _) = h6_key(2);
        let before = sk.next_leaf();
        let mut budget = MemoryBudget::default();

        let _ = evaluate(&sk, &mut budget);
        assert_eq!(sk.next_leaf(), before, "no one-time leaf may be spent");
        assert_eq!(
            budget.total(),
            1,
            "one unit of the few-time budget is spent"
        );

        let _ = evaluate(&sk, &mut budget);
        assert_eq!(sk.next_leaf(), before);
        assert_eq!(budget.total(), 2);
    }

    #[test]
    fn a_store_that_cannot_record_the_spend_refuses_to_evaluate() {
        let (sk, _) = h6_key(3);
        let mut budget = MemoryBudget {
            fail: true,
            ..MemoryBudget::default()
        };
        let mut proof = vec![0u8; proof_len_stateless::<H6>()];
        assert_eq!(
            sign_stateless::<H6>(&sk, &mut budget, INPUT, &mut OsRng, &mut proof),
            Err(Error::BudgetStoreFailed)
        );
        assert!(
            proof.iter().all(|b| *b == 0) || proof[SR_HEADER..].iter().all(|b| *b == 0),
            "no binding may be released when the spend did not land"
        );
    }

    #[test]
    fn an_exhausted_budget_refuses_to_evaluate() {
        let (sk, _) = h6_key(4);
        let material = <<H6 as StatefulSuite>::Pq as PqStatefulScheme>::stateless_key_material(
            sk.pq_verify_key(),
        )
        .expect("material");
        let mut budget = MemoryBudget::default();
        budget
            .record(
                &BudgetKey::from_material(material),
                <<H6 as StatefulSuite>::Pq as PqStatefulScheme>::STATELESS_BUDGET,
            )
            .expect("prime the store at the bound");

        let mut proof = vec![0u8; proof_len_stateless::<H6>()];
        assert_eq!(
            sign_stateless::<H6>(&sk, &mut budget, INPUT, &mut OsRng, &mut proof),
            Err(Error::StatelessBudgetExhausted)
        );
    }

    /// The uniqueness check for H6. A stateless SHRINCS signature is not
    /// unique either: its FORS-C counter search is a search over valid
    /// signatures. So the same rule has to hold here.
    #[test]
    fn a_second_evaluation_gives_the_same_output() {
        let (sk, pk) = h6_key(5);
        let mut budget = MemoryBudget::default();
        let first = evaluate(&sk, &mut budget);
        let second = evaluate(&sk, &mut budget);

        assert!(verify_stateless::<H6>(&pk, INPUT, &first));
        assert!(verify_stateless::<H6>(&pk, INPUT, &second));
        assert_eq!(
            first[..PRE_OUTPUT_LEN],
            second[..PRE_OUTPUT_LEN],
            "the pre-output is a deterministic function of the key and the input"
        );

        let a: [u8; 32] =
            make_bytes_stateless::<H6, [u8; 32]>(&pk, INPUT, &first, OUT_CTX).expect("bytes");
        let b: [u8; 32] =
            make_bytes_stateless::<H6, [u8; 32]>(&pk, INPUT, &second, OUT_CTX).expect("bytes");
        assert_eq!(a, b, "a re-evaluated binding must not move the output");
    }

    fn h5_key(seed: u8) -> (SecretKey<H5>, Vec<u8>) {
        let (sk, pk) = keygen::<H5>(&[seed; 32], 8).expect("keygen");
        let mut verify_pk = Vec::with_capacity(<H5 as StatefulSuite>::VERIFY_PUBLIC_KEY_LEN);
        verify_pk.extend_from_slice(pk.classical());
        verify_pk.extend_from_slice(pk.pq_verify_key());
        (sk, verify_pk)
    }

    fn evaluate_h5(sk: &SecretKey<H5>, budget: &mut MemoryBudget) -> Vec<u8> {
        let mut proof = vec![0u8; proof_len_stateless::<H5>()];
        let written =
            sign_stateless::<H5>(sk, budget, INPUT, &mut OsRng, &mut proof).expect("evaluate");
        assert_eq!(written, proof.len());
        proof
    }

    #[test]
    fn an_ed25519_stateless_proof_round_trips() {
        let (sk, pk) = h5_key(6);
        let mut budget = MemoryBudget::default();
        let proof = evaluate_h5(&sk, &mut budget);
        assert_eq!(
            proof.len(),
            header_len::<Ed25519>()
                + <<H5 as StatefulSuite>::Pq as PqStatefulScheme>::STATELESS_SIG_LEN
        );
        assert!(verify_stateless::<H5>(&pk, INPUT, &proof));
        assert!(!verify_stateless::<H5>(&pk, b"another input", &proof));
        assert_eq!(budget.total(), 1, "one unit of the few-time budget");
    }

    /// The H5 uniqueness check. The SHRINCS binding's FORS-C counter search
    /// makes a second, equally valid binding cheap to reach, so a
    /// re-evaluation must land on the same output.
    #[test]
    fn a_second_ed25519_evaluation_gives_the_same_output() {
        let (sk, pk) = h5_key(7);
        let mut budget = MemoryBudget::default();
        let first = evaluate_h5(&sk, &mut budget);
        let second = evaluate_h5(&sk, &mut budget);

        assert!(verify_stateless::<H5>(&pk, INPUT, &first));
        assert!(verify_stateless::<H5>(&pk, INPUT, &second));
        assert_eq!(
            first[..PRE_OUTPUT_LEN],
            second[..PRE_OUTPUT_LEN],
            "the pre-output is a deterministic function of the key and the input"
        );

        let a: [u8; 32] =
            make_bytes_stateless::<H5, [u8; 32]>(&pk, INPUT, &first, OUT_CTX).expect("bytes");
        let b: [u8; 32] =
            make_bytes_stateless::<H5, [u8; 32]>(&pk, INPUT, &second, OUT_CTX).expect("bytes");
        assert_eq!(a, b, "a re-evaluated binding must not move the output");
    }
}
