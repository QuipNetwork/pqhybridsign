// SPDX-License-Identifier: AGPL-3.0-or-later
//! Composite signing, verification and keygen for any [`DeltaSuite`] (H2,
//! H4).
//!
//! [`crate::composite::sign`], [`crate::composite::sign_deterministic`] and
//! [`crate::composite::verify`] assume a suite's wire signature is
//! [`Suite::SIGNATURE_LEN`](crate::Suite::SIGNATURE_LEN) bytes split at the
//! fixed offset [`Suite::SPLIT`](crate::Suite::SPLIT). Neither holds for
//! FN-DSA-512: its wire form carries a 1-byte length field between the
//! classical and post-quantum halves (`crate::encoding_delta`), so this
//! module -- parallel to `composite`, the way `stateful_composite` is
//! parallel to it for [`StatefulSuite`](crate::StatefulSuite) -- supplies
//! the delta-length-aware sign/verify/keygen triple over any `S:
//! DeltaSuite`, without perturbing `composite` or the fixed-offset
//! functions H1 and H3 already use.
//!
//! `sign` and `sign_deterministic` write directly into the caller's
//! `sig_out`, slicing it into the classical, delta and post-quantum
//! regions, rather than building the post-quantum signature in a separate
//! buffer and copying it: [`PqScheme::SIGNATURE_LEN`] is a plain `usize` at
//! run time, but stable Rust cannot size a local array from a generic
//! type's associated const, so there is no smaller buffer to build it in
//! anyway. `sig_out` must be at least
//! [`DeltaSuite::MAX_SIGNATURE_LEN`] bytes; callers size it with that
//! constant.

use crate::composite::{at_least, exact, with_m_prime};
use crate::encoding_delta::{self, CLASSICAL_SIG_LEN, DELTA_LEN};
use crate::{derive_component_seeds, ClassicalScheme, DeltaSuite, Error, PqScheme, Result};
use subtle::Choice;
use zeroize::Zeroize;

/// Largest post-quantum seed this crate expands from the master seed.
///
/// Mirrors `composite::MAX_PQ_SEED`; kept as a separate constant because
/// `composite`'s is private to that module.
const MAX_PQ_SEED: usize = 64;

/// Derive a composite keypair from a 32-byte master seed.
///
/// The suite label is bound into the key derivation, so two suites from one
/// master seed produce independent keys, per specification section 9.
/// Mirrors [`crate::composite::keypair_from_seed`], duplicated rather than
/// shared because it is generic over [`DeltaSuite`] rather than [`Suite`].
///
/// [`Suite`]: crate::Suite
pub fn keypair_from_seed<S: DeltaSuite>(
    master: &[u8; 32],
    sk_out: &mut [u8],
    pk_out: &mut [u8],
) -> Result<()> {
    exact(sk_out, S::SECRET_KEY_LEN)?;
    exact(pk_out, S::PUBLIC_KEY_LEN)?;

    let pq_len = <S::Pq as PqScheme>::SEED_LEN;
    if pq_len > MAX_PQ_SEED {
        return Err(Error::OutputBufferTooSmall {
            needed: pq_len,
            actual: MAX_PQ_SEED,
        });
    }

    let mut classical_seed = [0u8; 32];
    let mut pq_seed = [0u8; MAX_PQ_SEED];

    let result = (|| {
        derive_component_seeds(
            master,
            S::LABEL,
            &mut classical_seed,
            &mut pq_seed[..pq_len],
        )?;
        let c_sk = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
        let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
        <S::Classical as ClassicalScheme>::derive(
            &classical_seed,
            &mut sk_out[..c_sk],
            &mut pk_out[..c_pk],
        )?;
        <S::Pq as PqScheme>::derive(&pq_seed[..pq_len], &mut sk_out[c_sk..], &mut pk_out[c_pk..])
    })();

    classical_seed.zeroize();
    pq_seed.zeroize();
    result
}

/// Hedged composite signing. Returns the number of bytes written into
/// `sig_out`, since the wire length varies with the post-quantum
/// component's actual signature length.
///
/// # Errors
///
/// [`Error::OutputBufferTooSmall`] when `sig_out` is smaller than the
/// encoding needs. [`Error::DeltaLengthOutOfRange`] when the post-quantum
/// component's actual signature length does not fit
/// `S::MIN_PQ_SIG_LEN..=S::MIN_PQ_SIG_LEN + 255`.
pub fn sign<S: DeltaSuite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    sig_out: &mut [u8],
) -> Result<usize> {
    with_m_prime::<usize>(S::LABEL, msg, ctx, |m| {
        let (sk_classical, sk_pq) = split_sk::<S>(sk)?;
        let (classical_slot, delta_slot, pq_slot) = split_sig_out::<S>(sig_out)?;

        <S::Classical as ClassicalScheme>::sign(sk_classical, m, S::LABEL, rng, classical_slot)?;
        <S::Pq as PqScheme>::sign(sk_pq, m, rng, pq_slot)?;
        delta_slot[0] = encoding_delta::encode_delta_byte(pq_slot.len(), S::MIN_PQ_SIG_LEN)?;

        Ok(CLASSICAL_SIG_LEN + DELTA_LEN + pq_slot.len())
    })
}

/// Deterministic composite signing. See [`crate::composite::sign_deterministic`]
/// for which components honour `nonce`; FN-DSA-512 does not sign
/// deterministically by specification, so H2 and H4 always vary their
/// post-quantum half with `nonce`, unlike ML-DSA-44 under H1/H3.
///
/// # Errors
///
/// The same as [`sign`].
pub fn sign_deterministic<S: DeltaSuite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
    sig_out: &mut [u8],
) -> Result<usize> {
    with_m_prime::<usize>(S::LABEL, msg, ctx, |m| {
        let (sk_classical, sk_pq) = split_sk::<S>(sk)?;
        let (classical_slot, delta_slot, pq_slot) = split_sig_out::<S>(sig_out)?;

        <S::Classical as ClassicalScheme>::sign_deterministic(
            sk_classical,
            m,
            nonce,
            S::LABEL,
            classical_slot,
        )?;
        <S::Pq as PqScheme>::sign_deterministic(sk_pq, m, nonce, pq_slot)?;
        delta_slot[0] = encoding_delta::encode_delta_byte(pq_slot.len(), S::MIN_PQ_SIG_LEN)?;

        Ok(CLASSICAL_SIG_LEN + DELTA_LEN + pq_slot.len())
    })
}

/// Composite verification. Both components must accept.
///
/// The two component results combine with a bitwise `Choice` conjunction,
/// never `&&`, mirroring [`crate::composite::verify`]: no short circuit, so
/// neither the result nor the running time reveals which component failed
/// or whether the wire encoding itself was malformed.
pub fn verify<S: DeltaSuite>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != S::PUBLIC_KEY_LEN {
        return false;
    }
    let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;

    let outcome = with_m_prime::<Choice>(S::LABEL, msg, ctx, |m| {
        // Decoding rejects a bad length field, a truncated body and
        // trailing bytes before anything below reads the post-quantum
        // signature (`crate::encoding_delta`'s own decode order).
        let decoded = encoding_delta::decode_delta(sig, S::MIN_PQ_SIG_LEN)?;

        let classical_ok = <S::Classical as ClassicalScheme>::verify(
            &pk[..c_pk],
            m,
            S::LABEL,
            &decoded.classical[..],
        );
        // A `decoded.pq` length the post-quantum component cannot verify
        // (any length other than its own `SIGNATURE_LEN`) fails inside
        // `verify` itself, the same way a malformed classical signature
        // does: there is no separate length check here to short-circuit on.
        let pq_ok = <S::Pq as PqScheme>::verify(&pk[c_pk..], m, decoded.pq);
        // Bitwise AND, never `&&`: no short circuit, no timing signal.
        Ok(classical_ok & pq_ok)
    });

    match outcome {
        // The only conversion to `bool`, at the API boundary.
        Ok(choice) => bool::from(choice),
        Err(_) => false,
    }
}

/// Split a composite secret key into its classical and post-quantum halves.
fn split_sk<S: DeltaSuite>(sk: &[u8]) -> Result<(&[u8], &[u8])> {
    exact(sk, S::SECRET_KEY_LEN)?;
    let sk_split = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
    Ok(sk.split_at(sk_split))
}

/// Split `sig_out` into the classical, delta and post-quantum slots the
/// wire encoding needs, sized from the post-quantum component's actual
/// (fixed, per specification section 6 caveat: fixed for `fn-dsa` 0.4.0)
/// [`PqScheme::SIGNATURE_LEN`].
///
/// # Errors
///
/// [`Error::OutputBufferTooSmall`] when `sig_out` is too small to hold the
/// encoding.
// The three slots are three disjoint mutable borrows of one buffer, which is
// exactly what `split_at_mut` produces and what the callers need: each slot
// is written by a different component. A named tuple struct would have to
// carry the same three lifetimes and would be constructed and destructured
// at the single call site, so it would rename the complexity rather than
// remove it. The alternative that does remove it -- returning the offsets
// and re-slicing in the caller -- gives up the compiler's proof that the
// three slots do not overlap, which is the one property worth having here.
#[allow(clippy::type_complexity)]
fn split_sig_out<S: DeltaSuite>(sig_out: &mut [u8]) -> Result<(&mut [u8], &mut [u8], &mut [u8])> {
    let pq_len = <S::Pq as PqScheme>::SIGNATURE_LEN;
    let needed = CLASSICAL_SIG_LEN + DELTA_LEN + pq_len;
    at_least(sig_out, needed)?;
    let (classical_slot, rest) = sig_out[..needed].split_at_mut(CLASSICAL_SIG_LEN);
    let (delta_slot, pq_slot) = rest.split_at_mut(DELTA_LEN);
    Ok((classical_slot, delta_slot, pq_slot))
}
