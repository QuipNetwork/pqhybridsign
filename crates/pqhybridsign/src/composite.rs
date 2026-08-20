// SPDX-License-Identifier: AGPL-3.0-or-later
//! Composite signing, verification and encoding.
//!
//! A composite signature is the classical signature followed by the
//! post-quantum signature, split at the constant offset [`Suite::SPLIT`],
//! per specification section 6. Keys use the same order.

use crate::{
    component::{ClassicalScheme, PqScheme},
    derive::derive_component_seeds,
    error::{Error, Result},
    message::{m_prime_len, write_m_prime},
    suite::Suite,
};
use subtle::Choice;
use zeroize::Zeroize;

/// Largest `M'` this crate builds on the stack. Longer messages need the
/// `alloc` feature.
///
/// 512 bytes is the largest buffer this crate is willing to place on the
/// stack of an embedded or wasm target that has no allocator. `M'` is
/// `0x01 || Label || len(ctx) || ctx || M`, so the space left for `M` is
/// `512 - 1 - Label.len() - 1 - ctx.len()`. Both shipped suites carry a
/// 26-byte label, which leaves 484 bytes for the message and the context
/// together. Beyond that, and without the `alloc` feature, signing and
/// verification return [`Error::OutputBufferTooSmall`]; nothing is
/// truncated.
const STACK_M_PRIME: usize = 512;

/// Largest post-quantum seed this crate expands from the master seed.
const MAX_PQ_SEED: usize = 64;

/// Derive a composite keypair from a 32-byte master seed.
///
/// The suite label is bound into the key derivation, so two suites from one
/// master seed produce independent keys, per specification section 9.
pub fn keypair_from_seed<S: Suite>(
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

/// Hedged composite signing.
///
/// Both components sign the same `M'`, which binds the suite label and the
/// application context into the message.
///
/// `rng` supplies fresh randomness to every component that accepts it:
/// sr25519 through schnorrkel, and ML-DSA-44 through the FIPS 204 hedged
/// `rnd` value. ed25519 is deterministic by RFC 8032 and takes no
/// randomness, so under H1 the classical half repeats across calls while
/// the post-quantum half does not.
///
/// Without the `alloc` feature, `M'` is built in a `STACK_M_PRIME`-byte
/// stack buffer. `ctx.len() + msg.len()` above 484 bytes for the shipped
/// 26-byte labels returns [`Error::OutputBufferTooSmall`]; the message is
/// never truncated.
///
/// `sig_out` must be at least [`Suite::SIGNATURE_LEN`] bytes; a larger
/// buffer is accepted, with only the first `SIGNATURE_LEN` bytes written, so
/// a caller can size one scratch buffer for the largest suite and reuse it
/// across suites. [`Error::OutputBufferTooSmall`] if it is smaller.
pub fn sign<S: Suite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    sig_out: &mut [u8],
) -> Result<()> {
    with_m_prime::<()>(S::LABEL, msg, ctx, |m| {
        let (sk_halves, sig_halves) = split::<S>(sk, sig_out)?;
        // The label is the classical component's signing context. Dropping
        // it would leave sr25519 signatures unbound to the suite.
        <S::Classical as ClassicalScheme>::sign(sk_halves.0, m, S::LABEL, rng, sig_halves.0)?;
        <S::Pq as PqScheme>::sign(sk_halves.1, m, rng, sig_halves.1)
    })
}

/// Deterministic composite signing.
///
/// Not every component honours `nonce`, and the API cannot report that:
///
/// - sr25519 binds it. The Schnorr nonce is seeded from
///   `H(sk || nonce || msg)` and attached to the schnorrkel transcript, so
///   a different `nonce` gives a different classical half under H3.
/// - ed25519 ignores it. RFC 8032 fixes `r = H(prefix || msg)`, and
///   `ed25519-zebra` exposes no hook for a caller-chosen `r`. The RFC 8032
///   nonce is already secret and unique per message, which is the property
///   `nonce` exists to provide.
/// - ML-DSA-44 ignores it. FIPS 204's deterministic variant fixes `rnd` to
///   all zeros.
///
/// The practical consequence: under H1 both halves ignore `nonce`, so two
/// different nonces over the same message and context give byte-identical
/// signatures. Under H3 only the classical half changes. Callers who need
/// distinct signatures over one message must either vary `ctx` or use
/// [`sign`].
///
/// The no-`alloc` message ceiling described on [`sign`] applies here too,
/// and so does its `sig_out` contract: at least [`Suite::SIGNATURE_LEN`]
/// bytes, [`Error::OutputBufferTooSmall`] otherwise, a larger buffer
/// accepted with only the first `SIGNATURE_LEN` bytes written.
pub fn sign_deterministic<S: Suite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
    sig_out: &mut [u8],
) -> Result<()> {
    with_m_prime::<()>(S::LABEL, msg, ctx, |m| {
        let (sk_halves, sig_halves) = split::<S>(sk, sig_out)?;
        <S::Classical as ClassicalScheme>::sign_deterministic(
            sk_halves.0,
            m,
            nonce,
            S::LABEL,
            sig_halves.0,
        )?;
        <S::Pq as PqScheme>::sign_deterministic(sk_halves.1, m, nonce, sig_halves.1)
    })
}

/// Composite verification. Both components must accept.
///
/// The two component results combine with a bitwise `Choice` conjunction,
/// never `&&`: there is no short circuit, so neither the result nor the
/// running time reveals which component failed. Malformed input returns
/// `false` rather than an error for the same reason, since an error variant
/// would leak through the error channel exactly what the constant-time
/// combination hides.
pub fn verify<S: Suite>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != S::PUBLIC_KEY_LEN || sig.len() != S::SIGNATURE_LEN {
        return false;
    }
    let c_pk = <S::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
    let split = S::SPLIT;

    let outcome = with_m_prime::<Choice>(S::LABEL, msg, ctx, |m| {
        let classical_ok =
            <S::Classical as ClassicalScheme>::verify(&pk[..c_pk], m, S::LABEL, &sig[..split]);
        let pq_ok = <S::Pq as PqScheme>::verify(&pk[c_pk..], m, &sig[split..]);
        // Bitwise AND, never `&&`: no short circuit, no timing signal.
        Ok(classical_ok & pq_ok)
    });

    match outcome {
        // The only conversion to `bool`, at the API boundary.
        Ok(choice) => bool::from(choice),
        Err(_) => false,
    }
}

type Halves<'a> = (&'a [u8], &'a [u8]);
type HalvesMut<'a> = (&'a mut [u8], &'a mut [u8]);

/// Split the secret key and the signature buffer into their two halves.
///
/// `sig_out` only needs to be *at least* [`Suite::SIGNATURE_LEN`]: see
/// [`at_least`]. Any bytes beyond that are left untouched and excluded from
/// the halves handed to the component signers, so a caller that reuses one
/// scratch buffer sized for the largest suite works for every suite.
fn split<'a, S: Suite>(sk: &'a [u8], sig_out: &'a mut [u8]) -> Result<(Halves<'a>, HalvesMut<'a>)> {
    exact(sk, S::SECRET_KEY_LEN)?;
    at_least(sig_out, S::SIGNATURE_LEN)?;
    let sk_split = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
    Ok((
        sk.split_at(sk_split),
        sig_out[..S::SIGNATURE_LEN].split_at_mut(S::SPLIT),
    ))
}

pub(crate) fn exact(buf: &[u8], want: usize) -> Result<()> {
    if buf.len() == want {
        Ok(())
    } else {
        Err(Error::BadLength {
            expected: want,
            actual: buf.len(),
        })
    }
}

/// Check that an output buffer is large enough, without requiring it be
/// exactly that size. Every signing entry point that uses this reports the
/// number of bytes it actually wrote through a separate `sig_written`/return
/// value, so accepting a larger buffer loses no information and lets a
/// caller size one scratch buffer for the largest suite and reuse it for
/// every suite -- unlike [`exact`], which fixed-size inputs (a secret key, a
/// seed) still need, since there the length itself is part of the encoding.
pub(crate) fn at_least(buf: &[u8], needed: usize) -> Result<()> {
    if buf.len() >= needed {
        Ok(())
    } else {
        Err(Error::OutputBufferTooSmall {
            needed,
            actual: buf.len(),
        })
    }
}

/// Build `M' = Prefix || Label || len(ctx) || ctx || M` for `label` and hand
/// it to `f`, then wipe the buffer.
///
/// `pub(crate)` so [`crate::composite_delta`] can share it: `M'` does not
/// depend on how a suite's signature is split, only on its label, so the
/// delta-length composite functions reuse this rather than duplicate the
/// stack/alloc fallback.
pub(crate) fn with_m_prime<T>(
    label: &'static [u8],
    msg: &[u8],
    ctx: &[u8],
    f: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    let needed = m_prime_len(label, ctx, msg)?;
    if needed <= STACK_M_PRIME {
        let mut buf = [0u8; STACK_M_PRIME];
        let out = match write_m_prime(&mut buf[..needed], label, ctx, msg) {
            Ok(n) => f(&buf[..n]),
            Err(e) => Err(e),
        };
        buf.zeroize();
        return out;
    }
    #[cfg(feature = "alloc")]
    {
        let mut buf = alloc::vec![0u8; needed];
        let out = match write_m_prime(&mut buf, label, ctx, msg) {
            Ok(n) => f(&buf[..n]),
            Err(e) => Err(e),
        };
        buf.zeroize();
        out
    }
    #[cfg(not(feature = "alloc"))]
    {
        Err(Error::OutputBufferTooSmall {
            needed,
            actual: STACK_M_PRIME,
        })
    }
}
