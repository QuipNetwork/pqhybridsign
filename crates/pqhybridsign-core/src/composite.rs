// SPDX-License-Identifier: AGPL-3.0-or-later
//! Composite signing, verification and encoding.
//!
//! A composite signature is the classical signature followed by the
//! post-quantum signature, split at the constant offset [`Suite::SPLIT`],
//! per specification section 6. Keys use the same order.

use crate::{
    derive_component_seeds, m_prime_len, write_m_prime, ClassicalScheme, Error, PqScheme, Result,
    Suite,
};
use subtle::Choice;
use zeroize::Zeroize;

/// Largest `M'` this crate builds on the stack. Longer messages need the
/// `alloc` feature.
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
pub fn sign<S: Suite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    sig_out: &mut [u8],
) -> Result<()> {
    with_m_prime::<S, ()>(msg, ctx, |m| {
        let (sk_halves, sig_halves) = split::<S>(sk, sig_out)?;
        // The label is the classical component's signing context. Dropping
        // it would leave sr25519 signatures unbound to the suite.
        <S::Classical as ClassicalScheme>::sign(sk_halves.0, m, S::LABEL, rng, sig_halves.0)?;
        <S::Pq as PqScheme>::sign(sk_halves.1, m, rng, sig_halves.1)
    })
}

/// Deterministic composite signing.
pub fn sign_deterministic<S: Suite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
    sig_out: &mut [u8],
) -> Result<()> {
    with_m_prime::<S, ()>(msg, ctx, |m| {
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

    let outcome = with_m_prime::<S, Choice>(msg, ctx, |m| {
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
fn split<'a, S: Suite>(sk: &'a [u8], sig_out: &'a mut [u8]) -> Result<(Halves<'a>, HalvesMut<'a>)> {
    exact(sk, S::SECRET_KEY_LEN)?;
    exact(sig_out, S::SIGNATURE_LEN)?;
    let sk_split = <S::Classical as ClassicalScheme>::SECRET_KEY_LEN;
    Ok((sk.split_at(sk_split), sig_out.split_at_mut(S::SPLIT)))
}

fn exact(buf: &[u8], want: usize) -> Result<()> {
    if buf.len() == want {
        Ok(())
    } else {
        Err(Error::BadLength {
            expected: want,
            actual: buf.len(),
        })
    }
}

/// Build `M'` and hand it to `f`, then wipe the buffer.
fn with_m_prime<S: Suite, T>(
    msg: &[u8],
    ctx: &[u8],
    f: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    let needed = m_prime_len(S::LABEL, ctx, msg)?;
    if needed <= STACK_M_PRIME {
        let mut buf = [0u8; STACK_M_PRIME];
        let out = match write_m_prime(&mut buf[..needed], S::LABEL, ctx, msg) {
            Ok(n) => f(&buf[..n]),
            Err(e) => Err(e),
        };
        buf.zeroize();
        return out;
    }
    #[cfg(feature = "alloc")]
    {
        let mut buf = alloc::vec![0u8; needed];
        let out = match write_m_prime(&mut buf, S::LABEL, ctx, msg) {
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
