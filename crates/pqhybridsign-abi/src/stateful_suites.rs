// SPDX-License-Identifier: AGPL-3.0-or-later
//! Entry points for the two stateful suites, H5 and H6.
//!
//! Every function here rejects H1 through H4 with
//! [`AbiError::WrongEntryPointForSuite`]. This module is the other half of
//! the split described on [`crate::stateless_suites`]: nothing here can be
//! reached by a call shaped for a stateless suite, and nothing in
//! `stateless_suites` can be reached by a call naming H5 or H6.
//!
//! A stateful secret key is not `Clone` in the generic layer (a cloned copy
//! would be a second holder of the same one-time leaf budget), and this
//! crate holds no state across calls: every function here rebuilds the key
//! from `sk` bytes ([`SecretKey::import`]) and, for [`sign_stateful`], hands
//! the advanced key back out through `sk_out`
//! ([`SecretKey::export`]) so the caller can persist it. See
//! [`sign_stateful`]'s documentation for why `sk_out` is written even when
//! the call fails.

use pqhybridsign_core::stateful::{LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign_core::stateful_composite::{keygen, SecretKey};
use pqhybridsign_core::StatefulSuite;
use pqhybridsign_shrincs::{H5, H6};

use crate::error::AbiError;
use crate::suite::Suite;

/// Derive a stateful keypair for `suite` from a 32-byte master seed, giving
/// it a budget of `max_stateful_signatures` one-time leaves.
///
/// `sk_out` and `pk_out` must be exactly [`crate::secret_key_len`] and
/// [`crate::public_key_len`] bytes for `suite`. `sk_out` is the exported
/// secret key blob [`sign_stateful`] and [`sign_stateless`] expect back as
/// `sk`, not the raw component secret key: it carries the leaf counter and
/// the cached verify key, both required to resume signing correctly.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4: use
/// [`crate::keygen_from_seed`] instead. [`AbiError::BadLength`] if `seed`
/// is not 32 bytes, or `sk_out`/`pk_out` are not exactly the suite's key
/// lengths. [`AbiError::ComponentFailure`] if `max_stateful_signatures` is
/// zero or exceeds the component's leaf capacity limit.
pub fn keygen_stateful_from_seed(
    suite: Suite,
    seed: &[u8],
    max_stateful_signatures: u32,
    sk_out: &mut [u8],
    pk_out: &mut [u8],
) -> Result<(), AbiError> {
    match suite {
        Suite::H5 => keygen_stateful::<H5>(seed, max_stateful_signatures, sk_out, pk_out),
        Suite::H6 => keygen_stateful::<H6>(seed, max_stateful_signatures, sk_out, pk_out),
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn keygen_stateful<S: StatefulSuite>(
    seed: &[u8],
    max_stateful_signatures: u32,
    sk_out: &mut [u8],
    pk_out: &mut [u8],
) -> Result<(), AbiError> {
    let seed: &[u8; 32] = seed.try_into().map_err(|_| AbiError::BadLength)?;
    let (sk, pk) = keygen::<S>(seed, max_stateful_signatures)?;
    write_exact(sk_out, &sk.export()?)?;
    write_exact(pk_out, pk.as_ref())
}

/// Sign `msg` under `ctx` for `suite`, spending one leaf.
///
/// `sk` is the exported secret key blob from [`keygen_stateful_from_seed`]
/// or a previous call to this function. `journal` durably records the
/// spent leaf before the signature is built; see
/// [`pqhybridsign_core::stateful::LeafJournal`] for the durability contract
/// an implementation must honour.
///
/// **`sk_out` is written on every outcome that reaches the component
/// signer, including a failed one.** [`pqhybridsign_core::stateful::StatefulSignError::GrindAbort`]
/// (surfaced here as [`AbiError::GrindAbort`]) is raised only after the
/// leaf is already durably committed in `journal`, so the leaf is spent
/// whether or not a signature comes back. Writing `sk_out` unconditionally
/// in that case is what keeps the caller's copy of the key in step with
/// the journal; skipping it on error is exactly the silent-leaf-drift
/// failure mode this crate exists to rule out. `sk_out` is not written if
/// `sk` fails to import (the key never existed for this call) or if
/// `sk_out` itself is the wrong length.
///
/// Returns the number of bytes written into `sig_out` on success.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4: use [`crate::sign`] or
/// [`crate::sign_deterministic`] instead. [`AbiError::BadLength`] if `sk`
/// or `sk_out` is not exactly [`crate::secret_key_len`] bytes for `suite`.
/// [`AbiError::LeavesExhausted`] if the key's leaf budget is spent, checked
/// before the journal is touched. [`AbiError::JournalFailed`] if the
/// journal could not durably commit; nothing was spent. See
/// [`pqhybridsign_core::stateful::StatefulSignError`] for the rest.
pub fn sign_stateful(
    suite: Suite,
    sk: &[u8],
    journal: &mut impl LeafJournal,
    msg: &[u8],
    ctx: &[u8],
    sk_out: &mut [u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    match suite {
        Suite::H5 => sign_stateful_suite::<H5>(sk, journal, msg, ctx, sk_out, sig_out),
        Suite::H6 => sign_stateful_suite::<H6>(sk, journal, msg, ctx, sk_out, sig_out),
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn sign_stateful_suite<S: StatefulSuite>(
    sk: &[u8],
    journal: &mut impl LeafJournal,
    msg: &[u8],
    ctx: &[u8],
    sk_out: &mut [u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    let mut sk = SecretKey::<S>::import(sk)?;

    let outcome = <S as StatefulHybridSignatureScheme>::sign_stateful(&mut sk, journal, msg, ctx);

    // Written regardless of `outcome`: see this function's caller-facing
    // documentation on `sign_stateful` for why a failed attempt can still
    // have spent a leaf.
    let exported = sk.export()?;
    write_exact(sk_out, &exported)?;

    let sig = outcome.map_err(AbiError::from)?;
    write_sig(sig_out, sig.as_ref())
}

/// Sign `msg` under `ctx` for `suite` without spending any leaf state.
///
/// Available on H5 and H6 because SHRINCS pairs its stateful fast path
/// with a stateless few-time path (specification section 21); no leaf is
/// consumed and no `sk_out` or journal is needed.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4. [`AbiError::BadLength`]
/// if `sk` is not exactly [`crate::secret_key_len`] bytes for `suite`. See
/// [`pqhybridsign_core::stateful::StatefulSignError`] for the rest.
pub fn sign_stateless(
    suite: Suite,
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    match suite {
        Suite::H5 => sign_stateless_suite::<H5>(sk, msg, ctx, sig_out),
        Suite::H6 => sign_stateless_suite::<H6>(sk, msg, ctx, sig_out),
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn sign_stateless_suite<S: StatefulSuite>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    let sk = SecretKey::<S>::import(sk)?;
    let sig = <S as StatefulHybridSignatureScheme>::sign_stateless(&sk, msg, ctx)
        .map_err(AbiError::from)?;
    write_sig(sig_out, sig.as_ref())
}

fn write_exact(out: &mut [u8], src: &[u8]) -> Result<(), AbiError> {
    if out.len() != src.len() {
        return Err(AbiError::BadLength);
    }
    out.copy_from_slice(src);
    Ok(())
}

fn write_sig(sig_out: &mut [u8], sig: &[u8]) -> Result<usize, AbiError> {
    if sig.len() > sig_out.len() {
        return Err(AbiError::OutputBufferTooSmall);
    }
    sig_out[..sig.len()].copy_from_slice(sig);
    Ok(sig.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhybridsign_core::stateful::LeafJournal;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct JournalState {
        committed: Vec<u32>,
    }
    struct MemoryJournal(Rc<RefCell<JournalState>>);
    impl LeafJournal for MemoryJournal {
        type Error = core::convert::Infallible;
        fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
            self.0.borrow_mut().committed.push(leaf);
            Ok(())
        }
        fn next_leaf(&self) -> u32 {
            self.0
                .borrow()
                .committed
                .iter()
                .copied()
                .max()
                .map_or(0, |m| m + 1)
        }
    }

    #[test]
    fn stateful_entry_points_reject_h1_through_h4() {
        let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
        for suite in [Suite::H1, Suite::H2, Suite::H3, Suite::H4] {
            assert_eq!(
                keygen_stateful_from_seed(suite, &[0u8; 32], 4, &mut [0u8; 4096], &mut [0u8; 4096]),
                Err(AbiError::WrongEntryPointForSuite)
            );
            assert_eq!(
                sign_stateful(
                    suite,
                    &[0u8; 4096],
                    &mut journal,
                    b"msg",
                    b"",
                    &mut [0u8; 4096],
                    &mut [0u8; 4096]
                ),
                Err(AbiError::WrongEntryPointForSuite)
            );
            assert_eq!(
                sign_stateless(suite, &[0u8; 4096], b"msg", b"", &mut [0u8; 4096]),
                Err(AbiError::WrongEntryPointForSuite)
            );
        }
    }

    #[test]
    fn a_short_output_buffer_returns_the_length_error_rather_than_panicking() {
        let mut sk = vec![0u8; crate::secret_key_len(Suite::H5)];
        let mut pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[3u8; 32], 4, &mut sk, &mut pk).expect("keygen");

        let mut journal = MemoryJournal(Rc::new(RefCell::new(JournalState::default())));
        let mut short_sk_out = [0u8; 1];
        let mut ok_sig_out = vec![0u8; crate::signature_len(Suite::H5)];
        assert_eq!(
            sign_stateful(
                Suite::H5,
                &sk,
                &mut journal,
                b"msg",
                b"",
                &mut short_sk_out,
                &mut ok_sig_out
            ),
            Err(AbiError::BadLength)
        );

        let mut short_sig_out = [0u8; 1];
        assert_eq!(
            sign_stateless(Suite::H5, &sk, b"msg", b"", &mut short_sig_out),
            Err(AbiError::OutputBufferTooSmall)
        );
        // sanity: the well-sized buffer succeeds.
        assert!(sign_stateless(Suite::H5, &sk, b"msg", b"", &mut ok_sig_out).is_ok());
    }
}
