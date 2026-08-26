// SPDX-License-Identifier: AGPL-3.0-or-later
//! An imported stateful secret key, held across signing calls.

use zeroize::Zeroize;

use pqhybridsign::budget::StatelessBudgetStore;
use pqhybridsign::shrincs::{EdSh, SrSh};
use pqhybridsign::stateful::{KeyIdentity, LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign::stateful_composite::SecretKey;
use pqhybridsign::suite::StatefulSuite;

use crate::error::AbiError;
use crate::suite::Suite;

/// An imported stateful secret key, held across signing calls.
///
/// [`crate::sign_stateful`] takes the exported blob and calls
/// `SecretKey::import` every time. `import` re-derives the hypertree
/// root, which at `profile-128s-q18` and `profile-128s-q20` costs about 47
/// seconds, the same walk as keygen. A caller that signs more than once
/// pays it more than once. This type pays it exactly once, in
/// [`StatefulKeyHandle::open`], and every later signature costs what the
/// in-process Rust API costs.
///
/// # The durability contract is unchanged
///
/// The handle advances the key in memory. It does not persist anything.
/// After [`sign_stateful_with_handle`] returns, **whether it returned a
/// signature or an error**, this handle holds the advanced key and the
/// caller must [`StatefulKeyHandle::export`] it and persist the result
/// before relying on any signature. The reason is the one
/// [`crate::sign_stateful`] documents: a leaf can be durably committed to
/// the journal and the signature still fail, and a caller whose stored key
/// did not advance with the journal is a caller whose next call is refused
/// for the rest of the key's life.
///
/// A handle is not a substitute for the journal. The journal is the
/// durable record of spent leaves and the only thing that survives a
/// crash.
///
/// # Only EdSh and SrSh
///
/// EdMl44 through SrFn512 are stateless and have nothing to hold open;
/// [`StatefulKeyHandle::open`] rejects them with
/// [`AbiError::WrongEntryPointForSuite`].
pub struct StatefulKeyHandle {
    inner: Inner,
}

enum Inner {
    EdSh(SecretKey<EdSh>),
    SrSh(SecretKey<SrSh>),
}

impl StatefulKeyHandle {
    /// Import `sk` once and hold it.
    ///
    /// This is the call that costs about 47 seconds at the 128s profiles.
    /// Every signature taken through the returned handle costs under 0.01
    /// seconds.
    ///
    /// # Errors
    ///
    /// [`AbiError::WrongEntryPointForSuite`] for EdMl44-SrFn512.
    /// [`AbiError::BadLength`] if `sk` is not [`crate::secret_key_len`]
    /// bytes for `suite`, checked before `import` runs.
    /// [`AbiError::ComponentFailure`] if the blob does not import.
    pub fn open(suite: Suite, sk: &[u8]) -> Result<Self, AbiError> {
        match suite {
            Suite::EdSh => Ok(Self {
                inner: Inner::EdSh(import_checked::<EdSh>(sk)?),
            }),
            Suite::SrSh => Ok(Self {
                inner: Inner::SrSh(import_checked::<SrSh>(sk)?),
            }),
            Suite::EdMl44 | Suite::EdFn512 | Suite::SrMl44 | Suite::SrFn512 => {
                Err(AbiError::WrongEntryPointForSuite)
            }
        }
    }

    /// The suite this handle was opened for.
    #[must_use]
    pub fn suite(&self) -> Suite {
        match self.inner {
            Inner::EdSh(_) => Suite::EdSh,
            Inner::SrSh(_) => Suite::SrSh,
        }
    }

    /// The identity of the key this handle holds.
    ///
    /// The value [`crate::adopt_key`] and [`crate::require_bound_key`]
    /// take. Derived from the cached post-quantum verify key, which is
    /// public; no secret byte reaches it.
    #[must_use]
    pub fn key_identity(&self) -> KeyIdentity {
        match &self.inner {
            Inner::EdSh(sk) => sk.key_identity(),
            Inner::SrSh(sk) => sk.key_identity(),
        }
    }

    /// Write the current exported blob into `sk_out`.
    ///
    /// Returns the number of bytes written, which is
    /// [`crate::secret_key_len`] for this handle's suite. Persist this
    /// after every [`sign_stateful_with_handle`] call; see the type
    /// documentation.
    ///
    /// # Errors
    ///
    /// [`AbiError::BadLength`] if `sk_out` is not exactly
    /// [`crate::secret_key_len`] bytes. [`AbiError::ComponentFailure`] if
    /// the key does not export.
    pub fn export(&self, sk_out: &mut [u8]) -> Result<usize, AbiError> {
        match &self.inner {
            Inner::EdSh(sk) => export_checked::<EdSh>(sk, sk_out),
            Inner::SrSh(sk) => export_checked::<SrSh>(sk, sk_out),
        }
    }
}

impl core::fmt::Debug for StatefulKeyHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatefulKeyHandle")
            .field("suite", &self.suite())
            .finish_non_exhaustive()
    }
}

fn import_checked<S: StatefulSuite>(sk: &[u8]) -> Result<SecretKey<S>, AbiError> {
    if sk.len() != SecretKey::<S>::exported_len() {
        return Err(AbiError::BadLength);
    }
    Ok(SecretKey::<S>::import(sk)?)
}

fn export_checked<S: StatefulSuite>(
    sk: &SecretKey<S>,
    sk_out: &mut [u8],
) -> Result<usize, AbiError> {
    if sk_out.len() != SecretKey::<S>::exported_len() {
        return Err(AbiError::BadLength);
    }
    // The temporary is wiped rather than dropped: it is a full plaintext
    // copy of the composite secret key carrying the leaf counter, so one
    // recovered from freed heap is a usable signer, not a fragment. This
    // matches `sign_stateful_suite` in `stateful_suites.rs`.
    let mut exported = sk.export()?;
    sk_out.copy_from_slice(&exported);
    let written = exported.len();
    exported.zeroize();
    Ok(written)
}

/// Sign `msg` under `ctx` with `handle`, spending one leaf.
///
/// The handle-held counterpart of [`crate::sign_stateful`]. Identical in
/// every respect except that the key is already imported and the advanced
/// key stays in `handle` instead of being written to an `sk_out` buffer.
///
/// `journal` must already be bound to this key ([`crate::adopt_key`]).
/// That is checked before its counter is read and before anything is
/// committed.
///
/// **The handle advances on every outcome that reaches the component
/// signer, including a failed one.** Export and persist it either way. See
/// [`StatefulKeyHandle`] for why.
///
/// Returns the number of bytes written into `sig_out`.
///
/// # Errors
///
/// [`AbiError::JournalKeyMismatch`] if `journal` is not bound to this key;
/// nothing was spent and the key is intact. [`AbiError::LeavesExhausted`]
/// if the key's leaf budget is spent, checked before the journal is
/// touched. [`AbiError::JournalFailed`] if the journal could not durably
/// commit; nothing was spent. [`AbiError::OutputBufferTooSmall`] if
/// `sig_out` is shorter than the signature. See
/// [`pqhybridsign::stateful::StatefulSignError`] for the rest.
pub fn sign_stateful_with_handle(
    handle: &mut StatefulKeyHandle,
    journal: &mut impl LeafJournal,
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    match &mut handle.inner {
        Inner::EdSh(sk) => sign_one::<EdSh>(sk, journal, msg, ctx, sig_out),
        Inner::SrSh(sk) => sign_one::<SrSh>(sk, journal, msg, ctx, sig_out),
    }
}

fn sign_one<S: StatefulSuite>(
    sk: &mut SecretKey<S>,
    journal: &mut impl LeafJournal,
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    let sig = <S as StatefulHybridSignatureScheme>::sign_stateful(sk, journal, msg, ctx)
        .map_err(AbiError::from)?;
    crate::stateful_suites::write_sig(sig_out, sig.as_ref())
}

/// Sign `msg` under `ctx` with `handle` without spending any leaf,
/// spending one unit of the few-time stateless budget instead.
///
/// The handle-held counterpart of [`crate::sign_stateless`]. `budget` is
/// required and no leaf journal substitutes for it, on the same terms.
///
/// Takes `&StatefulKeyHandle`, not `&mut`: the stateless path does not
/// advance the key, so there is nothing new to export afterwards.
///
/// Returns the number of bytes written into `sig_out`.
///
/// # Errors
///
/// [`AbiError::StatelessBudgetExhausted`] if this key's few-time budget is
/// spent. [`AbiError::BudgetStoreFailed`] if the store could not durably
/// record the spend. [`AbiError::OutputBufferTooSmall`] if `sig_out` is
/// shorter than the signature.
pub fn sign_stateless_with_handle(
    handle: &StatefulKeyHandle,
    budget: &mut impl StatelessBudgetStore,
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    match &handle.inner {
        Inner::EdSh(sk) => sign_one_stateless::<EdSh>(sk, budget, msg, ctx, sig_out),
        Inner::SrSh(sk) => sign_one_stateless::<SrSh>(sk, budget, msg, ctx, sig_out),
    }
}

fn sign_one_stateless<S: StatefulSuite>(
    sk: &SecretKey<S>,
    budget: &mut impl StatelessBudgetStore,
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    let sig = <S as StatefulHybridSignatureScheme>::sign_stateless(sk, budget, msg, ctx)
        .map_err(AbiError::from)?;
    crate::stateful_suites::write_sig(sig_out, sig.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keygen_stateful_from_seed, secret_key_len, signature_len, verify, verify_stateless, Suite,
    };
    use pqhybridsign::stateful::{KeyIdentity, LeafJournal};
    use pqhybridsign_test_support::MemoryBudget;

    /// An in-memory journal. Not durable; a real integrator persists every
    /// method to storage that survives a restart.
    #[derive(Default)]
    struct MemoryJournal {
        next: u32,
        bound: Option<KeyIdentity>,
    }

    impl LeafJournal for MemoryJournal {
        type Error = core::convert::Infallible;

        fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
            self.next = leaf + 1;
            Ok(())
        }

        fn next_leaf(&self) -> u32 {
            self.next
        }

        fn bound_key(&self) -> Option<KeyIdentity> {
            self.bound
        }

        fn bind_key(&mut self, identity: KeyIdentity) -> Result<(), Self::Error> {
            self.bound = Some(identity);
            Ok(())
        }
    }

    fn fresh_key(suite: Suite) -> (Vec<u8>, Vec<u8>) {
        let mut sk = vec![0u8; secret_key_len(suite)];
        let mut pk = vec![0u8; crate::public_key_len(suite)];
        keygen_stateful_from_seed(suite, &[7u8; 32], 4, &mut sk, &mut pk).unwrap();
        (sk, pk)
    }

    #[test]
    fn a_handle_signs_twice_and_the_signatures_verify() {
        let suite = Suite::EdSh;
        let (sk, pk) = fresh_key(suite);
        let mut handle = StatefulKeyHandle::open(suite, &sk).unwrap();
        assert_eq!(handle.suite(), suite);

        let mut journal = MemoryJournal::default();
        crate::adopt_key(&mut journal, handle.key_identity()).unwrap();

        let mut sig = vec![0u8; signature_len(suite)];
        for msg in [b"first".as_slice(), b"second".as_slice()] {
            let n = sign_stateful_with_handle(&mut handle, &mut journal, msg, b"ctx", &mut sig)
                .unwrap();
            assert!(verify(suite, &pk, msg, b"ctx", &sig[..n]));
        }
    }

    #[test]
    fn the_exported_key_advances_with_each_signature() {
        let suite = Suite::EdSh;
        let (sk, _pk) = fresh_key(suite);
        let mut handle = StatefulKeyHandle::open(suite, &sk).unwrap();
        let mut journal = MemoryJournal::default();
        crate::adopt_key(&mut journal, handle.key_identity()).unwrap();

        let mut before = vec![0u8; secret_key_len(suite)];
        handle.export(&mut before).unwrap();
        assert_eq!(before, sk, "an unused handle exports the blob it opened");

        let mut sig = vec![0u8; signature_len(suite)];
        sign_stateful_with_handle(&mut handle, &mut journal, b"m", b"c", &mut sig).unwrap();

        let mut after = vec![0u8; secret_key_len(suite)];
        handle.export(&mut after).unwrap();
        assert_ne!(before, after, "the handle did not advance the key");
    }

    #[test]
    fn a_reopened_export_continues_where_the_handle_left_off() {
        // This is the property the whole handle rests on: exporting and
        // reopening must land on the same key state, or a restart would
        // reissue a leaf the journal has already recorded as spent.
        let suite = Suite::EdSh;
        let (sk, pk) = fresh_key(suite);
        let mut handle = StatefulKeyHandle::open(suite, &sk).unwrap();
        let mut journal = MemoryJournal::default();
        crate::adopt_key(&mut journal, handle.key_identity()).unwrap();

        let mut sig = vec![0u8; signature_len(suite)];
        sign_stateful_with_handle(&mut handle, &mut journal, b"m1", b"c", &mut sig).unwrap();

        let mut exported = vec![0u8; secret_key_len(suite)];
        handle.export(&mut exported).unwrap();
        drop(handle);

        let mut reopened = StatefulKeyHandle::open(suite, &exported).unwrap();
        let n =
            sign_stateful_with_handle(&mut reopened, &mut journal, b"m2", b"c", &mut sig).unwrap();
        assert!(verify(suite, &pk, b"m2", b"c", &sig[..n]));
    }

    #[test]
    fn open_rejects_the_stateless_suites() {
        assert_eq!(
            StatefulKeyHandle::open(Suite::EdMl44, &[0u8; 32]).unwrap_err(),
            AbiError::WrongEntryPointForSuite
        );
    }

    #[test]
    fn open_rejects_a_wrong_length_blob() {
        assert_eq!(
            StatefulKeyHandle::open(Suite::EdSh, &[0u8; 7]).unwrap_err(),
            AbiError::BadLength
        );
    }

    #[test]
    fn export_rejects_a_wrong_length_buffer() {
        let (sk, _pk) = fresh_key(Suite::EdSh);
        let handle = StatefulKeyHandle::open(Suite::EdSh, &sk).unwrap();
        assert_eq!(
            handle.export(&mut [0u8; 7]).unwrap_err(),
            AbiError::BadLength
        );
    }

    #[test]
    fn signing_with_an_unbound_journal_is_refused() {
        let (sk, _pk) = fresh_key(Suite::EdSh);
        let mut handle = StatefulKeyHandle::open(Suite::EdSh, &sk).unwrap();
        let mut journal = MemoryJournal::default();
        let mut sig = vec![0u8; signature_len(Suite::EdSh)];
        assert_eq!(
            sign_stateful_with_handle(&mut handle, &mut journal, b"m", b"c", &mut sig).unwrap_err(),
            AbiError::JournalKeyMismatch
        );
    }

    #[test]
    fn a_handle_signs_statelessly_without_spending_a_leaf() {
        // The stateless path spends few-time budget, not a one-time leaf. The
        // leaf counter must be untouched afterwards, which is why this takes
        // `&StatefulKeyHandle` and not `&mut`: there is nothing to advance and
        // nothing new to export.
        let suite = Suite::EdSh;
        let (sk, pk) = fresh_key(suite);
        let handle = StatefulKeyHandle::open(suite, &sk).unwrap();

        let mut before = vec![0u8; secret_key_len(suite)];
        handle.export(&mut before).unwrap();

        let mut budget = MemoryBudget::default();
        let mut sig = vec![0u8; signature_len(suite)];
        let n = sign_stateless_with_handle(&handle, &mut budget, b"m", b"c", &mut sig).unwrap();

        // Checked before `verify_stateless` below, not after: a mutant that
        // routes this call through the stateful signer instead would advance
        // the leaf counter and produce a signature the stateless verifier
        // never accepts, so an assertion order with `verify_stateless` first
        // would mask the leaf-advance regression this test exists to catch.
        let mut after = vec![0u8; secret_key_len(suite)];
        handle.export(&mut after).unwrap();
        assert_eq!(before, after, "the stateless path advanced the key");

        // `crate::verify` accepts only the stateful path for EdSh/SrSh; a
        // stateless-path signature is checked with `verify_stateless`.
        assert!(verify_stateless(suite, &pk, b"m", b"c", &sig[..n]).unwrap());
    }

    #[test]
    fn a_spent_budget_refuses_a_stateless_signature() {
        let suite = Suite::EdSh;
        let (sk, _pk) = fresh_key(suite);
        let handle = StatefulKeyHandle::open(suite, &sk).unwrap();
        let mut budget = MemoryBudget::exhausted();
        let mut sig = vec![0u8; signature_len(suite)];
        assert_eq!(
            sign_stateless_with_handle(&handle, &mut budget, b"m", b"c", &mut sig).unwrap_err(),
            AbiError::StatelessBudgetExhausted
        );
    }
}
