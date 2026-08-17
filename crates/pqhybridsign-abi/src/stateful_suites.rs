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

use pqhybridsign_core::budget::StatelessBudgetStore;
use pqhybridsign_core::stateful::{KeyIdentity, LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign_core::stateful_composite::{keygen, CommittedVerifyKey, PublicKey, SecretKey};
use pqhybridsign_core::StatefulSuite;
use pqhybridsign_shrincs::{H5, H6};
use zeroize::Zeroize;

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
    // `export` hands back `ClassicalSK || PqSecretKey || nextLeaf ||
    // PqVerifyKey` in the clear -- a complete signer. Bind it so it can be
    // wiped on the way out instead of being dropped as a temporary, which
    // would leave that plaintext in freed heap for whatever allocates next.
    let mut exported = sk.export()?;
    let written = write_exact(sk_out, &exported);
    exported.zeroize();
    written?;
    write_exact(pk_out, pk.as_ref())
}

/// The identity of the key `public_key` describes.
///
/// `public_key` is the verify-form public key
/// [`keygen_stateful_from_seed`] writes to `pk_out`, exactly
/// [`crate::public_key_len`] bytes for `suite`. It is public material, so
/// this can be computed by a verifier, an operator or a provisioning script
/// that never holds the secret key.
///
/// Pass the result to [`adopt_key`] once, when the key's durable journal is
/// created. [`key_identity_from_secret_key`] returns the same value for the
/// matching secret key blob.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4, which have no journal and
/// so no identity to bind one to. [`AbiError::BadLength`] if `public_key` is
/// not [`crate::public_key_len`] bytes for `suite`.
pub fn key_identity(suite: Suite, public_key: &[u8]) -> Result<KeyIdentity, AbiError> {
    match suite {
        Suite::H5 => key_identity_of::<H5>(public_key),
        Suite::H6 => key_identity_of::<H6>(public_key),
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn key_identity_of<S: StatefulSuite>(public_key: &[u8]) -> Result<KeyIdentity, AbiError> {
    Ok(PublicKey::<S>::from_bytes(public_key)?.key_identity())
}

/// The identity of the key an exported secret key blob holds.
///
/// The same value [`key_identity`] returns for the matching public key: it is
/// derived from the blob's cached post-quantum **verify key**, which is
/// public, and no secret byte reaches it. This exists because the restart
/// path has the blob in hand and may not have kept the public key.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4. [`AbiError::BadLength`]
/// if `sk` is not [`crate::secret_key_len`] bytes for `suite`.
/// [`AbiError::ComponentFailure`] if the blob does not import.
pub fn key_identity_from_secret_key(suite: Suite, sk: &[u8]) -> Result<KeyIdentity, AbiError> {
    match suite {
        Suite::H5 => secret_key_identity_of::<H5>(sk),
        Suite::H6 => secret_key_identity_of::<H6>(sk),
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn secret_key_identity_of<S: StatefulSuite>(sk: &[u8]) -> Result<KeyIdentity, AbiError> {
    Ok(SecretKey::<S>::import(sk)?.key_identity())
}

/// Bind `journal` to `key`, unless it already belongs to a different key.
///
/// This is the explicit act an integrator performs once, when a key's durable
/// journal is first created. [`sign_stateful`] never does it implicitly:
/// pairing a key with a journal that has never seen it is how one key's
/// one-time leaves get spent twice, and it is refused with
/// [`AbiError::JournalKeyMismatch`] rather than silently accepted.
///
/// Idempotent for a journal already bound to `key`, so a provisioning step is
/// safe to re-run. See [`pqhybridsign_core::stateful::adopt_key`] for the
/// full contract, including why calling this on every process start
/// reinstates the defect it closes.
///
/// # Errors
///
/// [`AbiError::JournalKeyMismatch`] if `journal` already belongs to another
/// key; nothing is written. [`AbiError::JournalFailed`] if the binding did
/// not become durable.
pub fn adopt_key(journal: &mut impl LeafJournal, key: KeyIdentity) -> Result<(), AbiError> {
    pqhybridsign_core::stateful::adopt_key(journal, key).map_err(AbiError::from)
}

/// Refuse `journal` unless it already belongs to `key`.
///
/// The read-only half of [`adopt_key`], and the check [`sign_stateful`] runs
/// for itself before spending anything. It exists separately so that a
/// binding built around an explicit load step -- reopen the journal, load the
/// key blob, then sign many times -- can fail at the load, while an operator
/// is still watching, rather than at the first signature.
///
/// It binds nothing. A journal that has never been bound is refused exactly
/// as one bound to another key is: neither is a record of what this key has
/// spent. Use [`pqhybridsign_core::stateful::LeafJournal::bound_key`] to tell
/// the two apart.
///
/// # Errors
///
/// [`AbiError::JournalKeyMismatch`] if `journal` is unbound or bound to a
/// different key.
pub fn require_bound_key(journal: &impl LeafJournal, key: KeyIdentity) -> Result<(), AbiError> {
    pqhybridsign_core::stateful::require_bound_key(journal, key).map_err(AbiError::from)
}

/// Sign `msg` under `ctx` for `suite`, spending one leaf.
///
/// `sk` is the exported secret key blob from [`keygen_stateful_from_seed`]
/// or a previous call to this function. `journal` durably records the
/// spent leaf before the signature is built; see
/// [`pqhybridsign_core::stateful::LeafJournal`] for the durability contract
/// an implementation must honour.
///
/// `journal` must already be bound to this key ([`adopt_key`]). That is
/// checked before its counter is read and before anything is committed: a
/// journal that has never seen this key reports the same leaf `0` a correctly
/// reopened one reports for an unspent key, so proceeding on the counter
/// alone is what lets a second holder reissue every leaf.
///
/// **`sk_out` is written on every outcome that reaches the component
/// signer, including a failed one.** [`pqhybridsign_core::stateful::StatefulSignError::GrindAbort`]
/// (surfaced here as [`AbiError::GrindAbort`]) is raised only after the
/// leaf is already durably committed in `journal`, so the leaf is spent
/// whether or not a signature comes back. Writing `sk_out` unconditionally
/// in that case is what keeps the caller's copy of the key in step with
/// the journal; skipping it on error is exactly the silent-leaf-drift
/// failure mode this crate exists to rule out. `sk_out` is not written if
/// `sk` fails to import: the key never existed for this call, so no leaf
/// was spent either.
///
/// Both `sk` and `sk_out` are measured against [`crate::secret_key_len`]
/// before anything else happens, so a wrong-length buffer is rejected while
/// the call is still a no-op. A length checked after the signer ran would
/// return [`AbiError::BadLength`] for a call that had already committed a
/// leaf to `journal` and then refused to hand the advanced key back,
/// leaving the journal permanently ahead of the caller's key.
///
/// Returns the number of bytes written into `sig_out` on success.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4: use [`crate::sign`] or
/// [`crate::sign_deterministic`] instead. [`AbiError::BadLength`] if `sk`
/// or `sk_out` is not exactly [`crate::secret_key_len`] bytes for `suite`,
/// checked before the journal is touched.
/// [`AbiError::JournalKeyMismatch`] if `journal` is not bound to this key;
/// nothing was spent and the key is intact.
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
    // Both key buffers are measured first, before `import` and before the
    // component signer runs. The signer durably commits a leaf to the
    // caller's journal before it can fail, so any length rejected after
    // this point returns `BadLength` for a call that already spent a leaf
    // and never wrote the advanced key back: the journal moves on, the
    // caller's key does not, and `stateful_composite` then refuses every
    // later call because the two counters disagree. An off-by-one in the
    // caller's buffer arithmetic is enough to reach that, and `BadLength`
    // reads like a call that was rejected outright, so the caller has no
    // reason to suspect state moved. `exported_len` is exactly what
    // `crate::secret_key_len` reports for this suite.
    let expected_len = SecretKey::<S>::exported_len();
    if sk.len() != expected_len || sk_out.len() != expected_len {
        return Err(AbiError::BadLength);
    }

    let mut sk = SecretKey::<S>::import(sk)?;

    let outcome = <S as StatefulHybridSignatureScheme>::sign_stateful(&mut sk, journal, msg, ctx);

    // Written regardless of `outcome`: see this function's caller-facing
    // documentation on `sign_stateful` for why a failed attempt can still
    // have spent a leaf. The temporary is wiped rather than dropped: it is
    // a full plaintext copy of the composite secret key, produced on every
    // signing call, and it carries the leaf counter alongside it -- so one
    // recovered from freed heap is a usable signer, not a fragment.
    let mut exported = sk.export()?;
    let written = write_exact(sk_out, &exported);
    exported.zeroize();
    written?;

    let sig = outcome.map_err(AbiError::from)?;
    write_sig(sig_out, sig.as_ref())
}

/// Sign `msg` under `ctx` for `suite` without spending any leaf state,
/// spending one unit of the few-time stateless budget instead.
///
/// Available on H5 and H6 because SHRINCS pairs its stateful fast path
/// with a stateless few-time path (specification section 21); no leaf is
/// consumed and no `sk_out` or journal is needed.
///
/// `budget` is required, and no leaf journal substitutes for it. The
/// stateless path has a hard bound of its own -- `2^20` signatures, `2^18`
/// under the low-budget profile -- shared with rotation and recovery, and
/// exceeding it degrades the security assumption of the underlying few-time
/// scheme. The spend is made durable before the signature is built, on the
/// same terms [`sign_stateful`] commits its leaf; see
/// [`pqhybridsign_core::budget::StatelessBudgetStore`] for the durability
/// contract an implementation must honour.
///
/// The budget is keyed to the key's stateless material (`pkSeed ||
/// hypertreeRoot`), which this function reads out of `sk` itself. One store
/// therefore serves every key an integrator holds, and a rotation that does
/// not change that material continues the same count rather than starting a
/// new one.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4. [`AbiError::BadLength`]
/// if `sk` is not exactly [`crate::secret_key_len`] bytes for `suite`.
/// [`AbiError::StatelessBudgetExhausted`] if this key's stateless budget is
/// spent; nothing was recorded and no signature was built.
/// [`AbiError::BudgetStoreFailed`] if the store could not durably record the
/// spend; nothing was recorded either. See
/// [`pqhybridsign_core::stateful::StatefulSignError`] for the rest.
pub fn sign_stateless(
    suite: Suite,
    sk: &[u8],
    budget: &mut impl StatelessBudgetStore,
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    match suite {
        Suite::H5 => sign_stateless_suite::<H5>(sk, budget, msg, ctx, sig_out),
        Suite::H6 => sign_stateless_suite::<H6>(sk, budget, msg, ctx, sig_out),
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn sign_stateless_suite<S: StatefulSuite>(
    sk: &[u8],
    budget: &mut impl StatelessBudgetStore,
    msg: &[u8],
    ctx: &[u8],
    sig_out: &mut [u8],
) -> Result<usize, AbiError> {
    let sk = SecretKey::<S>::import(sk)?;
    let sig = <S as StatefulHybridSignatureScheme>::sign_stateless(&sk, budget, msg, ctx)
        .map_err(AbiError::from)?;
    write_sig(sig_out, sig.as_ref())
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, against a
/// signer-supplied verify key that must be the one `stored_public_key`
/// commits to.
///
/// This is the entry point for the deployment H5 and H6 are built for: the
/// verifier stores the small form (`ClassicalPK || commitment`,
/// [`StatefulSuite::STORED_PUBLIC_KEY_LEN`] bytes -- 64 for both suites) and
/// the signer supplies the full 164-byte commitment bundle alongside every
/// signature, because the bundle is too large to keep on an account.
///
/// `stored_public_key` is trusted and `pq_verify_key` is not. The commitment
/// is recomputed from `pq_verify_key` and matched against the stored one
/// before anything is verified, and the classical public key is taken from
/// `stored_public_key`, so nothing the signer supplied can substitute a key
/// of their own.
///
/// [`crate::verify`] is the other shape: it takes one whole verify-form
/// public key ([`crate::public_key_len`] bytes) and checks no commitment,
/// because it has nothing to check one against. Use it only where the
/// verify key itself came from a trusted place.
///
/// Returns `false`, never an error, for a commitment that does not match, a
/// malformed key or a malformed signature, on the same grounds as
/// [`crate::verify`]: an error channel would tell a caller which check
/// rejected.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H1-H4. Their public key is a
/// single form with no commitment in it, so there is nothing for this
/// function to bind; use [`crate::verify`].
pub fn verify_with_stored_public_key(
    suite: Suite,
    stored_public_key: &[u8],
    pq_verify_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, AbiError> {
    match suite {
        Suite::H5 => Ok(verify_stored::<H5>(
            stored_public_key,
            pq_verify_key,
            msg,
            ctx,
            sig,
        )),
        Suite::H6 => Ok(verify_stored::<H6>(
            stored_public_key,
            pq_verify_key,
            msg,
            ctx,
            sig,
        )),
        Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn verify_stored<S: StatefulSuite>(
    stored_public_key: &[u8],
    pq_verify_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> bool
where
    S::Pq: CommittedVerifyKey,
{
    let Ok(pk) =
        PublicKey::<S>::from_stored_commitment_and_bundle(stored_public_key, pq_verify_key)
    else {
        return false;
    };
    <S as StatefulHybridSignatureScheme>::verify(&pk, msg, ctx, &sig.to_vec())
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
    use pqhybridsign_core::budget::BudgetKey;
    use pqhybridsign_core::stateful::LeafJournal;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct JournalState {
        committed: Vec<u32>,
        bound: Option<KeyIdentity>,
    }
    /// An in-memory `StatelessBudgetStore`, the budget counterpart of
    /// `MemoryJournal` above. Not durable: these tests exercise whether the
    /// count is consulted, not persistence.
    #[derive(Default)]
    struct MemoryBudget(std::collections::HashMap<[u8; 32], u64>);

    impl StatelessBudgetStore for MemoryBudget {
        type Error = core::convert::Infallible;

        fn consumed(&self, key: &BudgetKey) -> Option<u64> {
            self.0.get(key.as_bytes()).copied()
        }

        fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
            self.0.insert(*key.as_bytes(), count);
            Ok(())
        }
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
        fn bound_key(&self) -> Option<KeyIdentity> {
            self.0.borrow().bound
        }
        fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
            self.0.borrow_mut().bound = Some(key);
            Ok(())
        }
    }

    /// A journal adopted by the key `pk` names: the one-off provisioning step
    /// an integrator writes when a key's durable journal is created.
    fn adopted_journal(state: &Rc<RefCell<JournalState>>, pk: &[u8]) -> MemoryJournal {
        let mut journal = MemoryJournal(Rc::clone(state));
        let identity = key_identity(Suite::H5, pk).expect("identity");
        adopt_key(&mut journal, identity).expect("adopt");
        journal
    }

    /// Offset of the 32-byte commitment inside a SHRINCS bundle
    /// (`statefulPublicKey(68) || commitment(32) || pkSeed || hypertreeRoot`).
    const COMMITMENT_AT: usize = 68;

    /// The small form a verifier installs: the classical public key and the
    /// commitment, lifted out of a verify-form public key its own keygen
    /// produced.
    fn stored_form(verify_public_key: &[u8]) -> Vec<u8> {
        let classical_len = crate::stored_public_key_len(Suite::H5) - 32;
        let mut stored = verify_public_key[..classical_len].to_vec();
        stored.extend_from_slice(&verify_public_key[classical_len + COMMITMENT_AT..][..32]);
        stored
    }

    /// The signer-supplied half: everything after the classical public key.
    fn bundle_of(verify_public_key: &[u8]) -> &[u8] {
        &verify_public_key[crate::stored_public_key_len(Suite::H5) - 32..]
    }

    /// A bundle an attacker generated verifies their own signature perfectly
    /// well through [`crate::verify`], which has no stored key to compare it
    /// against. Binding the two is what
    /// [`verify_with_stored_public_key`] adds.
    #[test]
    fn verify_with_stored_public_key_refuses_a_bundle_the_stored_key_does_not_name() {
        const MSG: &[u8] = b"transfer everything";

        let mut victim_sk = vec![0u8; crate::secret_key_len(Suite::H5)];
        let mut victim_pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[0xA1; 32], 4, &mut victim_sk, &mut victim_pk)
            .expect("victim keygen");

        let mut attacker_sk = vec![0u8; crate::secret_key_len(Suite::H5)];
        let mut attacker_pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(
            Suite::H5,
            &[0xB2; 32],
            4,
            &mut attacker_sk,
            &mut attacker_pk,
        )
        .expect("attacker keygen");

        let victim_stored = stored_form(&victim_pk);

        let mut sig = vec![0u8; crate::signature_len(Suite::H5)];
        let n = sign_stateless(
            Suite::H5,
            &attacker_sk,
            &mut MemoryBudget::default(),
            MSG,
            b"",
            &mut sig,
        )
        .expect("attacker signs");
        let forged = &sig[..n];

        // Whole-key verification accepts it: the key and the signature agree
        // with each other, and nothing else is consulted.
        assert!(crate::verify(Suite::H5, &attacker_pk, MSG, b"", forged));

        // Against the victim's installed commitment it is refused.
        assert_eq!(
            verify_with_stored_public_key(
                Suite::H5,
                &victim_stored,
                bundle_of(&attacker_pk),
                MSG,
                b"",
                forged
            ),
            Ok(false)
        );

        // The victim's own signature and bundle pass, so the refusal above
        // is the commitment check and not this entry point failing to
        // verify anything at all.
        let mut honest = vec![0u8; crate::signature_len(Suite::H5)];
        let n = sign_stateless(
            Suite::H5,
            &victim_sk,
            &mut MemoryBudget::default(),
            MSG,
            b"",
            &mut honest,
        )
        .expect("victim signs");
        assert_eq!(
            verify_with_stored_public_key(
                Suite::H5,
                &victim_stored,
                bundle_of(&victim_pk),
                MSG,
                b"",
                &honest[..n]
            ),
            Ok(true)
        );

        // A wrong-length stored key or bundle is a failed verification, not
        // an error: same rule as `crate::verify`.
        assert_eq!(
            verify_with_stored_public_key(
                Suite::H5,
                &victim_stored[..1],
                bundle_of(&victim_pk),
                MSG,
                b"",
                &honest[..n]
            ),
            Ok(false)
        );
        assert_eq!(
            verify_with_stored_public_key(Suite::H5, &victim_stored, &[], MSG, b"", &honest[..n]),
            Ok(false)
        );
    }

    /// One exported key blob, two never-used journals, two different
    /// messages: both signatures land on the same one-time leaf and both
    /// verify against the same public key. That is total loss of the key's
    /// post-quantum security, and no counter check can see it -- both fresh
    /// journals honestly report that leaf `0` is next, which is exactly what
    /// a legitimate first run reports too.
    ///
    /// The leaf indices asserted here are all **signer-side, zero-based**
    /// (`LeafJournal::next_leaf`), not the one-based wire `LeafCount`.
    #[test]
    fn a_second_fresh_journal_cannot_fork_one_keys_leaf_budget() {
        let sk_len = crate::secret_key_len(Suite::H5);
        let mut sk = vec![0u8; sk_len];
        let mut pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[0x5A; 32], 4, &mut sk, &mut pk).expect("keygen");

        // The key's own journal, adopted once when it was provisioned, and a
        // second independent store that has never seen this key.
        let first_state = Rc::new(RefCell::new(JournalState::default()));
        let second_state = Rc::new(RefCell::new(JournalState::default()));
        let mut first = adopted_journal(&first_state, &pk);
        let mut second = MemoryJournal(Rc::clone(&second_state));
        assert_eq!(
            second.next_leaf(),
            0,
            "the second journal's counter agrees with the key's, which is why \
             no counter check can catch this"
        );

        let mut sk_out = vec![0u8; sk_len];
        let mut sig_out = vec![0u8; crate::signature_len(Suite::H5)];
        let one = sign_stateful(
            Suite::H5,
            &sk,
            &mut first,
            b"message one",
            b"",
            &mut sk_out,
            &mut sig_out,
        )
        .expect("the key's own journal signs");
        assert_eq!(first_state.borrow().committed, vec![0]);
        assert!(crate::verify(
            Suite::H5,
            &pk,
            b"message one",
            b"",
            &sig_out[..one]
        ));

        // The same blob, a second journal. This must be refused: `second` is
        // not this key's journal, and nothing else in the system can tell
        // that a second holder just claimed leaf 0.
        let mut forked_sk_out = vec![0u8; sk_len];
        let mut forked_sig_out = vec![0u8; crate::signature_len(Suite::H5)];
        let forked = sign_stateful(
            Suite::H5,
            &sk,
            &mut second,
            b"message two",
            b"",
            &mut forked_sk_out,
            &mut forked_sig_out,
        );
        assert_eq!(
            forked,
            Err(AbiError::JournalKeyMismatch),
            "a journal that is not this key's journal must not spend its leaves"
        );
        assert!(
            second_state.borrow().committed.is_empty(),
            "the refusal must land before any leaf is committed"
        );

        // Adoption is available, and it is a line the integrator has to
        // write: what changes is that forking the budget is now a decision
        // somebody made, not the default outcome of restarting a process.
        let identity = key_identity(Suite::H5, &pk).expect("identity");
        adopt_key(&mut second, identity).expect("explicit adoption is allowed");
        assert!(sign_stateful(
            Suite::H5,
            &sk,
            &mut second,
            b"message two",
            b"",
            &mut forked_sk_out,
            &mut forked_sig_out
        )
        .is_ok());
    }

    /// The identity is derived from public material and names one key. A
    /// journal adopted by one key must refuse the other.
    #[test]
    fn an_identity_names_one_key_and_a_journal_holds_one_identity() {
        let sk_len = crate::secret_key_len(Suite::H5);
        let mut victim_sk = vec![0u8; sk_len];
        let mut victim_pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[0xC3; 32], 4, &mut victim_sk, &mut victim_pk)
            .expect("victim keygen");

        let mut other_sk = vec![0u8; sk_len];
        let mut other_pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[0xD4; 32], 4, &mut other_sk, &mut other_pk)
            .expect("other keygen");

        // The public key and the secret key blob name the same identity, and
        // two different keys name two different ones.
        let victim = key_identity(Suite::H5, &victim_pk).expect("identity");
        assert_eq!(
            victim,
            key_identity_from_secret_key(Suite::H5, &victim_sk).expect("identity")
        );
        assert_ne!(
            victim,
            key_identity(Suite::H5, &other_pk).expect("identity")
        );

        // A journal belongs to one key for its whole life.
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = adopted_journal(&state, &victim_pk);
        assert_eq!(
            adopt_key(
                &mut journal,
                key_identity(Suite::H5, &other_pk).expect("identity")
            ),
            Err(AbiError::JournalKeyMismatch)
        );

        // And the other key cannot sign through it.
        let mut sk_out = vec![0u8; sk_len];
        let mut sig_out = vec![0u8; crate::signature_len(Suite::H5)];
        assert_eq!(
            sign_stateful(
                Suite::H5,
                &other_sk,
                &mut journal,
                b"msg",
                b"",
                &mut sk_out,
                &mut sig_out
            ),
            Err(AbiError::JournalKeyMismatch)
        );
        assert!(state.borrow().committed.is_empty());

        // The key that owns the journal still signs, so the refusal above is
        // the binding and not this journal refusing everything.
        assert!(sign_stateful(
            Suite::H5,
            &victim_sk,
            &mut journal,
            b"msg",
            b"",
            &mut sk_out,
            &mut sig_out
        )
        .is_ok());
    }

    #[test]
    fn identity_entry_points_reject_stateless_suites_and_bad_lengths() {
        let mut sk = vec![0u8; crate::secret_key_len(Suite::H5)];
        let mut pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[0xE5; 32], 4, &mut sk, &mut pk).expect("keygen");

        for suite in [Suite::H1, Suite::H2, Suite::H3, Suite::H4] {
            assert_eq!(
                key_identity(suite, &pk),
                Err(AbiError::WrongEntryPointForSuite)
            );
            assert_eq!(
                key_identity_from_secret_key(suite, &sk),
                Err(AbiError::WrongEntryPointForSuite)
            );
        }
        assert_eq!(
            key_identity(Suite::H5, &pk[..pk.len() - 1]),
            Err(AbiError::BadLength)
        );
        assert_eq!(
            key_identity_from_secret_key(Suite::H5, &sk[..sk.len() - 1]),
            Err(AbiError::BadLength)
        );
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
                sign_stateless(
                    suite,
                    &[0u8; 4096],
                    &mut MemoryBudget::default(),
                    b"msg",
                    b"",
                    &mut [0u8; 4096]
                ),
                Err(AbiError::WrongEntryPointForSuite)
            );
            assert_eq!(
                verify_with_stored_public_key(
                    suite,
                    &[0u8; 64],
                    &[0u8; 164],
                    b"msg",
                    b"",
                    &[0u8; 1]
                ),
                Err(AbiError::WrongEntryPointForSuite)
            );
        }
    }

    #[test]
    fn a_short_output_buffer_returns_the_length_error_rather_than_panicking() {
        let mut sk = vec![0u8; crate::secret_key_len(Suite::H5)];
        let mut pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[3u8; 32], 4, &mut sk, &mut pk).expect("keygen");

        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = adopted_journal(&state, &pk);
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
        // The length is what makes this call a no-op: rejecting it after
        // the signer had committed a leaf would leave the journal ahead of
        // every copy of the key the caller holds, permanently.
        assert!(
            state.borrow().committed.is_empty(),
            "a wrong-length sk_out must be rejected before any leaf is spent"
        );

        let mut short_sig_out = [0u8; 1];
        assert_eq!(
            sign_stateless(
                Suite::H5,
                &sk,
                &mut MemoryBudget::default(),
                b"msg",
                b"",
                &mut short_sig_out
            ),
            Err(AbiError::OutputBufferTooSmall)
        );
        // sanity: the well-sized buffer succeeds.
        assert!(sign_stateless(
            Suite::H5,
            &sk,
            &mut MemoryBudget::default(),
            b"msg",
            b"",
            &mut ok_sig_out
        )
        .is_ok());
    }

    /// A wrong-length `sk_out` -- an off-by-one in the caller's buffer
    /// arithmetic is enough -- must leave the key exactly as usable as it
    /// was. Before the length check moved ahead of the signer, this
    /// sequence spent a leaf, wrote nothing back, and left the key unusable
    /// for the whole of its remaining budget.
    #[test]
    fn a_wrong_length_sk_out_leaves_the_key_and_the_journal_untouched() {
        let sk_len = crate::secret_key_len(Suite::H5);
        let mut sk = vec![0u8; sk_len];
        let mut pk = vec![0u8; crate::public_key_len(Suite::H5)];
        keygen_stateful_from_seed(Suite::H5, &[7u8; 32], 4, &mut sk, &mut pk).expect("keygen");

        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = adopted_journal(&state, &pk);
        let mut sig_out = vec![0u8; crate::signature_len(Suite::H5)];

        for wrong_len in [sk_len - 1, sk_len + 1] {
            let mut wrong_sk_out = vec![0u8; wrong_len];
            assert_eq!(
                sign_stateful(
                    Suite::H5,
                    &sk,
                    &mut journal,
                    b"msg",
                    b"",
                    &mut wrong_sk_out,
                    &mut sig_out
                ),
                Err(AbiError::BadLength)
            );
            assert!(state.borrow().committed.is_empty(), "len {wrong_len}");
        }

        // A wrong-length `sk` is rejected on the same terms.
        let mut good_sk_out = vec![0u8; sk_len];
        assert_eq!(
            sign_stateful(
                Suite::H5,
                &sk[..sk_len - 1],
                &mut journal,
                b"msg",
                b"",
                &mut good_sk_out,
                &mut sig_out
            ),
            Err(AbiError::BadLength)
        );
        assert!(state.borrow().committed.is_empty());

        // The key is still whole: the original blob signs, and the leaf it
        // spends is the first one, not a later one the journal had already
        // recorded on the caller's behalf.
        let n = sign_stateful(
            Suite::H5,
            &sk,
            &mut journal,
            b"msg",
            b"",
            &mut good_sk_out,
            &mut sig_out,
        )
        .expect("the key must still sign after a rejected wrong-length call");
        assert_eq!(state.borrow().committed, vec![0]);
        assert!(crate::verify(Suite::H5, &pk, b"msg", b"", &sig_out[..n]));
    }
}
