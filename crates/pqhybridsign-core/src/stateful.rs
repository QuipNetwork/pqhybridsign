// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stateful signing: the one-time-leaf contract and its durable-state port.
//!
//! A stateful hash-based scheme spends a single-use leaf per signature.
//! Signing two different messages under one leaf discloses one-time key
//! material and permits forgery; RFC 8391 states that no security guarantees
//! remain. A crash, a restored snapshot, or a copied key file can all reissue
//! a leaf, so leaf consumption must be durable before a signature exists.
//!
//! This module holds no I/O. The integrator supplies durability through
//! [`LeafJournal`], and [`sign_after_commit`] is the one flow that orders the
//! journal write ahead of signature construction.
//!
//! # Durability is not enough on its own
//!
//! A journal that durably records leaves still cannot say *whose* leaves they
//! are. Hand one key to two journals that have each recorded nothing and both
//! report that leaf `0` is next -- truthfully, for a journal that has never
//! seen this key, and identically to what one correctly reopened journal
//! reports for a key that has spent nothing. No comparison of counters can
//! separate those two situations, so a journal also records a
//! [`KeyIdentity`]: a public name for the key it belongs to, written once by
//! [`adopt_key`] and checked on every signature by [`require_bound_key`].

use core::fmt;

use sha2::{Digest, Sha256};

/// Width of a [`KeyIdentity`] in bytes.
pub const KEY_IDENTITY_LEN: usize = 32;

/// Domain separator for the key-identity hash. Versioned, because changing
/// the derivation orphans every journal record already written under the old
/// one.
const KEY_IDENTITY_DOMAIN: &[u8] = b"pqhybridsign/leaf-journal/key-identity/v1";

/// A fixed-width, public name for one stateful key.
///
/// A [`LeafJournal`] stores this alongside its counter so that the pairing of
/// a key with a journal is a fact the storage records, rather than something
/// re-guessed on every restart. Counters alone cannot express it: two
/// journals that have never seen any key both honestly report leaf `0`, which
/// is indistinguishable from one journal correctly reopened for a key that
/// has spent nothing.
///
/// # This is public data
///
/// It is a hash over the suite label and the post-quantum **verify key** --
/// material a verifier already holds and a signature already travels with.
/// No secret key byte reaches the hash, and the value discloses nothing about
/// one. It may be logged, stored in the clear, and compared with a plain
/// `==`: there is no secret for a timing difference to leak, which is why
/// this type uses ordinary [`Eq`] rather than the `subtle::Choice`
/// comparisons the secret-bearing paths in this crate use.
///
/// An identity is not a capability. Holding one lets a caller name a key, not
/// sign for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyIdentity([u8; KEY_IDENTITY_LEN]);

impl KeyIdentity {
    /// Derive the identity of the key whose suite label is `suite_label` and
    /// whose post-quantum verify key is `pq_verify_key`.
    ///
    /// Both inputs are public. The label is included so that two suites over
    /// one component key material cannot collide, and both fields are
    /// length-prefixed so that no pair of (label, verify key) values can be
    /// re-cut into another pair with the same concatenation.
    ///
    /// Lengths are written as `u64` big-endian: `usize` is 4 bytes on a
    /// 32-bit target and 8 on a 64-bit one, and an identity that depended on
    /// the pointer width of the machine that computed it would not survive
    /// being written down.
    #[must_use]
    pub fn derive(suite_label: &[u8], pq_verify_key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(KEY_IDENTITY_DOMAIN);
        hasher.update((suite_label.len() as u64).to_be_bytes());
        hasher.update(suite_label);
        hasher.update((pq_verify_key.len() as u64).to_be_bytes());
        hasher.update(pq_verify_key);
        Self(hasher.finalize().into())
    }

    /// Rebuild an identity from the bytes a journal wrote down.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_IDENTITY_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes to write down.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_IDENTITY_LEN] {
        &self.0
    }
}

/// A durable record of consumed leaves, and of the one key those leaves
/// belong to.
///
/// The crypto crates never do I/O. The integrator implements this over
/// whatever storage can honour the durability promise below: an fsynced file,
/// a transactional database row, an HSM counter.
///
/// A journal records two facts, and both must be durable: *how far* the key
/// has spent ([`next_leaf`](Self::next_leaf)) and *which key* it is spending
/// for ([`bound_key`](Self::bound_key)). The second exists because the first
/// cannot distinguish a journal correctly reopened for its own key from a
/// brand-new journal handed the same key by mistake -- both report `0` for a
/// key that has spent nothing, and signing under the second reissues every
/// leaf the first already spent.
pub trait LeafJournal {
    /// Whatever the backing store reports. It is never returned to the
    /// caller of a signing routine, which sees only
    /// [`StatefulSignError::JournalFailed`].
    type Error: fmt::Debug;

    /// Durably record that `leaf` is consumed.
    ///
    /// This MUST NOT return until the write is durable. Returning `Ok` is a
    /// promise that `leaf` can never be reissued, even if the process dies on
    /// the next instruction. An implementation that buffers the write and
    /// returns early breaks the whole scheme: a crash then replays a leaf that
    /// a signature already spent.
    ///
    /// Returning `Err` MUST mean nothing was recorded, so the caller may treat
    /// the leaf as still unused.
    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error>;

    /// The next unused leaf, as last committed.
    ///
    /// For a fresh key this is `0`. After a successful `commit(n)` it is
    /// `n + 1`, and it must survive a restart.
    fn next_leaf(&self) -> u32;

    /// The key this journal belongs to, or `None` if it has never been bound
    /// to one.
    ///
    /// This must be read from the same durable storage the counter lives in,
    /// and it must survive a restart. A journal that forgets which key it
    /// belongs to is a journal that will accept any key, which is the whole
    /// of the hazard this method exists to close.
    ///
    /// `None` means "never bound", not "unknown". An implementation that
    /// cannot read its storage MUST NOT report `None`: that is the answer
    /// [`adopt_key`] treats as an invitation to bind, and binding over a
    /// record that already exists is what forks the leaf budget. Fail the
    /// read at construction time instead, before a journal value exists.
    fn bound_key(&self) -> Option<KeyIdentity>;

    /// Durably record that this journal belongs to `key`.
    ///
    /// The same durability promise [`commit`](Self::commit) makes: returning
    /// `Ok` means the binding survives a crash on the next instruction, and
    /// returning `Err` means nothing was written.
    ///
    /// Implementations do not have to check whether a binding already
    /// exists -- [`adopt_key`] is the only caller in this crate and it checks
    /// first -- but an implementation that can enforce write-once in its
    /// storage (a `UNIQUE` column, an `O_EXCL` create) should, because that
    /// enforcement survives a caller who reaches past this crate.
    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error>;
}

/// Bind `journal` to `key`, unless it already belongs to a different key.
///
/// This is the **explicit** act of declaring "this journal is the durable
/// leaf record for this key". Signing never does it implicitly, and that is
/// the point: an unbound journal paired with an existing key is the
/// silent-fork case, and turning it into an error the integrator has to
/// answer for by writing this call is the whole of the fix.
///
/// Three outcomes:
///
/// * Never bound: `key` is written durably and this returns `Ok`.
/// * Already bound to `key`: nothing is written and this returns `Ok`, so
///   an idempotent provisioning step is safe to re-run.
/// * Already bound to a different key: nothing is written and this returns
///   [`StatefulSignError::JournalKeyMismatch`]. A journal belongs to one key
///   for its whole life; the leaf numbers in it mean nothing under another.
///
/// # Call this once, per key, at provisioning time
///
/// Calling it on a fresh journal every time a process restarts reinstates the
/// defect it closes: each restart would mint a new binding and each new
/// journal would start the budget over. The binding belongs with the durable
/// store, created when the key is created.
///
/// # Errors
///
/// [`StatefulSignError::JournalKeyMismatch`] if `journal` already belongs to
/// another key. [`StatefulSignError::JournalFailed`] if the write did not
/// become durable; nothing was bound and nothing was spent.
pub fn adopt_key<J>(journal: &mut J, key: KeyIdentity) -> Result<(), StatefulSignError>
where
    J: LeafJournal + ?Sized,
{
    match journal.bound_key() {
        None => journal
            .bind_key(key)
            .map_err(|_| StatefulSignError::JournalFailed),
        Some(bound) if bound == key => Ok(()),
        Some(_) => Err(StatefulSignError::JournalKeyMismatch),
    }
}

/// Refuse `journal` unless it is already durably bound to `key`.
///
/// The read-only half of [`adopt_key`], and the check every signing path
/// runs. It binds nothing: a journal that has never been bound is refused
/// here exactly as one bound to another key is, because the two are
/// indistinguishable in the way that matters -- neither is a record of what
/// this key has spent.
///
/// A caller that wants to tell the two apart calls
/// [`LeafJournal::bound_key`] and looks at the `Option`.
///
/// # Errors
///
/// [`StatefulSignError::JournalKeyMismatch`] if `journal` is unbound or bound
/// to a different key.
pub fn require_bound_key<J>(journal: &J, key: KeyIdentity) -> Result<(), StatefulSignError>
where
    J: LeafJournal + ?Sized,
{
    match journal.bound_key() {
        None => Err(StatefulSignError::JournalKeyMismatch),
        Some(bound) if bound == key => Ok(()),
        Some(_) => Err(StatefulSignError::JournalKeyMismatch),
    }
}

/// Why a stateful signing attempt produced no signature.
///
/// The distinction between permanent and transient is operational, not
/// cosmetic: retrying a permanent variant burns leaves or spins forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatefulSignError {
    /// The leaf budget for this key is spent. Permanent: every later attempt
    /// with this key fails the same way. Recover by rotating to a new key.
    /// Detected before any journal write, so nothing is consumed.
    LeavesExhausted,
    /// The signature-randomizer grind reached its bound. Permanent for this
    /// (key, message) pair: the randomizer is a deterministic function of the
    /// key and the message, so a retry with the same inputs walks the same
    /// candidates and reaches the same bound. MUST NOT be retried and MUST
    /// NOT be treated as transient. Change the message, or rotate the key.
    GrindAbort,
    /// The journal could not durably record the advanced leaf. No leaf was
    /// consumed and no signature was released, so the same leaf is still
    /// available once the storage fault is repaired.
    JournalFailed,
    /// The key's own leaf counter and the durable journal no longer agree.
    ///
    /// The two counters advance together, through
    /// [`StatefulHybridSignatureScheme::sign_stateful`] alone, so a
    /// disagreement means one advanced without the other. Two causes reach
    /// this: a key and a journal restored from different sessions, and a
    /// component failure raised after the journal already committed the leaf
    /// (see [`GrindAbort`](Self::GrindAbort), which spends the leaf).
    ///
    /// Permanent, and fail-closed: the key signs nothing further, because
    /// signing past a divergence is what would reissue a spent leaf. Recover
    /// by rotating to a new key. Do not "repair" the counters by hand --
    /// whichever counter is behind names a leaf the other may already have
    /// spent.
    CountersDiverged,
    /// The journal is not this key's journal: it has never been bound to any
    /// key, or it is durably bound to a different one.
    ///
    /// Distinct from [`CountersDiverged`](Self::CountersDiverged), which is
    /// about two counters that were once in step. This one fires even when
    /// the counters agree perfectly, and agreement is exactly what makes the
    /// case dangerous: a never-used journal reports leaf `0`, an exported key
    /// that has spent nothing also reports leaf `0`, and signing on that
    /// agreement is how one key's leaf budget gets spent twice under two
    /// different messages.
    ///
    /// Permanent for this pairing, and fail-closed. It is **not** a reason to
    /// rotate the key. The key is intact; what is wrong is which journal it
    /// was handed. Recover by reopening the durable journal that belongs to
    /// this key. Only if no such journal exists -- a genuinely new store for
    /// a key whose spending history is known by other means -- call
    /// [`adopt_key`], and understand that doing so on a key that has signed
    /// before, against a journal that does not know it, reissues every leaf.
    JournalKeyMismatch,
    /// The few-time stateless budget for this key's stateless material is
    /// spent (specification section 21).
    ///
    /// Distinct from [`LeavesExhausted`](Self::LeavesExhausted), which is
    /// about the stateful path's one-time leaves. The two budgets are
    /// separate and are exhausted by separate things: ordinary application
    /// signing spends leaves and never touches this one, while stateless
    /// signing, rotation authorization and recovery all draw on this one and
    /// never touch leaves.
    ///
    /// Permanent for this stateless material, and fail-closed. Nothing was
    /// spent on the refused attempt. The remedy is a rotation that actually
    /// changes `pkSeed || hypertreeRoot`; a rotation that leaves the
    /// stateless material as it stands does not refill it, by design.
    StatelessBudgetExhausted,
    /// The caller's [`crate::budget::StatelessBudgetStore`] could not
    /// durably record the spend. No budget was consumed and no signature was
    /// released, so the same unit is still available once the storage fault
    /// is repaired.
    ///
    /// The stateless counterpart of
    /// [`JournalFailed`](Self::JournalFailed), and transient on the same
    /// terms.
    BudgetStoreFailed,
    /// A genuinely internal or transient failure inside the signing
    /// primitive, including rejected inputs.
    SigningFailed,
}

impl fmt::Display for StatefulSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeavesExhausted => {
                write!(f, "leaf budget exhausted for this key; rotate the key")
            }
            Self::GrindAbort => write!(
                f,
                "randomizer grind bound reached; permanent for this key and message"
            ),
            Self::JournalFailed => write!(
                f,
                "leaf journal could not durably commit; no leaf consumed, no signature released"
            ),
            Self::CountersDiverged => write!(
                f,
                "key counter and leaf journal diverged; this key can sign no more, rotate it"
            ),
            Self::JournalKeyMismatch => write!(
                f,
                "this leaf journal does not belong to this key; reopen the key's own journal"
            ),
            Self::StatelessBudgetExhausted => write!(
                f,
                "few-time stateless budget exhausted for this key's stateless material"
            ),
            Self::BudgetStoreFailed => write!(
                f,
                "stateless budget store could not durably record; nothing consumed"
            ),
            Self::SigningFailed => write!(f, "signing failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StatefulSignError {}

/// A hybrid signature scheme whose stateful mode spends one leaf per
/// signature.
pub trait StatefulHybridSignatureScheme {
    /// Public key, serialisable as bytes.
    type PublicKey: AsRef<[u8]> + Clone;
    /// Secret key.
    ///
    /// This MUST NOT implement `Clone`. A cloned stateful secret key is a
    /// second holder of the same leaf budget, and the two copies reissue every
    /// leaf. Advancing state through `&mut` is the only supported way to move
    /// a key forward.
    type SecretKey: zeroize::Zeroize;
    /// Signature, serialisable as bytes.
    type Signature: AsRef<[u8]>;

    /// Sign `msg` under `ctx`, spending one leaf.
    ///
    /// # Ordering contract
    ///
    /// An implementation MUST follow this order, and [`sign_after_commit`]
    /// exists so that it does not have to be re-derived:
    ///
    /// 1. Check that `journal` is durably bound to this key
    ///    ([`require_bound_key`]), then validate the inputs and the remaining
    ///    leaf budget.
    /// 2. Call [`LeafJournal::commit`] for the leaf about to be spent, and
    ///    observe that it returned `Ok`.
    /// 3. Only then construct the signature.
    /// 4. Only then return it.
    ///
    /// A crash between steps 2 and 3 wastes one leaf. That is acceptable. Any
    /// order that hands back a signature before its commit is durable risks
    /// reissuing a consumed leaf, which is a total loss of security for the
    /// key.
    ///
    /// # Errors
    ///
    /// [`StatefulSignError::JournalFailed`] means no leaf was consumed and no
    /// signature was released. [`StatefulSignError::LeavesExhausted`] is
    /// detected before any commit, so it consumes nothing either.
    /// [`StatefulSignError::GrindAbort`] is raised after the commit, so it
    /// wastes the leaf, and it MUST NOT be retried with the same message.
    /// [`StatefulSignError::CountersDiverged`] means the key and the journal
    /// no longer agree on the next leaf; the key is finished and must be
    /// rotated. [`StatefulSignError::JournalKeyMismatch`] means the journal
    /// is not this key's journal at all; the key is fine and the pairing is
    /// not, so nothing is consumed.
    fn sign_stateful(
        sk: &mut Self::SecretKey,
        journal: &mut impl LeafJournal,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<Self::Signature, StatefulSignError>;

    /// Sign `msg` under `ctx` without consuming leaf state, spending one
    /// unit of the few-time stateless budget instead.
    ///
    /// Available only for schemes whose signature does not spend a one-time
    /// key. A stateful-only scheme returns
    /// [`StatefulSignError::SigningFailed`].
    ///
    /// # `budget` is required, and that is the point
    ///
    /// The stateless path has a hard security bound of its own
    /// ([`crate::PqStatefulScheme::STATELESS_BUDGET`], specification section
    /// 21), shared with rotation and recovery, and exceeding it degrades the
    /// underlying few-time scheme's security assumption. It is therefore not
    /// a bound a caller may opt into: this method cannot be called without a
    /// durable store to charge, exactly as
    /// [`sign_stateful`](Self::sign_stateful) cannot be called without a
    /// [`LeafJournal`]. See [`crate::budget`] for the store contract.
    ///
    /// # Ordering contract
    ///
    /// The same shape [`sign_stateful`](Self::sign_stateful) follows, with
    /// the budget standing in for the journal:
    ///
    /// 1. Validate the inputs.
    /// 2. Call [`crate::budget::spend_stateless_budget`] against the key's
    ///    stateless material, and observe that it returned `Ok`.
    /// 3. Only then construct the signature.
    ///
    /// A crash between steps 2 and 3 wastes one unit of budget. That is
    /// acceptable. Releasing a stateless signature whose spend is not yet
    /// durable is not: a restart would hand the same unit out again, and the
    /// bound would be exceeded by however many signatures the lost writes
    /// covered.
    ///
    /// # Errors
    ///
    /// [`StatefulSignError::StatelessBudgetExhausted`] if the budget for
    /// this key's stateless material is spent; nothing is recorded and no
    /// signature is built. [`StatefulSignError::BudgetStoreFailed`] if the
    /// store could not durably record the spend; nothing is recorded either.
    /// Otherwise a [`StatefulSignError`] if the primitive rejects the inputs
    /// or fails internally.
    fn sign_stateless(
        sk: &Self::SecretKey,
        budget: &mut impl crate::budget::StatelessBudgetStore,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<Self::Signature, StatefulSignError>;

    /// Verify `sig` over `msg` under `ctx`.
    ///
    /// Returns `bool` rather than a `Result` so that a failure cannot reveal
    /// which component of the hybrid rejected the signature.
    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool;
}

/// Spend the next leaf, then build the signature: the reference flow for
/// [`StatefulHybridSignatureScheme::sign_stateful`].
///
/// `key` names the key whose leaf is about to be spent. `journal` must
/// already be durably bound to it ([`adopt_key`]); this is checked first, ahead
/// of the budget and ahead of any commit, because a journal that does not
/// belong to this key holds counters that mean nothing for it and must not be
/// read as a budget.
///
/// `leaf_capacity` is the total number of leaves the key holds, so valid
/// leaves are `0 .. leaf_capacity`. It is a `u64` because a full `u32` leaf
/// space has a capacity one past `u32::MAX`.
///
/// `build` receives the leaf that is already durably committed, and is the
/// only place a signature comes into existence. It runs after the commit, so
/// by the time any caller can hold a signature, its leaf is spent. Validate
/// the message and the key before calling this: work done inside `build` that
/// fails has already cost a leaf.
///
/// # Errors
///
/// - [`StatefulSignError::JournalKeyMismatch`] if `journal` is not bound to
///   `key`. Nothing is read as a budget, nothing is committed, and `build`
///   does not run.
/// - [`StatefulSignError::LeavesExhausted`] if the journal is at or past
///   `leaf_capacity`. Nothing is committed and `build` does not run.
/// - [`StatefulSignError::JournalFailed`] if the commit fails. Nothing is
///   consumed and `build` does not run.
/// - Whatever `build` returns, if it fails. The leaf is spent regardless.
pub fn sign_after_commit<J, S, F>(
    journal: &mut J,
    key: KeyIdentity,
    leaf_capacity: u64,
    build: F,
) -> Result<S, StatefulSignError>
where
    J: LeafJournal + ?Sized,
    F: FnOnce(u32) -> Result<S, StatefulSignError>,
{
    // Step 0: this journal is this key's journal, or there is no step 1.
    require_bound_key(journal, key)?;
    let leaf = journal.next_leaf();
    if u64::from(leaf) >= leaf_capacity {
        return Err(StatefulSignError::LeavesExhausted);
    }
    // Step 2: the leaf is durable before step 3 can start. A failure here
    // consumes nothing, so the same leaf stays available.
    journal
        .commit(leaf)
        .map_err(|_| StatefulSignError::JournalFailed)?;
    // Step 3: only now does a signature exist.
    build(leaf)
}

/// A durable record of the highest leaf index a verifier has accepted.
///
/// The verifier-side counterpart to [`LeafJournal`]. The signer's journal
/// stops that signer from reissuing a leaf; this stops a verifier from
/// accepting a leaf twice, whoever produced it. Both are needed: a signer
/// whose key was copied, or restored from a seed backup, will happily reissue
/// leaf 1, and the copy's signature is cryptographically valid. Only a
/// verifier that remembers can reject it.
///
/// The library holds no I/O. The integrator supplies storage, as with
/// [`LeafJournal`].
pub trait LeafIndexStore {
    /// Whatever the backing store reports. It never reaches the caller of
    /// [`accept_monotonic_leaf`], which sees only [`ReplayRejected`].
    type Error: fmt::Debug;

    /// The highest leaf index accepted so far, or `None` if none has been.
    ///
    /// This must survive a restart. A store that forgets accepts replays.
    fn highest_accepted(&self) -> Option<u32>;

    /// Durably record `leaf` as accepted.
    ///
    /// The same durability promise [`LeafJournal::commit`] makes: returning
    /// `Ok` means the record survives a crash on the next instruction.
    fn record(&mut self, leaf: u32) -> Result<(), Self::Error>;
}

/// Why a leaf index was refused before any cryptography ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayRejected {
    /// The leaf is not above every leaf already accepted. Either a replay or
    /// a reordering; the verifier cannot tell which, and both are refused.
    NotAboveHighest {
        /// The offered leaf index.
        leaf: u32,
        /// The highest index already accepted.
        highest: u32,
    },
    /// Leaf indices are one-based. Zero is never a valid stateful leaf.
    ZeroLeaf,
    /// The store failed. The leaf is refused, because an accepted leaf that
    /// was not recorded would be accepted again after a restart.
    StoreFailed,
}

/// Accept `leaf` only if it is strictly above every leaf accepted before, and
/// only once the acceptance is durable.
///
/// Call this with the `leaf_count` read out of a decoded stateful signature,
/// BEFORE verifying it. The index is four bytes of plaintext at a fixed
/// offset, so checking it first costs nothing and refuses a replay without
/// running any cryptography.
///
/// Strictly increasing, not merely unequal: a set of seen indices would grow
/// without bound, and a verifier that must remember every index forever is
/// one that eventually forgets.
///
/// This is a policy a verifier opts into. It is not part of signature
/// verification, and a signature this refuses may still be perfectly valid --
/// that is the point. Replay is not a property the cryptography can decide.
///
/// This function is the whole of the `MonotonicIndex` policy. A verifier
/// choosing between `MonotonicIndex`, `LeafBitmap`, and `RecoveryRotation`
/// per key epoch, with the freeze and recovery rules the spec layers on top,
/// wants [`crate::policy::LeafPolicyMachine`] instead, whose
/// `MonotonicIndex` arm calls this function unchanged.
pub fn accept_monotonic_leaf<S: LeafIndexStore>(
    store: &mut S,
    leaf: u32,
) -> Result<(), ReplayRejected> {
    if leaf == 0 {
        return Err(ReplayRejected::ZeroLeaf);
    }
    if let Some(highest) = store.highest_accepted() {
        if leaf <= highest {
            return Err(ReplayRejected::NotAboveHighest { leaf, highest });
        }
    }
    // Record before accepting, for the same reason the signer commits before
    // releasing: a crash between the two must not lose the fact.
    store
        .record(leaf)
        .map_err(|_| ReplayRejected::StoreFailed)?;
    Ok(())
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::vec::Vec;

    /// Two distinct stand-in identities, so a test can pair a journal with
    /// the wrong key.
    fn key_a() -> KeyIdentity {
        KeyIdentity::derive(b"suite-a\0", &[0xAA; 4])
    }
    fn key_b() -> KeyIdentity {
        KeyIdentity::derive(b"suite-b\0", &[0xBB; 4])
    }

    /// Everything the mock journal and the signing closure share.
    #[derive(Default)]
    struct JournalState {
        committed: Vec<u32>,
        log: Vec<Event>,
        fail_commit: bool,
        bound: Option<KeyIdentity>,
        fail_bind: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        /// A leaf became durable.
        Committed(u32),
        /// The signing closure ran for a leaf, and whether that leaf was
        /// already durable at that instant.
        Produced { leaf: u32, was_durable: bool },
    }

    struct MockJournal {
        state: Rc<RefCell<JournalState>>,
    }

    #[derive(Debug)]
    struct MockJournalError;

    impl LeafJournal for MockJournal {
        type Error = MockJournalError;

        fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
            let mut state = self.state.borrow_mut();
            if state.fail_commit {
                return Err(MockJournalError);
            }
            state.committed.push(leaf);
            state.log.push(Event::Committed(leaf));
            Ok(())
        }

        fn next_leaf(&self) -> u32 {
            let state = self.state.borrow();
            state.committed.iter().copied().max().map_or(0, |m| m + 1)
        }

        fn bound_key(&self) -> Option<KeyIdentity> {
            self.state.borrow().bound
        }

        fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
            let mut state = self.state.borrow_mut();
            if state.fail_bind {
                return Err(MockJournalError);
            }
            state.bound = Some(key);
            Ok(())
        }
    }

    /// A journal already bound to [`key_a`], the ordinary starting point for
    /// the tests below.
    fn bound_journal(state: &Rc<RefCell<JournalState>>) -> MockJournal {
        state.borrow_mut().bound = Some(key_a());
        MockJournal {
            state: Rc::clone(state),
        }
    }

    /// Records the produce event, then returns a signature naming its leaf.
    fn produce(state: &Rc<RefCell<JournalState>>, leaf: u32) -> [u8; 4] {
        let was_durable = state.borrow().committed.contains(&leaf);
        state
            .borrow_mut()
            .log
            .push(Event::Produced { leaf, was_durable });
        leaf.to_be_bytes()
    }

    #[test]
    fn journal_failure_yields_journal_failed_and_no_signature() {
        let state = Rc::new(RefCell::new(JournalState {
            fail_commit: true,
            ..JournalState::default()
        }));
        let mut journal = bound_journal(&state);

        let outcome = sign_after_commit(&mut journal, key_a(), 8, |leaf| Ok(produce(&state, leaf)));

        assert_eq!(outcome, Err(StatefulSignError::JournalFailed));
        assert!(state.borrow().committed.is_empty());
        assert!(state.borrow().log.is_empty());
    }

    #[test]
    fn no_signature_is_released_for_an_uncommitted_leaf() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = bound_journal(&state);

        for _ in 0..4 {
            let sig = sign_after_commit(&mut journal, key_a(), 8, |leaf| Ok(produce(&state, leaf)))
                .expect("signing succeeds below the leaf ceiling");
            let leaf = u32::from_be_bytes(sig);
            // The leaf the caller now holds is already durable.
            assert!(state.borrow().committed.contains(&leaf));
        }

        // Every produce saw its own leaf already durable, and each produce is
        // preceded in the log by the commit of that same leaf.
        let log = state.borrow().log.clone();
        for (index, event) in log.iter().enumerate() {
            if let Event::Produced { leaf, was_durable } = *event {
                assert!(
                    was_durable,
                    "leaf {leaf} was produced before it was durable"
                );
                assert!(
                    log[..index].contains(&Event::Committed(leaf)),
                    "produce of leaf {leaf} was not preceded by its commit"
                );
            }
        }
    }

    #[test]
    fn successive_signatures_advance_the_leaf() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = bound_journal(&state);

        let first = sign_after_commit(&mut journal, key_a(), 8, |leaf| Ok(produce(&state, leaf)))
            .expect("first signature");
        let second = sign_after_commit(&mut journal, key_a(), 8, |leaf| Ok(produce(&state, leaf)))
            .expect("second signature");

        assert_eq!(u32::from_be_bytes(first), 0);
        assert_eq!(u32::from_be_bytes(second), 1);
        assert_eq!(state.borrow().committed, [0, 1]);
    }

    #[test]
    fn exhaustion_commits_nothing() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = bound_journal(&state);

        for _ in 0..2 {
            sign_after_commit(&mut journal, key_a(), 2, |leaf| Ok(produce(&state, leaf)))
                .expect("the first two leaves are available");
        }
        let committed_before = state.borrow().committed.clone();

        let outcome = sign_after_commit(&mut journal, key_a(), 2, |leaf| Ok(produce(&state, leaf)));

        assert_eq!(outcome, Err(StatefulSignError::LeavesExhausted));
        assert_eq!(state.borrow().committed, committed_before);
        assert_eq!(
            state
                .borrow()
                .log
                .iter()
                .filter(|e| matches!(e, Event::Produced { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn an_identity_names_exactly_one_suite_and_verify_key() {
        let base = KeyIdentity::derive(b"suite\0", &[1, 2, 3, 4]);
        assert_eq!(base, KeyIdentity::derive(b"suite\0", &[1, 2, 3, 4]));
        assert_ne!(base, KeyIdentity::derive(b"other\0", &[1, 2, 3, 4]));
        assert_ne!(base, KeyIdentity::derive(b"suite\0", &[1, 2, 3, 5]));

        // Length-prefixed, not concatenated: moving the boundary between the
        // two fields must not produce the same identity. Without the
        // prefixes, `("ab", "cd")` and `("a", "bcd")` would hash the same
        // bytes, so a suite label chosen for one key could name another.
        assert_ne!(
            KeyIdentity::derive(b"ab", b"cd"),
            KeyIdentity::derive(b"a", b"bcd")
        );
    }

    #[test]
    fn an_identity_survives_being_written_down() {
        let identity = key_a();
        assert_eq!(KeyIdentity::from_bytes(*identity.as_bytes()), identity);
        assert_eq!(identity.as_bytes().len(), KEY_IDENTITY_LEN);
    }

    #[test]
    fn adopting_binds_once_and_refuses_a_second_key() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };
        assert_eq!(journal.bound_key(), None, "a fresh journal owns no key");

        assert_eq!(adopt_key(&mut journal, key_a()), Ok(()));
        assert_eq!(journal.bound_key(), Some(key_a()));

        // Idempotent for the same key, so re-running a provisioning step is
        // safe.
        assert_eq!(adopt_key(&mut journal, key_a()), Ok(()));

        // And closed against a second key: the leaf numbers already in this
        // journal describe key A's budget and mean nothing under key B.
        assert_eq!(
            adopt_key(&mut journal, key_b()),
            Err(StatefulSignError::JournalKeyMismatch)
        );
        assert_eq!(
            journal.bound_key(),
            Some(key_a()),
            "a refused adoption must not overwrite the binding"
        );
    }

    #[test]
    fn a_binding_that_did_not_become_durable_binds_nothing() {
        let state = Rc::new(RefCell::new(JournalState {
            fail_bind: true,
            ..JournalState::default()
        }));
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };

        assert_eq!(
            adopt_key(&mut journal, key_a()),
            Err(StatefulSignError::JournalFailed)
        );
        assert_eq!(journal.bound_key(), None);

        // Once the store recovers, the same adoption succeeds.
        state.borrow_mut().fail_bind = false;
        assert_eq!(adopt_key(&mut journal, key_a()), Ok(()));
    }

    #[test]
    fn requiring_a_binding_never_creates_one() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let journal = MockJournal {
            state: Rc::clone(&state),
        };

        assert_eq!(
            require_bound_key(&journal, key_a()),
            Err(StatefulSignError::JournalKeyMismatch),
            "an unbound journal is not this key's journal"
        );
        assert_eq!(
            journal.bound_key(),
            None,
            "checking must not adopt: adoption is the caller's explicit act"
        );

        state.borrow_mut().bound = Some(key_a());
        assert_eq!(require_bound_key(&journal, key_a()), Ok(()));
        assert_eq!(
            require_bound_key(&journal, key_b()),
            Err(StatefulSignError::JournalKeyMismatch)
        );
    }

    /// The reference flow must refuse a journal that is not the key's before
    /// it reads the counter, because a counter from another key's journal is
    /// not a budget for this one -- and a fresh journal's `0` agrees with an
    /// unspent key's `0` by coincidence, not by fact.
    #[test]
    fn the_reference_flow_refuses_an_unbound_journal_before_the_counter() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };

        let outcome = sign_after_commit(&mut journal, key_a(), 8, |leaf| Ok(produce(&state, leaf)));

        assert_eq!(outcome, Err(StatefulSignError::JournalKeyMismatch));
        assert!(state.borrow().committed.is_empty());
        assert!(state.borrow().log.is_empty(), "build must not have run");

        // A journal bound to another key is refused on the same terms, even
        // though its counter would have passed the budget check.
        state.borrow_mut().bound = Some(key_b());
        assert_eq!(
            sign_after_commit(&mut journal, key_a(), 8, |leaf| Ok(produce(&state, leaf))),
            Err(StatefulSignError::JournalKeyMismatch)
        );
        assert!(state.borrow().committed.is_empty());
    }

    #[test]
    fn permanent_variants_are_distinct_from_signing_failed() {
        assert_ne!(
            StatefulSignError::LeavesExhausted,
            StatefulSignError::GrindAbort
        );
        assert_ne!(
            StatefulSignError::LeavesExhausted,
            StatefulSignError::SigningFailed
        );
        assert_ne!(
            StatefulSignError::GrindAbort,
            StatefulSignError::SigningFailed
        );
        assert_ne!(
            StatefulSignError::JournalFailed,
            StatefulSignError::SigningFailed
        );
        // A divergence is the one failure an operator must act on by
        // rotating the key, so it must not collapse into the catch-all.
        assert_ne!(
            StatefulSignError::CountersDiverged,
            StatefulSignError::SigningFailed
        );
        assert_ne!(
            StatefulSignError::CountersDiverged,
            StatefulSignError::LeavesExhausted
        );
        // A wrong journal and a diverged counter demand opposite responses --
        // rotate the key, or reopen the right journal and leave the key
        // alone -- so they must never share a variant.
        assert_ne!(
            StatefulSignError::JournalKeyMismatch,
            StatefulSignError::CountersDiverged
        );
        assert_ne!(
            StatefulSignError::JournalKeyMismatch,
            StatefulSignError::SigningFailed
        );
        assert_ne!(
            StatefulSignError::JournalKeyMismatch,
            StatefulSignError::JournalFailed
        );
    }

    // A minimal scheme, to prove the trait is implementable and that a real
    // `sign_stateful` routed through `sign_after_commit` keeps the ordering.
    #[derive(Default, zeroize::Zeroize)]
    struct TestSecretKey {
        seed: [u8; 4],
    }

    struct TestScheme;

    impl StatefulHybridSignatureScheme for TestScheme {
        type PublicKey = [u8; 4];
        type SecretKey = TestSecretKey;
        type Signature = [u8; 8];

        fn sign_stateful(
            sk: &mut Self::SecretKey,
            journal: &mut impl LeafJournal,
            msg: &[u8],
            _ctx: &[u8],
        ) -> Result<Self::Signature, StatefulSignError> {
            if msg.is_empty() {
                return Err(StatefulSignError::SigningFailed);
            }
            let seed = sk.seed;
            sign_after_commit(journal, key_a(), 4, |leaf| {
                let mut sig = [0u8; 8];
                sig[..4].copy_from_slice(&seed);
                sig[4..].copy_from_slice(&leaf.to_be_bytes());
                Ok(sig)
            })
        }

        fn sign_stateless(
            _sk: &Self::SecretKey,
            _budget: &mut impl crate::budget::StatelessBudgetStore,
            _msg: &[u8],
            _ctx: &[u8],
        ) -> Result<Self::Signature, StatefulSignError> {
            Err(StatefulSignError::SigningFailed)
        }

        fn verify(pk: &Self::PublicKey, msg: &[u8], _ctx: &[u8], sig: &Self::Signature) -> bool {
            !msg.is_empty() && &sig[..4] == pk.as_ref()
        }
    }

    #[test]
    fn scheme_sign_stateful_commits_before_it_returns() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = bound_journal(&state);
        let mut sk = TestSecretKey { seed: [7, 7, 7, 7] };

        let sig =
            TestScheme::sign_stateful(&mut sk, &mut journal, b"m", b"").expect("a fresh key signs");

        let leaf = u32::from_be_bytes([sig[4], sig[5], sig[6], sig[7]]);
        assert!(state.borrow().committed.contains(&leaf));
        assert!(TestScheme::verify(&[7, 7, 7, 7], b"m", b"", &sig));
    }

    #[test]
    fn input_validation_precedes_any_commit() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = bound_journal(&state);
        let mut sk = TestSecretKey { seed: [7, 7, 7, 7] };

        let outcome = TestScheme::sign_stateful(&mut sk, &mut journal, b"", b"");

        assert_eq!(outcome, Err(StatefulSignError::SigningFailed));
        assert!(state.borrow().committed.is_empty());
    }

    /// A store that can be told to fail, so the fail-closed path is testable.
    #[derive(Default)]
    struct MemoryIndex {
        highest: Option<u32>,
        fail: bool,
    }

    impl LeafIndexStore for MemoryIndex {
        type Error = ();

        fn highest_accepted(&self) -> Option<u32> {
            self.highest
        }

        fn record(&mut self, leaf: u32) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            self.highest = Some(leaf);
            Ok(())
        }
    }

    #[test]
    fn increasing_leaves_are_accepted_and_replays_are_not() {
        let mut store = MemoryIndex::default();
        assert_eq!(accept_monotonic_leaf(&mut store, 1), Ok(()));
        assert_eq!(accept_monotonic_leaf(&mut store, 2), Ok(()));

        // The replay a signer-side journal cannot catch: another holder of
        // the same key offering leaf 1 again.
        assert_eq!(
            accept_monotonic_leaf(&mut store, 1),
            Err(ReplayRejected::NotAboveHighest {
                leaf: 1,
                highest: 2
            })
        );
        // Re-offering the highest is equally refused.
        assert_eq!(
            accept_monotonic_leaf(&mut store, 2),
            Err(ReplayRejected::NotAboveHighest {
                leaf: 2,
                highest: 2
            })
        );
        // A gap is fine: leaves may be spent without every signature arriving.
        assert_eq!(accept_monotonic_leaf(&mut store, 9), Ok(()));
    }

    #[test]
    fn a_zero_leaf_is_refused() {
        let mut store = MemoryIndex::default();
        assert_eq!(
            accept_monotonic_leaf(&mut store, 0),
            Err(ReplayRejected::ZeroLeaf)
        );
        assert_eq!(store.highest_accepted(), None);
    }

    #[test]
    fn a_failed_store_refuses_the_leaf_and_records_nothing() {
        let mut store = MemoryIndex {
            fail: true,
            ..Default::default()
        };
        assert_eq!(
            accept_monotonic_leaf(&mut store, 1),
            Err(ReplayRejected::StoreFailed)
        );
        assert_eq!(
            store.highest_accepted(),
            None,
            "a leaf that could not be recorded must not count as accepted"
        );

        // Once the store recovers, the same leaf is still available.
        store.fail = false;
        assert_eq!(accept_monotonic_leaf(&mut store, 1), Ok(()));
    }
}
