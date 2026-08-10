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

use core::fmt;

/// A durable record of consumed leaves.
///
/// The crypto crates never do I/O. The integrator implements this over
/// whatever storage can honour the durability promise below: an fsynced file,
/// a transactional database row, an HSM counter.
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
    /// 1. Validate the inputs and the remaining leaf budget.
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
    fn sign_stateful(
        sk: &mut Self::SecretKey,
        journal: &mut impl LeafJournal,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<Self::Signature, StatefulSignError>;

    /// Sign `msg` under `ctx` without consuming leaf state.
    ///
    /// Available only for schemes whose signature does not spend a one-time
    /// key. A stateful-only scheme returns
    /// [`StatefulSignError::SigningFailed`].
    ///
    /// # Errors
    ///
    /// Returns a [`StatefulSignError`] if the primitive rejects the inputs or
    /// fails internally.
    fn sign_stateless(
        sk: &Self::SecretKey,
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
/// - [`StatefulSignError::LeavesExhausted`] if the journal is at or past
///   `leaf_capacity`. Nothing is committed and `build` does not run.
/// - [`StatefulSignError::JournalFailed`] if the commit fails. Nothing is
///   consumed and `build` does not run.
/// - Whatever `build` returns, if it fails. The leaf is spent regardless.
pub fn sign_after_commit<J, S, F>(
    journal: &mut J,
    leaf_capacity: u64,
    build: F,
) -> Result<S, StatefulSignError>
where
    J: LeafJournal + ?Sized,
    F: FnOnce(u32) -> Result<S, StatefulSignError>,
{
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::vec::Vec;

    /// Everything the mock journal and the signing closure share.
    #[derive(Default)]
    struct JournalState {
        committed: Vec<u32>,
        log: Vec<Event>,
        fail_commit: bool,
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
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };

        let outcome = sign_after_commit(&mut journal, 8, |leaf| Ok(produce(&state, leaf)));

        assert_eq!(outcome, Err(StatefulSignError::JournalFailed));
        assert!(state.borrow().committed.is_empty());
        assert!(state.borrow().log.is_empty());
    }

    #[test]
    fn no_signature_is_released_for_an_uncommitted_leaf() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };

        for _ in 0..4 {
            let sig = sign_after_commit(&mut journal, 8, |leaf| Ok(produce(&state, leaf)))
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
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };

        let first = sign_after_commit(&mut journal, 8, |leaf| Ok(produce(&state, leaf)))
            .expect("first signature");
        let second = sign_after_commit(&mut journal, 8, |leaf| Ok(produce(&state, leaf)))
            .expect("second signature");

        assert_eq!(u32::from_be_bytes(first), 0);
        assert_eq!(u32::from_be_bytes(second), 1);
        assert_eq!(state.borrow().committed, [0, 1]);
    }

    #[test]
    fn exhaustion_commits_nothing() {
        let state = Rc::new(RefCell::new(JournalState::default()));
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };

        for _ in 0..2 {
            sign_after_commit(&mut journal, 2, |leaf| Ok(produce(&state, leaf)))
                .expect("the first two leaves are available");
        }
        let committed_before = state.borrow().committed.clone();

        let outcome = sign_after_commit(&mut journal, 2, |leaf| Ok(produce(&state, leaf)));

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
            sign_after_commit(journal, 4, |leaf| {
                let mut sig = [0u8; 8];
                sig[..4].copy_from_slice(&seed);
                sig[4..].copy_from_slice(&leaf.to_be_bytes());
                Ok(sig)
            })
        }

        fn sign_stateless(
            _sk: &Self::SecretKey,
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
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };
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
        let mut journal = MockJournal {
            state: Rc::clone(&state),
        };
        let mut sk = TestSecretKey { seed: [7, 7, 7, 7] };

        let outcome = TestScheme::sign_stateful(&mut sk, &mut journal, b"", b"");

        assert_eq!(outcome, Err(StatefulSignError::SigningFailed));
        assert!(state.borrow().committed.is_empty());
    }
}
