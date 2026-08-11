// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stateless few-time budget accounting, specification section 21.
//!
//! H5 and H6 pair a stateful fast path with a stateless path reserved for
//! rotation and recovery (section 20.2). That stateless path has its own
//! hard security bound -- `2^20` signatures, `2^18` under the low-budget
//! profile -- shared across every rotation and recovery a key ever performs.
//! It is not a quota a deployment can choose to enforce loosely: exceeding it
//! degrades the underlying few-time signature scheme's security assumption.
//!
//! **The bound MUST be keyed to the stateless key material itself --
//! `pkSeed || hypertreeRoot` (specification sections 3 and 19.3) -- never to
//! a rotation epoch, a `keyVersion`, or the public-key commitment.** A
//! rotation changes the commitment on every install, including a
//! stateful-only graft that leaves the stateless material untouched
//! (specification section 19.3). Keying the budget to anything a rotation
//! changes lets that rotation silently open a fresh counter -- refilling a
//! bound that must never refill while the underlying material survives. This
//! module keys the budget to the material precisely so that question never
//! has a second answer to get wrong: two verify keys sharing stateless
//! material always resolve to the same [`BudgetKey`], and two verify keys
//! with different stateless material never do, regardless of what any other
//! field says about rotation kind or label.
//!
//! The shape here mirrors [`crate::policy`]: a store port the integrator
//! implements over durable storage, plus a total function that decides.

use core::fmt;

use sha2::{Digest, Sha256};

/// Fixed-size identity a store can key entries by, derived from the
/// stateless key material.
///
/// The material itself is 64 bytes (`pkSeed(32) || hypertreeRoot(32)`,
/// specification section 3); hashing it down to a 32-byte digest is what
/// lets a store hold one fixed-size key per tracked material instead of
/// carrying the full 64 bytes per entry. SHA-256, because it is already a
/// dependency of this crate (see [`crate::derive::derive_component_seeds`])
/// and a collision here would let two distinct stateless keys share one
/// budget counter -- an unrelated key's spending would then count against
/// this one's bound, which SHA-256's collision resistance is exactly the
/// property relied on to rule out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BudgetKey([u8; 32]);

impl BudgetKey {
    /// Derive the key a store should use for `material` (the bytes
    /// [`crate::PqStatefulScheme::stateless_key_material`] returns).
    pub fn from_material(material: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(material);
        let digest = hasher.finalize();
        Self(digest.into())
    }

    /// The raw 32-byte digest, for a store that wants to use it directly as
    /// a map key or row identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A durable record of how many stateless signatures have been produced for
/// each tracked [`BudgetKey`].
///
/// The library holds no I/O; the integrator supplies storage, as with
/// [`crate::stateful::LeafJournal`] and [`crate::stateful::LeafIndexStore`].
pub trait StatelessBudgetStore {
    /// Whatever the backing store reports. It is never returned to the
    /// caller of [`spend_stateless_budget`], which sees only
    /// [`StatelessBudgetRejected::StoreFailed`].
    type Error: fmt::Debug;

    /// The number of stateless signatures already consumed for `key`, or
    /// `None` if this exact material has never been tracked before -- which
    /// is also what a store reports for material that changed from
    /// whatever it tracked previously: a new [`BudgetKey`] is a fresh entry,
    /// not a continuation of the old one.
    fn consumed(&self, key: &BudgetKey) -> Option<u64>;

    /// Durably record that `count` stateless signatures have now been
    /// consumed for `key`.
    ///
    /// The same durability promise [`crate::stateful::LeafJournal::commit`]
    /// makes: returning `Ok` means the record survives a crash on the next
    /// instruction. Returning `Err` MUST mean nothing was recorded, so the
    /// caller may treat the count as unchanged.
    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error>;
}

/// Why [`spend_stateless_budget`] refused to spend a unit of the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatelessBudgetRejected {
    /// This material's tracked consumption is already at or above `budget`.
    /// Permanent for this material: every later attempt fails the same way
    /// until the stateless key material itself changes (a rotation whose
    /// stateless half actually changes, specification section 19.3).
    BudgetExhausted {
        /// The count already on record before this attempt.
        consumed: u64,
        /// The budget this material was checked against.
        budget: u64,
    },
    /// The store failed. Nothing was recorded, so the same unit of budget is
    /// still available once the storage fault is repaired.
    StoreFailed,
}

impl fmt::Display for StatelessBudgetRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { consumed, budget } => write!(
                f,
                "stateless budget exhausted: {consumed} of {budget} already consumed"
            ),
            Self::StoreFailed => write!(
                f,
                "stateless budget store could not durably record; nothing consumed"
            ),
        }
    }
}

/// Spend one unit of the few-time stateless budget for `material`, and mark
/// it consumed in the same step.
///
/// Call this once per stateless signature produced -- including each
/// rotation authorization (specification section 21: "Every stateless
/// signature -- including each rotation authorization -- decrements the
/// few-time budget"). `budget` is the component's
/// [`crate::PqStatefulScheme::STATELESS_BUDGET`]; callers MUST NOT pass a
/// literal here; the constant is what keeps the bound in sync with the
/// active profile (specification section 21).
///
/// Fail closed and total: a count at or above `budget` refuses, a store
/// failure refuses, and every arithmetic step uses `checked_add` so a
/// counter can never wrap into a smaller value that would look like room
/// remains.
///
/// # Errors
///
/// [`StatelessBudgetRejected::BudgetExhausted`] if this material's tracked
/// consumption is already at or above `budget`. Nothing is recorded.
/// [`StatelessBudgetRejected::StoreFailed`] if the store could not durably
/// record the increment. Nothing is recorded.
pub fn spend_stateless_budget<S: StatelessBudgetStore>(
    store: &mut S,
    material: &[u8],
    budget: u64,
) -> Result<BudgetKey, StatelessBudgetRejected> {
    let key = BudgetKey::from_material(material);
    let consumed = store.consumed(&key).unwrap_or(0);
    if consumed >= budget {
        return Err(StatelessBudgetRejected::BudgetExhausted { consumed, budget });
    }
    // `consumed < budget` here, and `budget` is a component constant far
    // below `u64::MAX`, but the addition still goes through `checked_add`
    // rather than relying on that bound: a counter this security-critical
    // must not wrap even if some future budget value ever came close.
    let next = consumed
        .checked_add(1)
        .ok_or(StatelessBudgetRejected::BudgetExhausted { consumed, budget })?;
    store
        .record(&key, next)
        .map_err(|_| StatelessBudgetRejected::StoreFailed)?;
    Ok(key)
}

/// Proof that a rotation authorization's stateless signature has already
/// been charged against the *pre-rotation* material's budget.
///
/// Only [`spend_before_rotation`] constructs one, and that function takes
/// the pre-rotation material as its only material parameter -- there is no
/// post-rotation material for a caller to pass instead. A rotation-install
/// routine that requires this token before it will proceed cannot be driven
/// with the charge skipped, deferred, or aimed at the wrong (post-rotation)
/// key: specification section 19.3's ordering rule ("the rotation signature
/// ... MUST be counted against the pre-rotation budget") is expressed here
/// as a value that cannot exist until the charge against the right key has
/// already landed, rather than as a comment asking the caller to sequence
/// two calls correctly.
#[derive(Debug, Clone, Copy)]
pub struct RotationBudgetCharged(BudgetKey);

impl RotationBudgetCharged {
    /// The [`BudgetKey`] the charge was recorded against -- the pre-rotation
    /// material's key.
    pub fn charged_key(&self) -> BudgetKey {
        self.0
    }
}

/// Spend one unit of the stateless budget for a rotation authorization,
/// against `pre_rotation_material` -- the stateless key material as it
/// stands *before* the rotation installs (specification section 19.3).
///
/// This is [`spend_stateless_budget`] under the name and signature a
/// rotation call site should use: the parameter name and the returned
/// [`RotationBudgetCharged`] token both exist to keep a caller from
/// accidentally charging the material a rotation is about to install
/// instead of the material it is charged against.
///
/// # Errors
///
/// Same as [`spend_stateless_budget`].
pub fn spend_before_rotation<S: StatelessBudgetStore>(
    store: &mut S,
    pre_rotation_material: &[u8],
    budget: u64,
) -> Result<RotationBudgetCharged, StatelessBudgetRejected> {
    let key = spend_stateless_budget(store, pre_rotation_material, budget)?;
    Ok(RotationBudgetCharged(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store that can be told to fail, so the atomicity and fail-closed
    /// paths are testable without I/O. Small, fixed-capacity map: this
    /// module has no `alloc` feature, so tests use a linear scan over a
    /// bounded array rather than a `HashMap`.
    #[derive(Default)]
    struct MemoryStore {
        entries: [(Option<BudgetKey>, u64); 4],
        fail: bool,
    }

    impl StatelessBudgetStore for MemoryStore {
        type Error = ();

        fn consumed(&self, key: &BudgetKey) -> Option<u64> {
            self.entries
                .iter()
                .find(|(k, _)| *k == Some(*key))
                .map(|(_, count)| *count)
        }

        fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            if let Some(slot) = self.entries.iter_mut().find(|(k, _)| *k == Some(*key)) {
                slot.1 = count;
                return Ok(());
            }
            let slot = self
                .entries
                .iter_mut()
                .find(|(k, _)| k.is_none())
                .expect("test store capacity exceeded");
            *slot = (Some(*key), count);
            Ok(())
        }
    }

    const MATERIAL_A: [u8; 64] = [0xA1; 64];
    const MATERIAL_B: [u8; 64] = [0xB2; 64];

    // Rule 1: the budget is keyed to the stateless key material -- nothing
    // else. `spend_stateless_budget` takes no epoch, commitment, or
    // keyVersion parameter at all, so two calls naming the same material
    // resolve to the same tracked count regardless of any other context a
    // caller might have on hand, and the derived key is a pure function of
    // the material bytes.
    #[test]
    fn the_budget_is_keyed_to_stateless_key_material_alone() {
        let key_1 = BudgetKey::from_material(&MATERIAL_A);
        let key_2 = BudgetKey::from_material(&MATERIAL_A);
        assert_eq!(key_1, key_2);

        let mut store = MemoryStore::default();
        spend_stateless_budget(&mut store, &MATERIAL_A, 10).expect("first spend");
        spend_stateless_budget(&mut store, &MATERIAL_A, 10).expect("second spend");
        assert_eq!(store.consumed(&key_1), Some(2));

        // Different material is a different key and an independent count.
        let key_b = BudgetKey::from_material(&MATERIAL_B);
        assert_ne!(key_1, key_b);
        assert_eq!(store.consumed(&key_b), None);
    }

    // Rule 2: a stateful-only graft grafts a fresh stateful tree onto
    // unchanged stateless material. Consumption does not reset: spending
    // against the same material before and after a simulated graft (nothing
    // about a graft changes what is passed here) shows one continuous count.
    #[test]
    fn a_stateful_only_graft_preserves_the_budget() {
        let mut store = MemoryStore::default();
        spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("pre-graft spend");
        spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("pre-graft spend");

        // The graft itself grafts a fresh stateful tree; the stateless
        // material passed to this module is unchanged, so the next spend
        // against the same material continues the same count.
        let key = spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("post-graft spend");
        assert_eq!(store.consumed(&key), Some(3));
    }

    // Rule 3: a `FullSwap`-labelled rotation whose stateless material
    // happens to be unchanged also preserves the budget -- the exact shape
    // of the original audit finding. `spend_stateless_budget` and
    // `spend_before_rotation` take no `RotationKind` parameter at all, so
    // there is no code path here that could special-case `FullSwap`: the
    // material is the only thing that decides.
    #[test]
    fn a_full_swap_with_unchanged_material_also_preserves_the_budget() {
        let mut store = MemoryStore::default();
        spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("pre-swap spend");

        // A rotation labelled FullSwap, but whose NextCommitment differs
        // from CurrentCommitment while pkSeed/hypertreeRoot do not: the
        // rotation signature itself is charged here, against the material,
        // which is unchanged.
        let charged =
            spend_before_rotation(&mut store, &MATERIAL_A, 100).expect("rotation signature charge");
        assert_eq!(
            store.consumed(&charged.charged_key()),
            Some(2),
            "a FullSwap label must not reset the count when the material is unchanged"
        );

        // Signing continues to draw on the same, still-live count.
        let key = spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("post-swap spend");
        assert_eq!(store.consumed(&key), Some(3));
    }

    // Rule 4: the budget resets only when the stateless material actually
    // changes -- a fresh key derives a fresh `BudgetKey` with no prior
    // count, while the old material's count is left exactly where it was.
    #[test]
    fn the_budget_resets_only_when_the_material_actually_changes() {
        let mut store = MemoryStore::default();
        spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("spend against A");
        spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("spend against A");

        // Material actually changes (a real full swap): the new material's
        // key starts unconsumed, and the old key's count is untouched.
        let key_b = spend_stateless_budget(&mut store, &MATERIAL_B, 100).expect("spend against B");
        assert_eq!(store.consumed(&key_b), Some(1));

        let key_a = BudgetKey::from_material(&MATERIAL_A);
        assert_eq!(store.consumed(&key_a), Some(2));
    }

    // Rule 5: every stateless signature decrements the budget, including
    // each rotation authorization, and a rotation signature counts against
    // the pre-rotation budget. `spend_before_rotation` only accepts the
    // pre-rotation material -- there is no parameter to aim the charge at
    // the material a rotation is about to install.
    #[test]
    fn a_rotation_signature_counts_against_the_pre_rotation_budget() {
        let mut store = MemoryStore::default();
        spend_stateless_budget(&mut store, &MATERIAL_A, 100).expect("ordinary stateless spend");

        let charged = spend_before_rotation(&mut store, &MATERIAL_A, 100)
            .expect("rotation authorization charge");
        assert_eq!(store.consumed(&charged.charged_key()), Some(2));

        // Once the rotation installs new material, that material starts
        // fresh -- the charge above landed on the pre-rotation key, not on
        // whatever comes next.
        let key_b = spend_stateless_budget(&mut store, &MATERIAL_B, 100)
            .expect("first spend against the newly installed material");
        assert_eq!(store.consumed(&key_b), Some(1));
    }

    // Rule 6: the budget is a component constant, never a literal at the
    // call site. This module never defines the figure itself; every test
    // above passes a `budget` parameter it receives, mirroring how a real
    // caller passes `S::Pq::STATELESS_BUDGET`. The component-side constant
    // itself is asserted in `pqhybridsign-shrincs`.
    #[test]
    fn the_budget_is_supplied_by_the_caller_not_hardcoded_here() {
        let mut store = MemoryStore::default();
        // A budget of exactly 1 exercises the boundary with the smallest
        // meaningful value, proving the function has no built-in minimum.
        spend_stateless_budget(&mut store, &MATERIAL_A, 1).expect("first spend fits budget 1");
        assert_eq!(
            spend_stateless_budget(&mut store, &MATERIAL_A, 1),
            Err(StatelessBudgetRejected::BudgetExhausted {
                consumed: 1,
                budget: 1
            })
        );
    }

    // Rule 7 and the boundary case: refuse at the bound. The counter at
    // budget - 1 still spends, landing exactly at budget; the next attempt,
    // at the bound, is refused; and one attempt past that is refused the
    // same way, not wrapped or saturated silently.
    #[test]
    fn the_counter_refuses_at_the_bound_and_does_not_wrap_past_it() {
        let budget = 4u64;
        let mut store = MemoryStore::default();

        // Three spends land the count at budget - 1.
        for _ in 0..3 {
            spend_stateless_budget(&mut store, &MATERIAL_A, budget).expect("below the bound");
        }
        let key = BudgetKey::from_material(&MATERIAL_A);
        assert_eq!(store.consumed(&key), Some(3));

        // The fourth spend reaches the bound exactly.
        spend_stateless_budget(&mut store, &MATERIAL_A, budget).expect("reaches the bound");
        assert_eq!(store.consumed(&key), Some(4));

        // At the bound: refused.
        assert_eq!(
            spend_stateless_budget(&mut store, &MATERIAL_A, budget),
            Err(StatelessBudgetRejected::BudgetExhausted {
                consumed: 4,
                budget: 4
            })
        );
        assert_eq!(
            store.consumed(&key),
            Some(4),
            "a refused spend records nothing"
        );

        // One past the bound: still refused, the same way.
        assert_eq!(
            spend_stateless_budget(&mut store, &MATERIAL_A, budget),
            Err(StatelessBudgetRejected::BudgetExhausted {
                consumed: 4,
                budget: 4
            })
        );
    }

    // A store failure refuses the signature and records nothing: the same
    // fail-closed discipline `accept_monotonic_leaf` and `sign_after_commit`
    // apply.
    #[test]
    fn a_store_failure_refuses_the_spend_and_records_nothing() {
        let mut store = MemoryStore {
            fail: true,
            ..Default::default()
        };

        let outcome = spend_stateless_budget(&mut store, &MATERIAL_A, 10);

        assert_eq!(outcome, Err(StatelessBudgetRejected::StoreFailed));
        let key = BudgetKey::from_material(&MATERIAL_A);
        assert_eq!(store.consumed(&key), None);

        // Once the store recovers, the same unit of budget is still
        // available.
        store.fail = false;
        assert!(spend_stateless_budget(&mut store, &MATERIAL_A, 10).is_ok());
        assert_eq!(store.consumed(&key), Some(1));
    }
}
