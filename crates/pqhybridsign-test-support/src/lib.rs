//! Test doubles shared across the pqhybridsign workspace.
//!
//! Everything here exists to be constructed by a test and thrown away. None
//! of it is durable, and none of it belongs in a published artifact: the
//! crate sets `publish = false` and every consumer names it as a path-only
//! dev-dependency.

use std::collections::HashMap;

use pqhybridsign::budget::{BudgetKey, StatelessBudgetStore};

/// The error [`MemoryBudget::failing`] returns from
/// [`StatelessBudgetStore::record`].
///
/// A distinct type rather than `()` so a test that matches on it says what
/// it means, and so the failure cannot be confused with a unit return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetStoreFailed;

/// An in-memory [`StatelessBudgetStore`].
///
/// Not durable, which is what makes it a test double rather than a store:
/// [`StatelessBudgetStore::record`] promises the record survives a crash on
/// the next instruction, and a `HashMap` promises nothing. Tests use it
/// because `sign_stateless` needs a store to be callable at all.
///
/// Three behaviours, because three are needed and the workspace previously
/// spelled each one out separately at twelve sites:
///
/// - [`MemoryBudget::default`] counts what is spent and never fails.
/// - [`MemoryBudget::exhausted`] reports every key as fully spent, including
///   keys it has never seen, which drives the `BudgetExhausted` refusal.
/// - [`MemoryBudget::failing`] refuses to record, which drives the
///   `StoreFailed` refusal.
///
/// The associated error is [`BudgetStoreFailed`] rather than
/// `core::convert::Infallible` for all three. A single type cannot be both
/// infallible and able to fail, and the failure behaviour is the one that
/// cannot be reproduced any other way.
#[derive(Debug, Clone, Default)]
pub struct MemoryBudget {
    entries: HashMap<BudgetKey, u64>,
    /// When set, [`StatelessBudgetStore::consumed`] reports this count for
    /// every key it has no entry for. A `HashMap` cannot pre-load a
    /// [`BudgetKey`] that has not been seen, so [`MemoryBudget::exhausted`]
    /// needs this floor rather than a pre-populated map.
    floor: Option<u64>,
    fail: bool,
}

impl MemoryBudget {
    /// An empty store that counts what is spent and never fails.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that reports every key as fully spent.
    ///
    /// Reports `u64::MAX` for any key with no entry of its own, so a caller
    /// checking a budget bound refuses before it spends anything.
    #[must_use]
    pub fn exhausted() -> Self {
        Self {
            entries: HashMap::new(),
            floor: Some(u64::MAX),
            fail: false,
        }
    }

    /// A store whose [`StatelessBudgetStore::record`] always fails.
    ///
    /// Nothing is recorded, which is the contract a real store's `Err` makes:
    /// the caller may treat the count as unchanged and the same unit of
    /// budget as still available.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            entries: HashMap::new(),
            floor: None,
            fail: true,
        }
    }

    /// Every unit recorded across every key.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.entries.values().copied().sum()
    }
}

impl StatelessBudgetStore for MemoryBudget {
    type Error = BudgetStoreFailed;

    fn consumed(&self, key: &BudgetKey) -> Option<u64> {
        self.entries.get(key).copied().or(self.floor)
    }

    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
        if self.fail {
            return Err(BudgetStoreFailed);
        }
        self.entries.insert(*key, count);
        Ok(())
    }
}
