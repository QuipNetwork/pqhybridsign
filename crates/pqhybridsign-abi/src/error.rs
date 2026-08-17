// SPDX-License-Identifier: AGPL-3.0-or-later
use core::fmt;

use pqhybridsign_core::stateful::StatefulSignError;
use pqhybridsign_core::Error as CoreError;

/// One flat error enum for every function in this crate, with a stable
/// integer code per variant.
///
/// A C caller gets an integer back and nothing else, so this is the whole
/// vocabulary a binding has to translate failures into its own language's
/// idiom (an exception type, an error class, ...). It flattens two Rust
/// sources: [`pqhybridsign_core::Error`], from the stateless composite
/// layer H1-H4 share, and [`StatefulSignError`], from the stateful signing
/// path H5 and H6 use. Every current variant of both maps to a distinct
/// code here. Both sources are `#[non_exhaustive]`, and each conversion
/// ends in a catch-all arm, so a variant added upstream reaches a C caller
/// as a generic code rather than as a compile error here. Adding a variant
/// upstream therefore means adding a discriminant here in the same change.
///
/// [`Suite::code`](crate::Suite::code) is the sibling of this type: both
/// are pinned in `tests::codes_are_pinned` below, so an existing binding
/// compiled against an older version of this crate keeps working against a
/// newer one.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AbiError {
    /// A byte string had the wrong length. Mirrors
    /// [`CoreError::BadLength`].
    BadLength = 1,
    /// The application context exceeded 255 bytes. Mirrors
    /// [`CoreError::ContextTooLong`].
    ContextTooLong = 2,
    /// A caller-supplied output buffer was too small. Mirrors
    /// [`CoreError::OutputBufferTooSmall`].
    OutputBufferTooSmall = 3,
    // Code 4 was `SoftJunctionRejected`, removed: junction derivation has no
    // entry point in this crate, so no library code could ever construct
    // it. The discriminant is left unassigned rather than reused, so a
    // caller compiled against an older header that still branches on `4`
    // keeps reading it as "unknown" instead of colliding with whatever code
    // 4 might mean in a future release.
    /// A path-selected signature (H5/H6) carried an unknown selector.
    /// Mirrors [`CoreError::BadPathSelector`].
    BadPathSelector = 5,
    /// A stateful signature's declared leaf count was out of range.
    /// Mirrors [`CoreError::LeafCountOutOfRange`].
    LeafCountOutOfRange = 6,
    /// Bytes remained past the length an encoding implied. Mirrors
    /// [`CoreError::TrailingBytes`].
    TrailingBytes = 7,
    /// A component crate (the classical or post-quantum primitive)
    /// reported an internal failure. Mirrors [`CoreError::ComponentFailure`].
    ComponentFailure = 8,
    /// A rotation payload carried an unknown rotation kind. Mirrors
    /// [`CoreError::BadRotationKind`]. Rotation itself is out of scope for
    /// this crate; this variant exists because the error type it maps is
    /// shared with encodings this crate does touch.
    BadRotationKind = 9,
    /// A delta-length-encoded (H2/H4) signature's length did not fit the
    /// 1-byte delta field. Mirrors [`CoreError::DeltaLengthOutOfRange`].
    DeltaLengthOutOfRange = 10,
    /// H5/H6 only: the key's one-time leaf budget is spent. Permanent;
    /// rotate the key. Mirrors [`StatefulSignError::LeavesExhausted`].
    LeavesExhausted = 11,
    /// H5/H6 only: the signature-randomizer grind reached its bound.
    /// Permanent for this (key, message) pair. The leaf this attempt
    /// consumed is already spent -- see [`crate::sign_stateful`]'s
    /// documentation on why `sk_out` is still written on this error.
    /// Mirrors [`StatefulSignError::GrindAbort`].
    GrindAbort = 12,
    /// H5/H6 only: the caller's [`crate::LeafJournal`] could not durably
    /// record the advancing leaf. No leaf was consumed. Mirrors
    /// [`StatefulSignError::JournalFailed`].
    JournalFailed = 13,
    /// H5/H6 only: a transient or internal failure inside the signing
    /// primitive. Mirrors [`StatefulSignError::SigningFailed`].
    SigningFailed = 14,
    /// The suite code or name did not name one of the six suites this
    /// crate knows.
    InvalidSuite = 15,
    /// The wrong entry point was called for this suite: a stateless
    /// function ([`crate::sign`], [`crate::sign_deterministic`],
    /// [`crate::keygen_from_seed`]) was called with H5 or H6, or a stateful
    /// function ([`crate::sign_stateful`], [`crate::sign_stateless`],
    /// [`crate::keygen_stateful_from_seed`]) was called with H1-H4.
    WrongEntryPointForSuite = 16,
    /// H5/H6 only: the secret key's leaf counter and the leaf journal no
    /// longer agree, so this key can sign no more. Mirrors
    /// [`StatefulSignError::CountersDiverged`].
    ///
    /// Distinct from [`Self::SigningFailed`] because the remedy differs:
    /// a diverged key is permanently unusable and must be rotated, while
    /// a signing failure may be worth retrying. Repairing the counters by
    /// hand reissues a spent leaf, which destroys the key's security.
    CountersDiverged = 17,
    /// H5/H6 only: the leaf journal does not belong to this key. It has never
    /// been bound to any key, or it is bound to a different one. Mirrors
    /// [`StatefulSignError::JournalKeyMismatch`].
    ///
    /// Distinct from [`Self::CountersDiverged`] because the two demand
    /// opposite responses. A divergence means the key is finished and must be
    /// rotated. This means the key is intact and the *journal* is wrong:
    /// rotating would destroy a perfectly good key, and nothing was spent.
    /// Recover by reopening the durable journal that belongs to this key, or,
    /// if there genuinely is none, by adopting one explicitly with
    /// [`crate::adopt_key`].
    JournalKeyMismatch = 18,
    /// H5/H6 only: the few-time stateless budget for this key's stateless
    /// material is spent (specification section 21). Mirrors
    /// [`StatefulSignError::StatelessBudgetExhausted`] and
    /// [`CoreError::StatelessBudgetExhausted`].
    ///
    /// Distinct from [`Self::LeavesExhausted`], which is the stateful path's
    /// separate one-time leaf budget. Ordinary application signing spends
    /// leaves and never touches this bound; stateless signing, rotation
    /// authorization and recovery all draw on this one and never touch
    /// leaves. Nothing was spent on the refused attempt.
    ///
    /// This is not a quota to raise. Exceeding it degrades the security
    /// assumption of the underlying few-time scheme. It clears only when a
    /// rotation actually changes `pkSeed || hypertreeRoot`.
    StatelessBudgetExhausted = 19,
    /// H5/H6 only: the caller's stateless budget store could not durably
    /// record the spend, so no stateless signature was released. Mirrors
    /// [`StatefulSignError::BudgetStoreFailed`] and
    /// [`CoreError::BudgetStoreFailed`].
    ///
    /// The stateless counterpart of [`Self::JournalFailed`], and transient on
    /// the same terms: nothing was recorded, so the same unit of budget is
    /// still available once the storage fault is repaired.
    BudgetStoreFailed = 20,
}

impl AbiError {
    /// The stable integer code a C caller receives.
    ///
    /// Pinned by `tests::codes_are_pinned`.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::BadLength => "a byte string had the wrong length",
            Self::ContextTooLong => "the application context exceeded 255 bytes",
            Self::OutputBufferTooSmall => "the output buffer was too small",
            Self::BadPathSelector => "the signature carried an unknown path selector",
            Self::LeafCountOutOfRange => "the declared leaf count was out of range",
            Self::TrailingBytes => "the signature carried trailing bytes",
            Self::ComponentFailure => "a component algorithm failed",
            Self::BadRotationKind => "the rotation payload carried an unknown rotation kind",
            Self::DeltaLengthOutOfRange => "the delta-encoded signature length was out of range",
            Self::LeavesExhausted => "the key's one-time leaf budget is spent; rotate the key",
            Self::GrindAbort => "the randomizer grind bound was reached for this key and message",
            Self::JournalFailed => "the leaf journal could not durably commit",
            Self::SigningFailed => "signing failed",
            Self::InvalidSuite => "the suite code or name is not one of H1-H6",
            Self::WrongEntryPointForSuite => "this entry point does not accept this suite",
            Self::CountersDiverged => {
                "the key counter and leaf journal diverged; this key can sign no more, rotate it"
            }
            Self::JournalKeyMismatch => {
                "this leaf journal does not belong to this key; reopen the key's own journal"
            }
            Self::StatelessBudgetExhausted => {
                "the few-time stateless budget for this key's stateless material is spent"
            }
            Self::BudgetStoreFailed => {
                "the stateless budget store could not durably record; nothing consumed"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AbiError {}

impl From<CoreError> for AbiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::BadLength { .. } => Self::BadLength,
            CoreError::ContextTooLong => Self::ContextTooLong,
            CoreError::OutputBufferTooSmall { .. } => Self::OutputBufferTooSmall,
            CoreError::BadPathSelector { .. } => Self::BadPathSelector,
            CoreError::LeafCountOutOfRange { .. } => Self::LeafCountOutOfRange,
            CoreError::TrailingBytes { .. } => Self::TrailingBytes,
            CoreError::ComponentFailure => Self::ComponentFailure,
            CoreError::BadRotationKind { .. } => Self::BadRotationKind,
            CoreError::DeltaLengthOutOfRange { .. } => Self::DeltaLengthOutOfRange,
            CoreError::StatelessBudgetExhausted => Self::StatelessBudgetExhausted,
            CoreError::BudgetStoreFailed => Self::BudgetStoreFailed,
            // `CoreError` is `#[non_exhaustive]`: only a variant added after
            // this crate was written can reach this arm, since every
            // variant that exists today has its own arm above.
            _ => Self::ComponentFailure,
        }
    }
}

impl From<StatefulSignError> for AbiError {
    fn from(e: StatefulSignError) -> Self {
        match e {
            StatefulSignError::LeavesExhausted => Self::LeavesExhausted,
            StatefulSignError::GrindAbort => Self::GrindAbort,
            StatefulSignError::JournalFailed => Self::JournalFailed,
            StatefulSignError::SigningFailed => Self::SigningFailed,
            StatefulSignError::CountersDiverged => Self::CountersDiverged,
            StatefulSignError::JournalKeyMismatch => Self::JournalKeyMismatch,
            StatefulSignError::StatelessBudgetExhausted => Self::StatelessBudgetExhausted,
            StatefulSignError::BudgetStoreFailed => Self::BudgetStoreFailed,
            // `StatefulSignError` is `#[non_exhaustive]` too; see the note
            // on the `CoreError` conversion above.
            _ => Self::SigningFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code a C caller may already have on disk. See the note on
    /// `Suite::tests::discriminants_are_pinned`: this exists so a later
    /// reordering of the enum fails the build rather than silently
    /// renumbering an error an integrator already branches on.
    #[test]
    fn codes_are_pinned() {
        assert_eq!(AbiError::BadLength.code(), 1);
        assert_eq!(AbiError::ContextTooLong.code(), 2);
        assert_eq!(AbiError::OutputBufferTooSmall.code(), 3);
        // Code 4 was `SoftJunctionRejected`, removed; the gap is left
        // unfilled rather than closed.
        assert_eq!(AbiError::BadPathSelector.code(), 5);
        assert_eq!(AbiError::LeafCountOutOfRange.code(), 6);
        assert_eq!(AbiError::TrailingBytes.code(), 7);
        assert_eq!(AbiError::ComponentFailure.code(), 8);
        assert_eq!(AbiError::BadRotationKind.code(), 9);
        assert_eq!(AbiError::DeltaLengthOutOfRange.code(), 10);
        assert_eq!(AbiError::LeavesExhausted.code(), 11);
        assert_eq!(AbiError::GrindAbort.code(), 12);
        assert_eq!(AbiError::JournalFailed.code(), 13);
        assert_eq!(AbiError::SigningFailed.code(), 14);
        assert_eq!(AbiError::InvalidSuite.code(), 15);
        assert_eq!(AbiError::WrongEntryPointForSuite.code(), 16);
        assert_eq!(AbiError::CountersDiverged.code(), 17);
        assert_eq!(AbiError::JournalKeyMismatch.code(), 18);
        assert_eq!(AbiError::StatelessBudgetExhausted.code(), 19);
        assert_eq!(AbiError::BudgetStoreFailed.code(), 20);
    }

    #[test]
    fn every_core_error_variant_maps_to_its_own_code() {
        assert_eq!(
            AbiError::from(CoreError::BadLength {
                expected: 1,
                actual: 2
            }),
            AbiError::BadLength
        );
        assert_eq!(
            AbiError::from(CoreError::ContextTooLong),
            AbiError::ContextTooLong
        );
        assert_eq!(
            AbiError::from(CoreError::OutputBufferTooSmall {
                needed: 1,
                actual: 0
            }),
            AbiError::OutputBufferTooSmall
        );
        assert_eq!(
            AbiError::from(CoreError::BadPathSelector { selector: 0x99 }),
            AbiError::BadPathSelector
        );
        assert_eq!(
            AbiError::from(CoreError::LeafCountOutOfRange {
                leaf_count: 0,
                max_signatures: 4
            }),
            AbiError::LeafCountOutOfRange
        );
        assert_eq!(
            AbiError::from(CoreError::TrailingBytes {
                expected: 1,
                actual: 2
            }),
            AbiError::TrailingBytes
        );
        assert_eq!(
            AbiError::from(CoreError::ComponentFailure),
            AbiError::ComponentFailure
        );
        assert_eq!(
            AbiError::from(CoreError::BadRotationKind { kind: 0x99 }),
            AbiError::BadRotationKind
        );
        assert_eq!(
            AbiError::from(CoreError::DeltaLengthOutOfRange {
                actual_len: 1,
                min_len: 2
            }),
            AbiError::DeltaLengthOutOfRange
        );
        assert_eq!(
            AbiError::from(CoreError::StatelessBudgetExhausted),
            AbiError::StatelessBudgetExhausted
        );
        assert_eq!(
            AbiError::from(CoreError::BudgetStoreFailed),
            AbiError::BudgetStoreFailed
        );
    }

    #[test]
    fn every_stateful_sign_error_variant_maps_to_its_own_code() {
        assert_eq!(
            AbiError::from(StatefulSignError::LeavesExhausted),
            AbiError::LeavesExhausted
        );
        assert_eq!(
            AbiError::from(StatefulSignError::GrindAbort),
            AbiError::GrindAbort
        );
        assert_eq!(
            AbiError::from(StatefulSignError::JournalFailed),
            AbiError::JournalFailed
        );
        assert_eq!(
            AbiError::from(StatefulSignError::SigningFailed),
            AbiError::SigningFailed
        );
        assert_eq!(
            AbiError::from(StatefulSignError::CountersDiverged),
            AbiError::CountersDiverged
        );
        assert_eq!(
            AbiError::from(StatefulSignError::JournalKeyMismatch),
            AbiError::JournalKeyMismatch
        );
        assert_eq!(
            AbiError::from(StatefulSignError::StatelessBudgetExhausted),
            AbiError::StatelessBudgetExhausted
        );
        assert_eq!(
            AbiError::from(StatefulSignError::BudgetStoreFailed),
            AbiError::BudgetStoreFailed
        );
    }
}
