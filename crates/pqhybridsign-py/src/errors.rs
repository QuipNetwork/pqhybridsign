// SPDX-License-Identifier: AGPL-3.0-or-later
//! One Python exception type per [`pqhybridsign_abi::AbiError`] variant, all
//! deriving from a common [`PqHybridSignError`] base so a caller can catch
//! broadly or narrowly.
//!
//! A single catch-all exception would force every caller to inspect a
//! string or code to tell a bad-length input from an exhausted stateful
//! key, which is exactly the branch-on-an-opaque-value pattern Python
//! exceptions exist to avoid.

use pqhybridsign_abi::AbiError;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(
    _pqhybridsign,
    PqHybridSignError,
    PyException,
    "Base class for every exception this module raises."
);

macro_rules! sub_exception {
    ($name:ident, $doc:literal) => {
        create_exception!(_pqhybridsign, $name, PqHybridSignError, $doc);
    };
}

sub_exception!(BadLengthError, "A byte string had the wrong length.");
sub_exception!(
    ContextTooLongError,
    "The application context exceeded 255 bytes."
);
sub_exception!(
    OutputBufferTooSmallError,
    "An internal output buffer was too small for this signature."
);
sub_exception!(
    BadPathSelectorError,
    "A path-selected signature (H5/H6) carried an unknown selector."
);
sub_exception!(
    LeafCountOutOfRangeError,
    "A stateful signature's declared leaf count was out of range."
);
sub_exception!(
    TrailingBytesError,
    "Bytes remained past the length an encoding implied."
);
sub_exception!(
    ComponentFailureError,
    "A component algorithm (the classical or post-quantum primitive) failed."
);
sub_exception!(
    BadRotationKindError,
    "A rotation payload carried an unknown rotation kind."
);
sub_exception!(
    DeltaLengthOutOfRangeError,
    "A delta-encoded (H2/H4) signature's length was out of range."
);
sub_exception!(
    LeavesExhaustedError,
    "The key's one-time leaf budget is spent; rotate the key."
);
sub_exception!(
    GrindAbortError,
    "The signature-randomizer grind bound was reached for this key and message."
);
sub_exception!(
    JournalFailedError,
    "The leaf journal could not durably commit; nothing was spent."
);
sub_exception!(SigningFailedError, "Signing failed.");
sub_exception!(
    InvalidSuiteError,
    "The suite code or name is not one of H1-H6."
);
sub_exception!(
    WrongEntryPointForSuiteError,
    "This entry point does not accept this suite."
);
sub_exception!(
    CountersDivergedError,
    "The key counter and the leaf journal diverged; this key can sign no more, rotate it. \
     Repairing the counters by hand reissues a spent leaf, which destroys the key's security."
);
sub_exception!(
    JournalKeyMismatchError,
    "This leaf journal does not belong to this key: it has never been bound to any key, \
     or it is bound to a different one. Nothing was spent and the key is intact -- unlike \
     CountersDivergedError, this is not a reason to rotate. Reopen the durable journal that \
     belongs to this key, or, if there genuinely is none, bind one explicitly with \
     adopt_key()."
);
sub_exception!(
    StatelessBudgetExhaustedError,
    "The few-time stateless budget for this key's stateless material is spent. Nothing was \
     spent on the refused attempt. This is not the stateful path's leaf budget \
     (LeavesExhaustedError) and it is not a quota to raise: exceeding it degrades the \
     security assumption of the underlying few-time scheme. It clears only when a rotation \
     actually changes the stateless key material."
);
sub_exception!(
    BudgetStoreFailedError,
    "The stateless budget store could not durably record the spend, so no signature was \
     released. Nothing was recorded, so the same unit of budget is still available once the \
     storage fault is repaired."
);
sub_exception!(
    StatefulKeyNotCloneableError,
    "A stateful (H5/H6) secret key cannot be copied, deep-copied or pickled: \
     doing so would let the same one-time leaf be spent twice."
);

/// Translate an [`AbiError`] into the matching Python exception.
pub(crate) fn to_py_err(e: AbiError) -> PyErr {
    let msg = e.to_string();
    match e {
        AbiError::BadLength => BadLengthError::new_err(msg),
        AbiError::ContextTooLong => ContextTooLongError::new_err(msg),
        AbiError::OutputBufferTooSmall => OutputBufferTooSmallError::new_err(msg),
        AbiError::BadPathSelector => BadPathSelectorError::new_err(msg),
        AbiError::LeafCountOutOfRange => LeafCountOutOfRangeError::new_err(msg),
        AbiError::TrailingBytes => TrailingBytesError::new_err(msg),
        AbiError::BadRotationKind => BadRotationKindError::new_err(msg),
        AbiError::DeltaLengthOutOfRange => DeltaLengthOutOfRangeError::new_err(msg),
        AbiError::LeavesExhausted => LeavesExhaustedError::new_err(msg),
        AbiError::GrindAbort => GrindAbortError::new_err(msg),
        AbiError::JournalFailed => JournalFailedError::new_err(msg),
        AbiError::SigningFailed => SigningFailedError::new_err(msg),
        AbiError::InvalidSuite => InvalidSuiteError::new_err(msg),
        AbiError::WrongEntryPointForSuite => WrongEntryPointForSuiteError::new_err(msg),
        AbiError::CountersDiverged => CountersDivergedError::new_err(msg),
        AbiError::JournalKeyMismatch => JournalKeyMismatchError::new_err(msg),
        AbiError::StatelessBudgetExhausted => StatelessBudgetExhaustedError::new_err(msg),
        AbiError::BudgetStoreFailed => BudgetStoreFailedError::new_err(msg),
        // `AbiError` is `#[non_exhaustive]`: only a variant added after
        // this crate was written can reach this arm, since every variant
        // that exists today has its own arm above.
        _ => ComponentFailureError::new_err(msg),
    }
}

pub(crate) fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PqHybridSignError", py.get_type::<PqHybridSignError>())?;
    m.add("BadLengthError", py.get_type::<BadLengthError>())?;
    m.add("ContextTooLongError", py.get_type::<ContextTooLongError>())?;
    m.add(
        "OutputBufferTooSmallError",
        py.get_type::<OutputBufferTooSmallError>(),
    )?;
    m.add(
        "BadPathSelectorError",
        py.get_type::<BadPathSelectorError>(),
    )?;
    m.add(
        "LeafCountOutOfRangeError",
        py.get_type::<LeafCountOutOfRangeError>(),
    )?;
    m.add("TrailingBytesError", py.get_type::<TrailingBytesError>())?;
    m.add(
        "ComponentFailureError",
        py.get_type::<ComponentFailureError>(),
    )?;
    m.add(
        "BadRotationKindError",
        py.get_type::<BadRotationKindError>(),
    )?;
    m.add(
        "DeltaLengthOutOfRangeError",
        py.get_type::<DeltaLengthOutOfRangeError>(),
    )?;
    m.add(
        "LeavesExhaustedError",
        py.get_type::<LeavesExhaustedError>(),
    )?;
    m.add("GrindAbortError", py.get_type::<GrindAbortError>())?;
    m.add("JournalFailedError", py.get_type::<JournalFailedError>())?;
    m.add("SigningFailedError", py.get_type::<SigningFailedError>())?;
    m.add("InvalidSuiteError", py.get_type::<InvalidSuiteError>())?;
    m.add(
        "WrongEntryPointForSuiteError",
        py.get_type::<WrongEntryPointForSuiteError>(),
    )?;
    m.add(
        "CountersDivergedError",
        py.get_type::<CountersDivergedError>(),
    )?;
    m.add(
        "JournalKeyMismatchError",
        py.get_type::<JournalKeyMismatchError>(),
    )?;
    m.add(
        "StatelessBudgetExhaustedError",
        py.get_type::<StatelessBudgetExhaustedError>(),
    )?;
    m.add(
        "BudgetStoreFailedError",
        py.get_type::<BudgetStoreFailedError>(),
    )?;
    m.add(
        "StatefulKeyNotCloneableError",
        py.get_type::<StatefulKeyNotCloneableError>(),
    )?;
    Ok(())
}
