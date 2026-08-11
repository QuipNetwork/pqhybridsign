# SPDX-License-Identifier: AGPL-3.0-or-later
"""Python bindings for pqhybridsign.

This package re-exports the ``_pqhybridsign`` native extension. See the
``pqhybridsign`` crate's documentation for the suites (H1 through H6) and
the split between the stateless (H1-H4) and stateful (H5, H6) signing
paths.
"""

from pqhybridsign._pqhybridsign import (
    BadLengthError,
    BadPathSelectorError,
    BadRotationKindError,
    ComponentFailureError,
    ContextTooLongError,
    DeltaLengthOutOfRangeError,
    GrindAbortError,
    InvalidSuiteError,
    JournalFailedError,
    LeafCountOutOfRangeError,
    LeavesExhaustedError,
    OutputBufferTooSmallError,
    PqHybridSignError,
    SigningFailedError,
    SoftJunctionRejectedError,
    StatefulKeyNotCloneableError,
    StatefulSecretKey,
    Suite,
    TrailingBytesError,
    WrongEntryPointForSuiteError,
    keygen_from_seed,
    keygen_stateful_from_seed,
    load_stateful_secret_key,
    profile_name,
    sign,
    sign_deterministic,
    verify,
)

__all__ = [
    "BadLengthError",
    "BadPathSelectorError",
    "BadRotationKindError",
    "ComponentFailureError",
    "ContextTooLongError",
    "DeltaLengthOutOfRangeError",
    "GrindAbortError",
    "InvalidSuiteError",
    "JournalFailedError",
    "LeafCountOutOfRangeError",
    "LeavesExhaustedError",
    "OutputBufferTooSmallError",
    "PqHybridSignError",
    "SigningFailedError",
    "SoftJunctionRejectedError",
    "StatefulKeyNotCloneableError",
    "StatefulSecretKey",
    "Suite",
    "TrailingBytesError",
    "WrongEntryPointForSuiteError",
    "keygen_from_seed",
    "keygen_stateful_from_seed",
    "load_stateful_secret_key",
    "profile_name",
    "sign",
    "sign_deterministic",
    "verify",
]
