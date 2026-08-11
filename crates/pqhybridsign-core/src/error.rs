// SPDX-License-Identifier: AGPL-3.0-or-later
//! The error type shared across every operation in this crate.

use core::fmt;

/// Errors from encoding, decoding and key handling.
///
/// Every variant describes public data. Verification failure is not an
/// error variant: verification returns `bool` so it cannot reveal which
/// component failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A byte string had the wrong length.
    BadLength {
        /// The length the encoding requires.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },
    /// The application context exceeded 255 bytes.
    ContextTooLong,
    /// A caller-supplied output buffer was too small.
    OutputBufferTooSmall {
        /// The number of bytes the operation needed to write.
        needed: usize,
        /// The number of bytes the caller's buffer actually held.
        actual: usize,
    },
    /// A soft derivation junction was supplied. Only hard junctions exist.
    SoftJunctionRejected,
    /// A path-selected signature carried a selector other than `0x01`
    /// (stateful) or `0x02` (stateless).
    BadPathSelector {
        /// The byte actually found where `PathSelector` is expected.
        selector: u8,
    },
    /// A declared `LeafCount` was below 1 or above the `maxSignatures` the
    /// verified commitment bundle records.
    LeafCountOutOfRange {
        /// The leaf count that was rejected.
        leaf_count: u32,
        /// The declared budget for this key, from its verified commitment
        /// bundle.
        max_signatures: u32,
    },
    /// Bytes remained past the length the encoding implies.
    TrailingBytes {
        /// The length the encoding implies.
        expected: usize,
        /// The length actually supplied, greater than `expected`.
        actual: usize,
    },
    /// A component crate reported an internal failure.
    ComponentFailure,
    /// A rotation payload carried a `RotationKind` other than `0x01`
    /// (stateful graft) or `0x02` (full swap).
    BadRotationKind {
        /// The byte actually found where `RotationKind` is expected.
        kind: u8,
    },
    /// A delta-length-encoded post-quantum signature had a length outside
    /// `min_len..=min_len + 255`, the range the 1-byte `DeltaLen` field can
    /// represent.
    DeltaLengthOutOfRange {
        /// The post-quantum signature length that was rejected.
        actual_len: usize,
        /// The suite's `MIN_PQ_SIG_LEN`: the low end of the range the
        /// 1-byte `DeltaLen` field can represent.
        min_len: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { expected, actual } => {
                write!(f, "bad length: expected {expected} bytes, got {actual}")
            }
            Self::ContextTooLong => write!(f, "context exceeds 255 bytes"),
            Self::OutputBufferTooSmall { needed, actual } => {
                write!(
                    f,
                    "output buffer too small: need {needed} bytes, got {actual}"
                )
            }
            Self::SoftJunctionRejected => {
                write!(
                    f,
                    "soft derivation junctions are rejected for every hybrid suite"
                )
            }
            Self::BadPathSelector { selector } => {
                write!(f, "path selector {selector:#04x} is not 0x01 or 0x02")
            }
            Self::LeafCountOutOfRange {
                leaf_count,
                max_signatures,
            } => write!(
                f,
                "leaf count {leaf_count} outside 1..={max_signatures} for this key"
            ),
            Self::TrailingBytes { expected, actual } => {
                write!(
                    f,
                    "trailing bytes: encoding implies {expected} bytes, got {actual}"
                )
            }
            Self::ComponentFailure => write!(f, "component algorithm failed"),
            Self::BadRotationKind { kind } => {
                write!(f, "rotation kind {kind:#04x} is not 0x01 or 0x02")
            }
            Self::DeltaLengthOutOfRange {
                actual_len,
                min_len,
            } => write!(
                f,
                "post-quantum signature length {actual_len} outside {min_len}..={} \
                 for the 1-byte delta field",
                min_len + 255
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_copy_and_displays() {
        let e = Error::BadLength {
            expected: 32,
            actual: 31,
        };
        let copied = e;
        assert_eq!(copied, e);
        #[cfg(feature = "std")]
        assert!(!std::string::ToString::to_string(&e).is_empty());
    }

    #[test]
    fn context_too_long_is_distinct_from_bad_length() {
        assert_ne!(
            Error::ContextTooLong,
            Error::BadLength {
                expected: 1,
                actual: 2
            }
        );
    }
}
