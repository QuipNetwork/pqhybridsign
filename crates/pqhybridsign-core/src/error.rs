// SPDX-License-Identifier: AGPL-3.0-or-later
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
    BadLength { expected: usize, actual: usize },
    /// The application context exceeded 255 bytes.
    ContextTooLong,
    /// A caller-supplied output buffer was too small.
    OutputBufferTooSmall { needed: usize, actual: usize },
    /// A soft derivation junction was supplied. Only hard junctions exist.
    SoftJunctionRejected,
    /// A path-selected signature carried a selector other than `0x01`
    /// (stateful) or `0x02` (stateless).
    BadPathSelector { selector: u8 },
    /// A declared `LeafCount` was below 1 or above the `maxSignatures` the
    /// verified commitment bundle records.
    LeafCountOutOfRange {
        leaf_count: u32,
        max_signatures: u32,
    },
    /// Bytes remained past the length the encoding implies.
    TrailingBytes { expected: usize, actual: usize },
    /// A component crate reported an internal failure.
    ComponentFailure,
    /// A rotation payload carried a `RotationKind` other than `0x01`
    /// (stateful graft) or `0x02` (full swap).
    BadRotationKind { kind: u8 },
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
