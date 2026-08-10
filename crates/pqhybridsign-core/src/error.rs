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
    /// A component crate reported an internal failure.
    ComponentFailure,
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
            Self::ComponentFailure => write!(f, "component algorithm failed"),
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
