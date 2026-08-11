// SPDX-License-Identifier: AGPL-3.0-or-later
use core::fmt;
use core::str::FromStr;

use crate::error::AbiError;

/// One of the six hybrid suites this workspace ships, named at run time.
///
/// Every suite in `pqhybridsign` and `pqhybridsign-shrincs` is a
/// compile-time type (`H1`, `H3`, ..., callers write `sign::<H1>(...)`).
/// No C header, JavaScript function or Python module can name a type
/// parameter, so this enum is the runtime stand-in every function in this
/// crate dispatches on.
///
/// `H1`/`H3` pair a classical scheme with ML-DSA-44. `H2`/`H4` pair a
/// classical scheme with FN-DSA-512. `H5`/`H6` pair a classical scheme with
/// SHRINCS, a stateful hash-based scheme: see the crate documentation for
/// why H5 and H6 are never accepted by [`crate::sign`] or
/// [`crate::sign_deterministic`].
///
/// The discriminant returned by [`Suite::code`] is pinned by
/// `tests::discriminants_are_pinned` below: reordering the variants below
/// cannot silently renumber the ABI, because the test would fail first.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Suite {
    /// ed25519 + ML-DSA-44.
    H1 = 1,
    /// ed25519 + FN-DSA-512.
    H2 = 2,
    /// sr25519 + ML-DSA-44.
    H3 = 3,
    /// sr25519 + FN-DSA-512.
    H4 = 4,
    /// ed25519 + SHRINCS (stateful).
    H5 = 5,
    /// sr25519 + SHRINCS (stateful).
    H6 = 6,
}

impl Suite {
    /// The stable `u8` discriminant a C caller passes.
    ///
    /// Pinned by `tests::discriminants_are_pinned`: this value never
    /// changes for an existing suite, even if the variants above are
    /// reordered in source.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Recover a [`Suite`] from its [`Suite::code`].
    ///
    /// # Errors
    ///
    /// [`AbiError::InvalidSuite`] for any byte other than `1..=6`.
    pub const fn from_code(code: u8) -> Result<Self, AbiError> {
        match code {
            1 => Ok(Self::H1),
            2 => Ok(Self::H2),
            3 => Ok(Self::H3),
            4 => Ok(Self::H4),
            5 => Ok(Self::H5),
            6 => Ok(Self::H6),
            _ => Err(AbiError::InvalidSuite),
        }
    }

    /// The registry name a JavaScript or Python caller passes, `"H1"` ..
    /// `"H6"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H1 => "H1",
            Self::H2 => "H2",
            Self::H3 => "H3",
            Self::H4 => "H4",
            Self::H5 => "H5",
            Self::H6 => "H6",
        }
    }

    /// `true` for H5 and H6: the two suites whose post-quantum half spends
    /// a one-time leaf per signature and is driven through
    /// [`crate::sign_stateful`]/[`crate::sign_stateless`] rather than
    /// [`crate::sign`]/[`crate::sign_deterministic`].
    #[must_use]
    pub const fn is_stateful(self) -> bool {
        matches!(self, Self::H5 | Self::H6)
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Suite {
    type Err = AbiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "H1" => Ok(Self::H1),
            "H2" => Ok(Self::H2),
            "H3" => Ok(Self::H3),
            "H4" => Ok(Self::H4),
            "H5" => Ok(Self::H5),
            "H6" => Ok(Self::H6),
            _ => Err(AbiError::InvalidSuite),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every discriminant a C caller may already have on disk. Changing any
    /// of these values is a breaking change to the ABI; this test exists so
    /// that a later reordering of the enum fails the build instead of
    /// silently renumbering suites underneath an existing integration.
    #[test]
    fn discriminants_are_pinned() {
        assert_eq!(Suite::H1.code(), 1);
        assert_eq!(Suite::H2.code(), 2);
        assert_eq!(Suite::H3.code(), 3);
        assert_eq!(Suite::H4.code(), 4);
        assert_eq!(Suite::H5.code(), 5);
        assert_eq!(Suite::H6.code(), 6);
    }

    #[test]
    fn from_code_round_trips_and_rejects_unknown_values() {
        for suite in [
            Suite::H1,
            Suite::H2,
            Suite::H3,
            Suite::H4,
            Suite::H5,
            Suite::H6,
        ] {
            assert_eq!(Suite::from_code(suite.code()), Ok(suite));
        }
        assert_eq!(Suite::from_code(0), Err(AbiError::InvalidSuite));
        assert_eq!(Suite::from_code(7), Err(AbiError::InvalidSuite));
    }

    #[test]
    fn as_str_and_from_str_round_trip() {
        for suite in [
            Suite::H1,
            Suite::H2,
            Suite::H3,
            Suite::H4,
            Suite::H5,
            Suite::H6,
        ] {
            assert_eq!(suite.as_str().parse(), Ok(suite));
        }
        assert_eq!("H7".parse::<Suite>(), Err(AbiError::InvalidSuite));
        assert_eq!("".parse::<Suite>(), Err(AbiError::InvalidSuite));
    }

    #[test]
    fn is_stateful_matches_h5_and_h6_only() {
        assert!(!Suite::H1.is_stateful());
        assert!(!Suite::H2.is_stateful());
        assert!(!Suite::H3.is_stateful());
        assert!(!Suite::H4.is_stateful());
        assert!(Suite::H5.is_stateful());
        assert!(Suite::H6.is_stateful());
    }
}
