// SPDX-License-Identifier: AGPL-3.0-or-later
use core::fmt;

use crate::error::AbiError;

/// One of the six hybrid suites this workspace ships, named at run time.
///
/// Every suite in `pqhybridsign` and `pqhybridsign-shrincs` is a
/// compile-time type (`EdMl44`, `SrMl44`, ..., callers write
/// `sign::<EdMl44>(...)`). No C header, JavaScript function or Python
/// module can name a type parameter, so this enum is the runtime stand-in
/// every function in this crate dispatches on.
///
/// `EdMl44`/`SrMl44` pair a classical scheme with ML-DSA-44.
/// `EdFn512`/`SrFn512` pair a classical scheme with FN-DSA-512.
/// `EdSh`/`SrSh` pair a classical scheme with SHRINCS, a stateful
/// hash-based scheme: see the crate documentation for why `EdSh` and `SrSh`
/// are never accepted by [`crate::sign`] or [`crate::sign_deterministic`].
///
/// The discriminant returned by [`Suite::code`] is pinned by
/// `tests::discriminants_are_pinned` below: reordering the variants below
/// cannot silently renumber the ABI, because the test would fail first.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Suite {
    /// ed25519 + ML-DSA-44.
    EdMl44 = 1,
    /// ed25519 + FN-DSA-512.
    EdFn512 = 2,
    /// sr25519 + ML-DSA-44.
    SrMl44 = 3,
    /// sr25519 + FN-DSA-512.
    SrFn512 = 4,
    /// ed25519 + SHRINCS (stateful).
    EdSh = 5,
    /// sr25519 + SHRINCS (stateful).
    SrSh = 6,
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
            1 => Ok(Self::EdMl44),
            2 => Ok(Self::EdFn512),
            3 => Ok(Self::SrMl44),
            4 => Ok(Self::SrFn512),
            5 => Ok(Self::EdSh),
            6 => Ok(Self::SrSh),
            _ => Err(AbiError::InvalidSuite),
        }
    }

    /// The registry name a JavaScript or Python caller passes, `"ED-ML-44"`
    /// .. `"SR-SH"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EdMl44 => "ED-ML-44",
            Self::EdFn512 => "ED-FN-512",
            Self::SrMl44 => "SR-ML-44",
            Self::SrFn512 => "SR-FN-512",
            Self::EdSh => "ED-SH",
            Self::SrSh => "SR-SH",
        }
    }

    /// Recover a [`Suite`] from its [`Suite::name`].
    ///
    /// # Errors
    ///
    /// [`AbiError::InvalidSuite`] for any string other than the six names
    /// returned by [`Suite::name`].
    pub fn from_name(name: &str) -> Result<Self, AbiError> {
        match name {
            "ED-ML-44" => Ok(Self::EdMl44),
            "ED-FN-512" => Ok(Self::EdFn512),
            "SR-ML-44" => Ok(Self::SrMl44),
            "SR-FN-512" => Ok(Self::SrFn512),
            "ED-SH" => Ok(Self::EdSh),
            "SR-SH" => Ok(Self::SrSh),
            _ => Err(AbiError::InvalidSuite),
        }
    }

    /// `true` for `EdSh` and `SrSh`: the two suites whose post-quantum half
    /// spends a one-time leaf per signature and is driven through
    /// [`crate::sign_stateful`]/[`crate::sign_stateless`] rather than
    /// [`crate::sign`]/[`crate::sign_deterministic`].
    #[must_use]
    pub const fn is_stateful(self) -> bool {
        matches!(self, Self::EdSh | Self::SrSh)
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unchanged_by_the_rename() {
        // The numeric code is an ABI value: C callers pass it as `uint8_t suite`
        // and it appears in stored artefacts. The rename must not move it.
        assert_eq!(Suite::EdMl44.code(), 1);
        assert_eq!(Suite::EdFn512.code(), 2);
        assert_eq!(Suite::SrMl44.code(), 3);
        assert_eq!(Suite::SrFn512.code(), 4);
        assert_eq!(Suite::EdSh.code(), 5);
        assert_eq!(Suite::SrSh.code(), 6);
    }

    #[test]
    fn names_round_trip_and_reject_the_old_spelling() {
        for suite in [
            Suite::EdMl44,
            Suite::EdFn512,
            Suite::SrMl44,
            Suite::SrFn512,
            Suite::EdSh,
            Suite::SrSh,
        ] {
            assert_eq!(Suite::from_name(suite.name()), Ok(suite));
        }
        assert_eq!(Suite::EdMl44.name(), "ED-ML-44");
        assert_eq!(Suite::EdSh.name(), "ED-SH");
        // No aliases: the old spelling is not a suite name any more.
        assert!(Suite::from_name("H1").is_err());
    }

    /// Every discriminant a C caller may already have on disk. Changing any
    /// of these values is a breaking change to the ABI; this test exists so
    /// that a later reordering of the enum fails the build instead of
    /// silently renumbering suites underneath an existing integration.
    #[test]
    fn discriminants_are_pinned() {
        assert_eq!(Suite::EdMl44.code(), 1);
        assert_eq!(Suite::EdFn512.code(), 2);
        assert_eq!(Suite::SrMl44.code(), 3);
        assert_eq!(Suite::SrFn512.code(), 4);
        assert_eq!(Suite::EdSh.code(), 5);
        assert_eq!(Suite::SrSh.code(), 6);
    }

    #[test]
    fn from_code_round_trips_and_rejects_unknown_values() {
        for suite in [
            Suite::EdMl44,
            Suite::EdFn512,
            Suite::SrMl44,
            Suite::SrFn512,
            Suite::EdSh,
            Suite::SrSh,
        ] {
            assert_eq!(Suite::from_code(suite.code()), Ok(suite));
        }
        assert_eq!(Suite::from_code(0), Err(AbiError::InvalidSuite));
        assert_eq!(Suite::from_code(7), Err(AbiError::InvalidSuite));
    }

    #[test]
    fn from_name_rejects_unknown_values() {
        assert_eq!(Suite::from_name("ED-ML-45"), Err(AbiError::InvalidSuite));
        assert_eq!(Suite::from_name(""), Err(AbiError::InvalidSuite));
    }

    #[test]
    fn is_stateful_matches_ed_sh_and_sr_sh_only() {
        assert!(!Suite::EdMl44.is_stateful());
        assert!(!Suite::EdFn512.is_stateful());
        assert!(!Suite::SrMl44.is_stateful());
        assert!(!Suite::SrFn512.is_stateful());
        assert!(Suite::EdSh.is_stateful());
        assert!(Suite::SrSh.is_stateful());
    }
}
