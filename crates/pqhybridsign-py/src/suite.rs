// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Python-visible `Suite` enum and its conversion to and from
//! [`pqhybridsign_abi::Suite`].
//!
//! `pqhybridsign_abi::Suite` cannot be exposed to Python directly: it is
//! `#[non_exhaustive]`, so a match against it must always keep a catch-all
//! arm ready for a variant this crate does not yet know, and pyo3's
//! `eq_int` enum support needs an exhaustive match to generate `__eq__`.
//! This local copy is kept in lock-step by `suite_round_trips_every_value`.

use pyo3::prelude::*;

/// One of the six hybrid suites `pqhybridsign` ships.
///
/// `H1`/`H3` pair a classical scheme with ML-DSA-44. `H2`/`H4` pair a
/// classical scheme with FN-DSA-512. `H5`/`H6` pair a classical scheme
/// with SHRINCS, a stateful hash-based scheme -- see
/// [`StatefulSecretKey`](crate::stateful::StatefulSecretKey) for why H5
/// and H6 secret keys are a distinct Python type from the `bytes` the
/// other four suites use.
#[pyclass(
    module = "pqhybridsign",
    name = "Suite",
    eq,
    eq_int,
    frozen,
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PySuite {
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

impl From<PySuite> for pqhybridsign_abi::Suite {
    fn from(s: PySuite) -> Self {
        match s {
            PySuite::H1 => Self::H1,
            PySuite::H2 => Self::H2,
            PySuite::H3 => Self::H3,
            PySuite::H4 => Self::H4,
            PySuite::H5 => Self::H5,
            PySuite::H6 => Self::H6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `PySuite` variant maps to the `pqhybridsign_abi::Suite`
    /// variant with the same name, so the two enums cannot drift apart.
    #[test]
    fn suite_round_trips_every_value() {
        for (py_suite, expected) in [
            (PySuite::H1, pqhybridsign_abi::Suite::H1),
            (PySuite::H2, pqhybridsign_abi::Suite::H2),
            (PySuite::H3, pqhybridsign_abi::Suite::H3),
            (PySuite::H4, pqhybridsign_abi::Suite::H4),
            (PySuite::H5, pqhybridsign_abi::Suite::H5),
            (PySuite::H6, pqhybridsign_abi::Suite::H6),
        ] {
            let converted: pqhybridsign_abi::Suite = py_suite.into();
            assert_eq!(converted, expected);
        }
    }
}
