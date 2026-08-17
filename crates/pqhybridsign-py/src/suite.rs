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

use crate::errors::to_py_err;

/// One of the six hybrid suites `pqhybridsign` ships.
///
/// `H1`/`H3` pair a classical scheme with ML-DSA-44. `H2`/`H4` pair a
/// classical scheme with FN-DSA-512. `H5`/`H6` pair a classical scheme
/// with SHRINCS, a stateful hash-based scheme -- see
/// [`StatefulSecretKey`](crate::stateful::StatefulSecretKey) for why H5
/// and H6 secret keys are a distinct Python type from the `bytes` the
/// other four suites use.
///
/// Frozen and hashable. Compares equal to its integer suite code. Not a
/// Python `IntEnum`: construct from a stored code with [`Self::from_code`].
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

#[pymethods]
impl PySuite {
    /// Recover a `Suite` from the integer code used on the wire and by
    /// the C ABI (`1` through `6`).
    ///
    /// # Errors
    ///
    /// `InvalidSuiteError` if `code` is not one of `1` through `6`.
    #[staticmethod]
    fn from_code(code: u8) -> PyResult<Self> {
        let suite = pqhybridsign_abi::Suite::from_code(code).map_err(to_py_err)?;
        Self::from_abi(suite).ok_or_else(|| to_py_err(pqhybridsign_abi::AbiError::InvalidSuite))
    }

    /// The integer suite code used on the wire and by the C ABI.
    #[getter]
    fn value(&self) -> u8 {
        *self as u8
    }

    /// Same as [`Self::value`]: `int(Suite.H1) == 1`.
    fn __int__(&self) -> u8 {
        *self as u8
    }

    /// Hash as the integer suite code, so `Suite.H1 == 1` and
    /// `hash(Suite.H1) == hash(1)` stay consistent.
    ///
    /// `#[pyclass(hash)]` is not used: it would hash with Rust's hasher
    /// and break the `eq_int` contract that this class compares equal
    /// to its integer code.
    fn __hash__(&self) -> u64 {
        u64::from(*self as u8)
    }
}

impl PySuite {
    fn from_abi(suite: pqhybridsign_abi::Suite) -> Option<Self> {
        match suite {
            pqhybridsign_abi::Suite::H1 => Some(Self::H1),
            pqhybridsign_abi::Suite::H2 => Some(Self::H2),
            pqhybridsign_abi::Suite::H3 => Some(Self::H3),
            pqhybridsign_abi::Suite::H4 => Some(Self::H4),
            pqhybridsign_abi::Suite::H5 => Some(Self::H5),
            pqhybridsign_abi::Suite::H6 => Some(Self::H6),
            _ => None,
        }
    }
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
    ///
    /// `test = false` on this crate's lib target means `cargo test`
    /// does not run this function. The pytest
    /// `test_suite_round_trips_every_value` is the running pin.
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
            assert_eq!(PySuite::from_abi(expected), Some(py_suite));
            assert_eq!(py_suite as u8, expected.code());
        }
    }
}
