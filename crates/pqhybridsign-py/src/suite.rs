// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Python-visible `Suite` enum and its conversion to and from
//! [`pqhybridsign_abi::Suite`].
//!
//! `pqhybridsign_abi::Suite` cannot be exposed to Python directly: it is
//! `#[non_exhaustive]`, so a match against it must always keep a catch-all
//! arm ready for a variant this crate does not yet know, and pyo3's
//! `eq_int` enum support needs an exhaustive match to generate `__eq__`.
//! This local copy is kept in lock-step by `suite_round_trips_every_value`.

// PyO3 exposes each variant's Rust spelling to Python as-is, and Python
// enum members are conventionally upper snake case, not Rust type names.
#![allow(non_camel_case_types)]

use pyo3::prelude::*;

use crate::errors::to_py_err;

/// One of the six hybrid suites `pqhybridsign` ships.
///
/// `ED_ML_44`/`SR_ML_44` pair a classical scheme with ML-DSA-44.
/// `ED_FN_512`/`SR_FN_512` pair a classical scheme with FN-DSA-512.
/// `ED_SH`/`SR_SH` pair a classical scheme with SHRINCS, a stateful
/// hash-based scheme -- see
/// [`StatefulSecretKey`](crate::stateful::StatefulSecretKey) for why
/// `ED_SH` and `SR_SH` secret keys are a distinct Python type from the
/// `bytes` the other four suites use.
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
    ED_ML_44 = 1,
    /// ed25519 + FN-DSA-512.
    ED_FN_512 = 2,
    /// sr25519 + ML-DSA-44.
    SR_ML_44 = 3,
    /// sr25519 + FN-DSA-512.
    SR_FN_512 = 4,
    /// ed25519 + SHRINCS (stateful).
    ED_SH = 5,
    /// sr25519 + SHRINCS (stateful).
    SR_SH = 6,
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

    /// Same as [`Self::value`]: `int(Suite.ED_ML_44) == 1`.
    fn __int__(&self) -> u8 {
        *self as u8
    }

    /// Hash as the integer suite code, so `Suite.ED_ML_44 == 1` and
    /// `hash(Suite.ED_ML_44) == hash(1)` stay consistent.
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
            pqhybridsign_abi::Suite::EdMl44 => Some(Self::ED_ML_44),
            pqhybridsign_abi::Suite::EdFn512 => Some(Self::ED_FN_512),
            pqhybridsign_abi::Suite::SrMl44 => Some(Self::SR_ML_44),
            pqhybridsign_abi::Suite::SrFn512 => Some(Self::SR_FN_512),
            pqhybridsign_abi::Suite::EdSh => Some(Self::ED_SH),
            pqhybridsign_abi::Suite::SrSh => Some(Self::SR_SH),
            _ => None,
        }
    }
}

impl From<PySuite> for pqhybridsign_abi::Suite {
    fn from(s: PySuite) -> Self {
        match s {
            PySuite::ED_ML_44 => Self::EdMl44,
            PySuite::ED_FN_512 => Self::EdFn512,
            PySuite::SR_ML_44 => Self::SrMl44,
            PySuite::SR_FN_512 => Self::SrFn512,
            PySuite::ED_SH => Self::EdSh,
            PySuite::SR_SH => Self::SrSh,
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
            (PySuite::ED_ML_44, pqhybridsign_abi::Suite::EdMl44),
            (PySuite::ED_FN_512, pqhybridsign_abi::Suite::EdFn512),
            (PySuite::SR_ML_44, pqhybridsign_abi::Suite::SrMl44),
            (PySuite::SR_FN_512, pqhybridsign_abi::Suite::SrFn512),
            (PySuite::ED_SH, pqhybridsign_abi::Suite::EdSh),
            (PySuite::SR_SH, pqhybridsign_abi::Suite::SrSh),
        ] {
            let converted: pqhybridsign_abi::Suite = py_suite.into();
            assert_eq!(converted, expected);
            assert_eq!(PySuite::from_abi(expected), Some(py_suite));
            assert_eq!(py_suite as u8, expected.code());
        }
    }
}
