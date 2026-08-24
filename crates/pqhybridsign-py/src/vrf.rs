// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hybrid verifiable random function, dispatched by suite.
//!
//! `vrf_prove` and `vrf_prove_deterministic` cover H1 through H4 and reject
//! H5 and H6, on the same terms `sign` refuses them: those two suites spend
//! one unit of the few-time stateless budget per evaluation and need a
//! durable store to record it, so a call that looked free and was not would
//! be the worst failure this module could offer. [`VrfStatelessKey`] and its
//! `prove` method cover H5 and H6 through a dedicated key and a caller-
//! supplied budget store.

use std::cell::RefCell;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use rand_core::OsRng;
use zeroize::Zeroizing;

use pqhybridsign_abi::{AbiError, BudgetKey, MASTER_SEED_LEN, VRF_OUTPUT_LEN};

use crate::bytes_in::extract_bytes;
use crate::errors::to_py_err;
use crate::suite::PySuite;

/// A [`pqhybridsign_abi::StatelessBudgetStore`] backed by a Python object
/// exposing `consumed(key: bytes) -> int | None` and
/// `record(key: bytes, count: int) -> None`.
///
/// The same bridge [`crate::stateful`]'s `sign_stateless` uses for the
/// stateless signing budget, duplicated here rather than shared: the two
/// call sites are independent and the module keeps each entry point's
/// dependencies local. See that module's `PyBudget` for the reasoning
/// behind capturing a raising `consumed`/`record` call in `error` instead
/// of propagating it directly -- `StatelessBudgetStore::consumed` cannot
/// return a `Result`, so a Python exception raised there is recorded and
/// re-raised by the caller after the ABI call returns.
struct PyBudget<'py> {
    budget: Bound<'py, PyAny>,
    error: RefCell<Option<PyErr>>,
}

impl<'py> PyBudget<'py> {
    fn new(budget: Bound<'py, PyAny>) -> Self {
        Self {
            budget,
            error: RefCell::new(None),
        }
    }

    fn take_error(&self) -> Option<PyErr> {
        self.error.borrow_mut().take()
    }

    fn record_error(&self, err: PyErr) {
        *self.error.borrow_mut() = Some(err);
    }
}

impl pqhybridsign_abi::StatelessBudgetStore for PyBudget<'_> {
    /// The Python exception is recorded on `self` and re-raised by the
    /// caller; this marker only tells the ABI layer that nothing was
    /// recorded, which maps to `AbiError::BudgetStoreFailed`.
    type Error = BudgetCallFailed;

    fn consumed(&self, key: &BudgetKey) -> Option<u64> {
        let bytes = PyBytes::new(self.budget.py(), key.as_bytes());
        let value = match self.budget.call_method1("consumed", (bytes,)) {
            Ok(value) => value,
            Err(err) => {
                self.record_error(err);
                return None;
            }
        };
        if value.is_none() {
            return None;
        }
        match value.extract::<u64>() {
            Ok(count) => Some(count),
            Err(err) => {
                self.record_error(err);
                None
            }
        }
    }

    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
        let bytes = PyBytes::new(self.budget.py(), key.as_bytes());
        match self.budget.call_method1("record", (bytes, count)) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.record_error(err);
                Err(BudgetCallFailed)
            }
        }
    }
}

#[derive(Debug)]
struct BudgetCallFailed;

/// Length in bytes of a hybrid VRF proof for `suite`.
///
/// For H1 and H3 this is exact. For H2 and H4 this is the maximum a
/// delta-length binding can occupy. For H5 and H6 this is exact.
#[pyfunction]
fn vrf_proof_len(suite: PySuite) -> PyResult<usize> {
    pqhybridsign_abi::vrf_proof_len(suite.into()).map_err(to_py_err)
}

/// Evaluate the hybrid VRF for `suite`. Returns the proof as `bytes`.
///
/// Two evaluations of one input under one key give the same
/// `vrf_make_bytes` result, so a prover cannot re-roll for a better value;
/// that holds for every suite regardless of whether the classical half
/// hedges its nonce.
///
/// H1 through H4 only. H5 and H6 spend one unit of a few-time stateless
/// budget on every evaluation and need a durable store to record it, so
/// they have their own entry point, `VrfStatelessKey.prove`, for the same
/// reason `sign` refuses them there: a call that looks free and is not is
/// the worst failure mode this module could offer.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H5 and H6. `BadLengthError` if
/// `secret_key` is not the suite's secret-key length. `ComponentFailureError`
/// if either component rejects its key.
#[pyfunction]
fn vrf_prove(
    py: Python<'_>,
    suite: PySuite,
    secret_key: &Bound<'_, PyAny>,
    input: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let suite = suite.into();
    let secret_key = extract_bytes(py, secret_key)?;
    let input = extract_bytes(py, input)?;

    let mut proof = vec![0u8; pqhybridsign_abi::vrf_proof_len(suite).map_err(to_py_err)?];
    let n = pqhybridsign_abi::vrf_prove(suite, &secret_key, &input, &mut OsRng, &mut proof)
        .map_err(to_py_err)?;
    Ok(PyBytes::new(py, &proof[..n]).unbind())
}

/// Evaluate the hybrid VRF for `suite` with a reproducible classical proof.
/// Returns the proof as `bytes`.
///
/// H1 through H4 only, on the same terms as `vrf_prove`: H5 and H6 spend a
/// few-time budget unit and prove through `VrfStatelessKey.prove`.
///
/// # Errors
///
/// The same as `vrf_prove`.
#[pyfunction]
fn vrf_prove_deterministic(
    py: Python<'_>,
    suite: PySuite,
    secret_key: &Bound<'_, PyAny>,
    input: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let suite = suite.into();
    let secret_key = extract_bytes(py, secret_key)?;
    let input = extract_bytes(py, input)?;

    let mut proof = vec![0u8; pqhybridsign_abi::vrf_proof_len(suite).map_err(to_py_err)?];
    let n = pqhybridsign_abi::vrf_prove_deterministic(suite, &secret_key, &input, &mut proof)
        .map_err(to_py_err)?;
    Ok(PyBytes::new(py, &proof[..n]).unbind())
}

/// Verify a hybrid VRF proof for `suite`. Both halves must accept.
///
/// Covers all six suites: verifying never spends anything, so there is
/// nothing to keep apart by statefulness.
///
/// Returns `False`, never raises, for malformed `bytes`/`bytearray`
/// `public_key` or `proof` input. A `public_key`, `input`, or `proof`
/// argument that is neither `bytes` nor `bytearray` (a `str`, a
/// `memoryview`, `None`, ...) still raises `TypeError` from the input
/// conversion, before verification runs.
#[pyfunction]
fn vrf_verify(
    py: Python<'_>,
    suite: PySuite,
    public_key: &Bound<'_, PyAny>,
    input: &Bound<'_, PyAny>,
    proof: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let suite = suite.into();
    let public_key = extract_bytes(py, public_key)?;
    let input = extract_bytes(py, input)?;
    let proof = extract_bytes(py, proof)?;
    Ok(pqhybridsign_abi::vrf_verify(
        suite,
        &public_key,
        &input,
        &proof,
    ))
}

/// Derive 32 output bytes from a verified VRF proof for `suite`.
///
/// **Verify the proof first.** `vrf_verify` is what establishes that the
/// pre-output belongs to this key and this input. Deriving bytes from an
/// unverified proof derives bytes from whatever an attacker supplied.
///
/// `context` separates two uses of one proof: the same proof under
/// `b"leadership"` and `b"randomness"` gives unrelated bytes, so one
/// evaluation can feed two consumers without either learning the other's
/// value early.
///
/// # Errors
///
/// `BadLengthError` if `proof` is shorter than the proof header or
/// `public_key` shorter than the classical public key. `ComponentFailureError`
/// if the public key or the pre-output does not decode.
#[pyfunction]
fn vrf_make_bytes(
    py: Python<'_>,
    suite: PySuite,
    public_key: &Bound<'_, PyAny>,
    input: &Bound<'_, PyAny>,
    proof: &Bound<'_, PyAny>,
    context: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let suite = suite.into();
    let public_key = extract_bytes(py, public_key)?;
    let input = extract_bytes(py, input)?;
    let proof = extract_bytes(py, proof)?;
    let context = extract_bytes(py, context)?;

    let mut out = [0u8; VRF_OUTPUT_LEN];
    pqhybridsign_abi::vrf_make_bytes(suite, &public_key, &input, &proof, &context, &mut out)
        .map_err(to_py_err)?;
    Ok(PyBytes::new(py, &out).unbind())
}

/// A SHRINCS key dedicated to VRF evaluation, held across calls.
///
/// H5 and H6 evaluate the VRF through their post-quantum half's few-time
/// stateless path, which draws on a budget shared with rotation and
/// recovery. The key that carries an identity's rotation and recovery
/// authority must not also spend that budget on VRF evaluations, so this
/// type holds a **separate**, dedicated key: `derive` gets one from the
/// master seed under a label disjoint from the identity key's, so the two
/// never collide.
///
/// The key lives only in memory. There is no export and no way to recover
/// one from bytes: a dedicated VRF key is derived from the master seed
/// when it is needed, not stored. `derive` is deliberately the only
/// constructor this binding exposes -- the ABI's `adopt_unchecked` (build
/// one from a caller-supplied blob, on the caller's unverified word that
/// it is not the identity key) is not wrapped here. `derive` carries the
/// identity-key disjointness guarantee structurally, through the label it
/// derives under; `adopt_unchecked` rests on an assertion a caller could
/// get wrong, and that warning carries less weight across a language
/// boundary than it does at a Rust call site.
///
/// One consequence: `prove` has no Python-level test. `derive` being the
/// only constructor means exercising `prove` from Python costs a real
/// keygen (about 47 seconds at a 128s profile), which the test suite does
/// not pay for by default. The underlying call, `vrf_prove_stateless`, is
/// covered at the ABI layer (see `pqhybridsign-abi`'s `vrf` module tests,
/// `#[ignore]`d for the same cost and run by the profile-matrix job); what
/// a Python test would add on top is confidence that this wrapper threads
/// its arguments to that call correctly, and that gap is open here.
#[pyclass(module = "pqhybridsign", name = "VrfStatelessKey")]
pub(crate) struct VrfStatelessKey {
    inner: pqhybridsign_abi::VrfStatelessKey,
}

#[pymethods]
impl VrfStatelessKey {
    /// Derive a dedicated VRF key from `master` for `suite`.
    ///
    /// Returns `(key, public_key)`. The derivation uses a label disjoint
    /// from the identity key's, so a VRF key and a rotation-and-recovery
    /// identity key derived from the same master seed never collide.
    ///
    /// This runs a real key generation: about 47 seconds at a 128s
    /// profile. Released from the GIL while it runs, so other Python
    /// threads are not blocked for that long.
    ///
    /// # Errors
    ///
    /// `WrongEntryPointForSuiteError` for H1 through H4: they have no
    /// stateful half and so no dedicated VRF key to derive.
    /// `BadLengthError` if `master` is not 32 bytes. `ComponentFailureError`
    /// if derivation fails.
    #[classmethod]
    fn derive(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        suite: PySuite,
        master: &Bound<'_, PyAny>,
    ) -> PyResult<(Self, Py<PyBytes>)> {
        let suite = suite.into();
        // Checked here, before `master` is converted, because the suite
        // determines which length is even correct: a length verdict on a
        // suite this entry point does not serve tells the caller nothing
        // true. Written in terms of the suites this entry point DOES
        // serve, so a seventh suite added later is refused by default
        // rather than admitted by default.
        if !matches!(
            suite,
            pqhybridsign_abi::Suite::H5 | pqhybridsign_abi::Suite::H6
        ) {
            return Err(to_py_err(AbiError::WrongEntryPointForSuite));
        }
        let master = extract_bytes(py, master)?;
        let master: Zeroizing<[u8; MASTER_SEED_LEN]> = Zeroizing::new(
            <[u8; MASTER_SEED_LEN]>::try_from(&master[..])
                .map_err(|_| to_py_err(AbiError::BadLength))?,
        );

        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(suite)];
        let inner =
            py.detach(|| pqhybridsign_abi::VrfStatelessKey::derive(suite, &master, &mut pk));
        let inner = inner.map_err(to_py_err)?;
        Ok((Self { inner }, PyBytes::new(py, &pk).unbind()))
    }

    /// Evaluate the VRF on `input`, spending one unit of this key's
    /// few-time stateless budget through `budget`.
    ///
    /// `budget` must implement `consumed(key: bytes) -> int | None` and
    /// `record(key: bytes, count: int) -> None`, and `record` must not
    /// return until the write is durable -- the same contract
    /// `StatefulSecretKey.sign_stateless`'s `budget` argument carries.
    ///
    /// Pass the same durable store on every call for this key. A fresh
    /// store on each call restarts the count from empty, so the few-time
    /// bound never advances and is exceeded with nothing reporting it.
    ///
    /// Returns the proof as `bytes`.
    ///
    /// # Errors
    ///
    /// `StatelessBudgetExhaustedError` if this key's stateless budget is
    /// spent; nothing was recorded and no proof was built.
    /// `BudgetStoreFailedError` if `budget.record` raised or otherwise
    /// failed to run; nothing was recorded. Any exception `budget.consumed`
    /// or `budget.record` itself raised is re-raised unchanged.
    fn prove(
        &self,
        py: Python<'_>,
        budget: &Bound<'_, PyAny>,
        input: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyBytes>> {
        let input = extract_bytes(py, input)?;
        let suite = self.inner.suite();
        let mut proof = vec![0u8; pqhybridsign_abi::vrf_proof_len(suite).map_err(to_py_err)?];
        let mut budget = PyBudget::new(budget.clone());

        let outcome = pqhybridsign_abi::vrf_prove_stateless(
            &self.inner,
            &mut budget,
            &input,
            &mut OsRng,
            &mut proof,
        );

        if let Some(err) = budget.take_error() {
            return Err(err);
        }
        let n = outcome.map_err(to_py_err)?;
        Ok(PyBytes::new(py, &proof[..n]).unbind())
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VrfStatelessKey>()?;
    m.add_function(wrap_pyfunction!(vrf_proof_len, m)?)?;
    m.add_function(wrap_pyfunction!(vrf_prove, m)?)?;
    m.add_function(wrap_pyfunction!(vrf_prove_deterministic, m)?)?;
    m.add_function(wrap_pyfunction!(vrf_verify, m)?)?;
    m.add_function(wrap_pyfunction!(vrf_make_bytes, m)?)?;
    Ok(())
}
