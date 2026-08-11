// SPDX-License-Identifier: AGPL-3.0-or-later
//! `StatefulSecretKey`, the Python type for H5 and H6 secret keys, and the
//! module functions that create and load one.
//!
//! In the generic Rust API a stateful secret key is deliberately not
//! `Clone`: cloning it would let two holders spend the same one-time leaf,
//! which is a total loss of the key's post-quantum security. Python has no
//! equivalent of "this type cannot be cloned" -- `copy.copy`,
//! `copy.deepcopy` and `pickle` all work on any object by default -- so
//! this type overrides `__copy__`, `__deepcopy__` and `__reduce__` to raise
//! [`StatefulKeyNotCloneableError`] instead of silently forking the leaf
//! counter. [`StatefulSecretKey::export`] is the one sanctioned way to get
//! the key's bytes out, for a caller that wants to persist them; loading
//! them back is an explicit call to [`load_stateful_secret_key`], never an
//! implicit copy.

use std::cell::RefCell;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

use crate::bytes_in::extract_bytes;
use crate::errors::{to_py_err, StatefulKeyNotCloneableError};
use crate::suite::PySuite;

/// A [`pqhybridsign_abi::LeafJournal`] backed by a Python object exposing
/// `commit(leaf: int) -> None` and `next_leaf() -> int`.
///
/// [`pqhybridsign_abi::LeafJournal::next_leaf`] cannot return a `Result`,
/// so a Python exception raised from `next_leaf` cannot be propagated
/// through that call directly. Instead it is captured in `error` and a
/// leaf value guaranteed to fail range validation is returned, so the ABI
/// call itself still fails rather than proceeding on bad data; the caller
/// checks `take_error` after the ABI call returns and re-raises the
/// original Python exception in preference to whatever the ABI reported.
struct PyJournal<'py> {
    journal: Bound<'py, PyAny>,
    error: RefCell<Option<PyErr>>,
}

impl<'py> PyJournal<'py> {
    fn new(journal: Bound<'py, PyAny>) -> Self {
        Self {
            journal,
            error: RefCell::new(None),
        }
    }

    fn take_error(&self) -> Option<PyErr> {
        self.error.borrow_mut().take()
    }

    fn record(&self, err: PyErr) {
        *self.error.borrow_mut() = Some(err);
    }
}

impl pqhybridsign_abi::LeafJournal for PyJournal<'_> {
    /// The Python exception is recorded on `self` and re-raised by the
    /// caller; this marker only tells the ABI layer that the commit did
    /// not happen, which maps to `AbiError::JournalFailed`.
    type Error = JournalCallFailed;

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        match self.journal.call_method1("commit", (leaf,)) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.record(err);
                Err(JournalCallFailed)
            }
        }
    }

    fn next_leaf(&self) -> u32 {
        match self.journal.call_method0("next_leaf") {
            Ok(value) => value.extract::<u32>().unwrap_or_else(|err| {
                self.record(err);
                u32::MAX
            }),
            Err(err) => {
                self.record(err);
                u32::MAX
            }
        }
    }
}

#[derive(Debug)]
struct JournalCallFailed;

/// A loaded H5 or H6 secret key.
///
/// Signing through [`Self::sign_stateful`] advances this object in place
/// and requires a caller-supplied journal object so the one-time leaf it
/// spends is durably recorded before the signature is returned; see
/// `pqhybridsign_abi::LeafJournal` for the durability contract the
/// journal's `commit` method must honour. [`Self::sign_stateless`] spends
/// no leaf and needs no journal.
#[pyclass(module = "pqhybridsign", name = "StatefulSecretKey")]
pub(crate) struct StatefulSecretKey {
    suite: PySuite,
    bytes: Vec<u8>,
}

impl Drop for StatefulSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[pymethods]
impl StatefulSecretKey {
    /// The suite this key was created for.
    #[getter]
    fn suite(&self) -> PySuite {
        self.suite
    }

    /// Sign `msg` under `ctx`, spending one leaf.
    ///
    /// `journal` must implement `commit(leaf: int) -> None` and
    /// `next_leaf() -> int`, and `commit` must not return until the write
    /// is durable: returning early there is the one way this method could
    /// let a leaf be reissued after a crash. This key's internal bytes are
    /// updated in place to the advanced key on every outcome that reaches
    /// the component signer, including a failed one -- see
    /// `pqhybridsign_abi::sign_stateful` for why.
    ///
    /// Returns the signature as `bytes`.
    ///
    /// # Errors
    ///
    /// `LeavesExhaustedError` if the key's leaf budget is spent.
    /// `JournalFailedError` if `journal.commit` raised or otherwise failed
    /// to run; nothing was spent. Any exception `journal.commit` or
    /// `journal.next_leaf` itself raised is re-raised unchanged.
    fn sign_stateful(
        &mut self,
        py: Python<'_>,
        msg: &Bound<'_, PyAny>,
        ctx: &Bound<'_, PyAny>,
        journal: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyBytes>> {
        let msg = extract_bytes(py, msg)?;
        let ctx = extract_bytes(py, ctx)?;
        let suite: pqhybridsign_abi::Suite = self.suite.into();

        let mut sk_out = self.bytes.clone();
        let mut sig_out = vec![0u8; pqhybridsign_abi::signature_len(suite)];
        let mut journal = PyJournal::new(journal.clone());

        let outcome = pqhybridsign_abi::sign_stateful(
            suite,
            &self.bytes,
            &mut journal,
            &msg,
            &ctx,
            &mut sk_out,
            &mut sig_out,
        );

        // `sk_out` reflects the advanced key on every outcome that reached
        // the component signer, and is an unchanged copy of `self.bytes`
        // otherwise: adopting it unconditionally is always correct, never
        // a silent leaf-drift risk.
        self.bytes.zeroize();
        self.bytes = sk_out;

        if let Some(err) = journal.take_error() {
            return Err(err);
        }
        let n = outcome.map_err(to_py_err)?;
        Ok(PyBytes::new(py, &sig_out[..n]).unbind())
    }

    /// Sign `msg` under `ctx` without spending any leaf.
    ///
    /// Available because H5 and H6 pair their stateful fast path with a
    /// stateless few-time path (SHRINCS specification section 21); no
    /// journal is needed and this key is not modified.
    ///
    /// Returns the signature as `bytes`.
    fn sign_stateless(
        &self,
        py: Python<'_>,
        msg: &Bound<'_, PyAny>,
        ctx: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyBytes>> {
        let msg = extract_bytes(py, msg)?;
        let ctx = extract_bytes(py, ctx)?;
        let suite: pqhybridsign_abi::Suite = self.suite.into();

        let mut sig_out = vec![0u8; pqhybridsign_abi::signature_len(suite)];
        let n = pqhybridsign_abi::sign_stateless(suite, &self.bytes, &msg, &ctx, &mut sig_out)
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &sig_out[..n]).unbind())
    }

    /// The key's current exported bytes, for persisting to storage.
    ///
    /// This is the sanctioned way to get this key's bytes out of the
    /// process; load them back with `load_stateful_secret_key`. It is a
    /// deliberately explicit pair of calls, unlike copying or pickling,
    /// because a caller who round-trips through `export` and
    /// `load_stateful_secret_key` has to notice they now hold two
    /// independent objects over the same leaf budget, the exact hazard
    /// `__copy__` and `__reduce__` refuse to hand out silently.
    fn export<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.bytes)
    }

    fn __copy__(&self) -> PyResult<Py<Self>> {
        Err(StatefulKeyNotCloneableError::new_err(
            "a stateful secret key cannot be copied: use export() and \
             load_stateful_secret_key() if you deliberately need a second \
             copy of the key bytes, and track their leaf budgets as one",
        ))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<Py<Self>> {
        Err(StatefulKeyNotCloneableError::new_err(
            "a stateful secret key cannot be deep-copied: use export() and \
             load_stateful_secret_key() if you deliberately need a second \
             copy of the key bytes, and track their leaf budgets as one",
        ))
    }

    fn __reduce__(&self) -> PyResult<Py<Self>> {
        Err(StatefulKeyNotCloneableError::new_err(
            "a stateful secret key cannot be pickled: use export() and \
             load_stateful_secret_key() to persist the key bytes explicitly",
        ))
    }

    fn __repr__(&self) -> String {
        format!("<StatefulSecretKey suite={}>", self.suite.as_repr_str())
    }
}

impl PySuite {
    fn as_repr_str(self) -> &'static str {
        pqhybridsign_abi::Suite::from(self).as_str()
    }
}

/// Derive a stateful keypair for `suite` from a 32-byte master seed, with a
/// budget of `max_stateful_signatures` one-time leaves.
///
/// Returns `(StatefulSecretKey, public_key: bytes)`.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4: use
/// `keygen_from_seed` instead. `BadLengthError` if `seed` is not 32 bytes.
/// `ComponentFailureError` if `max_stateful_signatures` is zero or exceeds
/// the component's leaf capacity limit.
#[pyfunction]
fn keygen_stateful_from_seed(
    py: Python<'_>,
    suite: PySuite,
    seed: &Bound<'_, PyAny>,
    max_stateful_signatures: u32,
) -> PyResult<(StatefulSecretKey, Py<PyBytes>)> {
    let abi_suite: pqhybridsign_abi::Suite = suite.into();
    let seed = extract_bytes(py, seed)?;

    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(abi_suite)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(abi_suite)];
    pqhybridsign_abi::keygen_stateful_from_seed(
        abi_suite,
        &seed,
        max_stateful_signatures,
        &mut sk,
        &mut pk,
    )
    .map_err(to_py_err)?;

    Ok((
        StatefulSecretKey { suite, bytes: sk },
        PyBytes::new(py, &pk).unbind(),
    ))
}

/// Load a previously exported stateful secret key.
///
/// `blob` must be exactly `secret_key_len(suite)` bytes, in the form
/// `StatefulSecretKey.export` produces: it carries the leaf counter and
/// cached verify key, not just the raw component secret key, so loading
/// arbitrary component key bytes here fails rather than silently
/// resetting the leaf counter to zero.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4. `BadLengthError` if
/// `blob` is not exactly `secret_key_len(suite)` bytes for `suite`.
#[pyfunction]
fn load_stateful_secret_key(
    py: Python<'_>,
    suite: PySuite,
    blob: &Bound<'_, PyAny>,
) -> PyResult<StatefulSecretKey> {
    let abi_suite: pqhybridsign_abi::Suite = suite.into();
    if !abi_suite.is_stateful() {
        return Err(to_py_err(
            pqhybridsign_abi::AbiError::WrongEntryPointForSuite,
        ));
    }
    let blob = extract_bytes(py, blob)?;
    if blob.len() != pqhybridsign_abi::secret_key_len(abi_suite) {
        return Err(to_py_err(pqhybridsign_abi::AbiError::BadLength));
    }
    Ok(StatefulSecretKey { suite, bytes: blob })
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<StatefulSecretKey>()?;
    m.add_function(wrap_pyfunction!(keygen_stateful_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(load_stateful_secret_key, m)?)?;
    Ok(())
}
