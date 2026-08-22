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
//!
//! `export()` followed by `load_stateful_secret_key()` is nonetheless a
//! second, sanctioned way to end up with two `StatefulSecretKey` objects
//! over the same leaf budget -- the whole point of `export` is to let a
//! caller persist the key and load it back after a restart. What must not
//! happen is two *independent* journals both believing they own that
//! budget: [`keygen_stateful_from_seed`] and [`load_stateful_secret_key`]
//! therefore bind a `journal` to the key at construction time, and
//! [`StatefulSecretKey::sign_stateful`] always signs through that bound
//! journal rather than accepting a fresh one on every call. That closes the
//! hole where a caller passes a *different* journal to two signing calls on
//! what is meant to be one key.
//!
//! Binding a journal object is not enough on its own, because a caller can
//! load the same exported blob twice, each time with its own brand-new
//! journal that (correctly, for a journal that has never seen this key)
//! reports leaf 0. Two such journals agree with the blob and with each
//! other, so no comparison of counters can tell them apart from a legitimate
//! restart.
//!
//! What separates them is **identity**. A journal records which key it is
//! the leaf record for, as durably as it records the counter, and
//! [`load_stateful_secret_key`] refuses a journal that does not already
//! carry this key's identity. Creating that record is one explicit call,
//! [`adopt_key`], made once when the key's durable journal is provisioned --
//! [`keygen_stateful_from_seed`] makes it for a key it has just created,
//! because a brand-new key has no history to fork. A restart that reopens
//! the key's own journal finds the identity already there and proceeds; a
//! restart handed a fresh journal raises
//! [`JournalKeyMismatchError`](crate::errors::JournalKeyMismatchError)
//! instead of silently starting the leaf budget over.
//!
//! The lockstep counter check is unchanged and still runs after the identity
//! check. It is what catches the cases where the right journal is present but
//! out of step: a stale blob loaded against an already-advanced journal, an
//! advanced blob loaded against a journal that missed a commit, or a second
//! key object that shares its sibling's journal instance and tries to sign
//! after the sibling already has. Those surface as
//! [`CountersDivergedError`](crate::errors::CountersDivergedError), from the
//! same check `sign_stateful` has always used internally (see
//! `pqhybridsign::stateful_composite`'s `sign_stateful`).

use std::cell::RefCell;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

use pqhybridsign_abi::{BudgetKey, KeyIdentity, LeafJournal, KEY_IDENTITY_LEN};

use crate::bytes_in::extract_bytes;
use crate::errors::{to_py_err, StatefulKeyNotCloneableError};
use crate::suite::PySuite;

/// A [`pqhybridsign_abi::LeafJournal`] backed by a Python object exposing
/// `commit(leaf: int) -> None`, `next_leaf() -> int`,
/// `bound_key() -> bytes | None` and `bind_key(identity: bytes) -> None`.
///
/// [`pqhybridsign_abi::LeafJournal::next_leaf`] cannot return a `Result`,
/// so a Python exception raised from `next_leaf` cannot be propagated
/// through that call directly. Instead it is captured in `error` and a
/// leaf value guaranteed to fail range validation is returned, so the ABI
/// call itself still fails rather than proceeding on bad data; the caller
/// checks `take_error` after the ABI call returns and re-raises the
/// original Python exception in preference to whatever the ABI reported.
///
/// `bound_key` is memoized in `bound_key_cache`: the first call reaches
/// `journal.bound_key()`, and every later call on the same `PyJournal`
/// returns the cached answer without calling back into Python. A caller
/// that needs a read fault to be visible before the ABI's own read -- see
/// `adopt_key` below -- gets that only if a transient fault has exactly one
/// place to land; two independent calls into the same Python method would
/// give it two, and a fault that lands on the second would go unnoticed by
/// a guard checked after the first.
///
/// `bind_key` clears `bound_key_cache` on success, so a `bound_key` read
/// after a `bind_key` write on the same instance sees the new binding rather
/// than a `None` cached from before it. No current caller reads
/// `bound_key` again after `bind_key` on one `PyJournal` -- `adopt_key`
/// reads it once, before its own single call to `bind_key`, and
/// `sign_stateful` never calls `bind_key` at all -- but the type does not
/// enforce that ordering, and a future entry point that adopts and then
/// re-reads must not see a stale `None`: that is exactly the never-bound
/// condition `JournalKeyMismatch` exists to catch. Any method added to this
/// `impl` that writes through to Python must maintain this invariant.
struct PyJournal<'py> {
    journal: Bound<'py, PyAny>,
    error: RefCell<Option<PyErr>>,
    bound_key_cache: RefCell<Option<Option<KeyIdentity>>>,
}

impl<'py> PyJournal<'py> {
    fn new(journal: Bound<'py, PyAny>) -> Self {
        Self {
            journal,
            error: RefCell::new(None),
            bound_key_cache: RefCell::new(None),
        }
    }

    fn take_error(&self) -> Option<PyErr> {
        self.error.borrow_mut().take()
    }

    fn record(&self, err: PyErr) {
        *self.error.borrow_mut() = Some(err);
    }
}

impl LeafJournal for PyJournal<'_> {
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

    /// `bound_key()` returns the recorded identity as `bytes`, or `None` if
    /// this journal has never been bound to a key.
    ///
    /// Like `next_leaf`, this cannot return a `Result`, so a Python
    /// exception -- or a return value of the wrong type or length -- is
    /// recorded on `self` and reported here as `None`. `None` is the
    /// fail-closed answer for signing, which refuses it. The caller re-raises
    /// the recorded exception in preference to whatever the ABI reported.
    ///
    /// Memoized (see `bound_key_cache` on the struct): `journal.bound_key`
    /// is called at most once per `PyJournal` between calls to `bind_key`,
    /// however many times this method is called. `bind_key` clears the
    /// cache on success, so a call after a successful bind reaches
    /// `journal.bound_key` again rather than returning a stale answer.
    fn bound_key(&self) -> Option<KeyIdentity> {
        if let Some(cached) = *self.bound_key_cache.borrow() {
            return cached;
        }
        let result = match self.journal.call_method0("bound_key") {
            Ok(value) if value.is_none() => None,
            Ok(value) => match value.extract::<[u8; KEY_IDENTITY_LEN]>() {
                Ok(bytes) => Some(KeyIdentity::from_bytes(bytes)),
                Err(err) => {
                    self.record(err);
                    None
                }
            },
            Err(err) => {
                self.record(err);
                None
            }
        };
        *self.bound_key_cache.borrow_mut() = Some(result);
        result
    }

    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        let bytes = PyBytes::new(self.journal.py(), key.as_bytes());
        match self.journal.call_method1("bind_key", (bytes,)) {
            Ok(_) => {
                // Invalidate `bound_key_cache`: a stale `None` cached from a
                // read before this write would read back as never-bound,
                // which is the exact condition `JournalKeyMismatch` exists
                // to catch. The next `bound_key()` call re-reads
                // `journal.bound_key`.
                *self.bound_key_cache.borrow_mut() = None;
                Ok(())
            }
            Err(err) => {
                self.record(err);
                Err(JournalCallFailed)
            }
        }
    }
}

#[derive(Debug)]
struct JournalCallFailed;

/// A [`pqhybridsign_abi::StatelessBudgetStore`] backed by a Python object
/// exposing `consumed(key: bytes) -> int | None` and
/// `record(key: bytes, count: int) -> None`.
///
/// The stateless counterpart of [`PyJournal`], and it captures Python
/// exceptions the same way and for the same reason:
/// [`pqhybridsign_abi::StatelessBudgetStore::consumed`] cannot return a
/// `Result`, so an exception raised there is recorded in `error` and
/// reported as `None`. `None` means "never tracked", which reads as a full
/// budget, so the caller MUST check `take_error` after the ABI call and
/// re-raise in preference to whatever the ABI reported -- otherwise a broken
/// store would look like a fresh key.
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

/// A loaded H5 or H6 secret key.
///
/// Bound to a journal object at construction, by [`keygen_stateful_from_seed`]
/// or [`load_stateful_secret_key`]. Signing through [`Self::sign_stateful`]
/// advances this object in place and always spends the leaf through that
/// bound journal, never one supplied at call time, so the one-time leaf it
/// spends is durably recorded before the signature is returned; see
/// `pqhybridsign_abi::LeafJournal` for the durability contract the
/// journal's `commit` method must honour. [`Self::sign_stateless`] spends
/// no leaf and needs no journal.
#[pyclass(module = "pqhybridsign", name = "StatefulSecretKey")]
pub(crate) struct StatefulSecretKey {
    suite: PySuite,
    bytes: Vec<u8>,
    journal: Py<PyAny>,
    budget: Py<PyAny>,
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

    /// Sign `msg` under `ctx`, spending one leaf from this key's bound
    /// journal (the one passed to [`keygen_stateful_from_seed`] or
    /// [`load_stateful_secret_key`] when this key was created).
    ///
    /// The journal must implement `commit(leaf: int) -> None` and
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
    /// to run; nothing was spent. `JournalKeyMismatchError` if the bound
    /// journal no longer carries this key's identity; nothing was spent.
    /// `CountersDivergedError` if this key's own
    /// leaf counter and the bound journal's `next_leaf()` disagree -- see
    /// the module documentation for the two ways that happens and the one
    /// way it does not, and why. Any exception `journal.commit` or
    /// `journal.next_leaf` itself raised is re-raised unchanged.
    fn sign_stateful(
        &mut self,
        py: Python<'_>,
        msg: &Bound<'_, PyAny>,
        ctx: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyBytes>> {
        let msg = extract_bytes(py, msg)?;
        let ctx = extract_bytes(py, ctx)?;
        let suite: pqhybridsign_abi::Suite = self.suite.into();

        let mut sk_out = self.bytes.clone();
        let mut sig_out = vec![0u8; pqhybridsign_abi::signature_len(suite)];
        let mut journal = PyJournal::new(self.journal.bind(py).clone());

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

    /// Sign `msg` under `ctx` without spending any leaf, spending one unit
    /// of this key's few-time stateless budget instead.
    ///
    /// Available because H5 and H6 pair their stateful fast path with a
    /// stateless few-time path (SHRINCS specification section 21). No leaf
    /// is spent and this key is not modified, but the stateless path has a
    /// hard bound of its own -- `2**20` signatures, `2**18` under the
    /// low-budget profile -- shared with rotation and recovery, and
    /// exceeding it degrades the security assumption of the underlying
    /// few-time scheme.
    ///
    /// The spend goes through the `budget` object bound to this key at
    /// construction, never one supplied at call time, for the same reason
    /// signing goes through the bound journal: a caller who could pass a
    /// fresh store on each call would hold a bound that never advances. The
    /// store must implement `consumed(key: bytes) -> int | None` and
    /// `record(key: bytes, count: int) -> None`, and `record` must not
    /// return until the write is durable.
    ///
    /// Returns the signature as `bytes`.
    ///
    /// # Errors
    ///
    /// `StatelessBudgetExhaustedError` if this key's stateless budget is
    /// spent; nothing was recorded and no signature was built.
    /// `BudgetStoreFailedError` if `budget.record` raised or otherwise
    /// failed to run; nothing was recorded. Any exception `budget.consumed`
    /// or `budget.record` itself raised is re-raised unchanged.
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
        let mut budget = PyBudget::new(self.budget.bind(py).clone());
        let outcome = pqhybridsign_abi::sign_stateless(
            suite,
            &self.bytes,
            &mut budget,
            &msg,
            &ctx,
            &mut sig_out,
        );

        // The recorded Python exception wins over the ABI's flat code: a
        // store that raised from `consumed` reports `None` to the ABI, which
        // reads as an untracked material and a full budget, so the ABI code
        // alone would describe a successful signature rather than a broken
        // store.
        if let Some(err) = budget.take_error() {
            return Err(err);
        }
        let n = outcome.map_err(to_py_err)?;
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

/// The identity a leaf journal records for the key `public_key` names.
///
/// `public_key` is the `bytes` `keygen_stateful_from_seed` returned. It is
/// public material, so this identity can be computed by anyone holding the
/// public key and discloses nothing about the secret one.
///
/// Pass it to `adopt_key` once, when the key's durable journal is created.
/// `key_identity_from_secret_key` returns the same value for the matching
/// exported blob.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4, which have no journal
/// and so no identity. `BadLengthError` if `public_key` is the wrong length
/// for `suite`.
#[pyfunction]
fn key_identity<'py>(
    py: Python<'py>,
    suite: PySuite,
    public_key: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let public_key = extract_bytes(py, public_key)?;
    let identity = pqhybridsign_abi::key_identity(suite.into(), &public_key).map_err(to_py_err)?;
    Ok(PyBytes::new(py, identity.as_bytes()))
}

/// The identity a leaf journal records for the key an exported blob holds.
///
/// The same value `key_identity` returns for the matching public key: it
/// comes from the blob's cached post-quantum verify key, which is public.
/// This exists because the restart path has the blob in hand and may not have
/// kept the public key.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4. `BadLengthError` if
/// `blob` is not `secret_key_len(suite)` bytes. `ComponentFailureError` if
/// the blob does not import.
#[pyfunction]
fn key_identity_from_secret_key<'py>(
    py: Python<'py>,
    suite: PySuite,
    blob: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let blob = extract_bytes(py, blob)?;
    let identity =
        pqhybridsign_abi::key_identity_from_secret_key(suite.into(), &blob).map_err(to_py_err)?;
    Ok(PyBytes::new(py, identity.as_bytes()))
}

/// Bind `journal` to the key `identity` names, unless it already belongs to
/// a different key.
///
/// This is the explicit act performed once, when a key's durable journal is
/// created. `load_stateful_secret_key` never does it: pairing a key with a
/// journal that has never seen it is how one key's one-time leaves get spent
/// twice, and it raises `JournalKeyMismatchError` instead.
///
/// Calling this on a journal already bound to `identity` is a no-op, so a
/// provisioning step is safe to re-run. Calling it on a fresh journal at
/// every process start is not: that mints a new binding each time and starts
/// the leaf budget over, which is the defect the binding closes.
///
/// # Errors
///
/// `BadLengthError` if `identity` is not the length `key_identity` returns.
/// `JournalKeyMismatchError` if `journal` already belongs to another key;
/// nothing is written. `JournalFailedError` if `journal.bind_key` reported
/// the write did not become durable. Any exception `journal.bound_key` or
/// `journal.bind_key` itself raised is re-raised unchanged.
///
/// A `journal.bound_key` that raises prevents `bind_key` from being called
/// at all, so a read fault can never replace an existing binding.
#[pyfunction]
fn adopt_key(
    py: Python<'_>,
    journal: &Bound<'_, PyAny>,
    identity: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let identity = extract_bytes(py, identity)?;
    let bytes = <[u8; KEY_IDENTITY_LEN]>::try_from(&identity[..])
        .map_err(|_| to_py_err(pqhybridsign_abi::AbiError::BadLength))?;
    let mut journal = PyJournal::new(journal.clone());
    // Read the binding once, and surface a read fault, before anything can
    // write. The bridge reports a raising `bound_key` to the abi as `None`,
    // which the abi reads as never-bound: it would call `bind_key` and only
    // then let the deferred exception surface. Against an already-bound
    // journal whose `bind_key` is not write-once, that silently replaces the
    // binding, which is what the JournalKeyMismatch guard exists to prevent.
    let _ = journal.bound_key();
    if let Some(err) = journal.take_error() {
        return Err(err);
    }
    let outcome = pqhybridsign_abi::adopt_key(&mut journal, KeyIdentity::from_bytes(bytes));
    if let Some(err) = journal.take_error() {
        return Err(err);
    }
    outcome.map_err(to_py_err)
}

/// Refuse `journal` unless it already carries the identity of the key in
/// `blob`.
///
/// Shared by `keygen_stateful_from_seed` -- which adopts first, so the check
/// always passes -- and `load_stateful_secret_key`, which does not.
fn require_journal_owns(suite: PySuite, blob: &[u8], journal: &Bound<'_, PyAny>) -> PyResult<()> {
    let identity =
        pqhybridsign_abi::key_identity_from_secret_key(suite.into(), blob).map_err(to_py_err)?;
    let py_journal = PyJournal::new(journal.clone());
    let outcome = pqhybridsign_abi::require_bound_key(&py_journal, identity);
    if let Some(err) = py_journal.take_error() {
        return Err(err);
    }
    outcome.map_err(to_py_err)
}

/// Derive a stateful keypair for `suite` from a 32-byte master seed, with a
/// budget of `max_stateful_signatures` one-time leaves.
///
/// `journal` is bound to the returned key for its whole lifetime: every
/// later `sign_stateful` call on it spends leaves through this same
/// journal object.
///
/// `budget` is bound the same way, and every later `sign_stateless` call
/// spends the few-time stateless budget through it. It is required, on the
/// same grounds `journal` is: the stateless bound of specification section
/// 21 is a security assumption, not a quota, and a key with no store to
/// charge would have no bound at all. Unlike `journal`, `budget` needs no
/// adoption step -- its entries are keyed by the key's own stateless
/// material -- so one store object may serve every key a process holds.
///
/// This function also **adopts** `journal` for the new key, writing the key's
/// identity into it, which is what `load_stateful_secret_key` later checks
/// for. Adopting here is safe where adopting on a restart is not: the key is
/// brand new, so there is no spending history for a second journal to fork.
/// A `journal` already bound to some other key is refused.
///
/// Returns `(StatefulSecretKey, public_key: bytes)`.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4: use
/// `keygen_from_seed` instead. `BadLengthError` if `seed` is not 32 bytes.
/// `ComponentFailureError` if `max_stateful_signatures` is zero or exceeds
/// the component's leaf capacity limit. `JournalKeyMismatchError` if
/// `journal` already belongs to a different key. `JournalFailedError` if
/// `journal.bind_key` could not durably record the binding.
#[pyfunction]
fn keygen_stateful_from_seed(
    py: Python<'_>,
    suite: PySuite,
    seed: &Bound<'_, PyAny>,
    max_stateful_signatures: u32,
    journal: &Bound<'_, PyAny>,
    budget: &Bound<'_, PyAny>,
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

    let identity = PyBytes::new(
        py,
        pqhybridsign_abi::key_identity(abi_suite, &pk)
            .map_err(to_py_err)?
            .as_bytes(),
    );
    adopt_key(py, journal, identity.as_any())?;

    Ok((
        StatefulSecretKey {
            suite,
            bytes: sk,
            journal: journal.clone().unbind(),
            budget: budget.clone().unbind(),
        },
        PyBytes::new(py, &pk).unbind(),
    ))
}

/// Load a previously exported stateful secret key and bind it to `journal`.
///
/// `blob` must be exactly `secret_key_len(suite)` bytes, in the form
/// `StatefulSecretKey.export` produces: it carries the leaf counter and
/// cached verify key, not just the raw component secret key, so loading
/// arbitrary component key bytes here fails rather than silently
/// resetting the leaf counter to zero.
///
/// `journal` must already carry this key's identity, which is checked here
/// rather than deferred to the first signature. A journal that has never
/// been bound to any key, and one bound to a different key, are both refused
/// with `JournalKeyMismatchError`. That refusal is the whole point: a
/// brand-new journal reports that leaf 0 is next, so does the key's own
/// journal for a key that has spent nothing, and proceeding on that
/// agreement is how one key's one-time leaves get spent twice under two
/// different messages. Adopting a journal for an existing key is still
/// possible, through an explicit `adopt_key` call the caller has to write.
///
/// `journal` is then bound to the returned key for its whole lifetime: every
/// later `sign_stateful` call on it spends leaves through this same journal
/// object, never one supplied at call time.
///
/// `budget` is bound the same way and serves `sign_stateless`. It carries no
/// identity check, because its entries are keyed by the key's own stateless
/// material rather than by an identity written alongside a bare counter: a
/// store that has never seen this material reports nothing for this material
/// alone, and cannot be confused with a store holding a different key's
/// count. What a wrong store loses is history, not attribution, so the
/// obligation it carries is durability -- reopen the same store after a
/// restart, or the bound restarts at zero.
///
/// The identity check does not validate the *counter*. A journal that is
/// this key's but out of step with `blob` still surfaces as
/// `CountersDivergedError` from the first `sign_stateful` call, because this
/// crate cannot read the key's counter without attempting a signature.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4. `BadLengthError` if
/// `blob` is not exactly `secret_key_len(suite)` bytes for `suite`.
/// `JournalKeyMismatchError` if `journal` does not already belong to this
/// key. Any exception `journal.bound_key` itself raised is re-raised
/// unchanged.
#[pyfunction]
fn load_stateful_secret_key(
    py: Python<'_>,
    suite: PySuite,
    blob: &Bound<'_, PyAny>,
    journal: &Bound<'_, PyAny>,
    budget: &Bound<'_, PyAny>,
) -> PyResult<StatefulSecretKey> {
    let abi_suite: pqhybridsign_abi::Suite = suite.into();
    if !abi_suite.is_stateful() {
        return Err(to_py_err(
            pqhybridsign_abi::AbiError::WrongEntryPointForSuite,
        ));
    }
    let mut blob = extract_bytes(py, blob)?;
    if blob.len() != pqhybridsign_abi::secret_key_len(abi_suite) {
        return Err(to_py_err(pqhybridsign_abi::AbiError::BadLength));
    }
    require_journal_owns(suite, &blob, journal)?;
    // Take the bytes out of the `Zeroizing` wrapper so this type's
    // `Drop` owns the only remaining copy. The wrapper then drops an
    // empty `Vec`.
    Ok(StatefulSecretKey {
        suite,
        bytes: std::mem::take(&mut *blob),
        journal: journal.clone().unbind(),
        budget: budget.clone().unbind(),
    })
}

/// The stored public key length for `suite`, in bytes: the form a verifier
/// keeps, which is what `verify_with_stored_public_key_stateful` and
/// `verify_with_stored_public_key_stateless` take as `stored_public_key`.
///
/// For H5 and H6 this is the classical public key and a 32-byte commitment
/// to the post-quantum verify key, smaller than the verify-form length
/// `keygen_stateful_from_seed`'s public key uses, because the verify key
/// itself is supplied per signature rather than stored. For H1 through H4
/// the stored and verify forms are the same bytes, so this equals the
/// public key length for `suite`; there is no error case for any suite.
#[pyfunction]
fn stored_public_key_len(suite: PySuite) -> usize {
    pqhybridsign_abi::stored_public_key_len(suite.into())
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by `sign_stateful`, against one whole
/// verify-form public key `pk`.
///
/// `verify` is the total dispatcher across all six suites and, for H5 and
/// H6, behaves exactly as this function does; call this one directly only
/// where the suite is already known to be H5 or H6. A signature whose wire
/// `PathSelector` names the stateless path is refused before either
/// component signature is checked. Call `verify_stateless` for a message
/// deliberately signed on that path.
///
/// Returns `False`, never raises, for a malformed `pk` or `sig`, on the
/// same terms as `verify`.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4; use `verify` instead.
#[pyfunction]
fn verify_stateful(
    py: Python<'_>,
    suite: PySuite,
    pk: &Bound<'_, PyAny>,
    msg: &Bound<'_, PyAny>,
    ctx: &Bound<'_, PyAny>,
    sig: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let pk = extract_bytes(py, pk)?;
    let msg = extract_bytes(py, msg)?;
    let ctx = extract_bytes(py, ctx)?;
    let sig = extract_bytes(py, sig)?;
    pqhybridsign_abi::verify_stateful(suite.into(), &pk, &msg, &ctx, &sig).map_err(to_py_err)
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by `sign_stateless`, against one whole
/// verify-form public key `pk`.
///
/// The mirror image of `verify_stateful`. Use this for rotation and
/// recovery authorizations, and for any other message an application has
/// deliberately chosen to sign on the few-time stateless path.
///
/// # Errors
///
/// The same as `verify_stateful`.
#[pyfunction]
fn verify_stateless(
    py: Python<'_>,
    suite: PySuite,
    pk: &Bound<'_, PyAny>,
    msg: &Bound<'_, PyAny>,
    ctx: &Bound<'_, PyAny>,
    sig: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let pk = extract_bytes(py, pk)?;
    let msg = extract_bytes(py, msg)?;
    let ctx = extract_bytes(py, ctx)?;
    let sig = extract_bytes(py, sig)?;
    pqhybridsign_abi::verify_stateless(suite.into(), &pk, &msg, &ctx, &sig).map_err(to_py_err)
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by `sign_stateful`, against a signer-supplied
/// verify key that must be the one `stored_public_key` commits to.
///
/// This is the entry point the H5/H6 deployment is built for: the verifier
/// stores the small form (`ClassicalPK || commitment`,
/// `stored_public_key_len(suite)` bytes -- 64 for both suites) and the
/// signer supplies the full 164-byte commitment bundle alongside every
/// signature, because the bundle is too large to keep on an account.
///
/// `stored_public_key` is trusted and `pq_verify_key` is not. The
/// commitment is recomputed from `pq_verify_key` and matched against the
/// stored one before anything is verified, and the classical public key is
/// taken from `stored_public_key`, so nothing the signer supplied can
/// substitute a key of their own.
///
/// `verify_stateful` is the other shape: it takes one whole verify-form
/// public key and checks no commitment, because it has nothing to check one
/// against. Use it only where the verify key itself came from a trusted
/// place.
///
/// A signature whose wire `PathSelector` names the stateless path is
/// refused before either component signature is checked. A caller that
/// genuinely needs to accept a stateless-path signature under a stored
/// commitment calls `verify_with_stored_public_key_stateless` instead.
///
/// Returns `False`, never raises, for a commitment that does not match, a
/// malformed key or a malformed signature -- the same design `verify`
/// uses, so a caller cannot learn which check rejected.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H1 through H4: their public key is a
/// single form with no commitment in it, so there is nothing for this
/// entry point to bind; use `verify`.
#[pyfunction]
fn verify_with_stored_public_key_stateful(
    py: Python<'_>,
    suite: PySuite,
    stored_public_key: &Bound<'_, PyAny>,
    pq_verify_key: &Bound<'_, PyAny>,
    msg: &Bound<'_, PyAny>,
    ctx: &Bound<'_, PyAny>,
    sig: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let stored_public_key = extract_bytes(py, stored_public_key)?;
    let pq_verify_key = extract_bytes(py, pq_verify_key)?;
    let msg = extract_bytes(py, msg)?;
    let ctx = extract_bytes(py, ctx)?;
    let sig = extract_bytes(py, sig)?;
    pqhybridsign_abi::verify_with_stored_public_key_stateful(
        suite.into(),
        &stored_public_key,
        &pq_verify_key,
        &msg,
        &ctx,
        &sig,
    )
    .map_err(to_py_err)
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by `sign_stateless`, against a signer-supplied
/// verify key that must be the one `stored_public_key` commits to.
///
/// The mirror image of `verify_with_stored_public_key_stateful`. Use this
/// for rotation and recovery authorizations, and for any other message an
/// application has deliberately chosen to sign on the few-time stateless
/// path.
///
/// # Errors
///
/// The same as `verify_with_stored_public_key_stateful`.
#[pyfunction]
fn verify_with_stored_public_key_stateless(
    py: Python<'_>,
    suite: PySuite,
    stored_public_key: &Bound<'_, PyAny>,
    pq_verify_key: &Bound<'_, PyAny>,
    msg: &Bound<'_, PyAny>,
    ctx: &Bound<'_, PyAny>,
    sig: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let stored_public_key = extract_bytes(py, stored_public_key)?;
    let pq_verify_key = extract_bytes(py, pq_verify_key)?;
    let msg = extract_bytes(py, msg)?;
    let ctx = extract_bytes(py, ctx)?;
    let sig = extract_bytes(py, sig)?;
    pqhybridsign_abi::verify_with_stored_public_key_stateless(
        suite.into(),
        &stored_public_key,
        &pq_verify_key,
        &msg,
        &ctx,
        &sig,
    )
    .map_err(to_py_err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<StatefulSecretKey>()?;
    m.add_function(wrap_pyfunction!(keygen_stateful_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(load_stateful_secret_key, m)?)?;
    m.add_function(wrap_pyfunction!(key_identity, m)?)?;
    m.add_function(wrap_pyfunction!(key_identity_from_secret_key, m)?)?;
    m.add_function(wrap_pyfunction!(adopt_key, m)?)?;
    m.add_function(wrap_pyfunction!(stored_public_key_len, m)?)?;
    m.add_function(wrap_pyfunction!(verify_stateful, m)?)?;
    m.add_function(wrap_pyfunction!(verify_stateless, m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_stored_public_key_stateful, m)?)?;
    m.add_function(wrap_pyfunction!(
        verify_with_stored_public_key_stateless,
        m
    )?)?;
    Ok(())
}
