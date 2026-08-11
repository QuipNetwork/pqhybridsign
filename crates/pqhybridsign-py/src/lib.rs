// SPDX-License-Identifier: AGPL-3.0-or-later
//! Python bindings for `pqhybridsign`, over `pqhybridsign-abi`'s
//! type-erased dispatch layer.
//!
//! No function in this crate can panic across the Python/Rust boundary: an
//! `AbiError` becomes a Python exception (see the `errors` module) rather
//! than an `unwrap`, and every buffer this crate hands the ABI layer is
//! sized from
//! `pqhybridsign_abi::secret_key_len`/`public_key_len`/`signature_len`
//! rather than trusted from a caller. The only `unsafe` code reachable from
//! this crate is what pyo3's `#[pymodule]`/`#[pyclass]`/`#[pyfunction]`
//! macros generate to satisfy the CPython C API; nothing in this crate's
//! own source writes `unsafe`.
//!
//! H1 through H4 are ordinary `bytes` in, `bytes` out: see the `stateless`
//! module. H5 and H6 spend a one-time post-quantum leaf per signature, so
//! their secret key is `stateful::StatefulSecretKey`, a type that refuses
//! to be copied, deep-copied or pickled -- see that module's documentation
//! for why a `bytes` secret key is not safe for those two suites.

mod bytes_in;
mod errors;
mod stateful;
mod stateless;
mod suite;

use pyo3::prelude::*;

/// The `_pqhybridsign` native extension module. The `pqhybridsign` Python
/// package (see `python/pqhybridsign/__init__.py`) re-exports this
/// module's contents under a stable, documented name.
#[pymodule]
fn _pqhybridsign(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<suite::PySuite>()?;
    errors::register(py, m)?;
    stateless::register(m)?;
    stateful::register(m)?;
    Ok(())
}
