// SPDX-License-Identifier: AGPL-3.0-or-later
//! Module-level functions for the four stateless suites, H1 through H4.
//!
//! H5 and H6 are rejected here with `WrongEntryPointForSuiteError`, exactly
//! as `pqhybridsign_abi::stateless_suites` rejects them: see
//! [`crate::stateful`] for their entry points.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_core::OsRng;
use zeroize::Zeroize;

use crate::bytes_in::extract_bytes;
use crate::errors::to_py_err;
use crate::suite::PySuite;

/// Derive a keypair for `suite` from a 32-byte master seed.
///
/// Returns `(secret_key, public_key)` as `bytes`.
///
/// The returned secret key is a Python `bytes` object. A `bytes` object
/// cannot be zeroized, and this binding cannot reach into the interpreter
/// heap to wipe it. The function zeroizes its own Rust copies of the
/// seed and the secret key before they drop. Callers that need a secret
/// key that is wiped on drop should use
/// [`StatefulSecretKey`](crate::stateful::StatefulSecretKey) or the C ABI.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H5 or H6: use
/// `keygen_stateful_from_seed` instead. `BadLengthError` if `seed` is not
/// 32 bytes.
#[pyfunction]
pub(crate) fn keygen_from_seed(
    py: Python<'_>,
    suite: PySuite,
    seed: &Bound<'_, PyAny>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let suite: pqhybridsign_abi::Suite = suite.into();
    let seed = extract_bytes(py, seed)?;

    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(suite)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(suite)];
    let result = pqhybridsign_abi::keygen_from_seed(suite, &seed, &mut sk, &mut pk);
    let pair = result.map(|()| {
        (
            PyBytes::new(py, &sk).unbind(),
            PyBytes::new(py, &pk).unbind(),
        )
    });
    sk.zeroize();
    pair.map_err(to_py_err)
}

/// Hedged (randomized) signing for `suite`. Returns the signature as
/// `bytes`.
///
/// # Errors
///
/// `WrongEntryPointForSuiteError` for H5 or H6: use the
/// [`StatefulSecretKey`](crate::stateful::StatefulSecretKey) methods
/// instead. `BadLengthError` if `sk` is not exactly `secret_key_len(suite)`
/// bytes.
#[pyfunction]
pub(crate) fn sign(
    py: Python<'_>,
    suite: PySuite,
    sk: &Bound<'_, PyAny>,
    msg: &Bound<'_, PyAny>,
    ctx: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let suite: pqhybridsign_abi::Suite = suite.into();
    let sk = extract_bytes(py, sk)?;
    let msg = extract_bytes(py, msg)?;
    let ctx = extract_bytes(py, ctx)?;

    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];
    let n =
        pqhybridsign_abi::sign(suite, &sk, &msg, &ctx, &mut OsRng, &mut sig).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &sig[..n]).unbind())
}

/// Deterministic signing for `suite`. Returns the signature as `bytes`.
///
/// Not every suite's classical or post-quantum component honours `nonce`;
/// see `pqhybridsign_core::composite::sign_deterministic`.
///
/// # Errors
///
/// The same as [`sign`].
#[pyfunction]
pub(crate) fn sign_deterministic(
    py: Python<'_>,
    suite: PySuite,
    sk: &Bound<'_, PyAny>,
    msg: &Bound<'_, PyAny>,
    ctx: &Bound<'_, PyAny>,
    nonce: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let suite: pqhybridsign_abi::Suite = suite.into();
    let sk = extract_bytes(py, sk)?;
    let msg = extract_bytes(py, msg)?;
    let ctx = extract_bytes(py, ctx)?;
    let nonce = extract_bytes(py, nonce)?;

    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];
    let n = pqhybridsign_abi::sign_deterministic(suite, &sk, &msg, &ctx, &nonce, &mut sig)
        .map_err(to_py_err)?;
    Ok(PyBytes::new(py, &sig[..n]).unbind())
}

/// Verify `sig` over `msg` under `ctx` for `suite`, against `pk`.
///
/// Covers all six suites. Returns `False`, never raises, for a malformed
/// `pk` or `sig`: see `pqhybridsign_abi::verify` for why a verify failure
/// is never distinguished by cause.
#[pyfunction]
pub(crate) fn verify(
    py: Python<'_>,
    suite: PySuite,
    pk: &Bound<'_, PyAny>,
    msg: &Bound<'_, PyAny>,
    ctx: &Bound<'_, PyAny>,
    sig: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let suite: pqhybridsign_abi::Suite = suite.into();
    let pk = extract_bytes(py, pk)?;
    let msg = extract_bytes(py, msg)?;
    let ctx = extract_bytes(py, ctx)?;
    let sig = extract_bytes(py, sig)?;
    Ok(pqhybridsign_abi::verify(suite, &pk, &msg, &ctx, &sig))
}

/// The SHRINCS profile this build links against, for example
/// `"shrincs-256s"`.
///
/// A key, signature or verify key produced by a build against one profile
/// is not interchangeable with one from a build against another. Compare
/// this string between the two sides of an integration before trusting
/// anything on the wire.
#[pyfunction]
pub(crate) fn profile_name() -> &'static str {
    pqhybridsign_abi::profile_name()
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(keygen_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(sign_deterministic, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(profile_name, m)?)?;
    Ok(())
}
