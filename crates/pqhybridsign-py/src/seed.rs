// SPDX-License-Identifier: AGPL-3.0-or-later
//! Master seed derivation: recovery phrases and hard junctions.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

use pqhybridsign_abi::{AbiError, CHAIN_CODE_LEN, MASTER_SEED_LEN};

use crate::bytes_in::extract_bytes;
use crate::errors::to_py_err;

/// Turn an English BIP39 recovery phrase into a master seed.
///
/// This is Substrate's seed derivation, not standard BIP39: PBKDF2-HMAC-
/// SHA512 runs over the mnemonic's **entropy**, not over the phrase text,
/// salted with `"mnemonic" || password`, for 2048 rounds, and the first 32
/// bytes are the master seed. A caller that reproduces this with a stock
/// BIP39 library gets a different seed and therefore a different key.
///
/// `password` is the empty string when `None`, matching Substrate's
/// `Pair::from_phrase`.
///
/// The returned seed is a Python `bytes` object. A `bytes` object cannot be
/// zeroized, and this binding cannot reach into the interpreter heap to
/// wipe it; it zeroizes only its own Rust copy before it drops. See
/// `keygen_from_seed` for the same caveat on secret key material.
///
/// # Errors
///
/// `InvalidMnemonicError` if `phrase` is not a valid English BIP39
/// mnemonic: a wrong word count, an unknown word, or a bad checksum. The
/// three are not distinguished, because telling an attacker which part of
/// a guessed phrase was wrong narrows the search.
#[pyfunction]
#[pyo3(signature = (phrase, password=None))]
fn master_seed_from_mnemonic(
    py: Python<'_>,
    phrase: &str,
    password: Option<&str>,
) -> PyResult<Py<PyBytes>> {
    let mut seed = [0u8; MASTER_SEED_LEN];
    let result = pqhybridsign_abi::master_seed_from_mnemonic(phrase, password, &mut seed);
    let out = result.map(|()| PyBytes::new(py, &seed).unbind());
    seed.zeroize();
    out.map_err(to_py_err)
}

/// Derive a hard-junction child master seed.
///
/// `[a, b]` in `derive_hard_junction_path` means
/// `derive_hard_junction(derive_hard_junction(parent, a), b)`. Order is
/// part of the derivation.
///
/// # The re-keygen hazard
///
/// Derivation is deterministic, so the same parent and the same chain code
/// reach the same child seed on every host that computes it, and therefore
/// the same stateful tree starting at leaf 1. Deriving one child twice on
/// two hosts is the same failure as importing one key twice: both hosts
/// spend leaf 1, and the post-quantum security of that key is gone.
///
/// A derived child must be derived once, then persisted and restored
/// through the validating import path. A key pool spanning several nodes
/// must give each node its own distinct junction. Never re-derive one
/// junction on a second host.
///
/// The returned seed is a Python `bytes` object and holds secret material;
/// see `master_seed_from_mnemonic` for the same zeroizing caveat.
///
/// # Errors
///
/// `BadLengthError` if `parent_master` or `chain_code` is not 32 bytes.
/// `ComponentFailureError` if the key derivation function fails.
#[pyfunction]
fn derive_hard_junction(
    py: Python<'_>,
    parent_master: &Bound<'_, PyAny>,
    chain_code: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let parent_master = extract_bytes(py, parent_master)?;
    let parent_master = <[u8; MASTER_SEED_LEN]>::try_from(&parent_master[..])
        .map_err(|_| to_py_err(AbiError::BadLength))?;
    let chain_code = extract_bytes(py, chain_code)?;
    let chain_code = <[u8; CHAIN_CODE_LEN]>::try_from(&chain_code[..])
        .map_err(|_| to_py_err(AbiError::BadLength))?;

    let mut out = [0u8; MASTER_SEED_LEN];
    let result = pqhybridsign_abi::derive_hard_junction(&parent_master, &chain_code, &mut out);
    let bytes = result.map(|()| PyBytes::new(py, &out).unbind());
    out.zeroize();
    bytes.map_err(to_py_err)
}

/// Apply a sequence of chain codes in order, each child becoming the next
/// parent.
///
/// Every intermediate seed is wiped once the next is derived from it. Only
/// the final seed reaches the returned `bytes`.
///
/// **An empty `chain_codes` returns `parent_master` unchanged.** That is
/// the identity a path of no junctions should have, and it is a trap for a
/// caller building the path from parsed input: a parse that silently
/// yielded no junctions hands back the parent key rather than failing. A
/// caller that requires at least one junction must check for that itself.
///
/// See `derive_hard_junction` for the re-keygen hazard, which applies to
/// every seed this function returns.
///
/// # Errors
///
/// `BadLengthError` if `parent_master` is not 32 bytes. `ValueError`
/// naming the offending index if any element of `chain_codes` is not 32
/// bytes. `ComponentFailureError` if the key derivation function fails.
#[pyfunction]
fn derive_hard_junction_path(
    py: Python<'_>,
    parent_master: &Bound<'_, PyAny>,
    chain_codes: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let parent_master = extract_bytes(py, parent_master)?;
    let parent_master = <[u8; MASTER_SEED_LEN]>::try_from(&parent_master[..])
        .map_err(|_| to_py_err(AbiError::BadLength))?;

    let mut codes = Vec::new();
    for (i, code) in chain_codes.try_iter()?.enumerate() {
        let code = extract_bytes(py, &code?)?;
        let code = <[u8; CHAIN_CODE_LEN]>::try_from(&code[..]).map_err(|_| {
            PyValueError::new_err(format!(
                "chain code at index {i} must be {CHAIN_CODE_LEN} bytes, got {}",
                code.len()
            ))
        })?;
        codes.push(code);
    }

    let mut out = [0u8; MASTER_SEED_LEN];
    let result = pqhybridsign_abi::derive_hard_junction_path(&parent_master, &codes, &mut out);
    let bytes = result.map(|()| PyBytes::new(py, &out).unbind());
    out.zeroize();
    bytes.map_err(to_py_err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(master_seed_from_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(derive_hard_junction, m)?)?;
    m.add_function(wrap_pyfunction!(derive_hard_junction_path, m)?)?;
    Ok(())
}
