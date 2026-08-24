// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accept `bytes` or `bytearray` as byte-string input, copying either into
//! an owned [`zeroize::Zeroizing<Vec<u8>>`] the ABI layer can take a slice
//! of. The copy is wiped when it drops, matching
//! [`crate::stateful::StatefulSecretKey`].
//!
//! CPython's limited API -- which `abi3-py39` (see this crate's
//! `Cargo.toml`) builds against, so one wheel serves every interpreter
//! from 3.9 up -- did not expose the generic buffer-protocol C functions
//! (`PyObject_GetBuffer` and friends) until 3.11. Below 3.11 there is no
//! way to read an arbitrary buffer-protocol object (a `memoryview`, a
//! NumPy array, ...) through the limited API at all, so this crate
//! supports the two concrete types every caller actually reaches for --
//! `bytes` and `bytearray` -- by downcasting to each directly rather than
//! going through the buffer protocol. A caller holding a `memoryview` can
//! convert with `bytes(view)` before calling in.
//!
//! An owned copy, not a borrow, is used deliberately: a signing or keygen
//! call spans several ABI function calls, and a borrowed `bytearray`
//! could be mutated by Python code running in between if the object were
//! re-entered through a Python-level callback (the stateful journal is
//! exactly such a callback).

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use zeroize::Zeroizing;

/// Copy `obj`'s bytes into a new [`Zeroizing<Vec<u8>>`].
///
/// The copy is zeroized when the returned value drops, so a secret key
/// or seed argument does not linger in this crate's heap after the
/// call returns. That is the same contract [`crate::stateful::StatefulSecretKey`]
/// honours: its `handle` field holds a
/// `pqhybridsign_abi::StatefulKeyHandle`, which reaches
/// `pqhybridsign::stateful_composite::SecretKey`'s `ZeroizeOnDrop` wipe.
///
/// # Errors
///
/// A Python `TypeError` if `obj` is neither `bytes` nor `bytearray`.
pub(crate) fn extract_bytes(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
) -> PyResult<Zeroizing<Vec<u8>>> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(Zeroizing::new(b.as_bytes().to_vec()));
    }
    if let Ok(b) = obj.cast::<PyByteArray>() {
        // Safety-free copy: `to_vec` reads under the GIL we already hold,
        // before any other Python code can run and mutate the
        // `bytearray` out from under us.
        return Ok(Zeroizing::new(b.to_vec()));
    }
    Err(PyTypeError::new_err(
        "expected bytes or bytearray, got an object of a different type",
    ))
}
