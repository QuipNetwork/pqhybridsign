// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delta-length composite encoding for the FN-DSA-512 hybrids H2 and H4.
//!
//! ```text
//! ClassicalSig(64) || DeltaLen(1) || PqSig(min_len + DeltaLen)
//! ```
//!
//! `DeltaLen` encodes `pq_sig.len() - min_len` in a single byte, so the
//! post-quantum component's signature length must fall within
//! `min_len..=min_len + 255`, per specification section 6. `min_len` is
//! `MIN_FALCON512_SIG_LEN` for H2 and H4; this module stays independent of
//! Falcon and takes it as a parameter, mirroring how `encoding_path` takes
//! its component lengths as a [`PathProfile`](crate::encoding_path::PathProfile)
//! rather than hard-coding them.
//!
//! # Decode order
//!
//! [`decode_delta`] runs in this order, and the order is the security
//! property:
//!
//! 1. Reject an input shorter than the classical signature plus the
//!    `DeltaLen` field, before any length arithmetic runs.
//! 2. Recover `pq_len = min_len + DeltaLen`. The addition cannot overflow
//!    for any `min_len` this crate ships, but the check exists so a future,
//!    larger `min_len` fails closed rather than wrapping.
//! 3. Reject a body shorter than `pq_len`, before it is sliced.
//! 4. Reject trailing bytes past `pq_len`.
//!
//! Step 3 precedes any read of the post-quantum signature bytes: `pq_len`
//! is bounded by `min_len + 255` regardless of what the one declared byte
//! says, so there is no allocation-based denial of service here the way
//! [`encoding_path`](crate::encoding_path) guards against for `LeafCount`.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Length of the classical signature that opens every delta-length
/// encoding.
pub const CLASSICAL_SIG_LEN: usize = 64;

/// Length of the `DeltaLen` field.
pub const DELTA_LEN: usize = 1;

/// Largest value `DeltaLen` can hold.
const DELTA_MAX: usize = u8::MAX as usize;

/// A decoded (or to-be-encoded) delta-length composite signature.
///
/// Borrowed throughout: decoding slices the input and copies nothing, so a
/// rejected input never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaSig<'a> {
    /// The classical component signature.
    pub classical: &'a [u8; CLASSICAL_SIG_LEN],
    /// The post-quantum component signature.
    pub pq: &'a [u8],
}

/// Encoded length of a delta-length signature whose post-quantum half is
/// `pq_len` bytes.
pub fn delta_encoded_len(pq_len: usize) -> usize {
    CLASSICAL_SIG_LEN + DELTA_LEN + pq_len
}

/// Compute the `DeltaLen` byte for a post-quantum signature of `pq_len`
/// bytes, given the component's `min_len`.
///
/// # Errors
///
/// [`Error::DeltaLengthOutOfRange`] when `pq_len` is below `min_len` or more
/// than 255 bytes above it: the one-byte field cannot represent it.
pub fn encode_delta_byte(pq_len: usize, min_len: usize) -> Result<u8> {
    let out_of_range = Error::DeltaLengthOutOfRange {
        actual_len: pq_len,
        min_len,
    };
    let delta = pq_len.checked_sub(min_len).ok_or(out_of_range)?;
    if delta > DELTA_MAX {
        return Err(out_of_range);
    }
    // The comparison above already bounds `delta` to `u8`'s range.
    Ok(delta as u8)
}

/// Write `sig` into `out` in wire order, returning the number of bytes
/// written.
///
/// # Errors
///
/// - [`Error::DeltaLengthOutOfRange`] when `sig.pq.len()` does not fit
///   `min_len..=min_len + 255`.
/// - [`Error::OutputBufferTooSmall`] when `out` is shorter than
///   [`delta_encoded_len`] for `sig.pq.len()`. Nothing is written in that
///   case.
pub fn write_delta(out: &mut [u8], sig: &DeltaSig<'_>, min_len: usize) -> Result<usize> {
    let delta = encode_delta_byte(sig.pq.len(), min_len)?;

    let needed = delta_encoded_len(sig.pq.len());
    if out.len() < needed {
        return Err(Error::OutputBufferTooSmall {
            needed,
            actual: out.len(),
        });
    }

    out[..CLASSICAL_SIG_LEN].copy_from_slice(sig.classical);
    out[CLASSICAL_SIG_LEN] = delta;
    out[CLASSICAL_SIG_LEN + DELTA_LEN..needed].copy_from_slice(sig.pq);
    Ok(needed)
}

/// Allocating convenience wrapper around [`write_delta`].
///
/// # Errors
///
/// The same as [`write_delta`], except that the buffer is always large
/// enough.
#[cfg(feature = "alloc")]
pub fn encode_delta(sig: &DeltaSig<'_>, min_len: usize) -> Result<Vec<u8>> {
    let delta = encode_delta_byte(sig.pq.len(), min_len)?;
    let needed = delta_encoded_len(sig.pq.len());
    let mut out = alloc::vec![0u8; needed];
    out[..CLASSICAL_SIG_LEN].copy_from_slice(sig.classical);
    out[CLASSICAL_SIG_LEN] = delta;
    out[CLASSICAL_SIG_LEN + DELTA_LEN..].copy_from_slice(sig.pq);
    Ok(out)
}

/// Decode a delta-length composite signature.
///
/// The returned value borrows `input`. No allocation happens on any path,
/// accepted or rejected.
///
/// # Errors
///
/// - [`Error::BadLength`] when `input` is too short to hold the classical
///   signature and the `DeltaLen` field, or too short for the post-quantum
///   signature the field implies.
/// - [`Error::DeltaLengthOutOfRange`] if `min_len + DeltaLen` does not fit a
///   `usize` (unreachable for any `min_len` this crate ships, since
///   `DeltaLen` is a single byte).
/// - [`Error::TrailingBytes`] when bytes remain past the implied length.
pub fn decode_delta(input: &[u8], min_len: usize) -> Result<DeltaSig<'_>> {
    let header_len = CLASSICAL_SIG_LEN + DELTA_LEN;
    if input.len() < header_len {
        return Err(Error::BadLength {
            expected: header_len,
            actual: input.len(),
        });
    }
    let classical =
        <&[u8; CLASSICAL_SIG_LEN]>::try_from(&input[..CLASSICAL_SIG_LEN]).map_err(|_| {
            Error::BadLength {
                expected: CLASSICAL_SIG_LEN,
                actual: input.len(),
            }
        })?;
    let delta = input[CLASSICAL_SIG_LEN];

    // Step 2. Bounded by `min_len + 255`, so no attacker-chosen length ever
    // drives an allocation or a read before the bound below runs.
    let pq_len = min_len
        .checked_add(delta as usize)
        .ok_or(Error::DeltaLengthOutOfRange {
            actual_len: min_len,
            min_len,
        })?;

    let body = &input[header_len..];
    // Step 3.
    if body.len() < pq_len {
        return Err(Error::BadLength {
            expected: pq_len,
            actual: body.len(),
        });
    }
    // Step 4.
    if body.len() > pq_len {
        return Err(Error::TrailingBytes {
            expected: input.len() - (body.len() - pq_len),
            actual: input.len(),
        });
    }

    Ok(DeltaSig {
        classical,
        pq: &body[..pq_len],
    })
}
