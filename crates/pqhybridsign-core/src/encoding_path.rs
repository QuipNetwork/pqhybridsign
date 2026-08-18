// SPDX-License-Identifier: AGPL-3.0-or-later
//! Path-selected composite encoding for the stateful constructions H5 and H6.
//!
//! ```text
//! classical_sig(64) || PathSelector(1) || body
//!
//! PathSelector 0x01 (stateful)  body = LeafCount(4, big endian)
//!                                      || StatefulSig(FIXED_STATEFUL + 32 * LeafCount)
//! PathSelector 0x02 (stateless) body = StatelessSig(fixed length per profile)
//! ```
//!
//! `LeafCount` is the only leaf-index value on the wire. The stateful
//! component's authentication path holds exactly `LeafCount` nodes by
//! construction, so no second, independently encoded index exists to
//! disagree with it.
//!
//! # Decode order
//!
//! [`decode_path_selected`] runs specification section 6 in this order, and
//! the order is the security property:
//!
//! 1. Verify the commitment bundle. Reject a mismatch or an all-zero
//!    commitment. **The caller does this**, see [`TrustedMaxSignatures`].
//! 2. Read `maxSignatures` from the now-trusted bundle.
//! 3. Reject any `PathSelector` other than `0x01` or `0x02`.
//! 4. Reject `LeafCount` below 1 or above `maxSignatures`, before reading or
//!    allocating the authentication path.
//! 5. Reject trailing bytes past the implied length.
//!
//! Step 4 precedes any use of `LeafCount` as a length. `LeafCount` is
//! attacker controlled and each leaf costs 32 bytes, so a declared
//! `u32::MAX` asks for roughly 137 GB. Checking the range first turns that
//! from a denial of service into a rejected signature.
//!
//! # Layering
//!
//! Commitment verification lives in the `pqhybridsign-shrincs` crate, which
//! depends on this one. This module therefore cannot verify a bundle itself.
//! It takes the already-verified `maxSignatures` as an input instead, wrapped
//! in [`TrustedMaxSignatures`] so that step 1 is visible in the type of every
//! call.

use crate::error::{Error, Result};

/// Length of the classical signature that opens every path-selected
/// encoding.
pub const CLASSICAL_SIG_LEN: usize = 64;

/// Length of the `PathSelector` field.
pub const SELECTOR_LEN: usize = 1;

/// Length of the big-endian `LeafCount` field.
pub const LEAF_COUNT_LEN: usize = 4;

/// Length of one authentication-path node.
pub const AUTH_PATH_NODE_LEN: usize = 32;

/// `PathSelector` for the stateful path.
pub const SELECTOR_STATEFUL: u8 = 0x01;

/// `PathSelector` for the stateless path.
pub const SELECTOR_STATELESS: u8 = 0x02;

/// The profile-dependent component-signature lengths.
///
/// The SHRINCS profile fixes both. They reach this module as data so that the
/// decoder stays independent of any one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathProfile {
    /// Bytes of a stateful component signature excluding the authentication
    /// path.
    pub fixed_stateful_len: usize,
    /// Bytes of a stateless component signature, which carries no path.
    pub stateless_len: usize,
}

impl PathProfile {
    /// Length of a stateful component signature carrying `leaf_count` path
    /// nodes.
    ///
    /// Returns `None` when the length does not fit a `usize`, which only a
    /// `leaf_count` already outside the accepted range can cause.
    pub fn stateful_len(&self, leaf_count: u32) -> Option<usize> {
        let path = u64::from(leaf_count).checked_mul(AUTH_PATH_NODE_LEN as u64)?;
        let total = path.checked_add(self.fixed_stateful_len as u64)?;
        usize::try_from(total).ok()
    }
}

/// A `maxSignatures` value that came from a verified commitment bundle.
///
/// The wrapper exists to keep step 1 of the decode order honest. There is no
/// conversion from a raw `u32` other than
/// [`from_verified_bundle`](Self::from_verified_bundle), so a caller cannot
/// pass a `maxSignatures` read straight out of an untrusted signature without
/// naming what it is claiming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedMaxSignatures(u32);

impl TrustedMaxSignatures {
    /// Wrap a `maxSignatures` recovered from a bundle whose commitment the
    /// caller has already recomputed and matched against the stored
    /// commitment, having rejected an all-zero stored commitment.
    ///
    /// Calling this with a value taken from unverified input defeats the
    /// whole decode order: every length bound below derives from it.
    pub const fn from_verified_bundle(max_signatures: u32) -> Self {
        Self(max_signatures)
    }

    /// The wrapped value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The body of a path-selected signature, one variant per selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathBody<'a> {
    /// Selector `0x01`. `signature` is
    /// `fixed_stateful_len + 32 * leaf_count` bytes.
    Stateful {
        /// Nodes in the authentication path. Never zero.
        leaf_count: u32,
        /// The stateful component signature, path included.
        signature: &'a [u8],
    },
    /// Selector `0x02`. `signature` is `stateless_len` bytes.
    Stateless {
        /// The stateless component signature.
        signature: &'a [u8],
    },
}

/// A decoded path-selected composite signature.
///
/// Borrowed throughout: decoding slices the input and copies nothing, so a
/// rejected input never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSelectedSig<'a> {
    /// The classical component signature.
    pub classical: &'a [u8; CLASSICAL_SIG_LEN],
    /// The selected body.
    pub body: PathBody<'a>,
}

/// Encoded length of `sig`.
pub fn path_selected_len(sig: &PathSelectedSig<'_>) -> usize {
    let body = match sig.body {
        PathBody::Stateful { signature, .. } => LEAF_COUNT_LEN + signature.len(),
        PathBody::Stateless { signature } => signature.len(),
    };
    CLASSICAL_SIG_LEN + SELECTOR_LEN + body
}

/// Write `sig` into `out` in wire order, returning the number of bytes
/// written.
///
/// # Errors
///
/// - [`Error::BadLength`] when the component signature does not have the
///   length its variant and `profile` imply. For the stateful variant that
///   length is `fixed_stateful_len + 32 * leaf_count`, so an encoder cannot
///   emit a `LeafCount` that contradicts the path it ships.
/// - [`Error::LeafCountOutOfRange`] for a `leaf_count` of zero, or one whose
///   implied length does not fit a `usize`.
/// - [`Error::OutputBufferTooSmall`] when `out` is shorter than
///   [`path_selected_len`]. Nothing is written in that case.
pub fn write_path_selected(
    out: &mut [u8],
    sig: &PathSelectedSig<'_>,
    profile: &PathProfile,
) -> Result<usize> {
    check_body(&sig.body, profile)?;

    let needed = path_selected_len(sig);
    if out.len() < needed {
        return Err(Error::OutputBufferTooSmall {
            needed,
            actual: out.len(),
        });
    }

    out[..CLASSICAL_SIG_LEN].copy_from_slice(sig.classical);
    let mut at = CLASSICAL_SIG_LEN;
    match sig.body {
        PathBody::Stateful {
            leaf_count,
            signature,
        } => {
            out[at] = SELECTOR_STATEFUL;
            at += SELECTOR_LEN;
            out[at..at + LEAF_COUNT_LEN].copy_from_slice(&leaf_count.to_be_bytes());
            at += LEAF_COUNT_LEN;
            out[at..at + signature.len()].copy_from_slice(signature);
            at += signature.len();
        }
        PathBody::Stateless { signature } => {
            out[at] = SELECTOR_STATELESS;
            at += SELECTOR_LEN;
            out[at..at + signature.len()].copy_from_slice(signature);
            at += signature.len();
        }
    }
    Ok(at)
}

/// Allocating convenience wrapper around [`write_path_selected`].
///
/// # Errors
///
/// The same as [`write_path_selected`], except that the buffer is always
/// large enough.
#[cfg(feature = "alloc")]
pub fn encode_path_selected(sig: &PathSelectedSig<'_>, profile: &PathProfile) -> Result<Vec<u8>> {
    check_body(&sig.body, profile)?;
    let mut out = alloc::vec![0u8; path_selected_len(sig)];
    write_path_selected(&mut out, sig, profile)?;
    Ok(out)
}

/// Decode a path-selected composite signature.
///
/// `max_signatures` must come from a commitment bundle the caller has already
/// verified: that is step 1 of the order documented on this module, and every
/// bound below rests on it.
///
/// The returned value borrows `input`. No allocation happens on any path,
/// accepted or rejected.
///
/// # Errors
///
/// - [`Error::BadLength`] when `input` is too short to hold the classical
///   signature and a selector, too short for the `LeafCount` field, or too
///   short for the component signature the selector and `LeafCount` imply.
/// - [`Error::BadPathSelector`] for any selector other than `0x01` or `0x02`.
/// - [`Error::LeafCountOutOfRange`] for a `LeafCount` below 1 or above
///   `max_signatures`. This is decided from the four `LeafCount` bytes alone,
///   before the authentication path is read.
/// - [`Error::TrailingBytes`] when bytes remain past the implied length.
pub fn decode_path_selected<'a>(
    input: &'a [u8],
    max_signatures: TrustedMaxSignatures,
    profile: &PathProfile,
) -> Result<PathSelectedSig<'a>> {
    // Step 1 and step 2 happened in the caller: `max_signatures` is trusted,
    // and nothing below reads a bound out of `input`.
    let header_len = CLASSICAL_SIG_LEN + SELECTOR_LEN;
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
    let selector = input[CLASSICAL_SIG_LEN];
    let rest = &input[header_len..];

    // Step 3: an unknown selector is rejected before anything reads a length
    // out of the body.
    let body = match selector {
        SELECTOR_STATEFUL => decode_stateful(rest, max_signatures, profile, input.len())?,
        SELECTOR_STATELESS => decode_stateless(rest, profile, input.len())?,
        _ => return Err(Error::BadPathSelector { selector }),
    };

    Ok(PathSelectedSig { classical, body })
}

/// Decode the stateful body: `LeafCount(4) || StatefulSig`.
///
/// `total_len` is the length of the whole encoding, used only to report
/// trailing bytes against the same yardstick the caller supplied.
fn decode_stateful<'a>(
    rest: &'a [u8],
    max_signatures: TrustedMaxSignatures,
    profile: &PathProfile,
    total_len: usize,
) -> Result<PathBody<'a>> {
    if rest.len() < LEAF_COUNT_LEN {
        return Err(Error::BadLength {
            expected: LEAF_COUNT_LEN,
            actual: rest.len(),
        });
    }
    let mut raw = [0u8; LEAF_COUNT_LEN];
    raw.copy_from_slice(&rest[..LEAF_COUNT_LEN]);
    let leaf_count = u32::from_be_bytes(raw);

    // Step 4. This runs on the four declared bytes alone. Nothing below it
    // has read, sized or reserved the authentication path yet, so a declared
    // `u32::MAX` costs four bytes of parsing and no memory.
    let out_of_range = Error::LeafCountOutOfRange {
        leaf_count,
        max_signatures: max_signatures.get(),
    };
    if leaf_count < 1 || leaf_count > max_signatures.get() {
        return Err(out_of_range);
    }
    let signature_len = profile.stateful_len(leaf_count).ok_or(out_of_range)?;

    let body = &rest[LEAF_COUNT_LEN..];
    if body.len() < signature_len {
        return Err(Error::BadLength {
            expected: signature_len,
            actual: body.len(),
        });
    }
    // Step 5.
    if body.len() > signature_len {
        return Err(Error::TrailingBytes {
            expected: total_len - (body.len() - signature_len),
            actual: total_len,
        });
    }

    Ok(PathBody::Stateful {
        leaf_count,
        signature: body,
    })
}

/// Decode the stateless body, whose length the profile fixes.
fn decode_stateless<'a>(
    rest: &'a [u8],
    profile: &PathProfile,
    total_len: usize,
) -> Result<PathBody<'a>> {
    if rest.len() < profile.stateless_len {
        return Err(Error::BadLength {
            expected: profile.stateless_len,
            actual: rest.len(),
        });
    }
    // Step 5.
    if rest.len() > profile.stateless_len {
        return Err(Error::TrailingBytes {
            expected: total_len - (rest.len() - profile.stateless_len),
            actual: total_len,
        });
    }
    Ok(PathBody::Stateless { signature: rest })
}

/// Check that a body's component signature has the length its variant and
/// `profile` imply, so an encoding never carries a `LeafCount` that
/// contradicts the path beside it.
///
/// An encoder holds no verified bundle, so it enforces only the bounds that
/// hold for every key: `LeafCount` is at least 1, and its implied length fits
/// a `usize`. Both rejections report `max_signatures: u32::MAX`, the widest
/// upper bound any key can have. The key-specific ceiling is the decoder's to
/// apply, from a bundle it trusts.
fn check_body(body: &PathBody<'_>, profile: &PathProfile) -> Result<()> {
    match *body {
        PathBody::Stateful {
            leaf_count,
            signature,
        } => {
            let unbounded = Error::LeafCountOutOfRange {
                leaf_count,
                max_signatures: u32::MAX,
            };
            if leaf_count < 1 {
                return Err(unbounded);
            }
            let expected = profile.stateful_len(leaf_count).ok_or(unbounded)?;
            if signature.len() != expected {
                return Err(Error::BadLength {
                    expected,
                    actual: signature.len(),
                });
            }
        }
        PathBody::Stateless { signature } => {
            if signature.len() != profile.stateless_len {
                return Err(Error::BadLength {
                    expected: profile.stateless_len,
                    actual: signature.len(),
                });
            }
        }
    }
    Ok(())
}
