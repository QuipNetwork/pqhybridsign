// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::classical::{Ed25519, Sr25519};
use crate::pq::{Falcon512, MlDsa44};
use crate::{hybrid_delta_suite, hybrid_suite};

hybrid_suite! {
    /// H1: ed25519 + ML-DSA-44. Composite sizes 1344 / 2624 / 2484.
    H1,
    classical = Ed25519 as "ed25519",
    pq = MlDsa44 as "mldsa44",
    label = "hybrid-ed25519-mldsa44-v1",
    label_len = 26,
}

hybrid_suite! {
    /// H3: sr25519 + ML-DSA-44. Composite sizes 1344 / 2624 / 2484.
    H3,
    classical = Sr25519 as "sr25519",
    pq = MlDsa44 as "mldsa44",
    label = "hybrid-sr25519-mldsa44-v1",
    label_len = 26,
}

/// Smallest FN-DSA-512 (Falcon-512) signature the wire `DeltaLen` field can
/// represent, specification section 6.
///
/// Derivation: `DeltaLen` is one byte, so it spans 256 values (0..=255).
/// `fn-dsa` 0.4.0's largest FN-DSA-512 signature, measured by running the
/// crate (`Falcon512::SIGNATURE_LEN`), is 666 bytes. The smallest length
/// the field can represent is therefore `666 - 255 = 411`. Pinning the
/// minimum at 666 instead would only leave the field able to encode
/// lengths at or above the maximum -- the wrong direction, since a shorter
/// signature is the case the delta field exists to reach.
pub const MIN_FALCON512_SIG_LEN: usize = 411;

hybrid_delta_suite! {
    /// H2: ed25519 + FN-DSA-512. Composite sizes 1409 / 3969 / up to 731
    /// (variable: `65 + FalconSigLen`, and `fn-dsa` 0.4.0's `FalconSigLen`
    /// is always 666).
    H2,
    classical = Ed25519 as "ed25519",
    pq = Falcon512 as "falcon512",
    label = "hybrid-ed25519-falcon512-v1",
    label_len = 28,
    min_pq_sig_len = MIN_FALCON512_SIG_LEN,
}

hybrid_delta_suite! {
    /// H4: sr25519 + FN-DSA-512. Composite sizes 1409 / 3969 / up to 731
    /// (variable: `65 + FalconSigLen`, and `fn-dsa` 0.4.0's `FalconSigLen`
    /// is always 666).
    H4,
    classical = Sr25519 as "sr25519",
    pq = Falcon512 as "falcon512",
    label = "hybrid-sr25519-falcon512-v1",
    label_len = 28,
    min_pq_sig_len = MIN_FALCON512_SIG_LEN,
}
