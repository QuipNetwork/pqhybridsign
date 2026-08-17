// SPDX-License-Identifier: AGPL-3.0-or-later
//! Property tests over the encoders, required by DESIGN.md lines 485-491.
//!
//! The hand-written tests in `tests/encoding_path.rs` and
//! `tests/encoding_delta.rs` already walk every `DeltaLen` from 0 to 255,
//! tamper every byte, and truncate at every framing boundary. These add
//! what an example-based suite cannot: inputs nobody thought to write,
//! including a `PathProfile` whose implied body length overflows `usize`
//! and a `min_len` large enough to overflow the delta decoder's addition.
//!
//! Every property here except the two `m_prime` ones is a negative one. A
//! decoder that accepts arbitrary bytes is the dangerous failure; a decoder
//! that rejects a valid encoding is caught by the round-trip tests that
//! already exist.

use pqhybridsign_core::encoding_delta::decode_delta;
use pqhybridsign_core::encoding_path::{decode_path_selected, PathProfile, TrustedMaxSignatures};
#[cfg(feature = "alloc")]
use pqhybridsign_core::m_prime;
use pqhybridsign_core::rotation::RotationPayload;
use pqhybridsign_core::{m_prime_len, write_m_prime};
use proptest::prelude::*;

/// A `usize` strategy weighted toward two regions: small, realistic lengths
/// and lengths within a few thousand of `usize::MAX`. The second region is
/// what an example-based suite never reaches by hand, and it is exactly
/// where a `checked_mul`/`checked_add` overflow check earns its keep.
fn len_near_boundary_or_small() -> impl Strategy<Value = usize> {
    prop_oneof![(0usize..4096), (usize::MAX - 4096..=usize::MAX),]
}

fn arb_path_profile() -> impl Strategy<Value = PathProfile> {
    (len_near_boundary_or_small(), len_near_boundary_or_small()).prop_map(
        |(fixed_stateful_len, stateless_len)| PathProfile {
            fixed_stateful_len,
            stateless_len,
        },
    )
}

proptest! {
    /// Arbitrary bytes must never panic in the path decoder, for any
    /// trusted `max_signatures` and any profile, including profiles whose
    /// implied stateful body length overflows `usize`.
    #[test]
    fn decode_path_selected_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
        max_signatures in any::<u32>(),
        profile in arb_path_profile(),
    ) {
        let trusted = TrustedMaxSignatures::from_verified_bundle(max_signatures);
        let _ = decode_path_selected(&bytes, trusted, &profile);
    }

    /// The same for the delta decoder, including a `min_len` large enough
    /// to overflow `min_len + DeltaLen`.
    #[test]
    fn decode_delta_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
        min_len in len_near_boundary_or_small(),
    ) {
        let _ = decode_delta(&bytes, min_len);
    }

    /// `m_prime_len` must agree with what `write_m_prime` writes, for every
    /// label, ctx and message length the API accepts.
    #[test]
    fn m_prime_len_matches_bytes_written(
        label in prop::collection::vec(any::<u8>(), 1..32),
        ctx in prop::collection::vec(any::<u8>(), 0..=255),
        msg in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut label = label;
        label.push(0);                       // labels are null-terminated
        let Ok(len) = m_prime_len(&label, &ctx, &msg) else { return Ok(()) };
        let mut out = vec![0u8; len];
        let written = write_m_prime(&mut out, &label, &ctx, &msg)
            .expect("write must succeed for a buffer m_prime_len sized");
        prop_assert_eq!(written, len);
    }

    /// Two different ctx values must never produce the same M' for one
    /// (label, msg). This is the length-prefixing guarantee, and it is the
    /// property the whole domain-separation scheme rests on.
    #[cfg(feature = "alloc")]
    #[test]
    fn distinct_ctx_never_collide_for_one_label_and_message(
        ctx_a in prop::collection::vec(any::<u8>(), 0..=255),
        ctx_b in prop::collection::vec(any::<u8>(), 0..=255),
        msg in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(ctx_a != ctx_b);
        let label = b"prop-label\0";
        let a = m_prime(label, &ctx_a, &msg).expect("M' a");
        let b = m_prime(label, &ctx_b, &msg).expect("M' b");
        prop_assert_ne!(a, b);
    }

    /// Arbitrary bytes must never panic in the rotation payload decoder.
    #[test]
    fn rotation_payload_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = RotationPayload::decode(&bytes);
    }
}
