// SPDX-License-Identifier: AGPL-3.0-or-later
// Integration test binary: `cfg(test)` is always true here. `unwrap`/
// `expect`/`panic` are the normal way a test fails; the `hybrid_suite!`
// family of macros generates undocumented, unconditionally `pub` fixture
// structs, which is fine for a binary with no public API of its own.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        missing_docs,
        unreachable_pub
    )
)]
//! Property tests over the encoders, required by DESIGN.md lines 485-491.
//!
//! The hand-written tests in `tests/encoding_path.rs` and
//! `tests/encoding_delta.rs` already walk every `DeltaLen` from 0 to 255,
//! tamper every byte, and truncate at every framing boundary. These add
//! what an example-based suite cannot: inputs nobody thought to write.
//!
//! DESIGN.md:751-753 requires two things of a decoder: encode/decode round
//! trips, and that an arbitrary byte string must never decode into a valid
//! composite signature. A property that only checks "does not panic" proves
//! neither: a decoder that returns `Ok` for junk keeps such a property
//! green. Every decode property below inspects the `Result` instead —
//! either matching the decode order exactly (`decode_delta`,
//! `RotationPayload::decode`, both cheap enough to model precisely), or, for
//! `decode_path_selected`, asserting rejection under realistic parameters
//! and checking that a rare `Ok` is one the encoder could actually have
//! produced.
//!
//! `decode_path_selected` and `decode_delta` also get a dedicated,
//! *constructed* (not sampled) overflow case each. A wide-range random
//! `min_len`/`PathProfile` reaches the relevant `checked_add`/`checked_mul`
//! overflow with very low probability — for the path decoder, well under
//! the default 256 cases per run — so a property that only samples cannot
//! be trusted to cover it.

use pqhybridsign::encoding_delta::{
    decode_delta, CLASSICAL_SIG_LEN as DELTA_CLASSICAL_SIG_LEN, DELTA_LEN,
};
use pqhybridsign::encoding_path::{
    decode_path_selected, path_selected_len, write_path_selected, PathProfile,
    TrustedMaxSignatures, CLASSICAL_SIG_LEN as PATH_CLASSICAL_SIG_LEN, LEAF_COUNT_LEN,
    SELECTOR_LEN, SELECTOR_STATEFUL,
};
#[cfg(feature = "alloc")]
use pqhybridsign::message::m_prime;
use pqhybridsign::rotation::{RotationPayload, ROTATION_PAYLOAD_LEN};
use pqhybridsign::{
    error::Error,
    message::{m_prime_len, write_m_prime},
};
use proptest::prelude::*;

/// A stand-in `PathProfile`, matching `tests/encoding_path.rs:14-17`. The
/// real values come from the SHRINCS profile; the decoder only ever sees
/// them as parameters.
const PROFILE: PathProfile = PathProfile {
    fixed_stateful_len: 96,
    stateless_len: 176,
};

/// A stand-in `maxSignatures`, matching `tests/encoding_path.rs:19`.
const MAX_SIGNATURES: u32 = 8;

proptest! {
    /// `decode_delta` matches its documented decode order exactly, for
    /// every input length and a `min_len` that ranges from realistic values
    /// up to `usize::MAX`, so this also exercises the `checked_add`
    /// overflow branch (about 1.5% of a default run, enough given the exact
    /// match below rather than a bare "did not panic").
    #[test]
    fn decode_delta_matches_the_decode_order(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
        min_len in prop_oneof![(0usize..4096), (usize::MAX - 4096..=usize::MAX)],
    ) {
        let header_len = DELTA_CLASSICAL_SIG_LEN + DELTA_LEN;
        let result = decode_delta(&bytes, min_len);

        if bytes.len() < header_len {
            prop_assert_eq!(
                result,
                Err(Error::BadLength { expected: header_len, actual: bytes.len() })
            );
            return Ok(());
        }

        let delta = bytes[DELTA_CLASSICAL_SIG_LEN];
        let pq_len = match min_len.checked_add(delta as usize) {
            None => {
                prop_assert_eq!(
                    result,
                    Err(Error::DeltaLengthOutOfRange { actual_len: min_len, min_len })
                );
                return Ok(());
            }
            Some(pq_len) => pq_len,
        };

        let body_len = bytes.len() - header_len;
        if body_len < pq_len {
            prop_assert_eq!(
                result,
                Err(Error::BadLength { expected: pq_len, actual: body_len })
            );
        } else if body_len > pq_len {
            prop_assert_eq!(
                result,
                Err(Error::TrailingBytes {
                    expected: bytes.len() - (body_len - pq_len),
                    actual: bytes.len(),
                })
            );
        } else {
            let sig = result.expect("an exact-length input must decode");
            prop_assert_eq!(sig.classical.as_slice(), &bytes[..DELTA_CLASSICAL_SIG_LEN]);
            prop_assert_eq!(sig.pq, &bytes[header_len..]);
        }
    }

    /// Arbitrary bytes, under a realistic fixed profile, must never decode
    /// into a valid composite signature (DESIGN.md:751-753). On the rare
    /// `Ok` that fixed-length framing makes possible by chance, the decoded
    /// value must be one the encoder could have produced: re-encoding it
    /// must reproduce the input exactly.
    #[test]
    fn decode_path_selected_rejects_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let trusted = TrustedMaxSignatures::from_verified_bundle(MAX_SIGNATURES);
        match decode_path_selected(&bytes, trusted, &PROFILE) {
            Err(_) => {}
            Ok(sig) => {
                let mut out = vec![0u8; path_selected_len(&sig)];
                let written = write_path_selected(&mut out, &sig, &PROFILE)
                    .expect("a decoded signature must re-encode under the same profile");
                prop_assert_eq!(written, bytes.len());
                prop_assert_eq!(out, bytes);
            }
        }
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
        // `ctx` never exceeds 255 bytes here, so `m_prime_len` cannot
        // return `Error::ContextTooLong`.
        let len = m_prime_len(&label, &ctx, &msg).expect("ctx is within range");
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

    /// `RotationPayload::decode` matches its documented decode order
    /// exactly: any length but `ROTATION_PAYLOAD_LEN` is `BadLength`; that
    /// length with a kind byte outside `0x01`/`0x02` is `BadRotationKind`;
    /// otherwise the three fields must match the input slices exactly. The
    /// length strategy weights in the exact payload length, since a
    /// uniform `0..512` hits it only about once in 512 cases and the kind
    /// byte's split would otherwise almost never get exercised.
    #[test]
    fn rotation_payload_decode_matches_the_decode_order(
        bytes in prop_oneof![
            9 => 0usize..512,
            1 => Just(ROTATION_PAYLOAD_LEN),
        ].prop_flat_map(|len| prop::collection::vec(any::<u8>(), len..=len)),
    ) {
        let result = RotationPayload::decode(&bytes);

        if bytes.len() != ROTATION_PAYLOAD_LEN {
            prop_assert_eq!(
                result,
                Err(Error::BadLength { expected: ROTATION_PAYLOAD_LEN, actual: bytes.len() })
            );
            return Ok(());
        }

        let kind = bytes[0];
        if kind != 0x01 && kind != 0x02 {
            prop_assert_eq!(result, Err(Error::BadRotationKind { kind }));
            return Ok(());
        }

        let payload = result.expect("exact length and a valid kind must decode");
        prop_assert_eq!(payload.kind.to_u8(), kind);
        // The three 32-byte fields following the 1-byte kind. `FIELD_LEN`
        // is a private constant of the `rotation` module; derived here from
        // the public `ROTATION_PAYLOAD_LEN` (`1 + 3 * FIELD_LEN`) instead of
        // duplicating its value.
        let field_len = (ROTATION_PAYLOAD_LEN - 1) / 3;
        prop_assert_eq!(payload.current_commitment.as_slice(), &bytes[1..1 + field_len]);
        prop_assert_eq!(
            payload.next_commitment.as_slice(),
            &bytes[1 + field_len..1 + 2 * field_len]
        );
        prop_assert_eq!(
            payload.next_classical_pk.as_slice(),
            &bytes[1 + 2 * field_len..ROTATION_PAYLOAD_LEN]
        );
    }
}

/// Constructed, not sampled: `min_len` at `usize::MAX` with a `DeltaLen` of
/// 1 makes `min_len.checked_add(delta)` overflow. The random property above
/// reaches this only for the roughly 1.5% of runs where `min_len` lands in
/// the top 4096 values and the delta byte at `bytes[64]` is large enough;
/// this test reaches it every run.
#[test]
fn decode_delta_min_len_overflow_reports_out_of_range() {
    let mut bytes = [0u8; DELTA_CLASSICAL_SIG_LEN + DELTA_LEN];
    bytes[DELTA_CLASSICAL_SIG_LEN] = 1; // DeltaLen = 1
    assert_eq!(
        decode_delta(&bytes, usize::MAX),
        Err(Error::DeltaLengthOutOfRange {
            actual_len: usize::MAX,
            min_len: usize::MAX,
        })
    );
}

/// Constructed, not sampled: a `LeafCount` of 1 is in range for
/// `max_signatures >= 1`, so `decode_stateful` reaches
/// `PathProfile::stateful_len`. With `fixed_stateful_len = usize::MAX` that
/// overflows and reports `LeafCountOutOfRange`, the same variant the range
/// check itself would report — the overflow guard fails closed under the
/// same error as an out-of-range count. `decode_path_selected_rejects_arbitrary_bytes`
/// above reaches selector `0x01` only about 1/256 of the time and an
/// in-range `LeafCount` about half of that again, so it cannot be trusted
/// to cover this branch on its own.
#[test]
fn decode_path_selected_stateful_len_overflow_reports_leaf_count_out_of_range() {
    let mut input = [0u8; PATH_CLASSICAL_SIG_LEN + SELECTOR_LEN + LEAF_COUNT_LEN];
    input[PATH_CLASSICAL_SIG_LEN] = SELECTOR_STATEFUL;
    input[PATH_CLASSICAL_SIG_LEN + SELECTOR_LEN..].copy_from_slice(&1u32.to_be_bytes());
    let trusted = TrustedMaxSignatures::from_verified_bundle(1);
    let profile = PathProfile {
        fixed_stateful_len: usize::MAX,
        stateless_len: 0,
    };
    assert_eq!(
        decode_path_selected(&input, trusted, &profile),
        Err(Error::LeafCountOutOfRange {
            leaf_count: 1,
            max_signatures: 1,
        })
    );
}
