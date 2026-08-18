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
//! Path-selected encoding: round trips and every rejection the decode order
//! in specification section 6 requires.

use pqhybridsign_core::encoding_path::{
    decode_path_selected, encode_path_selected, path_selected_len, write_path_selected, PathBody,
    PathProfile, PathSelectedSig, TrustedMaxSignatures, AUTH_PATH_NODE_LEN, CLASSICAL_SIG_LEN,
    LEAF_COUNT_LEN, SELECTOR_LEN, SELECTOR_STATEFUL, SELECTOR_STATELESS,
};
use pqhybridsign_core::error::Error;

/// Stand-in profile lengths. The real values come from the SHRINCS profile;
/// the decoder only ever sees them as parameters.
const PROFILE: PathProfile = PathProfile {
    fixed_stateful_len: 96,
    stateless_len: 176,
};

const MAX_SIGNATURES: u32 = 8;

fn trusted() -> TrustedMaxSignatures {
    TrustedMaxSignatures::from_verified_bundle(MAX_SIGNATURES)
}

fn classical() -> [u8; CLASSICAL_SIG_LEN] {
    let mut bytes = [0u8; CLASSICAL_SIG_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = index as u8;
    }
    bytes
}

/// A stateful component signature of the length `leaf_count` implies.
fn stateful_body(leaf_count: u32) -> Vec<u8> {
    let len = PROFILE.fixed_stateful_len + AUTH_PATH_NODE_LEN * leaf_count as usize;
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn stateless_body() -> Vec<u8> {
    (0..PROFILE.stateless_len)
        .map(|index| (index % 241) as u8)
        .collect()
}

/// Build the wire form by hand, so a round trip is not checked against the
/// encoder alone.
fn raw_stateful(classical: &[u8], declared_leaf_count: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(classical);
    out.push(SELECTOR_STATEFUL);
    out.extend_from_slice(&declared_leaf_count.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn raw_stateless(classical: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(classical);
    out.push(SELECTOR_STATELESS);
    out.extend_from_slice(body);
    out
}

#[test]
fn encoding_path_round_trip_stateful() {
    let classical = classical();
    for leaf_count in [1u32, 2, 7] {
        let body = stateful_body(leaf_count);
        let signature = PathSelectedSig {
            classical: &classical,
            body: PathBody::Stateful {
                leaf_count,
                signature: &body,
            },
        };

        let encoded = encode_path_selected(&signature, &PROFILE).expect("a valid shape encodes");
        assert_eq!(encoded, raw_stateful(&classical, leaf_count, &body));
        assert_eq!(encoded.len(), path_selected_len(&signature));

        let decoded =
            decode_path_selected(&encoded, trusted(), &PROFILE).expect("its own encoding decodes");
        assert_eq!(decoded.classical, &classical);
        match decoded.body {
            PathBody::Stateful {
                leaf_count: decoded_count,
                signature: decoded_body,
            } => {
                assert_eq!(decoded_count, leaf_count);
                assert_eq!(decoded_body, body.as_slice());
            }
            PathBody::Stateless { .. } => panic!("selector 0x01 must decode as stateful"),
        }
    }
}

#[test]
fn encoding_path_round_trip_stateless() {
    let classical = classical();
    let body = stateless_body();
    let signature = PathSelectedSig {
        classical: &classical,
        body: PathBody::Stateless { signature: &body },
    };

    let encoded = encode_path_selected(&signature, &PROFILE).expect("a valid shape encodes");
    assert_eq!(encoded, raw_stateless(&classical, &body));

    let decoded =
        decode_path_selected(&encoded, trusted(), &PROFILE).expect("its own encoding decodes");
    assert_eq!(decoded.classical, &classical);
    match decoded.body {
        PathBody::Stateless {
            signature: decoded_body,
        } => assert_eq!(decoded_body, body.as_slice()),
        PathBody::Stateful { .. } => panic!("selector 0x02 must decode as stateless"),
    }
}

#[test]
fn encoding_path_wire_layout_matches_the_specification() {
    let classical = classical();
    let body = stateful_body(2);
    let encoded = encode_path_selected(
        &PathSelectedSig {
            classical: &classical,
            body: PathBody::Stateful {
                leaf_count: 2,
                signature: &body,
            },
        },
        &PROFILE,
    )
    .expect("a valid shape encodes");

    assert_eq!(&encoded[..CLASSICAL_SIG_LEN], &classical);
    assert_eq!(encoded[CLASSICAL_SIG_LEN], SELECTOR_STATEFUL);
    let leaf_count_at = CLASSICAL_SIG_LEN + SELECTOR_LEN;
    assert_eq!(
        &encoded[leaf_count_at..leaf_count_at + LEAF_COUNT_LEN],
        &2u32.to_be_bytes(),
        "LeafCount is big endian"
    );
    assert_eq!(&encoded[leaf_count_at + LEAF_COUNT_LEN..], body.as_slice());
}

#[test]
fn encoding_path_rejects_unknown_selectors() {
    let classical = classical();
    let body = stateless_body();

    for selector in [0x00u8, 0x03, 0x7f, 0xff] {
        let mut input = raw_stateless(&classical, &body);
        input[CLASSICAL_SIG_LEN] = selector;

        assert_eq!(
            decode_path_selected(&input, trusted(), &PROFILE).map(|_| ()),
            Err(Error::BadPathSelector { selector }),
            "selector {selector:#04x} must be rejected"
        );
    }
}

#[test]
fn encoding_path_rejects_zero_leaf_count() {
    let classical = classical();
    let input = raw_stateful(&classical, 0, &stateful_body(0));

    assert_eq!(
        decode_path_selected(&input, trusted(), &PROFILE).map(|_| ()),
        Err(Error::LeafCountOutOfRange {
            leaf_count: 0,
            max_signatures: MAX_SIGNATURES,
        })
    );
}

#[test]
fn encoding_path_rejects_leaf_count_above_max_signatures() {
    let classical = classical();
    let over = MAX_SIGNATURES + 1;
    let input = raw_stateful(&classical, over, &stateful_body(over));

    assert_eq!(
        decode_path_selected(&input, trusted(), &PROFILE).map(|_| ()),
        Err(Error::LeafCountOutOfRange {
            leaf_count: over,
            max_signatures: MAX_SIGNATURES,
        })
    );

    // The boundary itself stays valid.
    let at_max = raw_stateful(&classical, MAX_SIGNATURES, &stateful_body(MAX_SIGNATURES));
    assert!(decode_path_selected(&at_max, trusted(), &PROFILE).is_ok());
}

#[test]
fn encoding_path_rejects_declared_u32_max_without_allocating() {
    let classical = classical();
    // 69 bytes that merely *declare* an authentication path of 137 GB. If the
    // range check did not precede the read, this test would hang or die.
    let input = raw_stateful(&classical, u32::MAX, &[]);
    assert_eq!(
        input.len(),
        CLASSICAL_SIG_LEN + SELECTOR_LEN + LEAF_COUNT_LEN
    );

    let start = std::time::Instant::now();
    let outcome = decode_path_selected(&input, trusted(), &PROFILE).map(|_| ());
    let elapsed = start.elapsed();

    assert_eq!(
        outcome,
        Err(Error::LeafCountOutOfRange {
            leaf_count: u32::MAX,
            max_signatures: MAX_SIGNATURES,
        })
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "decode took {elapsed:?}: the range check is not running before the read"
    );
}

#[test]
fn encoding_path_rejects_trailing_bytes() {
    let classical = classical();

    let mut stateful = raw_stateful(&classical, 3, &stateful_body(3));
    let stateful_len = stateful.len();
    stateful.push(0xaa);
    assert_eq!(
        decode_path_selected(&stateful, trusted(), &PROFILE).map(|_| ()),
        Err(Error::TrailingBytes {
            expected: stateful_len,
            actual: stateful_len + 1,
        })
    );

    let mut stateless = raw_stateless(&classical, &stateless_body());
    let stateless_len = stateless.len();
    stateless.extend_from_slice(&[0xaa, 0xbb]);
    assert_eq!(
        decode_path_selected(&stateless, trusted(), &PROFILE).map(|_| ()),
        Err(Error::TrailingBytes {
            expected: stateless_len,
            actual: stateless_len + 2,
        })
    );
}

#[test]
fn encoding_path_rejects_truncated_bodies() {
    let classical = classical();

    // One node short of the path the declared LeafCount implies.
    let mut short_path = raw_stateful(&classical, 3, &stateful_body(3));
    short_path.truncate(short_path.len() - AUTH_PATH_NODE_LEN);
    assert!(matches!(
        decode_path_selected(&short_path, trusted(), &PROFILE),
        Err(Error::BadLength { .. })
    ));

    // A single byte short, so the truncation is not node aligned.
    let mut one_byte_short = raw_stateful(&classical, 2, &stateful_body(2));
    one_byte_short.pop();
    assert!(matches!(
        decode_path_selected(&one_byte_short, trusted(), &PROFILE),
        Err(Error::BadLength { .. })
    ));

    // A stateless body one byte short.
    let mut short_stateless = raw_stateless(&classical, &stateless_body());
    short_stateless.pop();
    assert!(matches!(
        decode_path_selected(&short_stateless, trusted(), &PROFILE),
        Err(Error::BadLength { .. })
    ));

    // The LeafCount field itself is truncated.
    let mut no_leaf_count = raw_stateful(&classical, 1, &[]);
    no_leaf_count.pop();
    assert!(matches!(
        decode_path_selected(&no_leaf_count, trusted(), &PROFILE),
        Err(Error::BadLength { .. })
    ));
}

#[test]
fn encoding_path_rejects_input_too_short_for_a_selector() {
    let classical = classical();
    for len in [0usize, 1, CLASSICAL_SIG_LEN] {
        let input = &classical[..core::cmp::min(len, CLASSICAL_SIG_LEN)];
        assert!(
            matches!(
                decode_path_selected(input, trusted(), &PROFILE),
                Err(Error::BadLength { .. })
            ),
            "a {len}-byte input carries no selector"
        );
    }
}

#[test]
fn encoding_path_selector_check_precedes_the_leaf_count_read() {
    // A bad selector on an input with no room for a LeafCount must report the
    // selector, not the length: step 3 runs before step 4.
    let classical = classical();
    let mut input = classical.to_vec();
    input.push(0x09);

    assert_eq!(
        decode_path_selected(&input, trusted(), &PROFILE).map(|_| ()),
        Err(Error::BadPathSelector { selector: 0x09 })
    );
}

#[test]
fn encoding_path_encoder_rejects_a_body_that_contradicts_its_leaf_count() {
    let classical = classical();
    let body = stateful_body(3);

    // The same bytes, declared as a different leaf count.
    let outcome = encode_path_selected(
        &PathSelectedSig {
            classical: &classical,
            body: PathBody::Stateful {
                leaf_count: 4,
                signature: &body,
            },
        },
        &PROFILE,
    );
    assert_eq!(
        outcome.map(|_| ()),
        Err(Error::BadLength {
            expected: PROFILE.fixed_stateful_len + AUTH_PATH_NODE_LEN * 4,
            actual: body.len(),
        })
    );

    let outcome = encode_path_selected(
        &PathSelectedSig {
            classical: &classical,
            body: PathBody::Stateless { signature: &body },
        },
        &PROFILE,
    );
    assert_eq!(
        outcome.map(|_| ()),
        Err(Error::BadLength {
            expected: PROFILE.stateless_len,
            actual: body.len(),
        })
    );
}

#[test]
fn encoding_path_write_reports_a_buffer_that_is_too_small() {
    let classical = classical();
    let body = stateless_body();
    let signature = PathSelectedSig {
        classical: &classical,
        body: PathBody::Stateless { signature: &body },
    };
    let needed = path_selected_len(&signature);

    let mut too_small = vec![0u8; needed - 1];
    assert_eq!(
        write_path_selected(&mut too_small, &signature, &PROFILE),
        Err(Error::OutputBufferTooSmall {
            needed,
            actual: needed - 1,
        })
    );

    let mut exact = vec![0u8; needed];
    assert_eq!(
        write_path_selected(&mut exact, &signature, &PROFILE),
        Ok(needed)
    );

    // A longer buffer is filled from the front and the written length is
    // reported, so the caller can slice it.
    let mut longer = vec![0u8; needed + 8];
    assert_eq!(
        write_path_selected(&mut longer, &signature, &PROFILE),
        Ok(needed)
    );
    assert_eq!(&longer[..needed], raw_stateless(&classical, &body));
}
