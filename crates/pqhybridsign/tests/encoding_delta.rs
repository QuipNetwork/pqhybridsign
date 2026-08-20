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
//! Delta-length encoding: round trips across the whole `DeltaLen` range and
//! every rejection the decode order in specification section 6 requires.

use pqhybridsign::encoding_delta::{
    decode_delta, delta_encoded_len, encode_delta_byte, write_delta, DeltaSig, CLASSICAL_SIG_LEN,
    DELTA_LEN,
};
use pqhybridsign::error::Error;

/// A stand-in `min_len`. The real value is `MIN_FALCON512_SIG_LEN` (411);
/// the decoder only ever sees it as a parameter.
const MIN_LEN: usize = 411;

fn classical(fill: u8) -> [u8; CLASSICAL_SIG_LEN] {
    [fill; CLASSICAL_SIG_LEN]
}

/// A synthetic post-quantum body, position-dependent so a mis-sliced
/// boundary shows up as a value mismatch rather than an accidental match.
fn synthetic_pq(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn raw(classical: &[u8], delta: u8, pq: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(classical);
    out.push(delta);
    out.extend_from_slice(pq);
    out
}

#[test]
fn every_delta_len_from_0_to_255_round_trips() {
    let classical = classical(0xAA);
    for delta in 0u16..=255 {
        let pq_len = MIN_LEN + delta as usize;
        let pq = synthetic_pq(pq_len);
        let sig = DeltaSig {
            classical: &classical,
            pq: &pq,
        };

        let mut out = vec![0u8; delta_encoded_len(pq_len)];
        let written = write_delta(&mut out, &sig, MIN_LEN).expect("encode");
        assert_eq!(written, out.len());
        assert_eq!(out, raw(&classical, delta as u8, &pq));

        let decoded = decode_delta(&out, MIN_LEN).expect("its own encoding decodes");
        assert_eq!(decoded.classical, &classical);
        assert_eq!(decoded.pq, pq.as_slice());
    }
}

#[test]
fn encode_delta_byte_computes_the_delta_from_the_actual_length() {
    assert_eq!(encode_delta_byte(MIN_LEN, MIN_LEN), Ok(0));
    assert_eq!(encode_delta_byte(MIN_LEN + 255, MIN_LEN), Ok(255));
    assert_eq!(encode_delta_byte(MIN_LEN + 42, MIN_LEN), Ok(42));
}

#[test]
fn a_pq_length_below_min_len_is_rejected() {
    let classical = classical(0xAA);
    let pq = synthetic_pq(MIN_LEN - 1);
    let sig = DeltaSig {
        classical: &classical,
        pq: &pq,
    };
    assert_eq!(
        write_delta(&mut vec![0u8; 1024], &sig, MIN_LEN),
        Err(Error::DeltaLengthOutOfRange {
            actual_len: MIN_LEN - 1,
            min_len: MIN_LEN,
        })
    );
}

#[test]
fn a_pq_length_256_above_min_len_is_rejected() {
    let classical = classical(0xAA);
    let pq = synthetic_pq(MIN_LEN + 256);
    let sig = DeltaSig {
        classical: &classical,
        pq: &pq,
    };
    assert_eq!(
        write_delta(&mut vec![0u8; 2048], &sig, MIN_LEN),
        Err(Error::DeltaLengthOutOfRange {
            actual_len: MIN_LEN + 256,
            min_len: MIN_LEN,
        })
    );
}

#[test]
fn a_declared_length_that_overruns_the_buffer_is_rejected_not_panicked_on() {
    let classical = classical(0x00);
    // DeltaLen = 255 implies a `MIN_LEN + 255`-byte body, far past the 10
    // bytes actually on hand.
    let input = raw(&classical, 255, &synthetic_pq(10));
    assert_eq!(
        decode_delta(&input, MIN_LEN),
        Err(Error::BadLength {
            expected: MIN_LEN + 255,
            actual: 10,
        })
    );
}

#[test]
fn trailing_bytes_are_rejected() {
    let classical = classical(0x11);
    let pq = synthetic_pq(20);
    let mut with_trailer = raw(&classical, 0, &pq);
    let exact_len = with_trailer.len();
    with_trailer.push(0xff);

    assert_eq!(
        decode_delta(&with_trailer, 20),
        Err(Error::TrailingBytes {
            expected: exact_len,
            actual: exact_len + 1,
        })
    );
}

#[test]
fn a_truncated_signature_is_rejected() {
    let classical = classical(0x33);
    let pq = synthetic_pq(20);
    let mut short = raw(&classical, 0, &pq);
    short.pop();

    assert_eq!(
        decode_delta(&short, 20),
        Err(Error::BadLength {
            expected: 20,
            actual: 19,
        })
    );
}

#[test]
fn an_input_shorter_than_the_header_is_rejected() {
    for len in [0usize, 1, CLASSICAL_SIG_LEN] {
        let input = vec![0u8; len];
        assert_eq!(
            decode_delta(&input, MIN_LEN),
            Err(Error::BadLength {
                expected: CLASSICAL_SIG_LEN + DELTA_LEN,
                actual: len,
            })
        );
    }
}

#[test]
fn write_reports_a_buffer_that_is_too_small() {
    let classical = classical(0x44);
    let pq = synthetic_pq(30);
    let sig = DeltaSig {
        classical: &classical,
        pq: &pq,
    };
    let needed = delta_encoded_len(pq.len());

    let mut too_small = vec![0u8; needed - 1];
    assert_eq!(
        write_delta(&mut too_small, &sig, 20),
        Err(Error::OutputBufferTooSmall {
            needed,
            actual: needed - 1,
        })
    );
    assert!(
        too_small.iter().all(|&b| b == 0),
        "a rejected write must not partially write"
    );

    let mut longer = vec![0u8; needed + 8];
    assert_eq!(write_delta(&mut longer, &sig, 20), Ok(needed));
    assert_eq!(&longer[..needed], raw(&classical, 10, &pq).as_slice());
}
