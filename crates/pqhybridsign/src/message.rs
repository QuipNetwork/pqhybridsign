// SPDX-License-Identifier: AGPL-3.0-or-later
//! `M'` framing, specification section 7: the domain-separated message every
//! component signature is actually computed over.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Hybrid construction version prefix, specification section 7.
pub const PREFIX: u8 = 0x01;

/// Length in bytes of `M'` for these inputs.
///
/// Returns [`Error::ContextTooLong`] when `ctx` exceeds 255 bytes, because
/// the length field is a single byte.
pub fn m_prime_len(label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<usize> {
    if ctx.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    Ok(1 + label.len() + 1 + ctx.len() + msg.len())
}

/// Write `M' = Prefix || Label || len(ctx) || ctx || M` into `out`.
///
/// `label` must already include its trailing null byte. Returns the number
/// of bytes written. Writes nothing when `out` is too small.
pub fn write_m_prime(out: &mut [u8], label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<usize> {
    let needed = m_prime_len(label, ctx, msg)?;
    if out.len() < needed {
        return Err(Error::OutputBufferTooSmall {
            needed,
            actual: out.len(),
        });
    }
    let mut at = 0;
    out[at] = PREFIX;
    at += 1;
    out[at..at + label.len()].copy_from_slice(label);
    at += label.len();
    // The cast is exact: m_prime_len already rejected ctx longer than 255.
    out[at] = ctx.len() as u8;
    at += 1;
    out[at..at + ctx.len()].copy_from_slice(ctx);
    at += ctx.len();
    out[at..at + msg.len()].copy_from_slice(msg);
    at += msg.len();
    Ok(at)
}

/// Allocating convenience wrapper around [`write_m_prime`].
#[cfg(feature = "alloc")]
pub fn m_prime(label: &[u8], ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let needed = m_prime_len(label, ctx, msg)?;
    let mut out = alloc::vec![0u8; needed];
    write_m_prime(&mut out, label, ctx, msg)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

    // Uses the allocating `m_prime` wrapper.
    #[cfg(feature = "alloc")]
    #[test]
    fn layout_matches_the_specification() {
        let out = m_prime(H1, b"chain", b"hello").expect("build");
        assert_eq!(out[0], 0x01, "prefix");
        assert_eq!(&out[1..1 + H1.len()], H1, "label including the null byte");
        assert_eq!(out[1 + H1.len()], 5, "len(ctx)");
        assert_eq!(&out[2 + H1.len()..7 + H1.len()], b"chain");
        assert_eq!(&out[7 + H1.len()..], b"hello");
    }

    // Uses the allocating `m_prime` wrapper.
    #[cfg(feature = "alloc")]
    #[test]
    fn empty_context_encodes_a_zero_length() {
        let out = m_prime(H1, b"", b"m").expect("build");
        assert_eq!(out[1 + H1.len()], 0);
        assert_eq!(&out[2 + H1.len()..], b"m");
    }

    // Uses the allocating `m_prime` wrapper.
    #[cfg(feature = "alloc")]
    #[test]
    fn context_over_255_bytes_is_rejected() {
        let ctx = [0u8; 256];
        assert_eq!(m_prime(H1, &ctx, b"m").unwrap_err(), Error::ContextTooLong);
        assert_eq!(
            m_prime_len(H1, &ctx, b"m").unwrap_err(),
            Error::ContextTooLong
        );
    }

    // Uses the allocating `m_prime` wrapper.
    #[cfg(feature = "alloc")]
    #[test]
    fn context_of_exactly_255_bytes_is_accepted() {
        let ctx = [7u8; 255];
        let out = m_prime(H1, &ctx, b"m").expect("255 is the maximum");
        assert_eq!(out[1 + H1.len()], 255);
    }

    #[test]
    fn declared_length_matches_written_length() {
        let need = m_prime_len(H1, b"ab", b"cde").expect("len");
        let mut buf = [0u8; 64];
        let wrote = write_m_prime(&mut buf[..need], H1, b"ab", b"cde").expect("write");
        assert_eq!(need, wrote);
        assert_eq!(need, 1 + H1.len() + 1 + 2 + 3);
    }

    #[test]
    fn a_short_buffer_is_rejected_and_not_partially_written() {
        let need = m_prime_len(H1, b"", b"m").expect("len");
        let mut storage = [0u8; 64];
        let buf = &mut storage[..need - 1];
        let err = write_m_prime(buf, H1, b"", b"m").unwrap_err();
        assert_eq!(
            err,
            Error::OutputBufferTooSmall {
                needed: need,
                actual: need - 1
            }
        );
        assert!(buf.iter().all(|b| *b == 0), "must not partially write");
    }

    // Uses the allocating `m_prime` wrapper.
    #[cfg(feature = "alloc")]
    #[test]
    fn different_labels_give_different_bindings() {
        const H3: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";
        assert_ne!(
            m_prime(H1, b"", b"m").unwrap(),
            m_prime(H3, b"", b"m").unwrap()
        );
    }
}
