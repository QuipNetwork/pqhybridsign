// SPDX-License-Identifier: AGPL-3.0-or-later
//! Component seed derivation, specification section 9.
//!
//! A hybrid key starts from one master seed; this module expands it into the
//! independent classical and post-quantum component seeds via HKDF, keeping
//! the two components' key material from ever overlapping.

use crate::error::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF salt from specification section 9.
const SALT: &[u8] = b"hybrid-sig";
/// Info prefix for the classical component.
const CLASSICAL_INFO_PREFIX: &[u8] = b"classical/";
/// Info prefix for the post-quantum component.
const PQ_INFO_PREFIX: &[u8] = b"pq/";
/// Longest label in the registry is 43 bytes. 64 leaves headroom.
const MAX_INFO: usize = 64 + 16;

/// Expand a master seed into the two component seeds.
///
/// `info` binds the suite label, as specification section 9 requires, so
/// two suites derived from one master seed produce independent keys.
/// `label` must be the full null-terminated registry value, exactly as it
/// appears in `M'`.
///
/// This differs from the deployed `quip-crypto-primitives`, which uses a
/// fixed info value for every suite. See QuipNetwork/quip-protocol-rs#9.
pub fn derive_component_seeds(
    master: &[u8; 32],
    label: &[u8],
    classical_out: &mut [u8; 32],
    pq_out: &mut [u8],
) -> Result<()> {
    // `Hkdf::new` is `extract(..).1`: it materializes the pseudorandom key
    // and drops the copy without wiping it. Extracting explicitly puts that
    // copy in a local this function can wipe. The PRK is worth more than
    // either component seed, because it is not label-bound -- whoever holds
    // it can re-expand `classical/<label>` and `pq/<label>` for every suite,
    // not just this one.
    //
    // Residual, recorded rather than glossed over: the `Hkdf` value below
    // holds the same key as an `hmac` 0.12 `HmacCore`, whose primed ipad and
    // opad states expand exactly what the PRK expands. `hmac` implements
    // neither `Drop` nor `Zeroize` on that type and exposes no field to
    // reach, so this function cannot wipe it, and neither can any caller.
    // Wiping the PRK removes one of the two copies, not both.
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(SALT), master);
    // `as_mut_slice` rather than `prk.zeroize()`: the PRK is a
    // `GenericArray`, and `zeroize` implements the trait for byte slices
    // without needing its optional `generic-array` integration.
    prk.as_mut_slice().zeroize();

    let mut info = [0u8; MAX_INFO];
    let write_info = |info: &mut [u8; MAX_INFO], prefix: &[u8]| -> Result<usize> {
        let n = prefix.len() + label.len();
        if n > MAX_INFO {
            return Err(Error::OutputBufferTooSmall {
                needed: n,
                actual: MAX_INFO,
            });
        }
        info[..prefix.len()].copy_from_slice(prefix);
        info[prefix.len()..n].copy_from_slice(label);
        Ok(n)
    };

    let n = write_info(&mut info, CLASSICAL_INFO_PREFIX)?;
    hk.expand(&info[..n], classical_out)
        .map_err(|_| Error::ComponentFailure)?;

    let n = write_info(&mut info, PQ_INFO_PREFIX)?;
    let result = hk
        .expand(&info[..n], pq_out)
        .map_err(|_| Error::ComponentFailure);
    info.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";
    const H3: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";

    fn seeds(master: &[u8; 32], label: &[u8]) -> ([u8; 32], [u8; 32]) {
        let (mut c, mut p) = ([0u8; 32], [0u8; 32]);
        derive_component_seeds(master, label, &mut c, &mut p).expect("derive");
        (c, p)
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(seeds(&[9u8; 32], H1), seeds(&[9u8; 32], H1));
    }

    #[test]
    fn classical_and_pq_seeds_differ() {
        let (c, p) = seeds(&[9u8; 32], H1);
        assert_ne!(c, p, "info strings must separate the two components");
    }

    #[test]
    fn suites_derive_independent_trees() {
        // Specification section 9: without suite separation two suites from
        // one master seed collide. For H5/H6 that collision means leaf reuse.
        assert_ne!(seeds(&[9u8; 32], H1), seeds(&[9u8; 32], H3));
    }

    #[test]
    fn different_master_seeds_differ() {
        assert_ne!(seeds(&[1u8; 32], H1), seeds(&[2u8; 32], H1));
    }

    #[test]
    fn pq_output_length_is_caller_chosen() {
        let (mut c, mut p) = ([0u8; 32], [0u8; 48]);
        derive_component_seeds(&[3u8; 32], H1, &mut c, &mut p).expect("48-byte pq seed");
        assert!(p.iter().any(|b| *b != 0));
    }
}
