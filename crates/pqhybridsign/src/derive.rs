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

/// Info prefix for hard-junction derivation. Distinct from `classical/` and
/// `pq/` above so a junction child can never collide with a component seed.
const JUNCTION_INFO_PREFIX: &[u8] = b"junction/hard/";
/// `JUNCTION_INFO_PREFIX` followed by a 32-byte chain code, with no length
/// prefix on either field: both are fixed-width, so unlike the
/// `classical/`/`pq/` labels above (which are caller-supplied and need the
/// `write_info` length check) there is no variable-length input here for a
/// length-prefix omission to make ambiguous.
const JUNCTION_INFO_LEN: usize = JUNCTION_INFO_PREFIX.len() + 32;

/// Info prefix for the dedicated hybrid-VRF stateless-binding seed
/// (specification section 20.3). Distinct from `classical/`, `pq/` above and
/// `junction/hard/` below in its very first byte, so no label of any length
/// can make this collide with either: a length-prefixed variable field and a
/// fixed-width one only need to differ somewhere to stay unambiguous, and
/// these differ at byte zero.
const VRF_STATELESS_INFO_PREFIX: &[u8] = b"vrf-stateless/";

/// Derives a master seed dedicated to one stateful suite's hybrid VRF
/// stateless binding, specification section 20.3.
///
/// # What this is for
///
/// EdSh and SrSh bind their hybrid VRF through the SHRINCS **stateless** path
/// (`vrf::sign_stateless`, behind the `vrf` feature -- named here rather
/// than linked because this module compiles whether or not that feature is
/// on, and rustdoc cannot resolve a link into a module that is not there),
/// which spends the same few-time budget
/// that key's rotation and recovery authorizations draw on
/// ([`crate::rotation::sign_rotation`]). Specification section 21 forbids
/// sharing that budget between ordinary signing and rotation/recovery, so a
/// deployment that evaluates a VRF frequently needs a **second** SHRINCS key
/// whose stateless material is disjoint from the identity key's -- not a
/// second counter over the same key (see [`crate::budget`]'s module
/// documentation for why a shared FORS-C key cannot be metered around: two
/// counters over one key permit more few-time signatures than the key's own
/// bound allows, which is a worse violation than an unmetered shared counter).
///
/// This function derives the master seed for that second key. Run it through
/// an ordinary [`crate::stateful_composite::keygen`] the same way any other
/// master seed is, and the result is a full, independent stateful-suite
/// keypair -- its own classical secret and its own SHRINCS commitment -- with
/// no key material in common with whatever `keygen` on the *parent* seed
/// produces for the same suite.
///
/// # Opt-in
///
/// Nothing calls this from an ordinary keygen path. A deployment that never
/// evaluates a VRF for this suite pays nothing for it: no second hypertree,
/// no change to the suite's `VERIFY_PUBLIC_KEY_LEN`, no change to the
/// identity key's exported secret-key blob. Only a caller that invokes this
/// function -- or that manages a dedicated stateless key by some other means
/// entirely, which is equally valid -- pays for the second key.
///
/// # Not a second allowance
///
/// The derived seed's key is bound by exactly the same few-time budget as
/// any other stateless key for this suite (`2^20`, or `2^18` under
/// `profile-128s-q18`). That bound follows from the profile's FORS-C
/// parameters, not from what the key is used for, so a dedicated key is not
/// a way to sign more; it is a way to stop one key's ordinary VRF use from
/// spending another key's rotation reserve.
///
/// # Errors
///
/// [`Error::OutputBufferTooSmall`] if `label` is long enough that the info
/// string overruns `MAX_INFO`, which no registry label comes close to doing.
/// [`Error::ComponentFailure`] if HKDF expansion fails, which does not
/// happen for any fixed-length output this crate requests.
pub fn derive_stateless_vrf_seed(master: &[u8; 32], label: &[u8]) -> Result<[u8; 32]> {
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(SALT), master);
    prk.as_mut_slice().zeroize();

    let n = VRF_STATELESS_INFO_PREFIX.len() + label.len();
    if n > MAX_INFO {
        return Err(Error::OutputBufferTooSmall {
            needed: n,
            actual: MAX_INFO,
        });
    }
    let mut info = [0u8; MAX_INFO];
    info[..VRF_STATELESS_INFO_PREFIX.len()].copy_from_slice(VRF_STATELESS_INFO_PREFIX);
    info[VRF_STATELESS_INFO_PREFIX.len()..n].copy_from_slice(label);

    let mut seed = [0u8; 32];
    let result = hk
        .expand(&info[..n], &mut seed)
        .map_err(|_| Error::ComponentFailure);
    info.zeroize();
    result.map(|()| seed)
}

/// Derives a new master seed from a parent master seed and a hard-derivation
/// chain code, specification section 10.
///
/// # What this is for, and what it is not
///
/// Specification section 10 derives a junction from the whole hybrid suite
/// at once: a new *master seed*, from which [`derive_component_seeds`] then
/// re-derives both the classical and post-quantum components exactly as it
/// would for any other master seed. Soft junctions are rejected suite-wide
/// -- including for sr25519 constructions, which support soft derivation on
/// their own -- because no derived master seed exists for a soft junction:
/// soft derivation only ever produces a child public key, not a child
/// secret. That is why this module offers hard derivation only and has no
/// soft-derivation entry point.
///
/// The chain code is a raw 32 bytes. Mapping a junction string such as
/// `//alice` to a chain code is SCALE encoding and secret-URI parsing, and
/// stays in the Substrate integration that consumes this crate; this
/// function does not parse junction syntax.
///
/// # The re-keygen hazard this inherits from section 9
///
/// A hard-derived child for a stateful suite (EdSh, SrSh) is a **fresh SHRINCS
/// tree that starts at leaf 1**. Derivation is a deterministic function of
/// `(parent seed, chain code)`: deriving "the same child" a second time --
/// on a second host that also holds the parent seed, or by re-running
/// derivation after a restore -- reaches the identical child seed and
/// therefore the identical tree, again starting at leaf 1. That is the
/// section 9 re-keygen hazard, reached through derivation instead of through
/// re-import. A derived child MUST be derived once, then persisted and
/// restored through the validating import path; it MUST NOT be re-derived on
/// a second host. A key pool spanning multiple nodes MUST give each node its
/// own distinct junction, never the same junction re-derived on two hosts.
pub fn derive_hard_junction(parent_master: &[u8; 32], chain_code: &[u8; 32]) -> Result<[u8; 32]> {
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(SALT), parent_master);
    prk.as_mut_slice().zeroize();

    let mut info = [0u8; JUNCTION_INFO_LEN];
    info[..JUNCTION_INFO_PREFIX.len()].copy_from_slice(JUNCTION_INFO_PREFIX);
    info[JUNCTION_INFO_PREFIX.len()..].copy_from_slice(chain_code);

    let mut child = [0u8; 32];
    hk.expand(&info, &mut child)
        .map_err(|_| Error::ComponentFailure)?;
    Ok(child)
}

/// Holds a master seed so its wipe happens on drop, exactly as
/// `classical::sr25519::Wiped` does and for the same reason: a bare
/// `zeroize()` call stops covering the value the moment an early return is
/// added above it, so the wipe needs to be structural instead.
struct Wiped<T: Zeroize>(T);

impl<T: Zeroize> Drop for Wiped<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Applies a sequence of hard-derivation chain codes in order, each child
/// becoming the next parent, and returns the final master seed.
///
/// `[a, b]` derives `derive_hard_junction(derive_hard_junction(parent, a),
/// b)`, not the other order: path order is part of the derivation, the same
/// way a filesystem path's components are ordered. Every intermediate
/// master seed is wiped once the next one is derived from it; only the
/// final seed is returned, and wiping that one is the caller's
/// responsibility. See [`derive_hard_junction`] for the re-keygen hazard
/// that applies to every seed this function returns.
///
/// An empty `chain_codes` returns the parent master seed unchanged, which is
/// the identity a path of no junctions should have. Note what that means for
/// a caller that builds the path from parsed input: an empty path is not an
/// error here, so a parse that silently yielded no junctions hands back the
/// parent key rather than a child. Callers that require at least one junction
/// must check for that themselves.
pub fn derive_hard_junction_path(
    parent_master: &[u8; 32],
    chain_codes: &[[u8; 32]],
) -> Result<[u8; 32]> {
    let mut current = Wiped(*parent_master);
    for chain_code in chain_codes {
        let next = derive_hard_junction(&current.0, chain_code)?;
        current.0.zeroize();
        current.0 = next;
    }
    Ok(current.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED_ML44: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";
    const SR_ML44: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";

    fn seeds(master: &[u8; 32], label: &[u8]) -> ([u8; 32], [u8; 32]) {
        let (mut c, mut p) = ([0u8; 32], [0u8; 32]);
        derive_component_seeds(master, label, &mut c, &mut p).expect("derive");
        (c, p)
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(seeds(&[9u8; 32], ED_ML44), seeds(&[9u8; 32], ED_ML44));
    }

    #[test]
    fn classical_and_pq_seeds_differ() {
        let (c, p) = seeds(&[9u8; 32], ED_ML44);
        assert_ne!(c, p, "info strings must separate the two components");
    }

    #[test]
    fn suites_derive_independent_trees() {
        // Specification section 9: without suite separation two suites from
        // one master seed collide. For EdSh/SrSh that collision means leaf reuse.
        assert_ne!(seeds(&[9u8; 32], ED_ML44), seeds(&[9u8; 32], SR_ML44));
    }

    #[test]
    fn different_master_seeds_differ() {
        assert_ne!(seeds(&[1u8; 32], ED_ML44), seeds(&[2u8; 32], ED_ML44));
    }

    #[test]
    fn pq_output_length_is_caller_chosen() {
        let (mut c, mut p) = ([0u8; 32], [0u8; 48]);
        derive_component_seeds(&[3u8; 32], ED_ML44, &mut c, &mut p).expect("48-byte pq seed");
        assert!(p.iter().any(|b| *b != 0));
    }

    #[test]
    fn hard_junction_derivation_is_deterministic() {
        let first = derive_hard_junction(&[9u8; 32], &[7u8; 32]).expect("derive");
        let second = derive_hard_junction(&[9u8; 32], &[7u8; 32]).expect("derive");
        assert_eq!(first, second);
    }

    #[test]
    fn different_chain_codes_give_different_children() {
        let a = derive_hard_junction(&[9u8; 32], &[7u8; 32]).expect("derive");
        let b = derive_hard_junction(&[9u8; 32], &[8u8; 32]).expect("derive");
        assert_ne!(a, b);
    }

    #[test]
    fn a_hard_junction_child_differs_from_its_parent() {
        let parent = [9u8; 32];
        let child = derive_hard_junction(&parent, &[7u8; 32]).expect("derive");
        assert_ne!(child, parent);
    }

    #[test]
    fn hard_junction_path_order_matters() {
        let a = [7u8; 32];
        let b = [8u8; 32];
        let parent = [9u8; 32];

        let ab = derive_hard_junction_path(&parent, &[a, b]).expect("derive");
        let ba = derive_hard_junction_path(&parent, &[b, a]).expect("derive");

        assert_ne!(ab, ba, "[a, b] must differ from [b, a]");
    }

    #[test]
    fn hard_junction_path_matches_sequential_single_step_derivation() {
        let a = [7u8; 32];
        let b = [8u8; 32];
        let parent = [9u8; 32];

        let via_path = derive_hard_junction_path(&parent, &[a, b]).expect("derive");
        let via_steps =
            derive_hard_junction(&derive_hard_junction(&parent, &a).expect("derive"), &b)
                .expect("derive");

        assert_eq!(via_path, via_steps);
    }

    /// An empty path is the identity. Pinned because a caller that builds a
    /// path from parsed input and gets an empty one back receives its parent
    /// key, not a child, and that has to be a documented behaviour rather
    /// than an accident of the loop.
    #[test]
    fn an_empty_hard_junction_path_returns_the_parent() {
        let parent = [9u8; 32];
        assert_eq!(
            derive_hard_junction_path(&parent, &[]).expect("derive"),
            parent
        );
    }

    /// The `junction/hard/` info prefix exists so a junction child can never
    /// be the same value as a component seed derived from the same parent.
    /// Without a test the claim rests on reading two constants.
    #[test]
    fn a_junction_child_cannot_collide_with_a_component_seed() {
        let parent = [9u8; 32];
        let child = derive_hard_junction(&parent, &[7u8; 32]).expect("derive");
        let (classical, pq) = seeds(&parent, ED_ML44);
        assert_ne!(child, classical);
        assert_ne!(child, pq);
    }

    /// Known-answer vector computed independently of this code (a standalone
    /// HKDF-SHA256 extract/expand over `hkdf` 0.12, not this crate). Pins the
    /// domain string and the info layout so a change to either fails here,
    /// not just in a determinism test that could not tell them apart.
    #[test]
    fn the_hard_junction_layout_is_pinned() {
        let child = derive_hard_junction(&[9u8; 32], &[7u8; 32]).expect("derive");
        assert_eq!(
            hex::encode(child),
            "949e575e305f4aca84004570a6e023634ad491b113e280ee6fabe2cb72d06331"
        );
    }

    /// EdSh's registry label, exactly as `hybrid_stateful_suite!` declares it
    /// for the `shrincs-256s` classical/ed25519 suite: 30 ASCII bytes plus the
    /// trailing null the registry convention requires.
    const ED_SH_LABEL: &[u8] = b"hybrid-ed25519-shrincs-256s-v1\0";
    /// SrSh's registry label, the sr25519 counterpart of [`ED_SH_LABEL`].
    const SR_SH_LABEL: &[u8] = b"hybrid-sr25519-shrincs-256s-v1\0";

    #[test]
    fn stateless_vrf_seed_derivation_is_deterministic() {
        assert_eq!(
            derive_stateless_vrf_seed(&[9u8; 32], ED_SH_LABEL).expect("derive"),
            derive_stateless_vrf_seed(&[9u8; 32], ED_SH_LABEL).expect("derive")
        );
    }

    #[test]
    fn different_master_seeds_give_different_stateless_vrf_seeds() {
        assert_ne!(
            derive_stateless_vrf_seed(&[9u8; 32], ED_SH_LABEL).expect("derive"),
            derive_stateless_vrf_seed(&[1u8; 32], ED_SH_LABEL).expect("derive")
        );
    }

    /// EdSh and SrSh must derive independent dedicated stateless keys from one
    /// master seed, the same separation `suites_derive_independent_trees`
    /// checks for the ordinary component seeds.
    #[test]
    fn different_suite_labels_give_different_stateless_vrf_seeds() {
        assert_ne!(
            derive_stateless_vrf_seed(&[9u8; 32], ED_SH_LABEL).expect("derive"),
            derive_stateless_vrf_seed(&[9u8; 32], SR_SH_LABEL).expect("derive")
        );
    }

    /// The dedicated stateless-VRF seed must never collide with this suite's
    /// ordinary component seeds or with a hard-junction child of the same
    /// master seed: three independent uses of one master seed, three
    /// disjoint outputs.
    #[test]
    fn a_stateless_vrf_seed_cannot_collide_with_a_component_seed_or_a_junction_child() {
        let parent = [9u8; 32];
        let vrf_seed = derive_stateless_vrf_seed(&parent, ED_SH_LABEL).expect("derive");
        let (classical, pq) = seeds(&parent, ED_SH_LABEL);
        let junction_child = derive_hard_junction(&parent, &[7u8; 32]).expect("derive");

        assert_ne!(vrf_seed, classical);
        assert_ne!(vrf_seed, pq);
        assert_ne!(vrf_seed, junction_child);
    }

    /// Known-answer vector computed independently of this code (a standalone
    /// HKDF-SHA256 extract/expand implemented directly over Python's `hmac`
    /// and `hashlib`, not this crate or the `hkdf` crate). Pins the salt, the
    /// `vrf-stateless/` domain string and the info layout: `SALT ||
    /// "vrf-stateless/" || label`, HKDF-SHA256 extract-then-expand to 32
    /// bytes.
    #[test]
    fn the_stateless_vrf_seed_layout_is_pinned() {
        assert_eq!(
            hex::encode(derive_stateless_vrf_seed(&[9u8; 32], ED_SH_LABEL).expect("derive")),
            "f2b6ec75aef05751bf39adaa9edd24f4916b52ff068533ed4f767486bdade6a8"
        );
        assert_eq!(
            hex::encode(derive_stateless_vrf_seed(&[9u8; 32], SR_SH_LABEL).expect("derive")),
            "45639b3bed9d951c52afcb2df79dc1f7ad0ea571e304baa1da51d17b4f7abdd7"
        );
        let mut sequential = [0u8; 32];
        for (i, b) in sequential.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            hex::encode(derive_stateless_vrf_seed(&sequential, ED_SH_LABEL).expect("derive")),
            "29e1268fd5928311c416ab6039a7d87df30c1fab2d8251e5d8c05acabd48f9f2"
        );
    }
}
