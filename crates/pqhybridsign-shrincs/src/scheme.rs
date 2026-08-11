// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`ShrincsScheme`]: the [`PqStatefulScheme`] implementation that lets H5
//! and H6 (declared in `suites.rs`) sign and verify through
//! `pqhybridsign_core::stateful_composite`'s generic driver.
//!
//! Everything SHRINCS-specific lives here: the commitment bundle, the
//! `ActionContext` mapping, and the flat wire encoding of a single
//! component signature. The generic driver in `pqhybridsign_core` never
//! sees any of it -- only the opaque `vk`/`sk`/`msg`/`sig` byte buffers this
//! trait's methods take and return.
//!
//! # Why the component signature is flattened by hand
//!
//! `hashsigs_rs::shrincs::Signature::to_bytes()` and
//! `sphincs_plus_c::Signature::to_bytes()` use upstream's Solidity ABI
//! encoding (`abi.encode`) -- offsets, padding, dynamic-array length words.
//! Re-deriving that framing by hand would be needless risk for a format we
//! do not need to interoperate with: `pqhybridsign_core::encoding_path` is
//! *our* composite wire format (specification section 6), not upstream's.
//! Every field these signatures carry is a public struct field (`pub
//! randomizer`, `pub chains`, ...; confirmed against the pinned upstream
//! source, `.superpowers/sdd/shrincs-api-reference.md`), so flattening them
//! into `randomizer || counter || fixed-count fields` is a direct
//! byte-for-byte reading of already-public data, not a reimplementation of
//! upstream's own codec.

use hashsigs_rs::shrincs::{
    Keys, PublicKey as ShrincsBundlePublicKey, ShrincsSigner, ShrincsVerifier,
};
use pqhybridsign_core::rotation::RotationPayload;
use pqhybridsign_core::{Error, PqStatefulScheme, Result};
use subtle::Choice;
use zeroize::Zeroize;

use crate::{action, bundle};

/// Marker type implementing [`PqStatefulScheme`] for SHRINCS.
#[derive(Clone, Copy, Debug)]
pub struct ShrincsScheme;

/// Offset of the 32-byte `publicKeyCommitment` field inside a
/// [`bundle::BUNDLE_LEN`]-byte SHRINCS bundle (`statefulPublicKey(68) ||
/// commitment(32) || ...`).
const BUNDLE_COMMITMENT_OFFSET: usize = 68;

/// Upper bound on `max_stateful_signatures`, mirroring upstream's
/// `pub(crate) MAX_STATEFUL_SIGNATURES_LIMIT` (`hashsigs_rs`
/// `src/shrincs/uxmss.rs:39`, unreachable from outside that crate). Kept in
/// sync by `tests::keygen_rejects_max_signatures_over_the_limit`.
const MAX_STATEFUL_SIGNATURES_LIMIT: u32 = 4096;

// ---------------------------------------------------------------------
// Profile-derived wire-format geometry, computed from `hashsigs_rs`' own
// re-exported profile constants so it stays correct across every profile
// without hardcoding per-profile numbers.
// ---------------------------------------------------------------------

const HASH_LEN: usize = hashsigs_rs::HASH_LEN;
const NUM_WOTS_CHAINS: usize = hashsigs_rs::shrincs::NUM_WOTS_CHAINS as usize;
const NUM_FORS_TREES: usize = hashsigs_rs::shrincs::NUM_FORS_TREES as usize;
const FORS_TREE_HEIGHT: usize = hashsigs_rs::shrincs::FORS_TREE_HEIGHT as usize;
const NUM_HYPERTREE_LAYERS: usize = hashsigs_rs::shrincs::NUM_HYPERTREE_LAYERS as usize;
const HYPERTREE_HEIGHT: usize = hashsigs_rs::shrincs::HYPERTREE_HEIGHT as usize;
const SUBTREE_HEIGHT: usize = HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS;

/// `randomizer(32) || counter(4) || chains(NUM_WOTS_CHAINS * 32)`: the
/// WOTS-C signature body shared by the stateful (UXMSS) fast path and every
/// hypertree layer of the stateless path.
const WOTS_C_SIG_LEN: usize = HASH_LEN + 4 + NUM_WOTS_CHAINS * HASH_LEN;

const FIXED_STATEFUL_LEN: usize = WOTS_C_SIG_LEN;

/// FORS-C reveals `NUM_FORS_TREES - 1` entries (the omitted final tree must
/// select leaf 0; see `hashsigs_rs::sphincs_plus_c::fors_c`).
const FORS_LEN: usize =
    HASH_LEN + 4 + (NUM_FORS_TREES - 1) * (HASH_LEN + FORS_TREE_HEIGHT * HASH_LEN);
const HYPERTREE_LEN: usize =
    NUM_HYPERTREE_LAYERS * (HASH_LEN + WOTS_C_SIG_LEN + SUBTREE_HEIGHT * HASH_LEN);
const STATELESS_LEN: usize = FORS_LEN + HYPERTREE_LEN;

/// The composite SHRINCS secret key: `Keys` plus its own `Zeroize`, since
/// upstream's `Keys` does not implement the trait itself.
///
/// The key lives in an `Option` so that `zeroize` can take it and drop it.
/// Upstream exposes no way to wipe a `Keys` in place -- both private halves
/// sit behind immutable accessors -- but each half is `ZeroizeOnDrop`, so
/// dropping the value is what actually clears the secret material. Taking the
/// `Option` is therefore a real wipe, not a gesture.
///
/// A wiped key is unusable rather than silently wrong: every accessor below
/// fails closed. That is the point of calling `zeroize` early.
pub struct ShrincsSecretKey {
    keys: Option<Keys>,
}

impl ShrincsSecretKey {
    /// Borrow the key material, or fail if it was already wiped.
    fn keys(&self) -> Result<&Keys> {
        self.keys.as_ref().ok_or(Error::ComponentFailure)
    }

    /// Mutably borrow the key material, or fail if it was already wiped.
    fn keys_mut(&mut self) -> Result<&mut Keys> {
        self.keys.as_mut().ok_or(Error::ComponentFailure)
    }
}

impl Zeroize for ShrincsSecretKey {
    fn zeroize(&mut self) {
        // Dropping the taken value runs `ZeroizeOnDrop` on both private
        // halves, which is the only wipe upstream makes reachable.
        drop(self.keys.take());
    }
}

impl PqStatefulScheme for ShrincsScheme {
    #[cfg(feature = "profile-256s")]
    const NAME: &'static str = "shrincs-256s";
    #[cfg(feature = "profile-256s-sha2")]
    const NAME: &'static str = "shrincs-256s-sha2";
    #[cfg(feature = "profile-128s-q18")]
    const NAME: &'static str = "shrincs-128s-q18";
    #[cfg(feature = "profile-128s-q20")]
    const NAME: &'static str = "shrincs-128s-q20";

    const SEED_LEN: usize = 32;
    /// Stored form: a 32-byte commitment.
    const PUBLIC_KEY_LEN: usize = 32;
    /// Verify form: the full commitment bundle.
    const VERIFY_KEY_LEN: usize = bundle::BUNDLE_LEN;
    const SECRET_KEY_LEN: usize = hashsigs_rs::shrincs::key::KEYS_BYTES;
    const LEAF_CAPACITY_LIMIT: u32 = MAX_STATEFUL_SIGNATURES_LIMIT;
    const FIXED_STATEFUL_SIG_LEN: usize = FIXED_STATEFUL_LEN;
    const STATELESS_SIG_LEN: usize = STATELESS_LEN;
    /// Specification section 21: `2^20`, except `2^18` under
    /// `profile-128s-q18`.
    #[cfg(not(feature = "profile-128s-q18"))]
    const STATELESS_BUDGET: u64 = 1 << 20;
    #[cfg(feature = "profile-128s-q18")]
    const STATELESS_BUDGET: u64 = 1 << 18;

    type SecretKey = ShrincsSecretKey;

    fn keygen_from_seed(
        seed: &[u8],
        max_signatures: u32,
        vk_out: &mut [u8],
    ) -> Result<Self::SecretKey> {
        if vk_out.len() != bundle::BUNDLE_LEN {
            return Err(Error::BadLength {
                expected: bundle::BUNDLE_LEN,
                actual: vk_out.len(),
            });
        }
        if max_signatures == 0 || max_signatures > MAX_STATEFUL_SIGNATURES_LIMIT {
            return Err(Error::ComponentFailure);
        }
        let (keys, public_key) =
            ShrincsSigner::keygen(seed, max_signatures).ok_or(Error::ComponentFailure)?;
        write_bundle(&public_key, vk_out);
        Ok(ShrincsSecretKey { keys: Some(keys) })
    }

    fn leaf_capacity(sk: &Self::SecretKey) -> u32 {
        // A wiped key has no remaining budget. Zero is the fail-closed
        // answer: the generic driver compares it against the next leaf and
        // refuses to sign.
        match sk.keys() {
            Ok(keys) => keys.stateful().public_key().max_signatures,
            Err(_) => 0,
        }
    }

    fn next_leaf(sk: &Self::SecretKey) -> u32 {
        // Upstream's `next_leaf_index` is 1-based (starts at 1); the
        // generic driver and `LeafJournal` use the 0-based convention
        // ("for a fresh key this is 0"). Normalize here, once, rather than
        // asking every caller to know upstream's off-by-one.
        match sk.keys() {
            Ok(keys) => keys.stateful().next_leaf_index().saturating_sub(1),
            // A wiped key reports no progress; `leaf_capacity` returns 0 for
            // the same key, so the driver sees an exhausted budget and stops.
            Err(_) => 0,
        }
    }

    /// Exports upstream's own `Keys::to_bytes` form: `stateful(136) ||
    /// stateless(128)`, where the stateful half ends in `maxSignatures(4) ||
    /// nextLeafIndex(4)`. The counter travels inside that blob verbatim, so
    /// an exhausted key exports its exhausted counter.
    fn export_secret_key(sk: &Self::SecretKey, out: &mut [u8]) -> Result<()> {
        if out.len() != Self::SECRET_KEY_LEN {
            return Err(Error::BadLength {
                expected: Self::SECRET_KEY_LEN,
                actual: out.len(),
            });
        }
        // `keys()` is what makes a wiped key export as an error rather than
        // as zeros.
        let mut blob = sk.keys()?.to_bytes();
        out.copy_from_slice(&blob);
        blob.zeroize();
        Ok(())
    }

    /// Validation is upstream's `Keys::import`, which re-derives the
    /// hypertree root and the stateless public key from the private seeds
    /// the blob carries and compares them against the public fields it also
    /// carries. A tampered root, a field spliced in from another key, and a
    /// counter outside `1..=maxSignatures + 1` are all rejected there. This
    /// crate does not re-implement any of it.
    fn import_secret_key(bytes: &[u8]) -> Result<Self::SecretKey> {
        if bytes.len() != Self::SECRET_KEY_LEN {
            return Err(Error::BadLength {
                expected: Self::SECRET_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let keys = Keys::import(bytes).ok_or(Error::ComponentFailure)?;
        Ok(ShrincsSecretKey { keys: Some(keys) })
    }

    fn precheck(msg: &[u8]) -> bool {
        let ctx = action::to_action_context(msg, [0u8; 32], [0u8; 32]);
        action::valid_action_context(&ctx)
    }

    fn max_stateful_sig_len(max_signatures: u32) -> usize {
        FIXED_STATEFUL_LEN + max_signatures as usize * 32
    }

    fn sign_stateful(
        sk: &mut Self::SecretKey,
        vk: &[u8],
        msg: &[u8],
        sig_out: &mut [u8],
    ) -> Result<usize> {
        let public_key = parse_bundle(vk)?;
        let action_ctx = action::to_action_context(msg, [0u8; 32], [0u8; 32]);
        // Nothing validates the `ActionContext` ahead of this call, and that
        // is deliberate: `sign_stateful_action` spends the leaf, and an
        // invalid context must consume it like any other attempt rather than
        // get a free retry. Validating first would create a signing path
        // that returns without advancing the counter, which is the
        // leaf-reuse hazard this ordering exists to remove.
        let sig = ShrincsSigner::sign_stateful_action(sk.keys_mut()?, &public_key, &action_ctx)
            .ok_or(Error::ComponentFailure)?;
        // The leaf is spent now, and both counters have advanced. Validate
        // here so the caller gets a real error instead of a signature that
        // could never verify. The leaf stays spent either way.
        if !action::valid_action_context(&action_ctx) {
            return Err(Error::ComponentFailure);
        }
        write_flat_stateful(&sig, sig_out)
    }

    fn sign_stateless(sk: &Self::SecretKey, msg: &[u8], sig_out: &mut [u8]) -> Result<usize> {
        let action_ctx = action::to_action_context(msg, [0u8; 32], [0u8; 32]);
        let keys = sk.keys()?;
        let commitment = *keys.public_key_commitment().as_bytes();
        let message = ShrincsVerifier::new().stateless_action_message_hash(commitment, &action_ctx);
        let sig =
            ShrincsSigner::sign_stateless_raw(keys, &message).ok_or(Error::ComponentFailure)?;
        write_flat_stateless(&sig, sig_out)
    }

    fn verify_stateful(vk: &[u8], msg: &[u8], sig: &[u8]) -> Choice {
        let Some((commitment, public_key)) = verify_bundle_self_consistent(vk) else {
            return Choice::from(0u8);
        };
        let Some(shrincs_sig) = read_flat_stateful(sig) else {
            return Choice::from(0u8);
        };
        let action_ctx = action::to_action_context(msg, [0u8; 32], [0u8; 32]);
        Choice::from(u8::from(ShrincsVerifier::new().verify_stateful(
            commitment,
            &public_key,
            &action_ctx,
            &shrincs_sig,
        )))
    }

    fn verify_stateless(vk: &[u8], msg: &[u8], sig: &[u8]) -> Choice {
        let Some((commitment, public_key)) = verify_bundle_self_consistent(vk) else {
            return Choice::from(0u8);
        };
        let Some(shrincs_sig) = read_flat_stateless(sig) else {
            return Choice::from(0u8);
        };
        let action_ctx = action::to_action_context(msg, [0u8; 32], [0u8; 32]);
        Choice::from(u8::from(ShrincsVerifier::new().verify_stateless(
            commitment,
            &public_key,
            &action_ctx,
            &shrincs_sig,
        )))
    }

    /// Signs on the stateless path, same as [`Self::sign_stateless`], but
    /// with `action_ctx.domain_separator` replacing
    /// [`action::HYBRID_DOMAIN_SEPARATOR`] with
    /// [`action::rotation_domain_separator`] -- bound to
    /// `payload.next_classical_pk` and `payload.kind`. That binding is what
    /// makes the resulting signature unusable against a different
    /// `NextClassicalPK`; see `crate::action::to_rotation_action_context`
    /// and specification section 19.2.
    fn sign_stateless_rotation(
        sk: &Self::SecretKey,
        payload: &RotationPayload,
        m_prime_rotation: &[u8],
        sig_out: &mut [u8],
    ) -> Result<usize> {
        let action_ctx = action::to_rotation_action_context(
            m_prime_rotation,
            &payload.next_classical_pk,
            payload.kind,
            [0u8; 32],
            [0u8; 32],
        );
        let keys = sk.keys()?;
        let commitment = *keys.public_key_commitment().as_bytes();
        let message = ShrincsVerifier::new().stateless_action_message_hash(commitment, &action_ctx);
        let sig =
            ShrincsSigner::sign_stateless_raw(keys, &message).ok_or(Error::ComponentFailure)?;
        write_flat_stateless(&sig, sig_out)
    }

    fn verify_stateless_rotation(
        vk: &[u8],
        payload: &RotationPayload,
        m_prime_rotation: &[u8],
        sig: &[u8],
    ) -> Choice {
        let Some((commitment, public_key)) = verify_bundle_self_consistent(vk) else {
            return Choice::from(0u8);
        };
        let Some(shrincs_sig) = read_flat_stateless(sig) else {
            return Choice::from(0u8);
        };
        let action_ctx = action::to_rotation_action_context(
            m_prime_rotation,
            &payload.next_classical_pk,
            payload.kind,
            [0u8; 32],
            [0u8; 32],
        );
        Choice::from(u8::from(ShrincsVerifier::new().verify_stateless(
            commitment,
            &public_key,
            &action_ctx,
            &shrincs_sig,
        )))
    }

    /// Returns the 64 contiguous bytes at
    /// [`bundle::STATELESS_KEY_MATERIAL_OFFSET`]: `pkSeed || hypertreeRoot`,
    /// never the commitment field that sits before them and that rotation
    /// changes on every install.
    fn stateless_key_material(vk: &[u8]) -> Result<&[u8]> {
        if vk.len() != bundle::BUNDLE_LEN {
            return Err(Error::BadLength {
                expected: bundle::BUNDLE_LEN,
                actual: vk.len(),
            });
        }
        Ok(&vk[bundle::STATELESS_KEY_MATERIAL_OFFSET
            ..bundle::STATELESS_KEY_MATERIAL_OFFSET + bundle::STATELESS_KEY_MATERIAL_LEN])
    }
}

/// Flatten a `hashsigs_rs::shrincs::PublicKey` into the
/// [`bundle::BUNDLE_LEN`]-byte bundle layout `statefulPublicKey(68) ||
/// commitment(32) || pkSeed(32) || hypertreeRoot(32)`.
fn write_bundle(pk: &ShrincsBundlePublicKey, out: &mut [u8]) {
    debug_assert_eq!(out.len(), bundle::BUNDLE_LEN);
    let mut at = 0;
    for field in [
        &pk.stateful_public_key,
        &pk.public_key_commitment,
        &pk.pk_seed,
        &pk.hypertree_root,
    ] {
        out[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
}

/// Parse a trusted (self-produced) bundle into a `PublicKey`, without
/// re-verifying the commitment. Used on the signing side, where `vk` is
/// always the caller's own cached verify key, never attacker-supplied.
fn parse_bundle(vk: &[u8]) -> Result<ShrincsBundlePublicKey> {
    if vk.len() != bundle::BUNDLE_LEN {
        return Err(Error::BadLength {
            expected: bundle::BUNDLE_LEN,
            actual: vk.len(),
        });
    }
    Ok(ShrincsBundlePublicKey {
        stateful_public_key: vk[..BUNDLE_COMMITMENT_OFFSET].to_vec(),
        public_key_commitment: vk[BUNDLE_COMMITMENT_OFFSET..BUNDLE_COMMITMENT_OFFSET + 32].to_vec(),
        pk_seed: vk[BUNDLE_COMMITMENT_OFFSET + 32..BUNDLE_COMMITMENT_OFFSET + 64].to_vec(),
        hypertree_root: vk[BUNDLE_COMMITMENT_OFFSET + 64..BUNDLE_COMMITMENT_OFFSET + 96].to_vec(),
    })
}

/// Parse and self-verify a possibly-untrusted `vk` on the verification
/// side: recomputes the commitment from the bundle and rejects any
/// mismatch (`bundle::verify_bundle`), so a single tampered byte anywhere
/// in `vk` is caught here rather than silently accepted.
fn verify_bundle_self_consistent(vk: &[u8]) -> Option<([u8; 32], ShrincsBundlePublicKey)> {
    if vk.len() != bundle::BUNDLE_LEN {
        return None;
    }
    let mut stored_commitment = [0u8; 32];
    stored_commitment.copy_from_slice(&vk[BUNDLE_COMMITMENT_OFFSET..BUNDLE_COMMITMENT_OFFSET + 32]);
    let public_key = bundle::verify_bundle(vk, &stored_commitment).ok()?;
    Some((stored_commitment, public_key))
}

fn write_flat_stateful(sig: &hashsigs_rs::shrincs::Signature, sig_out: &mut [u8]) -> Result<usize> {
    let needed = FIXED_STATEFUL_LEN + sig.auth_path.len() * 32;
    if sig_out.len() < needed {
        return Err(Error::OutputBufferTooSmall {
            needed,
            actual: sig_out.len(),
        });
    }
    let mut at = 0;
    write_bytes(sig_out, &mut at, &sig.randomizer);
    write_bytes(sig_out, &mut at, &sig.counter.to_be_bytes());
    for chain in &sig.chains {
        write_bytes(sig_out, &mut at, chain);
    }
    for node in &sig.auth_path {
        write_bytes(sig_out, &mut at, node);
    }
    Ok(at)
}

fn write_flat_stateless(
    sig: &hashsigs_rs::shrincs::StatelessSignature,
    sig_out: &mut [u8],
) -> Result<usize> {
    if sig_out.len() < STATELESS_LEN {
        return Err(Error::OutputBufferTooSmall {
            needed: STATELESS_LEN,
            actual: sig_out.len(),
        });
    }
    let mut at = 0;
    write_bytes(sig_out, &mut at, &sig.fors.randomizer);
    write_bytes(sig_out, &mut at, &sig.fors.counter.to_be_bytes());
    for entry in &sig.fors.entries {
        write_bytes(sig_out, &mut at, &entry.secret_leaf);
        for node in &entry.auth_path {
            write_bytes(sig_out, &mut at, node);
        }
    }
    for layer in &sig.hypertree {
        write_bytes(sig_out, &mut at, &layer.wots_c_pk_hash);
        write_bytes(sig_out, &mut at, &layer.wots_c_signature.randomizer);
        write_bytes(
            sig_out,
            &mut at,
            &layer.wots_c_signature.counter.to_be_bytes(),
        );
        for chain in &layer.wots_c_signature.chains {
            write_bytes(sig_out, &mut at, chain);
        }
        for node in &layer.auth_path {
            write_bytes(sig_out, &mut at, node);
        }
    }
    Ok(at)
}

fn write_bytes(out: &mut [u8], at: &mut usize, bytes: &[u8]) {
    out[*at..*at + bytes.len()].copy_from_slice(bytes);
    *at += bytes.len();
}

fn read_flat_stateful(bytes: &[u8]) -> Option<hashsigs_rs::shrincs::Signature> {
    if bytes.len() < FIXED_STATEFUL_LEN || (bytes.len() - FIXED_STATEFUL_LEN) % HASH_LEN != 0 {
        return None;
    }
    let mut at = 0;
    let randomizer = read_hash(bytes, &mut at)?;
    let counter = read_u32(bytes, &mut at)?;
    let chains = read_hashes(bytes, &mut at, NUM_WOTS_CHAINS)?;
    let remaining = (bytes.len() - at) / HASH_LEN;
    let auth_path = read_hashes(bytes, &mut at, remaining)?;
    Some(hashsigs_rs::shrincs::Signature {
        randomizer,
        counter,
        chains,
        auth_path,
    })
}

fn read_flat_stateless(bytes: &[u8]) -> Option<hashsigs_rs::shrincs::StatelessSignature> {
    if bytes.len() != STATELESS_LEN {
        return None;
    }
    let mut at = 0;

    let randomizer = read_hash(bytes, &mut at)?;
    let counter = read_u32(bytes, &mut at)?;
    let mut entries = Vec::with_capacity(NUM_FORS_TREES - 1);
    for _ in 0..NUM_FORS_TREES - 1 {
        let secret_leaf = read_hash(bytes, &mut at)?;
        let auth_path = read_hashes(bytes, &mut at, FORS_TREE_HEIGHT)?;
        entries.push(hashsigs_rs::sphincs_plus_c::ForsEntry {
            secret_leaf,
            auth_path,
        });
    }
    let fors = hashsigs_rs::sphincs_plus_c::ForsSignature {
        randomizer,
        counter,
        entries,
    };

    let mut hypertree = Vec::with_capacity(NUM_HYPERTREE_LAYERS);
    for _ in 0..NUM_HYPERTREE_LAYERS {
        let wots_c_pk_hash = read_hash(bytes, &mut at)?;
        let wots_randomizer = read_hash(bytes, &mut at)?;
        let wots_counter = read_u32(bytes, &mut at)?;
        let chains = read_hashes(bytes, &mut at, NUM_WOTS_CHAINS)?;
        let auth_path = read_hashes(bytes, &mut at, SUBTREE_HEIGHT)?;
        hypertree.push(hashsigs_rs::sphincs_plus_c::LayerSignature {
            wots_c_pk_hash,
            wots_c_signature: hashsigs_rs::wots_c::Signature {
                randomizer: wots_randomizer,
                counter: wots_counter,
                chains,
            },
            auth_path,
        });
    }

    debug_assert_eq!(at, STATELESS_LEN);
    Some(hashsigs_rs::shrincs::StatelessSignature { fors, hypertree })
}

fn read_hash(bytes: &[u8], at: &mut usize) -> Option<[u8; HASH_LEN]> {
    let slice = bytes.get(*at..*at + HASH_LEN)?;
    *at += HASH_LEN;
    <[u8; HASH_LEN]>::try_from(slice).ok()
}

fn read_u32(bytes: &[u8], at: &mut usize) -> Option<u32> {
    let slice = bytes.get(*at..*at + 4)?;
    *at += 4;
    Some(u32::from_be_bytes(<[u8; 4]>::try_from(slice).ok()?))
}

fn read_hashes(bytes: &[u8], at: &mut usize, count: usize) -> Option<Vec<[u8; HASH_LEN]>> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_hash(bytes, at)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x11; 32];

    #[test]
    fn keygen_rejects_max_signatures_over_the_limit() {
        let mut vk = [0u8; bundle::BUNDLE_LEN];
        assert!(ShrincsScheme::keygen_from_seed(&SEED, 0, &mut vk).is_err());
        assert!(
            ShrincsScheme::keygen_from_seed(&SEED, MAX_STATEFUL_SIGNATURES_LIMIT + 1, &mut vk)
                .is_err()
        );
    }

    /// `zeroize` must actually drop the key material, not merely satisfy the
    /// trait. Wiping is observable only through behaviour, so this asserts
    /// the fail-closed contract every accessor promises.
    ///
    /// Calls `keygen_from_seed`, which costs about 47 seconds at the 128s
    /// profiles. The fail-closed contract does not depend on the parameter
    /// set, so this test runs under the default profile only.
    #[cfg(feature = "profile-256s")]
    #[test]
    fn zeroize_wipes_the_key_and_every_accessor_fails_closed() {
        let mut vk = [0u8; bundle::BUNDLE_LEN];
        let mut sk = ShrincsScheme::keygen_from_seed(&SEED, 4, &mut vk).expect("keygen");

        // Live key: the budget is real and one stateful signature works.
        assert_eq!(ShrincsScheme::leaf_capacity(&sk), 4);
        let mut sig = vec![0u8; ShrincsScheme::max_stateful_sig_len(4)];
        assert!(ShrincsScheme::sign_stateful(&mut sk, &vk, b"before", &mut sig).is_ok());

        sk.zeroize();

        // Wiped key: no budget, no progress, and neither signing path runs.
        assert_eq!(
            ShrincsScheme::leaf_capacity(&sk),
            0,
            "a wiped key must report an exhausted budget"
        );
        assert_eq!(ShrincsScheme::next_leaf(&sk), 0);
        assert!(
            ShrincsScheme::sign_stateful(&mut sk, &vk, b"after", &mut sig).is_err(),
            "stateful signing must fail on a wiped key"
        );
        let mut stateless = vec![0u8; ShrincsScheme::STATELESS_SIG_LEN];
        assert!(
            ShrincsScheme::sign_stateless(&sk, b"after", &mut stateless).is_err(),
            "stateless signing must fail on a wiped key, and must fail before \
             it starts grinding"
        );

        // Wiping twice is not an error.
        sk.zeroize();
        assert_eq!(ShrincsScheme::leaf_capacity(&sk), 0);
    }

    /// Pins `stateless_key_material` to a byte range independently computed
    /// from the generated `PublicKey`'s own `pk_seed`/`hypertree_root`
    /// fields (not from `STATELESS_KEY_MATERIAL_OFFSET`), so a later change
    /// to the bundle layout that moves this range breaks this test loudly
    /// instead of silently keying the budget to the wrong bytes.
    ///
    /// Calls `keygen_from_seed`, which costs about 47 seconds at the 128s
    /// profiles. Bundle layout offsets are profile-independent at the
    /// composition layer checked here.
    #[cfg(feature = "profile-256s")]
    #[test]
    fn stateless_key_material_is_pk_seed_concatenated_with_hypertree_root() {
        let mut vk = [0u8; bundle::BUNDLE_LEN];
        ShrincsScheme::keygen_from_seed(&SEED, 4, &mut vk).expect("keygen");

        let public_key = parse_bundle(&vk).expect("parse trusted bundle");
        let mut expected = Vec::with_capacity(64);
        expected.extend_from_slice(&public_key.pk_seed);
        expected.extend_from_slice(&public_key.hypertree_root);
        assert_eq!(expected.len(), 64);

        let material = ShrincsScheme::stateless_key_material(&vk).expect("stateless key material");
        assert_eq!(material, expected.as_slice());
    }

    #[test]
    fn stateless_key_material_rejects_the_wrong_length() {
        assert_eq!(
            ShrincsScheme::stateless_key_material(&[0u8; 10]),
            Err(Error::BadLength {
                expected: bundle::BUNDLE_LEN,
                actual: 10,
            })
        );
    }

    /// Specification section 19.2: the rotation domain separator must bind
    /// `next_classical_pk` and `kind` *independently* of whatever message
    /// bytes a caller passes as `m_prime_rotation`.
    ///
    /// `pqhybridsign_core::rotation::verify_rotation` always builds
    /// `m_prime_rotation` itself, from the one `RotationPayload` both halves
    /// share, so its own front-running test cannot distinguish this
    /// method's domain-separator binding from the message-hash binding
    /// `m_prime_rotation` already provides -- confirmed by a manual
    /// mutation check (replacing this method's domain separator with the
    /// fixed `HYBRID_DOMAIN_SEPARATOR` left that test passing, since
    /// `m_prime_rotation` alone already differs whenever
    /// `next_classical_pk` does, for any caller that goes through
    /// `verify_rotation`). This test instead calls
    /// `sign_stateless_rotation`/`verify_stateless_rotation` directly with
    /// **identical** `m_prime_rotation` bytes across two different
    /// `next_classical_pk` values -- modelling a caller who (incorrectly)
    /// built the message from only the commitments, the exact failure mode
    /// section 19.2 warns about -- to prove the domain separator alone,
    /// not the message hash, is what closes it.
    ///
    /// Calls `keygen_from_seed` and `sign_stateless_rotation`, which cost
    /// minutes at the 128s profiles. Domain-separator binding does not
    /// depend on the SHRINCS parameter set.
    #[cfg(feature = "profile-256s")]
    #[test]
    fn domain_separator_alone_prevents_reuse_across_next_classical_pk() {
        use pqhybridsign_core::rotation::RotationKind;

        let seed = [0x55u8; 32];
        let mut vk = [0u8; bundle::BUNDLE_LEN];
        let sk = ShrincsScheme::keygen_from_seed(&seed, 1, &mut vk).expect("keygen");

        // Deliberately identical for both payloads below.
        let m_prime_rotation = b"commitments only, no next_classical_pk bound in";

        let payload_a = RotationPayload {
            kind: RotationKind::FullSwap,
            current_commitment: [1u8; 32],
            next_commitment: [2u8; 32],
            next_classical_pk: [0xAAu8; 32],
        };
        let mut payload_b = payload_a;
        payload_b.next_classical_pk = [0xBBu8; 32];

        let mut sig = vec![0u8; ShrincsScheme::STATELESS_SIG_LEN];
        ShrincsScheme::sign_stateless_rotation(&sk, &payload_a, m_prime_rotation, &mut sig)
            .expect("sign_stateless_rotation");

        assert!(
            bool::from(ShrincsScheme::verify_stateless_rotation(
                &vk,
                &payload_a,
                m_prime_rotation,
                &sig
            )),
            "the honest signature must still verify against its own payload"
        );
        assert!(
            !bool::from(ShrincsScheme::verify_stateless_rotation(
                &vk,
                &payload_b,
                m_prime_rotation,
                &sig
            )),
            "the same signature, over byte-for-byte identical message bytes, \
             must not verify once next_classical_pk changes -- the domain \
             separator, not the message hash, is what must catch this"
        );
    }
}
