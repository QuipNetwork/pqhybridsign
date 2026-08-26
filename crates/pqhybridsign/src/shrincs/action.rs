// SPDX-License-Identifier: AGPL-3.0-or-later
//! Maps the hybrid bound message `M'` into the SHRINCS signer's
//! `ActionContext` (specification section 7.1).
//!
//! `ActionContext` carries five 32-byte fields. Cross-suite and
//! cross-profile separation is carried entirely by `payload_hash` (`M'`
//! already embeds the suite label, specification section 7.1) and by the
//! public-key commitment, which is never shared across suites. That is why
//! `domain_separator` and `action_type` below are fixed constants shared
//! across every EdSh/SrSh suite and profile combination rather than varying per
//! suite.
//!
//! # Leaf-consuming signatures: the attempt spends the leaf
//!
//! `hashsigs_rs::shrincs::ShrincsSigner::sign_stateful_action` does not
//! validate its `ActionContext` argument before signing (confirmed by
//! reading the upstream source, see [`valid_action_context`] below), and it
//! spends the leaf either way. That is correct, and this crate matches it:
//! a signing path that can return without advancing the counter is a
//! leaf-reuse hazard, and reuse is total security failure for the key, while
//! a spent leaf is only availability loss.
//!
//! So callers MUST NOT treat [`valid_action_context`] as a guard that saves
//! a leaf, and MUST NOT run it before `sign_stateful_action`. Doing so would
//! create a signing path that returns without advancing the counter, which
//! is the hazard this ordering removes.
//!
//! On the stateful path the check runs **after** the signature is produced,
//! so that the leaf is already spent and both counters have advanced. It
//! turns a signature that could never verify into an explicit error. The
//! leaf stays spent either way. On the stateless path, where no leaf exists,
//! and in verification, the check runs first as an ordinary precondition.

use crate::rotation::RotationKind;
use hashsigs_rs::shrincs::ActionContext;
use sha3::{Digest, Keccak256};

/// Fixed 32-byte domain separator reserved for hybrid-layer SHRINCS use,
/// distinct from every other consumer of the upstream `hashsigs-rs` crate.
///
/// `keccak256(b"pqhybridsign/shrincs/domain-separator/v1")`.
pub const HYBRID_DOMAIN_SEPARATOR: [u8; 32] = [
    0xba, 0x0e, 0x5b, 0x3c, 0xbd, 0xe0, 0xec, 0xd2, 0xa8, 0x14, 0xc8, 0xc7, 0x36, 0x1e, 0x8d, 0x57,
    0xfe, 0x2f, 0x77, 0x2d, 0x89, 0x9c, 0x7f, 0xc1, 0xbe, 0x3e, 0xb7, 0x37, 0x63, 0x80, 0xee, 0xbc,
];

/// Fixed 32-byte action type shared across all EdSh/SrSh suite and profile
/// combinations. Suite separation is carried by `payload_hash`, not by this
/// field.
///
/// `keccak256(b"pqhybridsign/shrincs/action-type/v1")`.
pub const HYBRID_ACTION_TYPE: [u8; 32] = [
    0x8c, 0xfe, 0xa3, 0x40, 0x74, 0x62, 0x5e, 0xf4, 0x1c, 0x2e, 0x43, 0x42, 0xcd, 0xbe, 0xc1, 0x59,
    0x68, 0x95, 0xca, 0xaa, 0xff, 0x52, 0xee, 0x86, 0x64, 0x35, 0x4e, 0xa8, 0x76, 0xe1, 0xd0, 0x34,
];

/// Maps the hybrid bound message `M'` into an `ActionContext` per
/// specification section 7.1.
///
/// `payload_hash = keccak256(M')`; `domain_separator` and `action_type` are
/// the fixed constants above; `nonce` and `key_version` are the integrating
/// account's replay counters, or `[0u8; 32]` where no account state machine
/// exists. Deterministic: the same `m_prime`, `nonce`, and `key_version`
/// always produce the same `ActionContext`.
///
/// The returned context is not guaranteed valid — run
/// [`valid_action_context`] on it before signing.
pub fn to_action_context(m_prime: &[u8], nonce: [u8; 32], key_version: [u8; 32]) -> ActionContext {
    ActionContext {
        domain_separator: HYBRID_DOMAIN_SEPARATOR,
        nonce,
        key_version,
        action_type: HYBRID_ACTION_TYPE,
        payload_hash: keccak256(m_prime),
    }
}

/// Maps `m_prime_rotation` into an `ActionContext` for a rotation signature,
/// specification section 19.2. The same mapping as [`to_action_context`],
/// except that `domain_separator` is [`rotation_domain_separator`] instead
/// of the fixed [`HYBRID_DOMAIN_SEPARATOR`], and `payload_hash` is over the
/// rotation message rather than an ordinary `M'`.
///
/// Binding `next_classical_pk` and `kind` into the domain separator here --
/// not only into `m_prime_rotation`'s bytes -- is what stops a holder of a
/// compromised current classical key from reusing an honest stateless
/// rotation signature (which binds only the commitments) alongside a
/// co-signature over their own `NextClassicalPK`. See `RotationPayload`'s
/// documentation and specification section 19.2 for the full attack.
///
/// The returned context is not guaranteed valid -- run
/// [`valid_action_context`] on it before signing, same as
/// [`to_action_context`].
pub fn to_rotation_action_context(
    m_prime_rotation: &[u8],
    next_classical_pk: &[u8; 32],
    kind: RotationKind,
    nonce: [u8; 32],
    key_version: [u8; 32],
) -> ActionContext {
    ActionContext {
        domain_separator: rotation_domain_separator(next_classical_pk, kind),
        nonce,
        key_version,
        action_type: HYBRID_ACTION_TYPE,
        payload_hash: keccak256(m_prime_rotation),
    }
}

/// `keccak256("hybrid-rotate-ds" || NextClassicalPK || RotationKind)`,
/// specification section 19.2's rotation domain separator.
///
/// A function, not a constant like [`HYBRID_DOMAIN_SEPARATOR`]: it depends
/// on the payload being authorized, specifically on `next_classical_pk` and
/// `kind`. Binding those two fields here, inside the domain separator the
/// stateless signer actually signs over
/// (`ShrincsVerifier::stateless_action_message_hash` folds
/// `ActionContext.domain_separator` in), is what makes the stateless
/// rotation signature unusable against a different `NextClassicalPK`: see
/// [`to_rotation_action_context`].
pub fn rotation_domain_separator(next_classical_pk: &[u8; 32], kind: RotationKind) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"hybrid-rotate-ds");
    hasher.update(next_classical_pk);
    hasher.update([kind.to_u8()]);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Reimplementation of upstream `hashsigs_rs::shrincs::dispatch::valid_action_context`.
///
/// That function is `pub(crate)` in `hashsigs-rs` and unreachable from here,
/// so this mirrors its checks exactly. Quoted verbatim from the upstream
/// clone at `hashsigs-rs` commit `833de08d618b7e42b7991f7c684571133c3d88ab`,
/// `src/shrincs/dispatch.rs:106-110`:
///
/// ```text
/// pub(crate) fn valid_action_context(context: &ActionContext) -> bool {
///     context.domain_separator != [0u8; HASH_LEN]
///         && context.action_type != [0u8; HASH_LEN]
///         && context.payload_hash != [0u8; HASH_LEN]
/// }
/// ```
///
/// `nonce` and `key_version` may legitimately be zero; `domain_separator`,
/// `action_type`, and `payload_hash` must each be non-zero. Both upstream
/// verify paths (`verify_stateful`, `verify_stateless`) enforce this same
/// rule, but `ShrincsSigner::sign_stateful_action` does not — callers must
/// run this check before signing.
pub fn valid_action_context(context: &ActionContext) -> bool {
    context.domain_separator != [0u8; 32]
        && context.action_type != [0u8; 32]
        && context.payload_hash != [0u8; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: [u8; 32] = [0u8; 32];
    const NONZERO_NONCE: [u8; 32] = [7u8; 32];
    const NONZERO_KEY_VERSION: [u8; 32] = [9u8; 32];

    #[test]
    fn same_m_prime_maps_deterministically() {
        let m_prime = b"suite-ed_sh-hybrid-message";
        let a = to_action_context(m_prime, NONZERO_NONCE, NONZERO_KEY_VERSION);
        let b = to_action_context(m_prime, NONZERO_NONCE, NONZERO_KEY_VERSION);
        assert_eq!(a, b);
    }

    #[test]
    fn different_suite_labels_give_different_payload_hash() {
        // M' embeds the suite label (specification section 7.1), so two
        // messages differing only in that label must map to different
        // payload hashes.
        let m_prime_a = b"\x01hybrid-ed25519-mldsa44-v1\0\x00message";
        let m_prime_b = b"\x01hybrid-sr25519-mldsa44-v1\0\x00message";
        let ctx_a = to_action_context(m_prime_a, ZERO, ZERO);
        let ctx_b = to_action_context(m_prime_b, ZERO, ZERO);
        assert_ne!(ctx_a.payload_hash, ctx_b.payload_hash);
    }

    #[test]
    fn different_nonce_changes_the_context() {
        let m_prime = b"same message";
        let a = to_action_context(m_prime, ZERO, ZERO);
        let b = to_action_context(m_prime, NONZERO_NONCE, ZERO);
        assert_ne!(a, b);
    }

    #[test]
    fn different_key_version_changes_the_context() {
        let m_prime = b"same message";
        let a = to_action_context(m_prime, ZERO, ZERO);
        let b = to_action_context(m_prime, ZERO, NONZERO_KEY_VERSION);
        assert_ne!(a, b);
    }

    #[test]
    fn validation_accepts_a_context_built_by_the_normal_mapping_path() {
        let ctx = to_action_context(b"any message", ZERO, ZERO);
        assert!(valid_action_context(&ctx));
    }

    #[test]
    fn zero_nonce_and_zero_key_version_are_accepted() {
        // The specification allows zero nonce/key_version where no account
        // state machine exists.
        let ctx = to_action_context(b"any message", ZERO, ZERO);
        assert_eq!(ctx.nonce, ZERO);
        assert_eq!(ctx.key_version, ZERO);
        assert!(valid_action_context(&ctx));
    }

    #[test]
    fn validation_rejects_zero_domain_separator() {
        let mut ctx = to_action_context(b"any message", ZERO, ZERO);
        ctx.domain_separator = ZERO;
        assert!(!valid_action_context(&ctx));
    }

    #[test]
    fn validation_rejects_zero_action_type() {
        let mut ctx = to_action_context(b"any message", ZERO, ZERO);
        ctx.action_type = ZERO;
        assert!(!valid_action_context(&ctx));
    }

    #[test]
    fn validation_rejects_zero_payload_hash() {
        let mut ctx = to_action_context(b"any message", ZERO, ZERO);
        ctx.payload_hash = ZERO;
        assert!(!valid_action_context(&ctx));
    }

    #[test]
    fn rotation_domain_separator_differs_from_the_ordinary_one() {
        let ds = rotation_domain_separator(&[1u8; 32], RotationKind::StatefulGraft);
        assert_ne!(ds, HYBRID_DOMAIN_SEPARATOR);
    }

    #[test]
    fn rotation_domain_separator_binds_next_classical_pk() {
        let a = rotation_domain_separator(&[1u8; 32], RotationKind::StatefulGraft);
        let b = rotation_domain_separator(&[2u8; 32], RotationKind::StatefulGraft);
        assert_ne!(
            a, b,
            "two different NextClassicalPK values must give different domain separators"
        );
    }

    #[test]
    fn rotation_domain_separator_binds_rotation_kind() {
        let a = rotation_domain_separator(&[1u8; 32], RotationKind::StatefulGraft);
        let b = rotation_domain_separator(&[1u8; 32], RotationKind::FullSwap);
        assert_ne!(
            a, b,
            "two different RotationKind values must give different domain separators"
        );
    }

    #[test]
    fn rotation_action_context_round_trips_the_domain_separator() {
        let next_classical_pk = [3u8; 32];
        let ctx = to_rotation_action_context(
            b"m-prime-rotation",
            &next_classical_pk,
            RotationKind::FullSwap,
            ZERO,
            ZERO,
        );
        assert_eq!(
            ctx.domain_separator,
            rotation_domain_separator(&next_classical_pk, RotationKind::FullSwap)
        );
        assert!(valid_action_context(&ctx));
    }
}
