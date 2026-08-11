// SPDX-License-Identifier: AGPL-3.0-or-later
//! Specification section 19.2/19.3: the AND-gated rotation authorization,
//! against the real SHRINCS component (task pqhs-qy5.2).
//!
//! The stateless SHRINCS signature (`PqStatefulScheme::sign_stateless_rotation`)
//! grinds a target sum and costs seconds to produce. This file signs
//! exactly once, in `fixture()` below, shared across every `#[test]` here
//! through a `OnceLock`: every scenario reuses that one signature's
//! stateless half, and where a scenario needs an ordinary (non-rotation)
//! classical signature it reuses one cheap *stateful* composite signature
//! computed in the same fixture (stateful signing does not grind). The
//! cheap, fake-component equivalent of every case here lives in
//! `pqhybridsign-core/src/rotation.rs`'s own test module.

// Rotation AND-gate and payload binding are composition-layer behaviour and
// do not depend on the SHRINCS parameter set.
#![cfg(feature = "profile-256s")]

use pqhybridsign_core::encoding_path;
use pqhybridsign_core::rotation::{self, NextStoredPublicKey, RotationKind, RotationPayload};
use pqhybridsign_core::stateful::{LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign_shrincs::{keygen, PublicKey, SecretKey, H5};
use std::sync::OnceLock;

const CTX: &[u8] = b"pqhs-qy5.2-rotation";
const MAX_SIGNATURES: u32 = 1;

fn base_payload() -> RotationPayload {
    RotationPayload {
        kind: RotationKind::FullSwap,
        current_commitment: [0x11u8; 32],
        next_commitment: [0x22u8; 32],
        next_classical_pk: [0x33u8; 32],
    }
}

/// An in-memory `LeafJournal`, local to this file: `fixture()` below needs
/// exactly one stateful signature, and has no durable state to persist
/// across runs.
#[derive(Default)]
struct MemoryJournal {
    committed: Vec<u32>,
}

impl LeafJournal for MemoryJournal {
    type Error = core::convert::Infallible;

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.committed.push(leaf);
        Ok(())
    }
    fn next_leaf(&self) -> u32 {
        self.committed.iter().copied().max().map_or(0, |m| m + 1)
    }
}

struct Fixture {
    pk: PublicKey<H5>,
    payload_a: RotationPayload,
    /// The one expensive (stateless SHRINCS) rotation signature this file
    /// produces, authorizing `payload_a`.
    honest_sig: Vec<u8>,
    /// A cheap *stateful* composite signature from the same key, over an
    /// ordinary (non-rotation) message. Its classical half is a genuine
    /// ordinary classical signature, used by the splice test below without
    /// any extra stateless (expensive) SHRINCS signing.
    ordinary_sig: Vec<u8>,
    /// Retained so the attack/tamper cases can build fresh, cheap classical
    /// co-signatures with `rotation::sign_rotation_classical_half`.
    sk: SecretKey<H5>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (mut sk, pk) = keygen::<H5>(&[0x42u8; 32], MAX_SIGNATURES).expect("keygen");
        let payload_a = base_payload();

        let mut honest_sig = vec![0u8; rotation::rotation_signature_len::<H5>()];
        rotation::sign_rotation::<H5>(&sk, CTX, &payload_a, &mut honest_sig)
            .expect("sign_rotation");

        let mut journal = MemoryJournal::default();
        let ordinary_sig = H5::sign_stateful(&mut sk, &mut journal, b"ordinary message", CTX)
            .expect("sign_stateful");

        Fixture {
            pk,
            payload_a,
            honest_sig,
            ordinary_sig,
            sk,
        }
    })
}

// ---------------------------------------------------------------------
// 1. A valid rotation verifies, and installs atomically.
// ---------------------------------------------------------------------

#[test]
fn a_valid_rotation_verifies_and_installs_atomically() {
    let f = fixture();
    let installed = rotation::verify_rotation::<H5>(&f.pk, CTX, &f.payload_a, &f.honest_sig)
        .expect("a valid rotation must verify");
    assert_eq!(
        installed,
        NextStoredPublicKey {
            next_classical_pk: f.payload_a.next_classical_pk,
            next_commitment: f.payload_a.next_commitment,
        }
    );
}

// ---------------------------------------------------------------------
// 2. The front-running attack fails (specification section 19.2).
// ---------------------------------------------------------------------

#[test]
fn the_front_running_attack_fails() {
    let f = fixture();
    let classical_len = encoding_path::CLASSICAL_SIG_LEN;

    // The attacker keeps the honest stateless half (bound to
    // `f.payload_a.next_classical_pk`) unchanged, and pairs it with a
    // fresh, valid classical co-signature over a payload naming a
    // different `NextClassicalPK`.
    let mut payload_b = f.payload_a;
    payload_b.next_classical_pk = [0x44u8; 32];

    let mut forged = f.honest_sig.clone();
    rotation::sign_rotation_classical_half::<H5>(
        &f.sk,
        CTX,
        &payload_b,
        &mut forged[..classical_len],
    )
    .expect("classical co-signature");

    assert!(
        rotation::verify_rotation::<H5>(&f.pk, CTX, &payload_b, &forged).is_none(),
        "front-running: a stateless rotation signature bound to one \
         NextClassicalPK must not verify once paired with a classical \
         co-signature naming a different NextClassicalPK"
    );
}

// ---------------------------------------------------------------------
// 3/4. Either half alone, tampered, is rejected.
// ---------------------------------------------------------------------

#[test]
fn an_invalid_stateless_half_is_rejected_even_with_a_valid_classical_half() {
    let f = fixture();
    let mut sig = f.honest_sig.clone();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    assert!(rotation::verify_rotation::<H5>(&f.pk, CTX, &f.payload_a, &sig).is_none());
}

#[test]
fn an_invalid_classical_half_is_rejected_even_with_a_valid_stateless_half() {
    let f = fixture();
    let mut sig = f.honest_sig.clone();
    sig[0] ^= 0x01;
    assert!(rotation::verify_rotation::<H5>(&f.pk, CTX, &f.payload_a, &sig).is_none());
}

// ---------------------------------------------------------------------
// 5. An ordinary classical signature cannot stand in for the rotation
//    co-signature.
// ---------------------------------------------------------------------

#[test]
fn an_ordinary_classical_signature_cannot_be_spliced_in_as_the_rotation_co_signature() {
    let f = fixture();
    let classical_len = encoding_path::CLASSICAL_SIG_LEN;

    let mut spliced = f.honest_sig.clone();
    spliced[..classical_len].copy_from_slice(&f.ordinary_sig[..classical_len]);

    assert!(
        rotation::verify_rotation::<H5>(&f.pk, CTX, &f.payload_a, &spliced).is_none(),
        "an ordinary classical signature must not verify as a rotation \
         co-signature, because LABEL and ROTATE_LABEL differ"
    );
}

// ---------------------------------------------------------------------
// 6. Changing `RotationKind` alone invalidates the stateless half.
// ---------------------------------------------------------------------

#[test]
fn changing_rotation_kind_alone_invalidates_the_stateless_half() {
    let f = fixture();
    let classical_len = encoding_path::CLASSICAL_SIG_LEN;

    let mut flipped = f.payload_a;
    flipped.kind = match f.payload_a.kind {
        RotationKind::FullSwap => RotationKind::StatefulGraft,
        RotationKind::StatefulGraft => RotationKind::FullSwap,
    };

    // A fresh, valid classical co-signature over the flipped-kind payload,
    // paired with the original (unmodified) stateless half.
    let mut forged = f.honest_sig.clone();
    rotation::sign_rotation_classical_half::<H5>(
        &f.sk,
        CTX,
        &flipped,
        &mut forged[..classical_len],
    )
    .expect("classical co-signature");

    assert!(
        rotation::verify_rotation::<H5>(&f.pk, CTX, &flipped, &forged).is_none(),
        "the stateless half was bound to the original RotationKind and must \
         not verify once the kind changes"
    );
}

// ---------------------------------------------------------------------
// 7. Install returns the next stored public key, differing from the
//    current one in both halves, for a full swap.
// ---------------------------------------------------------------------

#[test]
fn install_returns_the_next_stored_key_differing_from_current_in_both_halves() {
    let f = fixture();
    let installed = rotation::verify_rotation::<H5>(&f.pk, CTX, &f.payload_a, &f.honest_sig)
        .expect("a valid rotation must verify");

    assert_ne!(
        &installed.next_classical_pk[..],
        f.pk.classical(),
        "the classical half must differ from the current stored key"
    );
    assert_ne!(
        installed.next_commitment, f.payload_a.current_commitment,
        "the commitment half must differ from the current stored key"
    );
}
