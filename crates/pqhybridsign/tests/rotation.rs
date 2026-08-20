// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stateful (SHRINCS) suite test. Compiled only under a profile feature.
#![cfg(any(
    feature = "profile-256s",
    feature = "profile-256s-sha2",
    feature = "profile-128s-q18",
    feature = "profile-128s-q20"
))]
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
//! Specification section 19.2/19.3: the AND-gated rotation authorization,
//! against the real SHRINCS component (task pqhs-qy5.2).
//!
//! The stateless SHRINCS signature (`PqStatefulScheme::sign_stateless_rotation`)
//! grinds a target sum and costs seconds to produce. This file signs
//! exactly twice, both in `fixture()` below, shared across every `#[test]`
//! here through a `OnceLock`: every scenario reuses one of those two
//! signatures' stateless halves, and where a scenario needs an ordinary
//! (non-rotation) classical signature it reuses one cheap *stateful*
//! composite signature computed in the same fixture (stateful signing does
//! not grind). The second rotation signature exists because
//! `current_commitment` is inside the signed message, so the only way to
//! test a payload naming the wrong key while both halves stay genuinely
//! valid is to sign that payload for real -- see `wrong_key_sig`. The
//! cheap, fake-component equivalent of every case here lives in
//! `pqhybridsign-core/src/rotation.rs`'s own test module.

// Rotation AND-gate and payload binding are composition-layer behaviour and
// do not depend on the SHRINCS parameter set.
#![cfg(feature = "profile-256s")]

use pqhybridsign::budget::{BudgetKey, StatelessBudgetStore};
use pqhybridsign::encoding_path;
use pqhybridsign::rotation::{self, NextStoredPublicKey, RotationKind, RotationPayload};
use pqhybridsign::shrincs::{keygen, PublicKey, SecretKey, H5};
use pqhybridsign::stateful::{adopt_key, KeyIdentity, LeafJournal, StatefulHybridSignatureScheme};
use std::sync::OnceLock;

const CTX: &[u8] = b"pqhs-qy5.2-rotation";
const MAX_SIGNATURES: u32 = 1;

/// The 32-byte SHRINCS commitment `pk` carries: bytes 68..100 of its
/// bundle, the same window the golden-vector tests read to build a stored
/// public key. This is the value an owner installed and therefore the value
/// a rotation authorization against `pk` must name.
///
/// Reading the bundle's own carried field is fixture convenience, not a
/// verification shortcut, and it cannot mask a failure. `bundle::verify_bundle`
/// recomputes the commitment from `statefulPublicKey`, `pkSeed` and
/// `hypertreeRoot` and rejects a bundle whose carried field disagrees with
/// that recomputation, so a wrong value here would make the honest rotation
/// test fail loudly rather than let a bad one pass. The gate never trusts
/// this field; only this fixture reads it, standing in for what an owner
/// installed.
fn stored_commitment(pk: &PublicKey<H5>) -> [u8; 32] {
    pk.pq_verify_key()[68..100]
        .try_into()
        .expect("a 32-byte window is 32 bytes")
}

/// `current_commitment` names the key the rotation is authorized against,
/// so it is derived from `pk` rather than written as a literal:
/// `verify_rotation` refuses any other value, and every negative test below
/// would otherwise pass on that refusal instead of on its own property.
fn base_payload(pk: &PublicKey<H5>) -> RotationPayload {
    RotationPayload {
        kind: RotationKind::FullSwap,
        current_commitment: stored_commitment(pk),
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
    /// Which key this journal is the leaf record for, as durable here as
    /// the counter.
    bound: Option<KeyIdentity>,
}

impl MemoryJournal {
    /// A journal already adopted by the key `identity` names: the one-off
    /// act an integrator performs when a key's durable journal is created.
    fn adopted(identity: KeyIdentity) -> Self {
        let mut journal = Self::default();
        adopt_key(&mut journal, identity).expect("adopt");
        journal
    }
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
    fn bound_key(&self) -> Option<KeyIdentity> {
        self.bound
    }

    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        self.bound = Some(key);
        Ok(())
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
    /// A payload identical to `payload_a` except that `current_commitment`
    /// names no key at all, rather than the key that signs it.
    payload_wrong_key: RotationPayload,
    /// A genuine rotation signature over `payload_wrong_key`: both halves
    /// valid, made by the same secret key over exactly those bytes. The
    /// second (and last) expensive signature in this file.
    wrong_key_sig: Vec<u8>,
    /// Retained so the attack/tamper cases can build fresh, cheap classical
    /// co-signatures with `rotation::sign_rotation_classical_half`.
    sk: SecretKey<H5>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (mut sk, pk) = keygen::<H5>(&[0x42u8; 32], MAX_SIGNATURES).expect("keygen");
        let payload_a = base_payload(&pk);

        let mut honest_sig = vec![0u8; rotation::rotation_signature_len::<H5>()];
        rotation::sign_rotation::<H5>(
            &sk,
            &mut MemoryBudget::default(),
            CTX,
            &payload_a,
            &mut honest_sig,
        )
        .expect("sign_rotation");

        // The same authorization against a commitment that is not this
        // key's, signed for real so neither half can be what rejects it.
        let payload_wrong_key = RotationPayload {
            current_commitment: [0x11u8; 32],
            ..payload_a
        };
        let mut wrong_key_sig = vec![0u8; rotation::rotation_signature_len::<H5>()];
        rotation::sign_rotation::<H5>(
            &sk,
            &mut MemoryBudget::default(),
            CTX,
            &payload_wrong_key,
            &mut wrong_key_sig,
        )
        .expect("sign_rotation");

        let mut journal = MemoryJournal::adopted(sk.key_identity());
        let ordinary_sig = H5::sign_stateful(&mut sk, &mut journal, b"ordinary message", CTX)
            .expect("sign_stateful");

        Fixture {
            pk,
            payload_a,
            honest_sig,
            ordinary_sig,
            payload_wrong_key,
            wrong_key_sig,
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

// ---------------------------------------------------------------------
// 8. A payload naming a different current key is refused, against the real
//    commitment scheme.
// ---------------------------------------------------------------------

/// The core-crate twin of this test proves the same property against a fake
/// component. This one proves it against the real
/// `ShrincsScheme::verify_committed_key` and `bundle::verify_bundle`, so the
/// gate is not merely a test double agreeing with itself.
///
/// `current_commitment` sits inside `M'_rotation`, so a payload naming a
/// different key cannot be produced by mutating a signed one -- that would
/// break both halves and the test would pass without the commitment check
/// ever running. The fixture therefore signs `payload_wrong_key` for real.
/// Both halves are valid by construction, over exactly these bytes, under
/// the same secret key whose honest rotation
/// `a_valid_rotation_verifies_and_installs_atomically` shows verifying. The
/// commitment is the only thing that differs, so it is the only thing left
/// that can reject.
#[test]
fn a_payload_naming_a_different_current_key_is_refused() {
    let f = fixture();

    assert_ne!(
        f.payload_wrong_key.current_commitment, f.payload_a.current_commitment,
        "the forged payload must actually name a different key"
    );

    assert!(
        rotation::verify_rotation::<H5>(&f.pk, CTX, &f.payload_wrong_key, &f.wrong_key_sig)
            .is_none(),
        "a payload whose current_commitment is not this key's must be refused, \
         even though both signatures over it are valid"
    );
}

/// An in-memory `StatelessBudgetStore`. Not durable across a process
/// restart, which is fine for a test: the property under test is that the
/// count is consulted and advanced at all, not real persistence. A
/// deployment must persist this, or the few-time bound of specification
/// section 21 can be exceeded silently after any restart.
#[derive(Default)]
struct MemoryBudget(std::collections::HashMap<[u8; 32], u64>);

impl StatelessBudgetStore for MemoryBudget {
    type Error = core::convert::Infallible;

    fn consumed(&self, key: &BudgetKey) -> Option<u64> {
        self.0.get(key.as_bytes()).copied()
    }

    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
        self.0.insert(*key.as_bytes(), count);
        Ok(())
    }
}
