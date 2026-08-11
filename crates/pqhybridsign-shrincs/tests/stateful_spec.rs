// SPDX-License-Identifier: AGPL-3.0-or-later
//! Specification section 17, conformance tests 15 to 32: the stateful
//! properties of H5/H6 that are not covered by the plain round trips in
//! `roundtrip.rs`.
//!
//! Several tests here assert that a property does **not** hold. Those are
//! deliberate. A stateful hash-based key is destroyed by leaf reuse, and the
//! most expensive mistake an integrator can make is to assume this library
//! prevents a reuse it cannot see. Each such test says, in place, what is
//! guaranteed and what is not.
//!
//! # What this crate does and does not enforce
//!
//! - Enforced: one leaf per successful `sign_stateful`, the journal commit
//!   ordered ahead of signature construction, a typed `LeavesExhausted` at
//!   the budget boundary, and rejection of every malformed encoding before
//!   any cryptography runs.
//! - Not enforced: that a leaf is spent only once across *all* copies of a
//!   key. Two copies of one key state, or one key state restored from a
//!   backup, both sign leaf `i` and both signatures verify. Preventing that
//!   is signer-side accounting -- a durable `LeafJournal` that is never
//!   rewound and never forked -- plus, on the verifying side, an index
//!   policy the integrator supplies (see `MonotonicIndex` below).

use hashsigs_rs::shrincs::{
    Keys, PublicKey as ShrincsBundlePublicKey, ShrincsSigner, PROFILE_NAME,
};
use pqhybridsign_core::encoding_path::{
    decode_path_selected, PathBody, PathProfile, TrustedMaxSignatures, AUTH_PATH_NODE_LEN,
    CLASSICAL_SIG_LEN, LEAF_COUNT_LEN, SELECTOR_LEN, SELECTOR_STATEFUL,
};
use pqhybridsign_core::stateful::{LeafJournal, StatefulHybridSignatureScheme, StatefulSignError};
use pqhybridsign_core::{m_prime, Error, PqStatefulScheme, StatefulSuite};
use pqhybridsign_shrincs::{action, keygen, PublicKey, ShrincsScheme, H5};
use sha3::{Digest, Keccak256};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

/// An in-memory `LeafJournal` that can also be *rewound*, which no durable
/// implementation may ever do. `rewind_to` exists only to build the failure
/// scenarios below; see `signer_guard_is_a_budget_check_not_a_reuse_detector`.
#[derive(Default, Clone)]
struct MemoryJournal {
    committed: Rc<RefCell<Vec<u32>>>,
}

impl MemoryJournal {
    fn committed(&self) -> Vec<u32> {
        self.committed.borrow().clone()
    }

    fn rewind_to(&self, next_leaf: u32) {
        self.committed.borrow_mut().retain(|&l| l < next_leaf);
    }
}

impl LeafJournal for MemoryJournal {
    type Error = core::convert::Infallible;

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.committed.borrow_mut().push(leaf);
        Ok(())
    }

    fn next_leaf(&self) -> u32 {
        self.committed
            .borrow()
            .iter()
            .copied()
            .max()
            .map_or(0, |m| m + 1)
    }
}

fn profile() -> PathProfile {
    PathProfile {
        fixed_stateful_len: <ShrincsScheme as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN,
        stateless_len: <ShrincsScheme as PqStatefulScheme>::STATELESS_SIG_LEN,
    }
}

/// Offset of the `PathSelector` byte, and of the big-endian `LeafCount`
/// field that follows it, in the composite encoding
/// (`pqhybridsign_core::encoding_path`).
const SELECTOR_AT: usize = CLASSICAL_SIG_LEN;
const LEAF_COUNT_AT: usize = CLASSICAL_SIG_LEN + SELECTOR_LEN;

/// The `LeafCount` a stateful composite signature declares on the wire.
///
/// This is the only leaf-index value the encoding carries, and it is not an
/// independent field: the SHRINCS authentication path holds exactly
/// `LeafCount` nodes, so the two cannot disagree
/// (`hashsigs_rs::shrincs::Signature::auth_path`, whose length *is* the leaf
/// index).
fn wire_leaf_count(sig: &[u8]) -> u32 {
    assert_eq!(sig[SELECTOR_AT], SELECTOR_STATEFUL, "stateful selector");
    u32::from_be_bytes(
        sig[LEAF_COUNT_AT..LEAF_COUNT_AT + LEAF_COUNT_LEN]
            .try_into()
            .expect("four LeafCount bytes"),
    )
}

/// The post-quantum half of a composite signature, as `ShrincsScheme`'s own
/// `verify_stateful` takes it.
fn pq_body(sig: &[u8], max_signatures: u32) -> &[u8] {
    let decoded = decode_path_selected(
        sig,
        TrustedMaxSignatures::from_verified_bundle(max_signatures),
        &profile(),
    )
    .expect("a signature this crate produced decodes");
    match decoded.body {
        PathBody::Stateful { signature, .. } => signature,
        PathBody::Stateless { .. } => panic!("stateful signature expected"),
    }
}

/// `M'` for H5, the message both component verifiers actually see
/// (specification section 7.1).
fn bound_message(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    m_prime(H5::LABEL, ctx, msg).expect("M' fits")
}

// ---------------------------------------------------------------------
// Shared fixtures
//
// SHRINCS keygen costs seconds, so every test that only needs *some* valid
// key and signatures shares one keypair. Tests that advance key state cannot
// share: `sign_stateful` takes `&mut`, and a shared mutable key would make
// the leaf a test-ordering artefact.
// ---------------------------------------------------------------------

const FIXTURE_MAX: u32 = 4;
const FIXTURE_CTX: &[u8] = b"spec-17";
/// Three signed messages, the third a repeat of the first, so that a test can
/// compare two signatures over one message that differ only by leaf advance.
const FIXTURE_MESSAGES: [&[u8]; 3] = [b"alpha", b"beta", b"alpha"];

struct Fixture {
    public_key: PublicKey<H5>,
    /// Signatures over `FIXTURE_MESSAGES`, spending leaves 1, 2 and 3.
    signatures: Vec<Vec<u8>>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (mut sk, public_key) = keygen::<H5>(&[17u8; 32], FIXTURE_MAX).expect("keygen");
        let mut journal = MemoryJournal::default();
        let signatures = FIXTURE_MESSAGES
            .iter()
            .map(|msg| {
                H5::sign_stateful(&mut sk, &mut journal, msg, FIXTURE_CTX).expect("fixture sign")
            })
            .collect();
        Fixture {
            public_key,
            signatures,
        }
    })
}

/// Upstream `Keys` values, for the import and export tests. The composite
/// `SecretKey<S>` has no import or export surface of its own (see the report
/// for this task), so the counter round trip is exercised at the layer that
/// does: `hashsigs_rs::shrincs::Keys`.
struct UpstreamKeys {
    keys: Keys,
    public_key: ShrincsBundlePublicKey,
    /// An independently generated key, for the field-splicing test.
    other: Keys,
}

/// Budget of the upstream fixture keys. Small, so that two signatures reach
/// the exhausted counter value `max + 1`.
const UPSTREAM_MAX: u32 = 2;

fn upstream() -> &'static UpstreamKeys {
    static UPSTREAM: OnceLock<UpstreamKeys> = OnceLock::new();
    UPSTREAM.get_or_init(|| {
        let (keys, public_key) =
            ShrincsSigner::keygen(b"spec-17 upstream seed", UPSTREAM_MAX).expect("keygen");
        let (other, _) =
            ShrincsSigner::keygen(b"spec-17 upstream other seed", UPSTREAM_MAX).expect("keygen");
        UpstreamKeys {
            keys,
            public_key,
            other,
        }
    })
}

/// Byte offsets inside the 264-byte `Keys::to_bytes` blob
/// (`stateful(136) || stateless(128)`, where the stateful half is
/// `PrivateKey(64) || pkSeed(32) || root(32) || maxSignatures(4) ||
/// nextLeafIndex(4)`).
const PK_SEED_AT: usize = 64;
const ROOT_AT: usize = 96;
const COUNTER_AT: usize = 132;

fn counter_of(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(
        bytes[COUNTER_AT..COUNTER_AT + 4]
            .try_into()
            .expect("counter"),
    )
}

fn with_counter(bytes: &[u8; 264], counter: u32) -> [u8; 264] {
    let mut out = *bytes;
    out[COUNTER_AT..COUNTER_AT + 4].copy_from_slice(&counter.to_be_bytes());
    out
}

// ---------------------------------------------------------------------
// 15. State advancement: the authentication path length encodes the leaf.
// ---------------------------------------------------------------------

#[test]
fn successive_signatures_advance_the_leaf_and_the_wire_leaf_count_follows_it() {
    let fixture = fixture();

    // Leaf i then i+1: the journal records 0, 1, 2 (the journal's convention
    // starts at 0), and the wire `LeafCount` reads 1, 2, 3 (the SHRINCS
    // convention starts at 1). The two differ by exactly the one-off that
    // `ShrincsScheme::next_leaf` normalizes; they never drift by more.
    for (index, sig) in fixture.signatures.iter().enumerate() {
        let expected = u32::try_from(index).expect("small index") + 1;
        assert_eq!(
            wire_leaf_count(sig),
            expected,
            "signature {index} must declare leaf {expected}"
        );

        // The declared count is not a free-standing field: it is the length
        // of the authentication path that follows the fixed-size part of the
        // component signature.
        let body = pq_body(sig, FIXTURE_MAX);
        let path_bytes = body.len() - <ShrincsScheme as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN;
        assert_eq!(
            path_bytes,
            expected as usize * AUTH_PATH_NODE_LEN,
            "the authentication path holds exactly LeafCount nodes"
        );
    }

    // Each signature grows by exactly one authentication-path node.
    assert_eq!(
        fixture.signatures[1].len() - fixture.signatures[0].len(),
        AUTH_PATH_NODE_LEN
    );
    assert_eq!(
        fixture.signatures[2].len() - fixture.signatures[1].len(),
        AUTH_PATH_NODE_LEN
    );

    for (msg, sig) in FIXTURE_MESSAGES.iter().zip(&fixture.signatures) {
        assert!(H5::verify(&fixture.public_key, msg, FIXTURE_CTX, sig));
    }
}

// ---------------------------------------------------------------------
// 16. Signer-guard scope: the bounds check is NOT a reuse detector.
// ---------------------------------------------------------------------

#[test]
fn signer_guard_is_a_budget_check_not_a_reuse_detector() {
    // What the signer guard actually is: `sign_after_commit` compares the
    // journal's next leaf against the key's leaf capacity, and the composite
    // driver additionally requires the key's own counter and the journal to
    // agree. Both are checks on *this* key paired with *this* journal. Neither
    // can observe another copy of the same key state, and neither is a record
    // of which leaves have been used before.
    let seed = [16u8; 32];

    let (mut sk, pk) = keygen::<H5>(&seed, 4).expect("keygen");
    let journal = MemoryJournal::default();
    let mut journal_handle = journal.clone();
    let first = H5::sign_stateful(&mut sk, &mut journal_handle, b"guard", b"").expect("first sign");
    assert_eq!(wire_leaf_count(&first), 1);

    // Case A -- one key, a rewound journal. The lockstep check fires, because
    // the in-memory key already advanced past the journal. This is drift
    // detection between two counters that must move together, not reuse
    // detection: the guard knows nothing about leaf 1 having been spent, only
    // that its two counters disagree.
    journal.rewind_to(0);
    let outcome = H5::sign_stateful(&mut sk, &mut journal_handle, b"guard again", b"");
    assert_eq!(outcome, Err(StatefulSignError::SigningFailed));
    assert!(
        journal.committed().is_empty(),
        "the rejected attempt committed nothing"
    );

    // Case B -- the case that matters, and the one no guard here can catch:
    // the key state itself is restored alongside the journal, as a snapshot
    // restore or a copied key file does. Both counters are consistent, both
    // guards pass, and leaf 1 is spent a second time over a different
    // message.
    let (mut restored_sk, restored_pk) = keygen::<H5>(&seed, 4).expect("re-keygen");
    let mut restored_journal = MemoryJournal::default();
    let reissued = H5::sign_stateful(&mut restored_sk, &mut restored_journal, b"reissued", b"")
        .expect("the guard does not stop this");

    assert_eq!(
        wire_leaf_count(&reissued),
        1,
        "leaf 1 was reissued under a different message"
    );
    assert_eq!(pk.as_ref(), restored_pk.as_ref(), "the same public key");
    assert!(H5::verify(&pk, b"guard", b"", &first));
    assert!(H5::verify(&pk, b"reissued", b"", &reissued));
    // Two one-time signatures under one leaf now exist. That is the state
    // RFC 8391 says leaves no security guarantee for the key.
}

// ---------------------------------------------------------------------
// 17. Leaf reuse is rejected at a `MonotonicIndex` verifier, before any
//     cryptography runs.
// ---------------------------------------------------------------------

/// A verifier-side index policy, of the kind the specification calls
/// `MonotonicIndex`.
///
/// This crate does **not** ship one: the composite verifier is stateless by
/// construction (see the note in
/// `two_messages_under_one_leaf_both_verify_because_it_is_not_a_verifier_property`),
/// so an integrator that needs replay and reuse rejection owns this state.
/// The policy is small, and its whole point is the *order*: the index check
/// decides before any cryptography is attempted, so a replay costs a
/// comparison rather than a verification.
struct MonotonicIndex {
    highest_accepted: u32,
    /// How many times the policy handed a signature to the cryptography.
    crypto_calls: u32,
}

#[derive(Debug, PartialEq, Eq)]
enum IndexVerdict {
    Accepted,
    /// Rejected on the declared leaf alone. No cryptography ran.
    ReplayedLeaf,
    /// Rejected by the signature check itself.
    BadSignature,
}

impl MonotonicIndex {
    fn new() -> Self {
        Self {
            highest_accepted: 0,
            crypto_calls: 0,
        }
    }

    fn submit(&mut self, pk: &PublicKey<H5>, msg: &[u8], ctx: &[u8], sig: &[u8]) -> IndexVerdict {
        let leaf = wire_leaf_count(sig);
        if leaf <= self.highest_accepted {
            return IndexVerdict::ReplayedLeaf;
        }
        self.crypto_calls += 1;
        if !H5::verify(pk, msg, ctx, &sig.to_vec()) {
            return IndexVerdict::BadSignature;
        }
        self.highest_accepted = leaf;
        IndexVerdict::Accepted
    }
}

#[test]
fn monotonic_index_rejects_a_reused_leaf_before_any_cryptography_runs() {
    let fixture = fixture();
    let mut index = MonotonicIndex::new();

    assert_eq!(
        index.submit(
            &fixture.public_key,
            FIXTURE_MESSAGES[0],
            FIXTURE_CTX,
            &fixture.signatures[0]
        ),
        IndexVerdict::Accepted
    );
    assert_eq!(
        index.submit(
            &fixture.public_key,
            FIXTURE_MESSAGES[1],
            FIXTURE_CTX,
            &fixture.signatures[1]
        ),
        IndexVerdict::Accepted
    );
    assert_eq!(index.crypto_calls, 2);

    // Resubmit leaf 1 after leaf 2 has been accepted.
    let verdict = index.submit(
        &fixture.public_key,
        FIXTURE_MESSAGES[0],
        FIXTURE_CTX,
        &fixture.signatures[0],
    );

    assert_eq!(verdict, IndexVerdict::ReplayedLeaf);
    assert_eq!(
        index.crypto_calls, 2,
        "the replay was decided before any verification ran"
    );
    // The rejection is the index policy's, not the cryptography's: that same
    // signature still verifies on its own.
    assert!(H5::verify(
        &fixture.public_key,
        FIXTURE_MESSAGES[0],
        FIXTURE_CTX,
        &fixture.signatures[0]
    ));
}

// ---------------------------------------------------------------------
// 18. Two messages under one leaf is NOT a verifier property.
// ---------------------------------------------------------------------

#[test]
fn two_messages_under_one_leaf_both_verify_because_it_is_not_a_verifier_property() {
    // A verifier sees one public key, one message, one signature. It holds no
    // record of which leaves this key has already spent, so it cannot know
    // that the leaf in front of it was also used for something else. Both
    // signatures below are valid, and `H5::verify` says so for both.
    //
    // What prevents this in production is signer-side accounting: a durable
    // `LeafJournal` that is written before the signature exists, never
    // rewound, and held by exactly one signer. `SecretKey` is deliberately not
    // `Clone` for the same reason. Optionally, a verifier-side
    // `MonotonicIndex` (above) rejects the second use, but that is an
    // integrator's policy layer, not a property of the signature scheme.
    let seed = [18u8; 32];

    let (mut sk_a, pk) = keygen::<H5>(&seed, 4).expect("keygen");
    let mut journal_a = MemoryJournal::default();
    let sig_a = H5::sign_stateful(&mut sk_a, &mut journal_a, b"pay alice 1", b"").expect("sign a");

    // A second holder of the same key state -- a restored backup, a copied
    // key file, a forked process.
    let (mut sk_b, _pk_b) = keygen::<H5>(&seed, 4).expect("keygen");
    let mut journal_b = MemoryJournal::default();
    let sig_b = H5::sign_stateful(&mut sk_b, &mut journal_b, b"pay bob 1000", b"").expect("sign b");

    assert_eq!(wire_leaf_count(&sig_a), 1);
    assert_eq!(wire_leaf_count(&sig_b), 1, "the same leaf");
    assert_ne!(sig_a, sig_b, "different messages, different signatures");

    assert!(H5::verify(&pk, b"pay alice 1", b"", &sig_a));
    assert!(
        H5::verify(&pk, b"pay bob 1000", b"", &sig_b),
        "both signatures verify: the verifier has no way to reject the second"
    );
}

// ---------------------------------------------------------------------
// 19. Exhaustion boundary: a typed `LeavesExhausted` at max + 1.
// ---------------------------------------------------------------------

#[test]
fn signing_past_the_budget_yields_leaves_exhausted_and_consumes_nothing() {
    let max = 2;
    let (mut sk, pk) = keygen::<H5>(&[19u8; 32], max).expect("keygen");
    let journal = MemoryJournal::default();
    let mut handle = journal.clone();

    for i in 0..max {
        let sig = H5::sign_stateful(&mut sk, &mut handle, b"within budget", b"").expect("sign");
        assert_eq!(wire_leaf_count(&sig), i + 1);
        assert!(H5::verify(&pk, b"within budget", b"", &sig));
    }
    let committed = journal.committed();
    assert_eq!(committed, vec![0, 1]);

    // Attempt max + 1.
    let outcome = H5::sign_stateful(&mut sk, &mut handle, b"one too many", b"");

    assert_eq!(
        outcome,
        Err(StatefulSignError::LeavesExhausted),
        "the boundary is a typed error, not a generic signing failure"
    );
    assert_ne!(outcome, Err(StatefulSignError::SigningFailed));
    assert_ne!(outcome, Err(StatefulSignError::GrindAbort));
    assert_eq!(
        journal.committed(),
        committed,
        "exhaustion is detected before any commit, so nothing is consumed"
    );

    // Permanent, not transient: a retry fails the same way.
    assert_eq!(
        H5::sign_stateful(&mut sk, &mut handle, b"retry", b""),
        Err(StatefulSignError::LeavesExhausted)
    );
}

// ---------------------------------------------------------------------
// 20 to 23. Import and export of the leaf counter.
//
// These run against `hashsigs_rs::shrincs::Keys`, the layer that owns the
// counter and the only one with an import path. The composite
// `SecretKey<S>` exposes neither export nor import; see the task report.
// ---------------------------------------------------------------------

#[test]
fn export_import_round_trip_preserves_the_advanced_counter() {
    let mut keys = upstream().keys.clone();
    let public_key = upstream().public_key.clone();
    let ctx = action::to_action_context(b"counter round trip", [0u8; 32], [0u8; 32]);

    assert_eq!(keys.stateful().next_leaf_index(), 1, "a fresh key");

    ShrincsSigner::sign_stateful_action(&mut keys, &public_key, &ctx).expect("first sign");
    let bytes = keys.to_bytes();
    assert_eq!(counter_of(&bytes), 2);

    let imported = Keys::import(&bytes).expect("a self-consistent key imports");
    assert_eq!(imported.stateful().next_leaf_index(), 2);
    assert_eq!(
        imported.to_bytes(),
        bytes,
        "import then export is byte-identical"
    );
}

#[test]
fn export_import_round_trip_preserves_the_exhausted_counter() {
    let mut keys = upstream().keys.clone();
    let public_key = upstream().public_key.clone();
    let ctx = action::to_action_context(b"exhausted counter", [0u8; 32], [0u8; 32]);

    for _ in 0..UPSTREAM_MAX {
        ShrincsSigner::sign_stateful_action(&mut keys, &public_key, &ctx).expect("sign");
    }

    let bytes = keys.to_bytes();
    assert_eq!(
        counter_of(&bytes),
        UPSTREAM_MAX + 1,
        "the exhausted position is max + 1"
    );

    // The exhausted value is a legitimate state, not corruption: it is what
    // spending the last leaf produces, and it must survive a restart --
    // otherwise a restore would silently hand back the final leaf.
    let imported = Keys::import(&bytes).expect("the exhausted counter imports");
    assert_eq!(imported.stateful().next_leaf_index(), UPSTREAM_MAX + 1);

    // And an exhausted key signs nothing more.
    let mut exhausted = imported;
    assert!(
        ShrincsSigner::sign_stateful_action(&mut exhausted, &public_key, &ctx).is_none(),
        "no leaf remains"
    );
}

#[test]
fn import_rejects_a_tampered_root() {
    let bytes = upstream().keys.to_bytes();
    assert!(Keys::import(&bytes).is_some(), "the untampered key imports");

    // The root is recomputed from the seeds on import, so a root that does
    // not match the seeds beside it is rejected. A trusted root is an input
    // to every signature, so this is the check that stops a restored key
    // from signing under someone else's tree.
    for offset in [ROOT_AT, ROOT_AT + 16, ROOT_AT + 31] {
        let mut tampered = bytes;
        tampered[offset] ^= 0x01;
        assert!(
            Keys::import(&tampered).is_none(),
            "a flipped root byte at {offset} must be rejected"
        );
    }
}

#[test]
fn import_rejects_a_spliced_field() {
    let mut spliced = upstream().keys.to_bytes();
    let other = upstream().other.to_bytes();
    assert_ne!(
        spliced[PK_SEED_AT..PK_SEED_AT + 32],
        other[PK_SEED_AT..PK_SEED_AT + 32],
        "the two fixture keys differ"
    );

    // One key's public seed against another key's private seed and root. Each
    // field is individually well formed and came from a real key; only the
    // combination is wrong, which is exactly what a structural parse would
    // wave through.
    spliced[PK_SEED_AT..PK_SEED_AT + 32].copy_from_slice(&other[PK_SEED_AT..PK_SEED_AT + 32]);
    assert!(Keys::import(&spliced).is_none());

    // The same at the stateless half: its private seeds swapped for another
    // key's, leaving its public root in place.
    let mut spliced_stateless = upstream().keys.to_bytes();
    spliced_stateless[136..136 + 64].copy_from_slice(&other[136..136 + 64]);
    assert!(Keys::import(&spliced_stateless).is_none());
}

#[test]
fn import_rejects_out_of_range_counters() {
    let bytes = upstream().keys.to_bytes();

    // Below the first leaf. The counter is 1-based upstream, so 0 is not a
    // fresh key -- it is a value no signer can produce.
    assert!(Keys::import(&with_counter(&bytes, 0)).is_none());

    // One past the exhausted position, which would claim a leaf the tree does
    // not have.
    assert!(Keys::import(&with_counter(&bytes, UPSTREAM_MAX + 2)).is_none());
    assert!(Keys::import(&with_counter(&bytes, u32::MAX)).is_none());

    // The two ends of the accepted range still import.
    assert!(Keys::import(&with_counter(&bytes, 1)).is_some());
    assert!(Keys::import(&with_counter(&bytes, UPSTREAM_MAX + 1)).is_some());
}

// ---------------------------------------------------------------------
// 24. The re-keygen-from-seed hazard.
// ---------------------------------------------------------------------

#[test]
fn keygen_from_the_same_seed_is_byte_identical_and_resets_the_counter() {
    // Keygen is deterministic in the master seed. That is a feature for
    // reproducible provisioning and a trap for recovery:
    //
    //   Re-running keygen from the seed MUST NOT be used as a restore path.
    //
    // It rebuilds the key with the counter back at its initial value, so the
    // restored signer reissues every leaf it already spent. For a stateful
    // hash-based key that is a total loss of security: each reissued leaf is
    // a second one-time signature under a key half that was only ever safe to
    // use once. The only correct restore path is the durable state -- the
    // journal, and an exported key blob imported through the validating
    // import above.
    let seed = [24u8; 32];

    let (mut original, pk) = keygen::<H5>(&seed, 4).expect("keygen");
    let mut journal = MemoryJournal::default();
    let first = H5::sign_stateful(&mut original, &mut journal, b"spent", b"").expect("sign");
    let second = H5::sign_stateful(&mut original, &mut journal, b"also spent", b"").expect("sign");
    assert_eq!(wire_leaf_count(&first), 1);
    assert_eq!(wire_leaf_count(&second), 2);

    let (mut rebuilt, rebuilt_pk) = keygen::<H5>(&seed, 4).expect("re-keygen");

    // Byte-identical key material: the public key is the same, so nothing
    // downstream can tell the two apart.
    assert_eq!(
        pk.as_ref(),
        rebuilt_pk.as_ref(),
        "the same seed rebuilds the same key"
    );

    // Counter back at the start. The rebuilt key spends leaf 1 again, and the
    // reissued signature verifies under the original public key.
    let mut fresh_journal = MemoryJournal::default();
    let reissued =
        H5::sign_stateful(&mut rebuilt, &mut fresh_journal, b"reissued", b"").expect("sign");
    assert_eq!(
        wire_leaf_count(&reissued),
        1,
        "the counter reset to the first leaf"
    );
    assert!(H5::verify(&pk, b"reissued", b"", &reissued));
    assert!(
        H5::verify(&pk, b"spent", b"", &first),
        "the original leaf-1 signature is still valid, so leaf 1 now carries two messages"
    );
}

// ---------------------------------------------------------------------
// 25 and 26. Commitment binding.
// ---------------------------------------------------------------------

#[test]
fn any_single_byte_flip_in_the_bundle_fails_verification() {
    let fixture = fixture();
    let vk = fixture.public_key.pq_verify_key();
    let bound = bound_message(FIXTURE_CTX, FIXTURE_MESSAGES[0]);
    let body = pq_body(&fixture.signatures[0], FIXTURE_MAX);

    assert!(
        bool::from(ShrincsScheme::verify_stateful(vk, &bound, body)),
        "the untouched bundle verifies"
    );

    // The commitment is recomputed from the bundle's other three fields and
    // checked against the field the bundle carries, so a flip anywhere --
    // including inside the carried commitment itself -- is caught. Sampled at
    // the first, middle and last byte of each of the four fields
    // (statefulPublicKey 0..68, commitment 68..100, pkSeed 100..132,
    // hypertreeRoot 132..164).
    let fields = [(0usize, 68usize), (68, 100), (100, 132), (132, 164)];
    for (start, end) in fields {
        for offset in [start, start + (end - start) / 2, end - 1] {
            let mut tampered = vk.to_vec();
            tampered[offset] ^= 0x01;
            assert!(
                !bool::from(ShrincsScheme::verify_stateful(&tampered, &bound, body)),
                "a flipped bundle byte at {offset} must fail verification"
            );
        }
    }

    // The composite `PublicKey<S>` has no constructor from bytes, so a
    // tampered bundle cannot be built at the composite layer at all; the
    // check above is at the component boundary, which is where an
    // attacker-supplied bundle actually arrives.
}

#[test]
fn the_commitment_binds_the_profile_name() {
    // Cross-profile separation cannot be tested inside one build: exactly one
    // `profile-*` feature compiles, so the wrong-profile key does not exist
    // here as a type. What can be tested, and is the mechanism that makes a
    // wrong-profile key fail, is that the active profile name is bound into
    // the commitment: two keys built from identical seeds under different
    // profiles commit to different values, so neither can verify against the
    // other's stored commitment.
    let fixture = fixture();
    let vk = fixture.public_key.pq_verify_key();
    let (stateful_public_key, rest) = vk.split_at(68);
    let carried_commitment = &rest[..32];
    let pk_seed = &rest[32..64];
    let hypertree_root = &rest[64..96];

    let commitment = |profile: &str| -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"shrincs-public-key/");
        hasher.update(profile.as_bytes());
        hasher.update(stateful_public_key);
        hasher.update(pk_seed);
        hasher.update(hypertree_root);
        hasher.finalize().into()
    };

    // The active profile reproduces the commitment the key actually carries,
    // which is what makes the next assertion meaningful.
    assert_eq!(
        commitment(PROFILE_NAME).as_slice(),
        carried_commitment,
        "the commitment preimage is keccak256(prefix || profile || fields)"
    );

    for other in ["shrincs-128s-q18", "shrincs-256s-sha2", "shrincs-256s"] {
        if other == PROFILE_NAME {
            continue;
        }
        assert_ne!(
            commitment(other).as_slice(),
            carried_commitment,
            "profile {other} must commit to a different value from identical fields"
        );
    }
}

// ---------------------------------------------------------------------
// 27 to 30. Composite encoding negatives, rejected before any cryptography.
//
// Each case asserts the rejection at the decode boundary
// (`decode_path_selected`, which allocates nothing and hashes nothing) and
// then that `H5::verify` also refuses the same bytes.
// ---------------------------------------------------------------------

fn decode_with_trusted_max(sig: &[u8], max_signatures: u32) -> Result<(), Error> {
    decode_path_selected(
        sig,
        TrustedMaxSignatures::from_verified_bundle(max_signatures),
        &profile(),
    )
    .map(|_| ())
}

#[test]
fn decode_rejects_an_unknown_path_selector() {
    let fixture = fixture();
    for selector in [0x00u8, 0x03, 0xff] {
        let mut mutated = fixture.signatures[0].clone();
        mutated[SELECTOR_AT] = selector;

        assert_eq!(
            decode_with_trusted_max(&mutated, FIXTURE_MAX),
            Err(Error::BadPathSelector { selector }),
            "selector {selector:#04x} is rejected before any length is read"
        );
        assert!(!H5::verify(
            &fixture.public_key,
            FIXTURE_MESSAGES[0],
            FIXTURE_CTX,
            &mutated
        ));
    }
}

#[test]
fn decode_rejects_a_short_body() {
    let fixture = fixture();
    let mut truncated = fixture.signatures[0].clone();
    truncated.pop();

    let expected = <ShrincsScheme as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN + AUTH_PATH_NODE_LEN;
    assert_eq!(
        decode_with_trusted_max(&truncated, FIXTURE_MAX),
        Err(Error::BadLength {
            expected,
            actual: expected - 1
        })
    );
    assert!(!H5::verify(
        &fixture.public_key,
        FIXTURE_MESSAGES[0],
        FIXTURE_CTX,
        &truncated
    ));

    // A header too short to hold the classical signature and the selector is
    // rejected on the same boundary.
    assert!(matches!(
        decode_with_trusted_max(&truncated[..CLASSICAL_SIG_LEN], FIXTURE_MAX),
        Err(Error::BadLength { .. })
    ));
}

#[test]
fn decode_rejects_trailing_bytes() {
    let fixture = fixture();
    let mut extended = fixture.signatures[0].clone();
    let valid_len = extended.len();
    extended.push(0x00);

    assert_eq!(
        decode_with_trusted_max(&extended, FIXTURE_MAX),
        Err(Error::TrailingBytes {
            expected: valid_len,
            actual: valid_len + 1
        }),
        "a signature is a fixed-length string, not a prefix of one"
    );
    assert!(!H5::verify(
        &fixture.public_key,
        FIXTURE_MESSAGES[0],
        FIXTURE_CTX,
        &extended
    ));
}

#[test]
fn decode_rejects_a_leaf_count_above_max_signatures() {
    let fixture = fixture();
    let mut mutated = fixture.signatures[0].clone();
    let over = FIXTURE_MAX + 1;
    mutated[LEAF_COUNT_AT..LEAF_COUNT_AT + LEAF_COUNT_LEN].copy_from_slice(&over.to_be_bytes());

    // With the `maxSignatures` from a verified bundle, the four declared
    // bytes alone decide it. Nothing has sized or read the authentication
    // path at this point, which is what keeps a declared `u32::MAX` (about
    // 137 GB of path) from costing memory.
    assert_eq!(
        decode_with_trusted_max(&mutated, FIXTURE_MAX),
        Err(Error::LeafCountOutOfRange {
            leaf_count: over,
            max_signatures: FIXTURE_MAX
        })
    );
    let mut huge = fixture.signatures[0].clone();
    huge[LEAF_COUNT_AT..LEAF_COUNT_AT + LEAF_COUNT_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        decode_with_trusted_max(&huge, FIXTURE_MAX),
        Err(Error::LeafCountOutOfRange {
            leaf_count: u32::MAX,
            max_signatures: FIXTURE_MAX
        })
    );

    // `H5::verify` reaches the same rejection by a different route, and the
    // difference is worth stating. The generic composite verifier cannot read
    // `maxSignatures` -- only the SHRINCS component knows where it lives
    // inside the bundle -- so it decodes with the widest possible bound and
    // the over-range `LeafCount` is caught by length arithmetic instead: the
    // declared count implies a longer body than the bytes supplied.
    assert_eq!(
        decode_with_trusted_max(&mutated, u32::MAX),
        Err(Error::BadLength {
            expected: <ShrincsScheme as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN
                + over as usize * AUTH_PATH_NODE_LEN,
            actual: <ShrincsScheme as PqStatefulScheme>::FIXED_STATEFUL_SIG_LEN
                + AUTH_PATH_NODE_LEN,
        })
    );
    assert!(!H5::verify(
        &fixture.public_key,
        FIXTURE_MESSAGES[0],
        FIXTURE_CTX,
        &mutated
    ));
    assert!(!H5::verify(
        &fixture.public_key,
        FIXTURE_MESSAGES[0],
        FIXTURE_CTX,
        &huge
    ));

    // Zero is out of range at the bottom of the same check.
    let mut zero = fixture.signatures[0].clone();
    zero[LEAF_COUNT_AT..LEAF_COUNT_AT + LEAF_COUNT_LEN].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        decode_with_trusted_max(&zero, FIXTURE_MAX),
        Err(Error::LeafCountOutOfRange {
            leaf_count: 0,
            max_signatures: FIXTURE_MAX
        })
    );
}

// ---------------------------------------------------------------------
// 31 and 32. Deterministic canonicality, redefined for a stateful scheme.
// ---------------------------------------------------------------------

#[test]
fn the_same_key_state_and_message_give_byte_identical_output() {
    // Canonicality for a stateful scheme is a statement about the *key
    // state*, not about the call: fix the leaf and the message, and the
    // output is a function of them. Both keys below are at leaf 1, from the
    // same seed, signing the same message.
    let seed = [31u8; 32];

    let (mut first_key, _pk) = keygen::<H5>(&seed, 4).expect("keygen");
    let (mut second_key, _pk2) = keygen::<H5>(&seed, 4).expect("keygen");
    let mut journal_a = MemoryJournal::default();
    let mut journal_b = MemoryJournal::default();

    let a = H5::sign_stateful(&mut first_key, &mut journal_a, b"canonical", b"ctx").expect("a");
    let b = H5::sign_stateful(&mut second_key, &mut journal_b, b"canonical", b"ctx").expect("b");

    assert_eq!(a, b, "same key state, same message, same bytes");

    // The classical half is deterministic too -- both halves are, so the
    // whole encoding is, byte for byte.
    assert_eq!(a[..CLASSICAL_SIG_LEN], b[..CLASSICAL_SIG_LEN]);
}

#[test]
fn repeat_calls_differ_by_leaf_advance_which_is_not_a_canonicality_failure() {
    // The other half of the same property, and the one that surprises people:
    // calling `sign_stateful` twice with the same message gives two different
    // signatures. The key state is not the same on the second call -- the
    // leaf advanced -- so this is the scheme working, not a canonicality
    // failure. Anything else would mean the leaf did not advance.
    let fixture = fixture();
    let first = &fixture.signatures[0];
    let repeat = &fixture.signatures[2];
    assert_eq!(
        FIXTURE_MESSAGES[0], FIXTURE_MESSAGES[2],
        "the same message twice"
    );

    assert_ne!(first, repeat);
    assert_eq!(wire_leaf_count(first), 1);
    assert_eq!(wire_leaf_count(repeat), 3);
    assert_ne!(
        first.len(),
        repeat.len(),
        "the authentication path grew with the leaf"
    );

    // Both are valid: the leaf is not part of the message, so nothing about
    // the advance invalidates the earlier signature.
    assert!(H5::verify(
        &fixture.public_key,
        FIXTURE_MESSAGES[0],
        FIXTURE_CTX,
        first
    ));
    assert!(H5::verify(
        &fixture.public_key,
        FIXTURE_MESSAGES[2],
        FIXTURE_CTX,
        repeat
    ));

    // The classical half is deterministic in the message, so it is identical
    // in both; the difference is entirely in the SHRINCS half. This is the
    // precise sense in which the output is a function of (key state,
    // message).
    assert_eq!(first[..CLASSICAL_SIG_LEN], repeat[..CLASSICAL_SIG_LEN]);
}
