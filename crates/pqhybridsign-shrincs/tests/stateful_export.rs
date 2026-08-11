// SPDX-License-Identifier: AGPL-3.0-or-later
//! Export and import of a live H5 composite secret key.
//!
//! `stateful_spec.rs` proves the counter properties at the upstream
//! `hashsigs_rs::shrincs::Keys` layer, where `to_bytes` and `import` live.
//! This file proves they survive the two layers this crate adds on top:
//! `ShrincsScheme`'s `PqStatefulScheme` implementation, and the composite
//! `SecretKey<S>` blob that carries the classical half, the post-quantum
//! half and the leaf counter together.
//!
//! SHRINCS keygen is slow, so every test here shares one key. Nothing in
//! this file calls `sign_stateless`, which grinds for minutes.

// Composite export and import round trips exercise the composition blob, not
// the SHRINCS parameter set.
#![cfg(feature = "profile-256s")]

use pqhybridsign_core::stateful::{LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign_core::stateful_composite::SecretKey;
use pqhybridsign_core::{Error, PqStatefulScheme};
use pqhybridsign_shrincs::{keygen, PublicKey, ShrincsScheme, H5};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Small budget, so two signatures leave the key one short of exhausted and
/// four reach the exhausted counter.
const MAX: u32 = 4;
const SEED: [u8; 32] = [0x5e; 32];

#[derive(Default, Clone)]
struct MemoryJournal {
    committed: Rc<RefCell<Vec<u32>>>,
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

/// One key, exported after two of its four leaves have been spent. Shared
/// because keygen dominates the runtime of this file.
struct Fixture {
    public_key: PublicKey<H5>,
    /// Export of the key with its counter at leaf 2.
    blob: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (mut sk, public_key) = keygen::<H5>(&SEED, MAX).expect("keygen");
        let mut journal = MemoryJournal::default();
        H5::sign_stateful(&mut sk, &mut journal, b"first", b"").expect("sign");
        H5::sign_stateful(&mut sk, &mut journal, b"second", b"").expect("sign");
        let blob = sk.export().expect("export");
        Fixture { public_key, blob }
    })
}

/// Offset of the composite blob's 4-byte leaf-counter field, and of the
/// upstream `Keys` blob nested ahead of it. The layout is `ClassicalSK ||
/// PqSecretKey || nextLeaf(4) || PqVerifyKey`.
const PQ_AT: usize = 64;
const COUNTER_AT: usize = PQ_AT + <ShrincsScheme as PqStatefulScheme>::SECRET_KEY_LEN;

/// Offset of the hypertree root inside the nested upstream `Keys` blob
/// (`PrivateKey(64) || pkSeed(32) || root(32) || ...`), which upstream
/// re-derives on import.
const ROOT_AT: usize = PQ_AT + 96;

// Blob layout length and trailing verify-key field live in
// `profile_conformance.rs` so they run under every profile against the
// fixture export blob without importing it.

/// The property that makes export a restore path at all: the restored signer
/// resumes at the leaf the original stopped at, instead of at the first leaf
/// the way re-running keygen from the seed would.
#[test]
fn import_restores_the_advanced_counter_and_the_signer_continues() {
    let fixture = fixture();
    let mut restored = SecretKey::<H5>::import(&fixture.blob).expect("import");

    // The restored counter is observable through the driver's lockstep check:
    // a fresh journal disagrees with a key that has already spent two leaves,
    // so signing is refused rather than reissuing leaf 0.
    let mut fresh = MemoryJournal::default();
    assert!(
        H5::sign_stateful(&mut restored, &mut fresh, b"rewound", b"").is_err(),
        "a restored key must not accept a journal that was rewound to the start"
    );

    // The journal is the integrator's durable record; a correct restore pairs
    // the imported key with the journal it was exported alongside.
    let journal = MemoryJournal::default();
    journal.committed.borrow_mut().extend([0, 1]);
    let mut journal = journal;

    let sig = H5::sign_stateful(&mut restored, &mut journal, b"third", b"").expect("sign");
    assert!(
        H5::verify(&fixture.public_key, b"third", b"", &sig),
        "the restored key signs under the original public key"
    );
    assert_eq!(journal.committed.borrow().as_slice(), &[0, 1, 2]);

    // Import then export is byte-identical before anything is signed, so the
    // blob is a faithful record and not a re-encoding that drifts.
    let untouched = SecretKey::<H5>::import(&fixture.blob).expect("import");
    assert_eq!(untouched.export().expect("export"), fixture.blob);
}

/// The exhausted counter (`max_signatures + 1` upstream, `max_signatures` in
/// this crate's 0-based convention) is the value a lossy round trip would
/// quietly turn back into a fresh budget.
#[test]
fn export_import_preserves_the_exhausted_counter() {
    let mut restored = SecretKey::<H5>::import(&fixture().blob).expect("import");
    let journal = MemoryJournal::default();
    journal.committed.borrow_mut().extend([0, 1]);
    let mut journal = journal;

    H5::sign_stateful(&mut restored, &mut journal, b"third", b"").expect("sign");
    H5::sign_stateful(&mut restored, &mut journal, b"fourth", b"").expect("sign");

    let spent = restored.export().expect("export");
    assert_eq!(
        u32::from_be_bytes(
            spent[COUNTER_AT..COUNTER_AT + 4]
                .try_into()
                .expect("counter")
        ),
        MAX,
        "the exhausted counter is carried, not clamped"
    );

    let mut again = SecretKey::<H5>::import(&spent).expect("an exhausted key still imports");
    assert!(
        H5::sign_stateful(&mut again, &mut journal, b"fifth", b"").is_err(),
        "the restored key is still exhausted"
    );
}

/// Upstream re-derives the hypertree root from the private seeds on import,
/// so tampering is caught. What this test proves is that the composite import
/// routes through that check rather than around it.
#[test]
fn import_rejects_a_tampered_component_half() {
    let mut tampered = fixture().blob.clone();
    tampered[ROOT_AT] ^= 0x01;
    assert_eq!(
        SecretKey::<H5>::import(&tampered).err(),
        Some(Error::ComponentFailure)
    );
}

/// The counter appears twice: inside the component blob and in the composite
/// blob's own field. Editing either alone must fail, so neither can be used
/// to rewind a restored signer onto leaves it already spent.
#[test]
fn import_rejects_an_edited_counter() {
    let blob = &fixture().blob;

    // The composite field alone: caught by the cross-check against the
    // counter the imported component key actually holds.
    for rewritten in [0u32, 3, u32::MAX] {
        let mut tampered = blob.clone();
        tampered[COUNTER_AT..COUNTER_AT + 4].copy_from_slice(&rewritten.to_be_bytes());
        assert_eq!(
            SecretKey::<H5>::import(&tampered).err(),
            Some(Error::ComponentFailure),
            "composite counter field rewritten to {rewritten}"
        );
    }

    // The component's own counter alone: caught upstream, where the
    // 1-based counter must lie in `1..=max + 1`.
    let component_counter_at = COUNTER_AT - 4;
    for out_of_range in [0u32, MAX + 2, u32::MAX] {
        let mut tampered = blob.clone();
        tampered[component_counter_at..component_counter_at + 4]
            .copy_from_slice(&out_of_range.to_be_bytes());
        assert_eq!(
            SecretKey::<H5>::import(&tampered).err(),
            Some(Error::ComponentFailure),
            "component counter rewritten to {out_of_range}"
        );
    }

    // Rewinding both together is still rejected: the component counter is
    // 1-based and the composite one is 0-based, so a pair that agrees on the
    // wire is a pair that disagrees after normalization.
    let mut rewound = blob.clone();
    rewound[component_counter_at..component_counter_at + 4].copy_from_slice(&1u32.to_be_bytes());
    rewound[COUNTER_AT..COUNTER_AT + 4].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        SecretKey::<H5>::import(&rewound).err(),
        Some(Error::ComponentFailure)
    );
}

#[test]
fn import_rejects_a_blob_of_the_wrong_length() {
    let blob = &fixture().blob;
    let expected = SecretKey::<H5>::exported_len();

    assert_eq!(
        SecretKey::<H5>::import(&blob[..expected - 1]).err(),
        Some(Error::BadLength {
            expected,
            actual: expected - 1
        })
    );
    let mut long = blob.clone();
    long.push(0);
    assert_eq!(
        SecretKey::<H5>::import(&long).err(),
        Some(Error::BadLength {
            expected,
            actual: expected + 1
        })
    );
}

/// A wiped key must not export a well-formed blob of zeros: that blob would
/// carry a counter no signer ever reached.
#[test]
fn a_wiped_key_fails_to_export() {
    let mut sk = SecretKey::<H5>::import(&fixture().blob).expect("import");
    assert!(sk.export().is_ok());
    sk.zeroize();
    assert_eq!(sk.export().err(), Some(Error::ComponentFailure));
}
