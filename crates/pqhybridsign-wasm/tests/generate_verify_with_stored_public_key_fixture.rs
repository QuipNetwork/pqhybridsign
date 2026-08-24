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
//! Generator for `tests/node/verify_with_stored_public_key.fixture.json`,
//! the H5 fixture `tests/node/sign_and_verify.mjs` checks
//! `verifyWithStoredPublicKey`/`storedPublicKeyLen` against.
//!
//! Ignored by default, following the convention of
//! `pqhybridsign/tests/generate_fixtures.rs`. Run explicitly and
//! commit the result after any change to the fixture's shape:
//!
//! ```text
//! cargo test -p pqhybridsign-wasm --test \
//!   generate_verify_with_stored_public_key_fixture -- --ignored --nocapture
//! ```
//!
//! `pqhybridsign-wasm` builds against exactly one SHRINCS profile feature
//! (see `pqhybridsign/Cargo.toml`'s `stateful = ["profile-256s"]`, on by
//! default and not overridden along the `pqhybridsign-abi` dependency this
//! crate builds against), the same one the checked-in fixture records.
//! Unlike `pqhybridsign`'s own multi-profile generator, there is only one
//! profile to regenerate against here.
//!
//! Writes the JSON file itself, using no dependency beyond what this
//! crate's own `Cargo.toml` already declares -- no `serde_json`, so the
//! encoding below is hand-rolled and deliberately minimal: every value is
//! either a hex string with no character `"` or `\` can ever produce, or a
//! plain integer.

use pqhybridsign_abi::{BudgetKey, KeyIdentity, LeafJournal, Suite};
use std::path::PathBuf;

/// An in-memory `StatelessBudgetStore`. Not durable -- fine for a
/// one-shot generator that exits immediately after writing the fixture.
#[derive(Default)]
struct MemoryBudget(std::collections::HashMap<[u8; 32], u64>);

impl pqhybridsign_abi::StatelessBudgetStore for MemoryBudget {
    type Error = core::convert::Infallible;

    fn consumed(&self, key: &BudgetKey) -> Option<u64> {
        self.0.get(key.as_bytes()).copied()
    }

    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
        self.0.insert(*key.as_bytes(), count);
        Ok(())
    }
}

/// An in-memory `LeafJournal`, used only to produce the stateful-selector
/// (`0x01`) signature the fixture also carries. Not durable, on the same
/// terms as `MemoryBudget`.
#[derive(Default)]
struct MemoryJournal {
    committed: Vec<u32>,
    bound: Option<KeyIdentity>,
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

/// Offset of the 32-byte commitment inside a SHRINCS bundle
/// (`statefulPublicKey(68) || commitment(32) || pkSeed || hypertreeRoot`),
/// matching the private `BUNDLE_COMMITMENT_OFFSET` constant at
/// `crates/pqhybridsign/src/shrincs/scheme.rs:48`, identical for H5 and H6
/// and independent of the active profile (see that constant's own
/// documentation and `crates/pqhybridsign/src/shrincs/bundle.rs`).
const COMMITMENT_AT: usize = 68;

/// The small form a verifier installs: the classical public key and the
/// commitment, lifted out of a verify-form public key its own keygen
/// produced. `pqhybridsign_abi::stateful_suites::tests` no longer builds
/// this the same way -- it calls
/// `stateful_composite::PublicKey::stored_form` instead, which computes the
/// commitment rather than assuming it sits at a fixed offset in the verify
/// form. This generator still assumes the fixed offset, the same way
/// `pqhybridsign-cffi::stateful::tests` and the Python test suite do,
/// deliberately parked for separate bindings work (`pqhs-0d2`).
fn stored_form(suite: Suite, verify_public_key: &[u8]) -> Vec<u8> {
    let classical_len = pqhybridsign_abi::stored_public_key_len(suite) - 32;
    let mut stored = verify_public_key[..classical_len].to_vec();
    stored.extend_from_slice(&verify_public_key[classical_len + COMMITMENT_AT..][..32]);
    stored
}

/// The signer-supplied half: everything after the classical public key.
fn bundle_of(suite: Suite, verify_public_key: &[u8]) -> &[u8] {
    &verify_public_key[pqhybridsign_abi::stored_public_key_len(suite) - 32..]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore]
fn generate_verify_with_stored_public_key_fixture() {
    const SUITE: Suite = Suite::H5;
    const MSG: &[u8] = b"the message the node test verifies";
    const CTX: &[u8] = b"node-verify-stored-test";

    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(SUITE)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(SUITE)];
    pqhybridsign_abi::keygen_stateful_from_seed(SUITE, &[0u8; 32], 4, &mut sk, &mut pk)
        .expect("keygen");

    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(SUITE)];
    let n = pqhybridsign_abi::sign_stateless(
        SUITE,
        &sk,
        &mut MemoryBudget::default(),
        MSG,
        CTX,
        &mut sig,
    )
    .expect("sign_stateless");
    sig.truncate(n);

    // A second signature over the stateful path (`PathSelector` 0x01, one
    // leaf spent), so the fixture exercises both
    // `verify_with_stored_public_key_stateful` and
    // `verify_with_stored_public_key_stateless` -- the stateless signature
    // above carries selector 0x02, and each entry point now accepts only its
    // own.
    let identity = pqhybridsign_abi::key_identity(SUITE, &pk).expect("key_identity");
    let mut journal = MemoryJournal::default();
    pqhybridsign_abi::adopt_key(&mut journal, identity).expect("adopt_key");
    let mut stateful_sk_out = sk.clone();
    let mut stateful_sig = vec![0u8; pqhybridsign_abi::signature_len(SUITE)];
    let stateful_n = pqhybridsign_abi::sign_stateful(
        SUITE,
        &sk,
        &mut journal,
        MSG,
        CTX,
        &mut stateful_sk_out,
        &mut stateful_sig,
    )
    .expect("sign_stateful");
    stateful_sig.truncate(stateful_n);

    let stored = stored_form(SUITE, &pk);
    let bundle = bundle_of(SUITE, &pk);
    assert!(pqhybridsign_abi::verify_with_stored_public_key_stateless(
        SUITE, &stored, bundle, MSG, CTX, &sig
    )
    .expect("the fixture's own stateless-path signature must verify before it is written out"));
    assert!(pqhybridsign_abi::verify_with_stored_public_key_stateful(
        SUITE,
        &stored,
        bundle,
        MSG,
        CTX,
        &stateful_sig
    )
    .expect("the fixture's stateful-path signature must verify before it is written out"));

    // A second, unrelated key: its bundle signs the same message and must
    // still be refused against the first key's stored commitment.
    let mut attacker_sk = vec![0u8; pqhybridsign_abi::secret_key_len(SUITE)];
    let mut attacker_pk = vec![0u8; pqhybridsign_abi::public_key_len(SUITE)];
    pqhybridsign_abi::keygen_stateful_from_seed(
        SUITE,
        &[1u8; 32],
        4,
        &mut attacker_sk,
        &mut attacker_pk,
    )
    .expect("attacker keygen");
    let attacker_bundle = bundle_of(SUITE, &attacker_pk);
    assert_eq!(
        pqhybridsign_abi::verify_with_stored_public_key_stateless(
            SUITE,
            &stored,
            attacker_bundle,
            MSG,
            CTX,
            &sig
        ),
        Ok(false),
        "the fixture's attacker bundle must not verify against the victim's stored key"
    );

    let stored_len = pqhybridsign_abi::stored_public_key_len(SUITE);
    let profile = pqhybridsign_abi::profile_name();

    let json = format!(
        "{{\n  \"msg\": \"{}\",\n  \"ctx\": \"{}\",\n  \"stored\": \"{}\",\n  \"bundle\": \"{}\",\n  \"attackerBundle\": \"{}\",\n  \"sig\": \"{}\",\n  \"statefulSig\": \"{}\",\n  \"storedLen\": {},\n  \"profile\": \"{}\"\n}}\n",
        hex(MSG),
        hex(CTX),
        hex(&stored),
        hex(bundle),
        hex(attacker_bundle),
        hex(&sig),
        hex(&stateful_sig),
        stored_len,
        profile,
    );

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("node")
        .join("verify_with_stored_public_key.fixture.json");
    std::fs::write(&out, json).expect("write fixture");
    println!("wrote {}", out.display());
}
