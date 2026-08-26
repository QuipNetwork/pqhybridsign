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
//! Generator for the per-profile fixture files under `tests/vectors/`.
//!
//! Ignored by default. Run explicitly under each profile in release mode:
//!
//! ```text
//! cargo test -p pqhybridsign-shrincs --release --no-default-features \
//!   --features <profile> --test generate_fixtures -- --ignored --nocapture
//! ```
//!
//! Release mode is mandatory: debug is about 67 times slower. The two 256s
//! profiles finish in seconds; each 128s profile costs roughly 7 minutes.
//!
//! Unlike `generate_vectors_stateful.rs`, this generator writes the JSON
//! file itself under `tests/vectors/` rather than printing to stdout. Four
//! profiles produce four files; paste-from-stdout does not scale.

use pqhybridsign::shrincs::{keygen, EdSh, ShrincsScheme, SrSh};
use pqhybridsign::stateful::{adopt_key, KeyIdentity, LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign::{component::PqStatefulScheme, suite::StatefulSuite};
use pqhybridsign_test_support::MemoryBudget;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

#[path = "profile_id/mod.rs"]
mod profile_id;

#[derive(Default, Clone)]
struct MemoryJournal {
    committed: Rc<RefCell<Vec<u32>>>,
    /// Which key this journal is the leaf record for, as durable here as
    /// the counter. A journal that has never been bound owns no key.
    bound: Rc<RefCell<Option<KeyIdentity>>>,
}

impl MemoryJournal {
    /// A journal already adopted by the key `identity` names: the one-off
    /// act an integrator performs when a key's durable journal is created.
    /// Signing refuses a journal that is not the key's.
    fn adopted(identity: KeyIdentity) -> Self {
        let mut journal = Self::default();
        adopt_key(&mut journal, identity).expect("adopt");
        journal
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
    fn bound_key(&self) -> Option<KeyIdentity> {
        *self.bound.borrow()
    }

    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        *self.bound.borrow_mut() = Some(key);
        Ok(())
    }
}

const MAX_SIGNATURES: u32 = 4;
const STATEFUL_CTX: &[u8] = b"fixture-stateful";
const STATELESS_CTX: &[u8] = b"fixture-stateless";
const STATEFUL_MSG: &[u8] = b"fixture leaf 1";
const STATELESS_MSG: &[u8] = b"fixture stateless message";

/// Cargo feature name for the active profile.
fn active_profile_feature() -> &'static str {
    #[cfg(feature = "profile-256s")]
    {
        "profile-256s"
    }
    #[cfg(feature = "profile-256s-sha2")]
    {
        "profile-256s-sha2"
    }
    #[cfg(feature = "profile-128s-q18")]
    {
        "profile-128s-q18"
    }
    #[cfg(feature = "profile-128s-q20")]
    {
        "profile-128s-q20"
    }
}

/// Output basename: the feature name with its `profile-` prefix stripped.
fn fixture_basename() -> String {
    let feature = active_profile_feature();
    let stripped = feature
        .strip_prefix("profile-")
        .expect("profile feature names start with profile-");
    format!("fixture-{stripped}.json")
}

fn emit_suite<S>(name: &str, master: [u8; 32]) -> String
where
    S: StatefulSuite<Pq = ShrincsScheme>
        + StatefulHybridSignatureScheme<
            Signature = Vec<u8>,
            SecretKey = pqhybridsign::shrincs::SecretKey<S>,
            PublicKey = pqhybridsign::shrincs::PublicKey<S>,
        >,
{
    let (mut sk, pk) = keygen::<S>(&master, MAX_SIGNATURES).expect("keygen");

    // Export while fresh, before any signing. The stored blob is a key that
    // has not spent a leaf, so a consuming test can import it and re-sign
    // leaf 1 live. `sign_stateful` is cheap; the export is what removes the
    // keygen cost.
    assert_eq!(
        sk.next_leaf(),
        0,
        "{name}: fresh key must still sit at the first unused leaf"
    );
    let secret_key = sk.export().expect("export fresh secret key");
    let public_key = pk.as_ref().to_vec();

    let mut journal = MemoryJournal::adopted(sk.key_identity());
    let stateful_signature =
        S::sign_stateful(&mut sk, &mut journal, STATEFUL_MSG, STATEFUL_CTX).expect("leaf 1");
    assert!(
        S::verify_stateful(&pk, STATEFUL_MSG, STATEFUL_CTX, &stateful_signature),
        "{name}: stateful leaf-1 signature must verify before the fixture is written"
    );

    let stateless_signature = S::sign_stateless(
        &sk,
        &mut MemoryBudget::default(),
        STATELESS_MSG,
        STATELESS_CTX,
    )
    .expect("stateless");
    assert!(
        S::verify_stateless(&pk, STATELESS_MSG, STATELESS_CTX, &stateless_signature),
        "{name}: stateless signature must verify before the fixture is written"
    );

    // Suite entry only. The outer object carries `profile_name` once.
    format!(
        r#"    {{
      "suite": "{name}",
      "max_signatures": {MAX_SIGNATURES},
      "master_seed_hex": "{}",
      "secret_key_hex": "{}",
      "public_key_hex": "{}",
      "stateful_ctx_hex": "{}",
      "stateful_msg_hex": "{}",
      "stateful_leaf_index": 1,
      "stateful_signature_hex": "{}",
      "stateless_ctx_hex": "{}",
      "stateless_msg_hex": "{}",
      "stateless_signature_hex": "{}"
    }}"#,
        hex::encode(master),
        hex::encode(&secret_key),
        hex::encode(&public_key),
        hex::encode(STATEFUL_CTX),
        hex::encode(STATEFUL_MSG),
        hex::encode(&stateful_signature),
        hex::encode(STATELESS_CTX),
        hex::encode(STATELESS_MSG),
        hex::encode(&stateless_signature),
    )
}

#[test]
#[ignore = "generator, run explicitly with --ignored --nocapture in release mode"]
fn generate_fixtures() {
    let profile_name = <ShrincsScheme as PqStatefulScheme>::NAME;
    eprintln!(
        "generating fixtures for profile {profile_name} (feature {})",
        active_profile_feature()
    );

    let h5 = emit_suite::<EdSh>("ED-SH", [0x50u8; 32]);
    let h6 = emit_suite::<SrSh>("SR-SH", [0x60u8; 32]);

    let profile_id_hex = hex::encode(profile_id::PROFILE_ID);
    let body = format!(
        "{{\n  \"profile_name\": \"{profile_name}\",\n  \"profile_id_hex\": \"{profile_id_hex}\",\n  \"suites\": [\n{h5},\n{h6}\n  ]\n}}\n"
    );

    let out_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors"));
    let out_path = out_dir.join(fixture_basename());
    std::fs::write(&out_path, body.as_bytes()).unwrap_or_else(|e| {
        panic!("failed to write {}: {e}", out_path.display());
    });
    eprintln!("wrote {}", out_path.display());
}
