// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared loader for the per-profile fixture files under `tests/vectors/`.
//!
//! A directory under `tests/` is not a test binary on its own. Consuming
//! integration tests pull this module in with `mod fixture;`.
//!
//! Each fixture file holds both H5 and H6 for one profile. The active
//! `profile-*` feature selects the file at compile time via `include_str!`,
//! so a missing file is a compile error. A file whose recorded
//! `profile_name` disagrees with the active profile panics and names the
//! generator command to re-run. There is no fallback to `keygen`.
//!
//! # Cost trap: `SecretKey::import` at 128s
//!
//! `SecretKey::import` costs about 47 seconds at the 128s profiles, because
//! upstream re-derives the hypertree root to validate the blob. Per-commit
//! consumers must therefore use the verify-only path: `public_key` plus the
//! stored signatures. Those cost under a second at every profile.
//! `secret_key` is there for the scheduled job and for the 256s profiles. A
//! test that imports it at 128s pays keygen-class cost, and `keygen` costs
//! the same, so importing buys nothing there.

use pqhybridsign_core::PqStatefulScheme;
use pqhybridsign_shrincs::ShrincsScheme;
use std::sync::OnceLock;

/// One suite entry from a per-profile fixture file.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub profile_name: String,
    /// `"H5"` or `"H6"`.
    pub suite: String,
    pub max_signatures: u32,
    pub master_seed: Vec<u8>,
    /// `SecretKey::export()` blob of a fresh key at leaf 1 (counter still at
    /// the first unused leaf).
    pub secret_key: Vec<u8>,
    /// Public key wire bytes, length `StatefulSuite::VERIFY_PUBLIC_KEY_LEN`.
    pub public_key: Vec<u8>,
    pub stateful_ctx: Vec<u8>,
    pub stateful_msg: Vec<u8>,
    /// Always `1`: the first leaf, recorded in the same 1-based convention
    /// the golden stateful vectors use.
    pub stateful_leaf_index: u32,
    pub stateful_signature: Vec<u8>,
    pub stateless_ctx: Vec<u8>,
    pub stateless_msg: Vec<u8>,
    pub stateless_signature: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct File {
    profile_name: String,
    suites: Vec<SuiteEntry>,
}

#[derive(serde::Deserialize)]
struct SuiteEntry {
    suite: String,
    max_signatures: u32,
    master_seed_hex: String,
    secret_key_hex: String,
    public_key_hex: String,
    stateful_ctx_hex: String,
    stateful_msg_hex: String,
    stateful_leaf_index: u32,
    stateful_signature_hex: String,
    stateless_ctx_hex: String,
    stateless_msg_hex: String,
    stateless_signature_hex: String,
}

/// Cargo feature name for the active profile, without the `profile-` prefix.
/// Used in the panic message that tells the operator which generator to run.
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

/// Basename of the fixture file for the active profile.
fn fixture_basename() -> &'static str {
    #[cfg(feature = "profile-256s")]
    {
        "fixture-256s.json"
    }
    #[cfg(feature = "profile-256s-sha2")]
    {
        "fixture-256s-sha2.json"
    }
    #[cfg(feature = "profile-128s-q18")]
    {
        "fixture-128s-q18.json"
    }
    #[cfg(feature = "profile-128s-q20")]
    {
        "fixture-128s-q20.json"
    }
}

fn fixture_json() -> &'static str {
    #[cfg(feature = "profile-256s")]
    {
        include_str!("../vectors/fixture-256s.json")
    }
    #[cfg(feature = "profile-256s-sha2")]
    {
        include_str!("../vectors/fixture-256s-sha2.json")
    }
    #[cfg(feature = "profile-128s-q18")]
    {
        include_str!("../vectors/fixture-128s-q18.json")
    }
    #[cfg(feature = "profile-128s-q20")]
    {
        include_str!("../vectors/fixture-128s-q20.json")
    }
}

fn decode_hex(field: &str, hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_else(|e| panic!("fixture field `{field}` is not hex: {e}"))
}

fn load_suite(want: &str) -> Fixture {
    let file: File = serde_json::from_str(fixture_json())
        .unwrap_or_else(|e| panic!("fixture {} failed to parse: {e}", fixture_basename()));

    let active_name = <ShrincsScheme as PqStatefulScheme>::NAME;
    if file.profile_name != active_name {
        panic!(
            "fixture {} is keyed on profile_name {:?}, but the active profile is {:?}. \
             Regenerate with:\n  cargo test -p pqhybridsign-shrincs --release \
             --no-default-features --features {} --test generate_fixtures -- --ignored --nocapture",
            fixture_basename(),
            file.profile_name,
            active_name,
            active_profile_feature(),
        );
    }

    let entry = file
        .suites
        .iter()
        .find(|s| s.suite == want)
        .unwrap_or_else(|| {
            panic!(
                "fixture {} has no suite entry for {want}",
                fixture_basename()
            )
        });

    Fixture {
        profile_name: file.profile_name,
        suite: entry.suite.clone(),
        max_signatures: entry.max_signatures,
        master_seed: decode_hex("master_seed_hex", &entry.master_seed_hex),
        secret_key: decode_hex("secret_key_hex", &entry.secret_key_hex),
        public_key: decode_hex("public_key_hex", &entry.public_key_hex),
        stateful_ctx: decode_hex("stateful_ctx_hex", &entry.stateful_ctx_hex),
        stateful_msg: decode_hex("stateful_msg_hex", &entry.stateful_msg_hex),
        stateful_leaf_index: entry.stateful_leaf_index,
        stateful_signature: decode_hex("stateful_signature_hex", &entry.stateful_signature_hex),
        stateless_ctx: decode_hex("stateless_ctx_hex", &entry.stateless_ctx_hex),
        stateless_msg: decode_hex("stateless_msg_hex", &entry.stateless_msg_hex),
        stateless_signature: decode_hex("stateless_signature_hex", &entry.stateless_signature_hex),
    }
}

/// H5 fixture for the active profile.
pub fn h5() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| load_suite("H5"))
}

/// H6 fixture for the active profile.
pub fn h6() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| load_suite("H6"))
}
