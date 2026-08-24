// SPDX-License-Identifier: AGPL-3.0-or-later
// Integration test binary: `cfg(test)` is always true here.
// `unwrap`/`expect`/`panic` are the normal way a test fails.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Fails when `src/lib.rs` has changed since the checked-in TypeScript
//! definitions under `npm/types/` were last regenerated.
//!
//! The C header check next door regenerates the header in memory and diffs
//! it. This one cannot: generating the `.d.ts` files needs a compiled
//! `wasm32-unknown-unknown` artifact, and `cargo test` runs on the host
//! target. It pins the input instead of the output.
//!
//! What this proves: somebody ran `scripts/regenerate-types.sh` at the
//! current revision of `src/lib.rs`. What it does not prove: that the
//! checked-in `.d.ts` files match what the generator would emit right now.
//! `scripts/check-types.sh`, run by the `wasm-npm` CI job, still proves
//! that. This test exists because that script runs in one job while
//! `cargo test --workspace` runs in every task's gate list.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

#[test]
fn typescript_definitions_were_regenerated_for_this_source() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = crate_dir.join("src").join("lib.rs");
    let stamp_path = crate_dir.join("npm").join("types").join("source.stamp");

    let source_bytes = std::fs::read(&source)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", source.display()));
    let actual = hex(&Sha256::digest(&source_bytes));

    let recorded = std::fs::read_to_string(&stamp_path)
        .unwrap_or_else(|e| {
            panic!(
                "could not read {}: {e}; run crates/pqhybridsign-wasm/scripts/regenerate-types.sh",
                stamp_path.display()
            )
        })
        .trim()
        .to_owned();

    assert_eq!(
        actual, recorded,
        "src/lib.rs changed since npm/types/*.d.ts were regenerated. Run \
         `crates/pqhybridsign-wasm/scripts/regenerate-types.sh` and commit \
         npm/types/, including source.stamp."
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
