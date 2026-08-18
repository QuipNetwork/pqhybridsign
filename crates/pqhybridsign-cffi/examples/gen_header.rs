// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regenerates `include/pqhybridsign.h` from this crate's source and
//! `cbindgen.toml`. Run with `cargo run --example gen_header
//! -p pqhybridsign-cffi` and commit the result; `cargo test -p
//! pqhybridsign-cffi` fails the build if the checked-in header disagrees
//! with what this would produce.

use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = crate_dir.join("include").join("pqhybridsign.h");

    #[expect(
        clippy::expect_used,
        reason = "a developer-run generator, not library code; a cbindgen failure should abort loudly here"
    )]
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(cbindgen::Config::from_root_or_default(&crate_dir))
        .generate()
        .expect("cbindgen failed to generate the C header")
        .write_to_file(&out);

    println!("wrote {}", out.display());
}
