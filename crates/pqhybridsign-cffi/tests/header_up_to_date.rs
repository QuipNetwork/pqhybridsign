// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regenerates the C header in memory and diffs it against the checked-in
//! `include/pqhybridsign.h`, so the header cannot drift from the source it
//! was generated from without failing `cargo test`.

use std::path::PathBuf;

#[test]
fn generated_header_matches_the_checked_in_file() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let checked_in = crate_dir.join("include").join("pqhybridsign.h");

    let bindings = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(cbindgen::Config::from_root_or_default(&crate_dir))
        .generate()
        .expect("cbindgen failed to generate the C header");
    let mut buf = Vec::new();
    bindings.write(&mut buf);
    let generated = String::from_utf8(buf).expect("cbindgen output is valid UTF-8");

    let on_disk = std::fs::read_to_string(&checked_in).unwrap_or_else(|e| {
        panic!(
            "could not read {}: {e}; run `cargo run --example gen_header -p pqhybridsign-cffi`",
            checked_in.display()
        )
    });

    assert_eq!(
        generated, on_disk,
        "include/pqhybridsign.h is out of date; regenerate it with \
         `cargo run --example gen_header -p pqhybridsign-cffi` and commit the result"
    );
}
