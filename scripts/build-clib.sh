#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

# The download name and release links promise Linux amd64. Refuse a native
# ARM build before doing any packaging, and name the Cargo target explicitly
# so CARGO_BUILD_TARGET cannot silently change the archive's architecture.
release_target=x86_64-unknown-linux-gnu
release_host=$(rustc -vV | sed -n 's/^host: //p')
if [ "$release_host" != "$release_target" ]; then
    echo "C library packaging requires $release_target; found $release_host" >&2
    exit 1
fi

# TAG from $1 or $TAG environment variable, defaulting to v<workspace version>
if [ "${1:-}" ]; then
    TAG="$1"
elif [ -z "${TAG:-}" ]; then
    # Extract version from Cargo.toml
    VERSION=$(grep -A 100 '^\[workspace.package\]' Cargo.toml | grep '^version = ' | head -1 | sed -E 's/^version = "(.+)"$/\1/')
    TAG="v${VERSION}"
fi

# Build the C FFI crate in release mode
cargo build --locked --release --target "$release_target" -p pqhybridsign-cffi

# Clean and prepare the staging directory
rm -f dist/pqhybridsign-clib-*
find dist/clib -type f -delete 2>/dev/null || true
mkdir -p dist/clib/include

# Copy the built artifacts
cp "target/$release_target/release/libpqhybridsign_cffi.so" dist/clib/
cp "target/$release_target/release/libpqhybridsign_cffi.a" dist/clib/

# Copy the header file
cp crates/pqhybridsign-cffi/include/pqhybridsign.h dist/clib/include/

# Copy the license
cp LICENSE dist/clib/

# Create the tarball
cd dist/clib && tar czf "../pqhybridsign-clib-${TAG}-linux-amd64.tar.gz" .
cd ../..

# Create the sha256 checksum file (format: hash  filename)
cd dist && sha256sum "pqhybridsign-clib-${TAG}-linux-amd64.tar.gz" > "pqhybridsign-clib-${TAG}-linux-amd64.tar.gz.sha256"
