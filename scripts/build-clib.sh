#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

# TAG from $1 or $TAG environment variable, defaulting to v<workspace version>
if [ "${1:-}" ]; then
    TAG="$1"
elif [ -z "${TAG:-}" ]; then
    # Extract version from Cargo.toml
    VERSION=$(grep -A 100 '^\[workspace.package\]' Cargo.toml | grep '^version = ' | head -1 | sed -E 's/^version = "(.+)"$/\1/')
    TAG="v${VERSION}"
fi

# Build the C FFI crate in release mode
cargo build --release -p pqhybridsign-cffi

# Clean and prepare the staging directory
rm -f dist/pqhybridsign-clib-*
find dist/clib -type f -delete 2>/dev/null || true
mkdir -p dist/clib/include

# Copy the built artifacts
cp target/release/libpqhybridsign_cffi.so dist/clib/
cp target/release/libpqhybridsign_cffi.a dist/clib/

# Copy the header file
cp crates/pqhybridsign-cffi/include/pqhybridsign.h dist/clib/include/

# Copy the license
cp LICENSE dist/clib/

# Create the tarball
cd dist/clib && tar czf "../pqhybridsign-clib-${TAG}-linux-amd64.tar.gz" .
cd ../..

# Create the sha256 checksum file (format: hash  filename)
cd dist && sha256sum "pqhybridsign-clib-${TAG}-linux-amd64.tar.gz" > "pqhybridsign-clib-${TAG}-linux-amd64.tar.gz.sha256"
