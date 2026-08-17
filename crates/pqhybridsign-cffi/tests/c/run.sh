#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds pqhybridsign-cffi, compiles tests/c/main.c against the generated
# header, links it against the built staticlib, and runs it. Exits nonzero
# on any failure -- a cargo build failure, a link failure, or the C
# program's own nonzero exit.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace_dir="$(cd "$crate_dir/../.." && pwd)"

cargo build --release -p pqhybridsign-cffi --manifest-path "$workspace_dir/Cargo.toml"

target_dir="$workspace_dir/target/release"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

# The archive is named on the command line rather than found through -L/-l.
# The crate builds both a cdylib and a staticlib into the same directory,
# and -lpqhybridsign_cffi prefers the shared object, which then has to be
# found again at run time. Naming the .a links it statically, which is what
# this test is for, and leaves the resulting binary with nothing to resolve
# at startup.
cc -std=c11 -Wall -Wextra -Werror \
    -I "$crate_dir/include" \
    "$crate_dir/tests/c/main.c" \
    -o "$out_dir/pqhybridsign_c_test" \
    "$target_dir/libpqhybridsign_cffi.a" \
    -lpthread -ldl -lm

"$out_dir/pqhybridsign_c_test"
