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

cc -std=c11 -Wall -Wextra -Werror \
    -I "$crate_dir/include" \
    "$crate_dir/tests/c/main.c" \
    -o "$out_dir/pqhybridsign_c_test" \
    -L "$target_dir" -lpqhybridsign_cffi \
    -lpthread -ldl -lm

# The staticlib is self-contained but still needs its runtime search path
# set for the odd platform that resolves symbols lazily; harmless where it
# isn't needed.
LD_LIBRARY_PATH="$target_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$out_dir/pqhybridsign_c_test"
