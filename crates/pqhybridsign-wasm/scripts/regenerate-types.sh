#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regenerates npm/types/pqhybridsign_wasm.{web,node}.d.ts from the current
# source. Run this after any change to crates/pqhybridsign-wasm/src/lib.rs's
# public surface, then commit the result. scripts/check-types.sh is the CI
# side of this: it fails if these files are out of date.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$crate_dir"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

wasm-pack build --release --target web --out-dir "$work/web" --out-name pqhybridsign_wasm --no-pack >/dev/null
wasm-pack build --release --target nodejs --out-dir "$work/node" --out-name pqhybridsign_wasm --no-pack >/dev/null

mkdir -p npm/types
cp "$work/web/pqhybridsign_wasm.d.ts" npm/types/pqhybridsign_wasm.web.d.ts
cp "$work/node/pqhybridsign_wasm.d.ts" npm/types/pqhybridsign_wasm.node.d.ts

echo "Regenerated npm/types/pqhybridsign_wasm.web.d.ts and .node.d.ts."
