#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regenerates npm/types/pqhybridsign_wasm.{web,node}.d.ts and
# npm/types/source.stamp from the current source. Run this after any change
# to crates/pqhybridsign-wasm/src/lib.rs, then commit the result.
# scripts/check-types.sh diffs the .d.ts files against a fresh build, and
# tests/types_up_to_date.rs checks the stamp under `cargo test`.
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

# The stamp records the source revision these definitions came from, so
# tests/types_up_to_date.rs can fail under `cargo test --workspace` when a
# later change to src/lib.rs skips this script. Written here, in the same
# run that writes the .d.ts files, so the two cannot disagree unless the
# stamp is edited by hand.
sha256sum src/lib.rs | cut -d' ' -f1 > npm/types/source.stamp

echo "Regenerated npm/types/pqhybridsign_wasm.web.d.ts, .node.d.ts and source.stamp."
