#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regenerates the wasm-bindgen TypeScript definitions for both npm targets
# and fails if they differ from the checked-in copies under npm/types/. Run
# after any change to crates/pqhybridsign-wasm/src/lib.rs's public surface,
# and in continuous integration, so the committed .d.ts files cannot drift
# from the source the same way the C header is diff-tested.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$crate_dir"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

wasm-pack build --release --target web --out-dir "$work/web" --out-name pqhybridsign_wasm --no-pack >/dev/null
wasm-pack build --release --target nodejs --out-dir "$work/node" --out-name pqhybridsign_wasm --no-pack >/dev/null

status=0
if ! diff -u npm/types/pqhybridsign_wasm.web.d.ts "$work/web/pqhybridsign_wasm.d.ts"; then
    echo "npm/types/pqhybridsign_wasm.web.d.ts is stale; run scripts/regenerate-types.sh" >&2
    status=1
fi
if ! diff -u npm/types/pqhybridsign_wasm.node.d.ts "$work/node/pqhybridsign_wasm.d.ts"; then
    echo "npm/types/pqhybridsign_wasm.node.d.ts is stale; run scripts/regenerate-types.sh" >&2
    status=1
fi

exit "$status"
