#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds crates/pqhybridsign-wasm for both npm targets and assembles the
# publishable package under npm/. Requires `wasm-pack` on PATH.
#
# The web and nodejs builds land in separate subdirectories because their
# glue code differs (async `init()` versus a synchronous `require`), and
# npm/package.json's `exports` map picks between them by environment.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$crate_dir"

wasm-pack build --release --target web --out-dir npm/web --out-name pqhybridsign_wasm --no-pack
wasm-pack build --release --target nodejs --out-dir npm/node --out-name pqhybridsign_wasm --no-pack

# wasm-pack writes its own package.json into each --out-dir; npm/package.json
# (the hand-authored template, checked into git) is the one that ships. Each
# subdirectory still needs its own minimal package.json, though: the web
# build is ES module syntax (`export function ...`) and the nodejs build is
# CommonJS (`exports.foo = ...`), and Node picks the parser for a `.js` file
# by walking up to the nearest package.json's "type" field, not the one at
# the package root that `exports` in npm/package.json resolves through.
rm -f npm/web/package.json npm/node/package.json npm/web/.gitignore npm/node/.gitignore
printf '{"type": "module"}\n' > npm/web/package.json
printf '{"type": "commonjs"}\n' > npm/node/package.json

echo "Built npm/web/ and npm/node/ (both gitignored build output)."
echo "Run scripts/check-types.sh to diff their .d.ts files against the checked-in"
echo "copies under npm/types/ before publishing."
