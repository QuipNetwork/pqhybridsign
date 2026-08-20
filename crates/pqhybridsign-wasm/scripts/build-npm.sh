#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds crates/pqhybridsign-wasm for both npm targets, compiles the
# TypeScript Promise API over them, and assembles the publishable package
# under npm/. Requires `wasm-pack` and `npm` on PATH. This one script is
# the whole build: it ends with npm/dist/ populated, so nothing downstream
# needs to run `npm run build` again before `npm test` or `npm pack`.
#
# The web and nodejs wasm builds land in separate subdirectories because
# their glue code differs (async `init()` versus a synchronous `require`),
# and npm/src/index.{node.cts,web.mts} -- and npm/package.json's `exports`
# map -- pick between them by environment.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$crate_dir"

workspace_root="$(cd "$crate_dir/../.." && pwd)"
workspace_version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$workspace_root/Cargo.toml" | head -n 1)
if [ -z "$workspace_version" ]; then
  echo "could not read workspace version from $workspace_root/Cargo.toml" >&2
  exit 1
fi
# The published npm version must name the workspace crate revision.
pkg_tmp="$(mktemp)"
sed "s/\"version\": \"[^\"]*\"/\"version\": \"$workspace_version\"/" npm/package.json > "$pkg_tmp"
mv -f "$pkg_tmp" npm/package.json

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

# npm/src/index.node.cts and npm/src/index.web.mts both import the wasm
# glue's checked-in .d.ts surface (see npm/types/ and scripts/check-types.sh),
# so this step must run after the wasm-pack builds above, not before.
( cd npm && npm install --no-audit --no-fund && npx tsc -p . )

echo "Compiled npm/src/ to npm/dist/ (gitignored build output)."
echo "Run scripts/check-types.sh to diff npm/web/ and npm/node/'s .d.ts files"
echo "against the checked-in copies under npm/types/ before publishing."
