// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

// wasm-bindgen emits InitOutput properties in Wasm export order, which can
// differ between builds without changing the API. Sort only these independent
// readonly properties. Preserve every declaration and everything outside this
// interface so signatures, documentation, and overload order remain checked.
export function normalizeTypes(source) {
  return source.replace(/^export interface InitOutput \{\n([\s\S]*?)^\}/m, (_match, body) => {
    const members = body.slice(0, -1).split("\n");
    if (!members.every((line) => /^    readonly [\w$]+: .+;$/.test(line))) {
      throw new Error("Unexpected InitOutput declaration format; review normalize-types.mjs");
    }
    return `export interface InitOutput {\n${members.sort().join("\n")}\n}`;
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length < 3) {
    throw new Error("Usage: node normalize-types.mjs <declaration.d.ts> [...]");
  }
  for (const path of process.argv.slice(2)) {
    writeFileSync(path, normalizeTypes(readFileSync(path, "utf8")));
  }
}
