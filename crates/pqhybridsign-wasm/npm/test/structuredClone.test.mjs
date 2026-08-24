// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Checks the claim in crates/pqhybridsign-wasm/src/lib.rs's "Why signing H5
// and H6 from JavaScript is safe" section: structuredClone does not reject a
// wasm-bindgen class, it clones the own enumerable properties into a plain
// object with no class prototype and therefore no methods. Uses the raw
// module through __loadForTest, because the claim is about the
// wasm-bindgen StatefulKey class, not the Promise-based wrapper this
// package's normal entry point returns.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const dist = require(join(here, "..", "dist", "index.node.cjs"));

test("structuredClone of a raw StatefulKey handle produces an inert plain object, and the original handle still answers", async () => {
  const raw = await dist.__loadForTest();
  const keyPair = raw.keygenStatefulFromSeed("H5", new Uint8Array(32).fill(0x2c), 4);
  const key = raw.StatefulKey.open("H5", keyPair.secretKey);
  keyPair.free();

  try {
    const clone = structuredClone(key);
    assert.equal(
      Object.getPrototypeOf(clone),
      Object.prototype,
      "the clone carries the StatefulKey prototype",
    );
    assert.equal(
      typeof clone.signStateful,
      "undefined",
      "the clone carries a callable signStateful",
    );
    assert.equal(typeof clone.free, "undefined", "the clone carries a callable free");
    assert.equal(
      typeof clone.__wbg_ptr,
      "number",
      "the clone lost the raw pointer field, so it is an empty object rather than a live but classless one",
    );

    const identity = key.keyIdentity();
    assert.equal(identity.length, 32, "the original handle stopped answering after the clone");
  } finally {
    key.free();
  }
});
