// SPDX-License-Identifier: AGPL-3.0-or-later
// QPA-02 must remain enforced through the published Promise API.
import { createRequire } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const pqhs = require("../dist/index.node.cjs");
const message = new TextEncoder().encode("QPA-02 npm regression");
const context = new TextEncoder().encode("qpa02");
const zero = new Uint8Array(64); // R = identity, s = 0.
zero[63] = 0x80;
const one = zero.slice();
one.set(Buffer.from("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76", "hex"));
one[32] = 1; // R = B, s = 1.

for (const suite of ["SR-ML-44", "SR-FN-512"]) {
  test(`${suite}: rejects an identity sr25519 key with a valid PQ signature`, async () => {
    const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, new Uint8Array(32).fill(42));
    const signature = await pqhs.signDeterministic(suite, secretKey, message, context, new Uint8Array());
    assert.equal(await pqhs.verify(suite, publicKey, message, context, signature), true);
    const key = publicKey.slice();
    key.fill(0, 0, 32);
    for (const classical of [zero, one]) {
      const forged = signature.slice();
      forged.set(classical, 0);
      assert.equal(await pqhs.verify(suite, key, message, context, forged), false);
    }
  });
}
