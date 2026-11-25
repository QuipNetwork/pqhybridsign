// SPDX-License-Identifier: AGPL-3.0-or-later
// QPA-01 must remain enforced through the published Promise API.
import { createRequire } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const pqhs = require("../dist/index.node.cjs");
const message = new TextEncoder().encode("QPA-01 npm regression");
const context = new TextEncoder().encode("qpa01");
const identity = new Uint8Array(32);
identity[0] = 1;
const signAlias = identity.slice();
signAlias[31] = 0x80;
const unreducedAlias = new Uint8Array(32).fill(0xff);
unreducedAlias[0] = 0xee;
unreducedAlias[31] = 0x7f;
const orderEight = Uint8Array.from(Buffer.from(
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex"));

for (const suite of ["ED-ML-44", "ED-FN-512"]) {
  test(`${suite}: rejects weak Ed25519 keys with a valid PQ signature`, async () => {
    const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, new Uint8Array(32).fill(42));
    const signature = await pqhs.signDeterministic(suite, secretKey, message, context, new Uint8Array());
    assert.equal(await pqhs.verify(suite, publicKey, message, context, signature), true);
    const forged = signature.slice();
    forged.fill(0, 0, 64);
    forged[0] = 1; // R = identity, s = 0; preserve the valid PQ half.
    for (const weak of [identity, signAlias, unreducedAlias, orderEight]) {
      const key = publicKey.slice();
      key.set(weak, 0);
      assert.equal(await pqhs.verify(suite, key, message, context, forged), false);
    }
  });
}
