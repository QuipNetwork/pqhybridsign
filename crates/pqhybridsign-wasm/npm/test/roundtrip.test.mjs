// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Exercises the Promise-based API this package ships, through the built
// Node.js (CommonJS) entry point at dist/index.node.cjs -- the same file
// package.json's "main" and exports["."].node point a consumer at. Run
// after `npm run build` (wired into "npm test" via the "build" script
// being a separate step -- see package.json):
//
//   npm run build
//   npm test
//
// Every seed below is a fixed byte pattern, not random: a signing test
// that only sometimes fails is worse than one that never runs.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const pqhs = require(join(here, "..", "dist", "index.node.cjs"));

const STATELESS_SUITES = ["H1", "H2", "H3", "H4"];
const MSG = new TextEncoder().encode("the message the npm roundtrip test signs");
const CTX = new TextEncoder().encode("npm-roundtrip-test");
const NONCE = new TextEncoder().encode("fixed-npm-roundtrip-nonce");

function seed(byte) {
  return new Uint8Array(32).fill(byte);
}

for (const [i, suite] of STATELESS_SUITES.entries()) {
  test(`${suite}: keygenFromSeed -> sign -> verify resolves true`, async () => {
    const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, seed(i + 1));
    const sig = await pqhs.sign(suite, secretKey, MSG, CTX);
    assert.equal(await pqhs.verify(suite, publicKey, MSG, CTX, sig), true);
  });

  test(`${suite}: verify resolves false for a tampered message`, async () => {
    const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, seed(i + 1));
    const sig = await pqhs.sign(suite, secretKey, MSG, CTX);
    const tampered = new TextEncoder().encode("a different message entirely");
    assert.equal(await pqhs.verify(suite, publicKey, tampered, CTX, sig), false);
  });

  test(`${suite}: signDeterministic with a fixed nonce is repeatable`, async () => {
    const { secretKey } = await pqhs.keygenFromSeed(suite, seed(i + 1));
    const sigA = await pqhs.signDeterministic(suite, secretKey, MSG, CTX, NONCE);
    const sigB = await pqhs.signDeterministic(suite, secretKey, MSG, CTX, NONCE);
    assert.deepEqual(sigA, sigB);
  });
}

test("H5: keygenFromSeed rejects (no stateful signing entry point)", async () => {
  await assert.rejects(() => pqhs.keygenFromSeed("H5", seed(1)));
});

test("H5: sign rejects (no stateful signing entry point)", async () => {
  // sign() needs a secret key; keygenFromSeed already rejects for H5, so
  // this exercises sign's own rejection independently with an
  // arbitrarily-sized placeholder key -- sign must reject before it ever
  // inspects the key's length.
  await assert.rejects(() => pqhs.sign("H5", new Uint8Array(32), MSG, CTX));
});

test("H5: signDeterministic rejects (no stateful signing entry point)", async () => {
  await assert.rejects(() =>
    pqhs.signDeterministic("H5", new Uint8Array(32), MSG, CTX, NONCE),
  );
});

test('storedPublicKeyLen("H5") resolves to a positive length', async () => {
  const len = await pqhs.storedPublicKeyLen("H5");
  assert.ok(len > 0);
});

test("profileName resolves to a non-empty string", async () => {
  const name = await pqhs.profileName();
  assert.equal(typeof name, "string");
  assert.ok(name.length > 0);
});
