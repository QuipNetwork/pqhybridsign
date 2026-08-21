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
const STATEFUL_SUITES = ["H5", "H6"];
const MSG = new TextEncoder().encode("the message the npm roundtrip test signs");
const MSG2 = new TextEncoder().encode("a second npm roundtrip message");
const CTX = new TextEncoder().encode("npm-roundtrip-test");
const NONCE = new TextEncoder().encode("fixed-npm-roundtrip-nonce");

function seed(byte) {
  return new Uint8Array(32).fill(byte);
}

// A synchronous in-memory LeafJournal, the shape signStateful drives. Not
// durable -- a real integrator persists commit()/bindKey() to storage that
// survives a restart -- but it exercises the identity binding and lockstep
// counter checks within a session exactly as a durable one would.
class MemoryLeafJournal {
  #next = 0;
  #bound = null;
  commit(leaf) {
    if (leaf + 1 > this.#next) this.#next = leaf + 1;
  }
  nextLeaf() {
    return this.#next;
  }
  boundKey() {
    return this.#bound === null ? null : this.#bound.slice();
  }
  bindKey(identity) {
    this.#bound = identity.slice();
  }
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

for (const suite of STATEFUL_SUITES) {
  test(`${suite}: the stateless entry points reject and name the stateful ones`, async () => {
    // keygenFromSeed/sign/signDeterministic are the stateless path; each must
    // reject H5/H6 rather than silently spend a one-time leaf. sign() rejects
    // before it inspects the placeholder key's length.
    for (const call of [
      () => pqhs.keygenFromSeed(suite, seed(1)),
      () => pqhs.sign(suite, new Uint8Array(32), MSG, CTX),
      () => pqhs.signDeterministic(suite, new Uint8Array(32), MSG, CTX, NONCE),
    ]) {
      await assert.rejects(call, /signStateful/);
    }
  });

  test(`${suite}: stateful round trip -- keygen, adopt, sign, verify`, async () => {
    const { secretKey, publicKey } = await pqhs.keygenStatefulFromSeed(suite, seed(0x50), 4);
    const journal = new MemoryLeafJournal();
    await pqhs.adoptKey(journal, await pqhs.keyIdentity(suite, publicKey));

    const { signature, nextSecretKey } = await pqhs.signStateful(
      suite,
      secretKey,
      journal,
      MSG,
      CTX,
    );
    assert.equal(nextSecretKey.length, await pqhs.secretKeyLen(suite));
    assert.equal(journal.nextLeaf(), 1);
    assert.equal(await pqhs.verify(suite, publicKey, MSG, CTX, signature), true);
  });

  test(`${suite}: reusing a stale blob is rejected, not signed`, async () => {
    const { secretKey, publicKey } = await pqhs.keygenStatefulFromSeed(suite, seed(0x70), 4);
    const journal = new MemoryLeafJournal();
    await pqhs.adoptKey(journal, await pqhs.keyIdentity(suite, publicKey));

    await pqhs.signStateful(suite, secretKey, journal, MSG, CTX);
    // The original blob is now stale; signing with it again is refused rather
    // than reissuing the spent leaf.
    await assert.rejects(
      () => pqhs.signStateful(suite, secretKey, journal, MSG2, CTX),
      /diverged/,
    );
  });
}

test('storedPublicKeyLen("H5") resolves to a positive length', async () => {
  const len = await pqhs.storedPublicKeyLen("H5");
  assert.ok(len > 0);
});

test("profileName resolves to a non-empty string", async () => {
  const name = await pqhs.profileName();
  assert.equal(typeof name, "string");
  assert.ok(name.length > 0);
});
