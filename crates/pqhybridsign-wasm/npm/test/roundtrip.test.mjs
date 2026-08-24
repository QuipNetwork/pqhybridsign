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

test("a stateful key handle signs twice and both signatures verify", async () => {
  const suite = "H5";
  const { publicKey, secretKey } = await pqhs.keygenStatefulFromSeed(suite, seed(0x21), 4);

  const key = await pqhs.openStatefulKey(suite, secretKey);
  try {
    const journal = new MemoryLeafJournal();
    await pqhs.adoptKey(journal, await key.keyIdentity());

    const before = await key.export();
    assert.deepEqual(before, secretKey);

    const sig1 = await key.signStateful(journal, MSG, CTX);
    assert.equal(await pqhs.verify(suite, publicKey, MSG, CTX, sig1), true);

    const after = await key.export();
    assert.notDeepEqual(after, before, "the key did not advance");

    const sig2 = await key.signStateful(journal, MSG2, CTX);
    assert.equal(await pqhs.verify(suite, publicKey, MSG2, CTX, sig2), true);
    assert.notDeepEqual(sig1, sig2);
  } finally {
    key.free();
  }
});

test("a stateful key handle rejects a stateless suite", async () => {
  await assert.rejects(() => pqhs.openStatefulKey("H1", new Uint8Array(32)));
});

// A synchronous in-memory StatelessBudgetStore. Not durable -- a real
// integrator persists record() -- but it exercises the few-time budget
// path the H5/H6 VRF spends on every evaluation.
class MemoryStatelessBudget {
  #counts = new Map();
  static #hex(bytes) {
    let s = "";
    for (const b of bytes) s += b.toString(16).padStart(2, "0");
    return s;
  }
  consumed(key) {
    const v = this.#counts.get(MemoryStatelessBudget.#hex(key));
    return v === undefined ? null : v;
  }
  record(key, count) {
    this.#counts.set(MemoryStatelessBudget.#hex(key), count);
  }
}

// The standard all-zero-entropy BIP39 test vector.
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const VRF_INPUT = new TextEncoder().encode("epoch-7/slot-42/randomness");
const VRF_CTX = new TextEncoder().encode("leadership-score");

test("the standard BIP39 test vector produces a stable master seed", async () => {
  const seed = await pqhs.masterSeedFromMnemonic(PHRASE);
  assert.equal(seed.length, 32);
  assert.notDeepEqual(seed, new Uint8Array(32));

  const again = await pqhs.masterSeedFromMnemonic(PHRASE);
  assert.deepEqual(seed, again);
});

test("an invalid recovery phrase is refused", async () => {
  await assert.rejects(() => pqhs.masterSeedFromMnemonic("not a mnemonic at all"));
});

test("a password changes the master seed", async () => {
  const without = await pqhs.masterSeedFromMnemonic(PHRASE);
  const withPw = await pqhs.masterSeedFromMnemonic(PHRASE, "pw");
  assert.notDeepEqual(without, withPw);
});

test("a junction child differs from its parent and its sibling", async () => {
  const parent = new Uint8Array(32).fill(3);
  const a = await pqhs.deriveHardJunction(parent, new Uint8Array(32).fill(1));
  const b = await pqhs.deriveHardJunction(parent, new Uint8Array(32).fill(2));
  assert.notDeepEqual(a, parent);
  assert.notDeepEqual(a, b);
});

test("a junction path equals the stepwise derivation", async () => {
  const parent = new Uint8Array(32).fill(3);
  const first = new Uint8Array(32).fill(1);
  const second = new Uint8Array(32).fill(2);

  const intermediate = await pqhs.deriveHardJunction(parent, first);
  const stepwise = await pqhs.deriveHardJunction(intermediate, second);
  const path = await pqhs.deriveHardJunctionPath(parent, [first, second]);
  assert.deepEqual(stepwise, path);

  const reversed = await pqhs.deriveHardJunctionPath(parent, [second, first]);
  assert.notDeepEqual(path, reversed);
});

test("an empty junction path returns the parent", async () => {
  const parent = new Uint8Array(32).fill(3);
  const out = await pqhs.deriveHardJunctionPath(parent, []);
  assert.deepEqual(out, parent);
});

test("a wrong-length chain code raises naming the index", async () => {
  const parent = new Uint8Array(32).fill(3);
  await assert.rejects(
    () => pqhs.deriveHardJunctionPath(parent, [new Uint8Array(32).fill(1), new Uint8Array(16)]),
    /index 1/,
  );
});

for (const [i, suite] of STATELESS_SUITES.entries()) {
  test(`${suite}: vrfProofLen bounds the proof vrfProve returns`, async () => {
    const { secretKey } = await pqhs.keygenFromSeed(suite, seed(i + 1));
    const proof = await pqhs.vrfProve(suite, secretKey, VRF_INPUT);
    const maxLen = await pqhs.vrfProofLen(suite);
    assert.ok(maxLen > 0);
    assert.ok(proof.length <= maxLen);
  });

  test(`${suite}: a VRF proof verifies`, async () => {
    const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, seed(i + 1));
    const proof = await pqhs.vrfProve(suite, secretKey, VRF_INPUT);
    assert.equal(await pqhs.vrfVerify(suite, publicKey, VRF_INPUT, proof), true);
  });

  test(`${suite}: a tampered VRF proof does not verify`, async () => {
    const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, seed(i + 1));
    const proof = await pqhs.vrfProve(suite, secretKey, VRF_INPUT);
    proof[0] ^= 0x01;
    assert.equal(await pqhs.vrfVerify(suite, publicKey, VRF_INPUT, proof), false);
  });

  test(`${suite}: vrfProveDeterministic repeats byte-for-byte and verifies`, async () => {
    const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, seed(i + 1));
    const proofA = await pqhs.vrfProveDeterministic(suite, secretKey, VRF_INPUT);
    const proofB = await pqhs.vrfProveDeterministic(suite, secretKey, VRF_INPUT);
    assert.deepEqual(proofA, proofB);
    assert.equal(await pqhs.vrfVerify(suite, publicKey, VRF_INPUT, proofA), true);
  });
}

test("vrfMakeBytes is stable across two proofs of one input", async () => {
  const suite = "H3";
  const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, seed(3));
  const proofA = await pqhs.vrfProve(suite, secretKey, VRF_INPUT);
  const proofB = await pqhs.vrfProve(suite, secretKey, VRF_INPUT);
  const outA = await pqhs.vrfMakeBytes(suite, publicKey, VRF_INPUT, proofA, VRF_CTX);
  const outB = await pqhs.vrfMakeBytes(suite, publicKey, VRF_INPUT, proofB, VRF_CTX);
  assert.equal(outA.length, 32);
  assert.deepEqual(outA, outB);
});

test("a different VRF output context gives different bytes", async () => {
  const suite = "H3";
  const { publicKey, secretKey } = await pqhs.keygenFromSeed(suite, seed(3));
  const proof = await pqhs.vrfProve(suite, secretKey, VRF_INPUT);
  const score = await pqhs.vrfMakeBytes(
    suite,
    publicKey,
    VRF_INPUT,
    proof,
    new TextEncoder().encode("leadership"),
  );
  const randomness = await pqhs.vrfMakeBytes(
    suite,
    publicKey,
    VRF_INPUT,
    proof,
    new TextEncoder().encode("randomness"),
  );
  assert.notDeepEqual(score, randomness);
});

test("vrfProve refuses H5 and H6 and names deriveVrfStatelessKey", async () => {
  // The placeholder key is 32 bytes, not a valid H5/H6 secret key -- but the
  // suite gate runs before the key length is ever inspected, exactly as the
  // sibling sign() test above documents, so the placeholder is safe here.
  for (const suite of STATEFUL_SUITES) {
    await assert.rejects(
      () => pqhs.vrfProve(suite, new Uint8Array(32), VRF_INPUT),
      /deriveVrfStatelessKey/,
    );
  }
});

test("vrfProveDeterministic refuses H5 and H6 and names deriveVrfStatelessKey", async () => {
  for (const suite of STATEFUL_SUITES) {
    await assert.rejects(
      () => pqhs.vrfProveDeterministic(suite, new Uint8Array(32), VRF_INPUT),
      /deriveVrfStatelessKey/,
    );
  }
});

for (const suite of STATELESS_SUITES) {
  test(`${suite}: deriveVrfStatelessKey rejects a stateless suite`, async () => {
    await assert.rejects(() => pqhs.deriveVrfStatelessKey(suite, seed(0x13)));
  });
}

for (const suite of STATEFUL_SUITES) {
  test(`${suite}: a derived VRF stateless key proves and verifies`, async () => {
    const { key, publicKey } = await pqhs.deriveVrfStatelessKey(suite, seed(0x13));
    try {
      const budget = new MemoryStatelessBudget();
      const proof = await key.prove(budget, VRF_INPUT);
      assert.equal(await pqhs.vrfVerify(suite, publicKey, VRF_INPUT, proof), true);
    } finally {
      key.free();
    }
  });
}
