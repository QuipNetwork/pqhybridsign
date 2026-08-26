// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Sign/verify roundtrip example for ED-ML-44 through SR-FN-512, built
 * against the published @quip.network/pqhybridsign npm package.
 *
 * For each suite: derive a keypair from a fixed seed, sign a message
 * deterministically, verify the signature, tamper one message byte, and
 * confirm verification then fails. Every seed and nonce is a fixed
 * constant, so the run needs no random number generator and is
 * byte-for-byte repeatable.
 *
 * Prints one line per suite checked and exits 0. On the first failure it
 * prints a message to stderr and exits nonzero.
 */

import {
  keygenFromSeed,
  signDeterministic,
  verify,
  type Suite,
} from "@quip.network/pqhybridsign";

// Application context bound into every signature.
const CTX = new TextEncoder().encode("pqhybridsign-example-ctx");
// Fixed nonce for deterministic signing. Not every component honours it
// (see the Rust `composite::sign_deterministic` documentation for which
// do), but it removes any dependency on a random number generator for
// this example.
const NONCE = new TextEncoder().encode("pqhybridsign-example-nonce");
// Message signed by every suite in this example.
const MESSAGE = new TextEncoder().encode("pqhybridsign roundtrip message");

interface SuiteCase {
  readonly suite: Suite;
  readonly seedByte: number;
}

// ED-SH and SR-SH reject keygenFromSeed and both sign functions, so this
// example -- which signs -- covers only the four stateless suites.
const SUITES: readonly SuiteCase[] = [
  { suite: "ED-ML-44", seedByte: 1 },
  { suite: "ED-FN-512", seedByte: 2 },
  { suite: "SR-ML-44", seedByte: 3 },
  { suite: "SR-FN-512", seedByte: 4 },
];

/** Flip the first byte of `msg`, producing the tampered message this
 * example verifies against. */
function tamper(msg: Uint8Array): Uint8Array {
  const tampered = new Uint8Array(msg);
  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  return tampered;
}

/** Roundtrip one suite: keygen, sign, verify true, tamper, verify false.
 * Throws on the first failure. */
async function checkSuite({ suite, seedByte }: SuiteCase): Promise<void> {
  // One fixed 32-byte master seed per suite, so a suite's keypair never
  // depends on another suite's.
  const seed = new Uint8Array(32).fill(seedByte);
  const { publicKey, secretKey } = await keygenFromSeed(suite, seed);

  const sig = await signDeterministic(suite, secretKey, MESSAGE, CTX, NONCE);

  const valid = await verify(suite, publicKey, MESSAGE, CTX, sig);
  if (!valid) {
    throw new Error(`${suite}: verify of the untampered signature returned false`);
  }

  const stillValid = await verify(suite, publicKey, tamper(MESSAGE), CTX, sig);
  if (stillValid) {
    throw new Error(`${suite}: verify of the tampered message returned true`);
  }

  console.log(`${suite}: keygen, sign, verify true, tamper, verify false -- OK`);
}

async function main(): Promise<number> {
  for (const suiteCase of SUITES) {
    try {
      await checkSuite(suiteCase);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`error: ${message}\n`);
      return 1;
    }
  }
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`error: ${message}\n`);
    process.exitCode = 1;
  });
