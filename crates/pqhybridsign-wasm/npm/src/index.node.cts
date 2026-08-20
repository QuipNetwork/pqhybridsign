// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Node.js (CommonJS) entry point for `@quip.network/pqhybridsign`.
 *
 * Loads `../node/pqhybridsign_wasm.js`, the `wasm-pack --target nodejs`
 * build assembled by `../../scripts/build-npm.sh`: its glue instantiates
 * the wasm module synchronously on `require`, so the loader below only
 * has to wrap that `require` call in a promise for {@link createApi} to
 * cache.
 *
 * `.cts` (rather than `.ts`) forces this file to compile to CommonJS
 * regardless of `tsconfig.json`'s `module` setting, matching
 * `package.json`'s `exports["."].node` entry point.
 */

import { createApi, type RawModule } from "./api.js";

export type { KeyPair, PqHybridSignApi, RawKeyPair, RawModule, Suite } from "./api.js";

function load(): Promise<RawModule> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return Promise.resolve(require("../node/pqhybridsign_wasm.js") as RawModule);
}

const api = createApi(load);

export const {
  keygenFromSeed,
  sign,
  signDeterministic,
  verify,
  verifyWithStoredPublicKey,
  publicKeyLen,
  secretKeyLen,
  signatureLen,
  storedPublicKeyLen,
  profileName,
} = api;

export default api;
