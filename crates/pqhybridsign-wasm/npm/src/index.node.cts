// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Node.js (CommonJS) entry point for `@quip.network/pqhybridsign`.
 *
 * Loads `../node/pqhybridsign_wasm.js`, the `wasm-pack --target nodejs`
 * build assembled by `../../scripts/build-npm.sh`: its glue instantiates
 * the wasm module synchronously on `require`. The loader below wraps that
 * `require` in a promise for {@link createApi} to cache, and drops the
 * `require` cache entry so a reload after a trap is a new instance.
 *
 * `.cts` (rather than `.ts`) forces this file to compile to CommonJS
 * regardless of `tsconfig.json`'s `module` setting, matching
 * `package.json`'s `exports["."].node` entry point.
 */

import { createApi, PqHybridSignPanic, type RawModule } from "./api.js";

export { createApi, PqHybridSignPanic };

export type {
  KeyPair,
  LeafJournal,
  PqHybridSignApi,
  RawKeyPair,
  RawModule,
  RawSignStatefulResult,
  SignStatefulResult,
  StatelessBudgetStore,
  Suite,
} from "./api.js";

function load(): Promise<RawModule> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const path = require.resolve("../node/pqhybridsign_wasm.js");
  // Dropping the cache entry is what makes a reload after a trap produce a
  // new instance rather than the crashed one. `require` keys its cache by
  // resolved path, so without this the module returned after a trap is the
  // same object with the same trapped memory.
  delete require.cache[path];
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return Promise.resolve(require(path) as RawModule);
}

/**
 * The loader, exposed for `test/panic.test.mjs`, which checks that calling
 * it twice yields a module that still answers. Not part of the supported
 * surface: it is prefixed and undocumented in the README for that reason.
 */
export function __loadForTest(): Promise<RawModule> {
  return load();
}

const api = createApi(load);

export const {
  keygenFromSeed,
  sign,
  signDeterministic,
  keygenStatefulFromSeed,
  keyIdentity,
  keyIdentityFromSecretKey,
  adoptKey,
  signStateful,
  signStateless,
  verify,
  verifyWithStoredPublicKey,
  publicKeyLen,
  secretKeyLen,
  signatureLen,
  storedPublicKeyLen,
  profileName,
} = api;

export default api;
