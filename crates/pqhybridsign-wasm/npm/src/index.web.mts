// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Browser (ESM) entry point for `@quip.network/pqhybridsign`.
 *
 * Loads `../web/pqhybridsign_wasm.js`, the `wasm-pack --target web`
 * build assembled by `../../scripts/build-npm.sh`: its glue instantiates
 * the wasm module lazily, behind a `default` init export that must be
 * awaited before any other export is safe to call. The loader below does
 * that inside {@link createApi}'s cached `load` callback, so the dynamic
 * `import()` and the `await init()` both run at most once per process
 * regardless of how many API methods a caller invokes concurrently
 * before the module is ready -- there is deliberately no top-level
 * `await` here, so importing this module itself never blocks.
 *
 * `.mts` (rather than `.ts`) forces this file to compile to native ESM
 * regardless of `tsconfig.json`'s `module` setting, matching
 * `package.json`'s `exports["."].default` entry point.
 */

import { createApi, type RawModule } from "./api.js";

export type { KeyPair, PqHybridSignApi, RawKeyPair, RawModule, Suite } from "./api.js";

async function load(): Promise<RawModule> {
  const mod = await import("../web/pqhybridsign_wasm.js");
  await mod.default();
  return mod as unknown as RawModule;
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
