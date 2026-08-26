// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Browser (ESM) entry point for `@quip.network/pqhybridsign`.
 *
 * Loads `../web/pqhybridsign_wasm.js`, the `wasm-pack --target web`
 * build assembled by `../../scripts/build-npm.sh`: its glue instantiates
 * the wasm module lazily, behind a `default` init export that must be
 * awaited before any other export is safe to call. The loader below does
 * that inside {@link createApi}'s cached `load` callback. Concurrent
 * callers share one load. After a trap the loader runs again with a
 * cache-busting specifier, because the glue caches its instance. There
 * is deliberately no top-level `await` here, so importing this module
 * itself never blocks.
 *
 * `.mts` (rather than `.ts`) forces this file to compile to native ESM
 * regardless of `tsconfig.json`'s `module` setting, matching
 * `package.json`'s `exports["."].default` entry point.
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
  RawStatefulKey,
  RawVrfKey,
  SignStatefulResult,
  StatefulKeyHandle,
  StatelessBudgetStore,
  Suite,
  VrfKeyHandle,
} from "./api.js";

let reloads = 0;

async function load(): Promise<RawModule> {
  // The query string is what forces a fresh module record. A dynamic
  // import() of the same specifier returns the cached one, and the web
  // glue's init export caches its instantiation, so without this a reload
  // after a trap hands back the crashed instance.
  const suffix = reloads === 0 ? "" : `?reload=${reloads}`;
  reloads += 1;
  const mod = await import(`../web/pqhybridsign_wasm.js${suffix}`);
  await mod.default();
  return mod as unknown as RawModule;
}

/** See the note on the Node entry point's `__loadForTest`. */
export function __loadForTest(): Promise<RawModule> {
  return load();
}

const api = createApi(load);

export const {
  masterSeedFromMnemonic,
  deriveHardJunction,
  deriveHardJunctionPath,
  /**
   * Length in bytes of a hybrid VRF proof for `suite`.
   *
   * For ED-ML-44 and SR-ML-44 this is exact. For ED-FN-512 and SR-FN-512
   * this is the maximum a delta-length binding can occupy. For ED-SH and
   * SR-SH this is exact. A caller
   * sizing storage from this value must treat it as an upper bound.
   *
   * Kept in sync with the doc on {@link PqHybridSignApi.vrfProofLen} in
   * `api.ts`: destructuring a named export off `api` does not carry that
   * doc comment into this file's declaration output, so it is repeated
   * here for the caller who imports `vrfProofLen` directly rather than
   * through the default `api` export.
   */
  vrfProofLen,
  vrfProve,
  vrfProveDeterministic,
  vrfVerify,
  vrfMakeBytes,
  deriveVrfStatelessKey,
  keygenFromSeed,
  sign,
  signDeterministic,
  keygenStatefulFromSeed,
  openStatefulKey,
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
