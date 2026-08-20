// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The Promise-based `pqhybridsign` API, built over either wasm-pack
 * target's synchronous glue.
 *
 * `crates/pqhybridsign-wasm/src/lib.rs`'s wasm-bindgen exports are
 * synchronous once the module is loaded, but loading itself differs by
 * environment: the `nodejs` target's glue runs its wasm instantiation on
 * `require`, while the `web` target's glue instantiates lazily behind its
 * `default` init export. `createApi` hides that difference behind one
 * `load` callback so `index.node.cts` and `index.web.mts` can each supply
 * their own loader and otherwise share every method below.
 */

/** One of the six SHRINCS suites this package's build links against. */
export type Suite = "H1" | "H2" | "H3" | "H4" | "H5" | "H6";

/** A stateless keypair: a secret key and its matching public key. */
export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * The wasm-bindgen `KeyPair` class as `keygenFromSeed` on the raw module
 * returns it: a disposable handle over wasm-owned memory, not a plain
 * object. See `npm/types/pqhybridsign_wasm.{node,web}.d.ts`.
 */
export interface RawKeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
  free(): void;
}

/**
 * The function surface both wasm-pack targets expose once loaded, typed
 * from the checked-in `npm/types/pqhybridsign_wasm.{node,web}.d.ts`
 * (identical across both targets apart from the `web` target's extra
 * `initSync`/`default` init exports, which the loaders in
 * `index.node.cts` and `index.web.mts` consume directly and this
 * interface has no need of).
 */
export interface RawModule {
  keygenFromSeed(suite: string, seed: Uint8Array): RawKeyPair;
  profileName(): string;
  publicKeyLen(suite: string): number;
  secretKeyLen(suite: string): number;
  sign(suite: string, secretKey: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array;
  signDeterministic(
    suite: string,
    secretKey: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
    nonce: Uint8Array,
  ): Uint8Array;
  signatureLen(suite: string): number;
  storedPublicKeyLen(suite: string): number;
  verify(
    suite: string,
    publicKey: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
    sig: Uint8Array,
  ): boolean;
  verifyWithStoredPublicKey(
    suite: string,
    storedPublicKey: Uint8Array,
    pqVerifyKey: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
    sig: Uint8Array,
  ): boolean;
}

/**
 * The `pqhybridsign` package's public API: every wasm-bindgen export
 * above, promisified so a caller never has to load the wasm module
 * itself.
 *
 * H5 and H6 are stateful suites; `crates/pqhybridsign-wasm` exposes no
 * signing entry point for them (see that crate's documentation for why),
 * so `keygenFromSeed`, `sign` and `signDeterministic` reject for those
 * two suite names -- the wasm layer throws, and the rejection carries its
 * message. `verify`, `verifyWithStoredPublicKey` and the four length
 * accessors are unrestricted by suite here; each resolves or rejects
 * exactly as the underlying wasm-bindgen export would throw or return.
 */
export interface PqHybridSignApi {
  keygenFromSeed(suite: Suite, seed: Uint8Array): Promise<KeyPair>;
  sign(suite: Suite, secretKey: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Promise<Uint8Array>;
  signDeterministic(
    suite: Suite,
    secretKey: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
    nonce: Uint8Array,
  ): Promise<Uint8Array>;
  verify(
    suite: Suite,
    publicKey: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
    sig: Uint8Array,
  ): Promise<boolean>;
  verifyWithStoredPublicKey(
    suite: Suite,
    storedPublicKey: Uint8Array,
    pqVerifyKey: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
    sig: Uint8Array,
  ): Promise<boolean>;
  publicKeyLen(suite: Suite): Promise<number>;
  secretKeyLen(suite: Suite): Promise<number>;
  signatureLen(suite: Suite): Promise<number>;
  storedPublicKeyLen(suite: Suite): Promise<number>;
  profileName(): Promise<string>;
}

/**
 * Build a {@link PqHybridSignApi} over `load`.
 *
 * `load` runs at most once per process: the first call from any method
 * below invokes it and caches the returned promise, so a caller that
 * calls several methods before the module finishes loading still pays
 * for exactly one load, and every method -- across the whole process --
 * awaits that same cached promise afterward.
 */
export function createApi(load: () => Promise<RawModule>): PqHybridSignApi {
  let modulePromise: Promise<RawModule> | undefined;

  function loadOnce(): Promise<RawModule> {
    if (modulePromise === undefined) {
      modulePromise = load();
    }
    return modulePromise;
  }

  return {
    async keygenFromSeed(suite, seed) {
      const raw = await loadOnce();
      const pair = raw.keygenFromSeed(suite, seed);
      try {
        // Copy both fields out before free(): free() releases the wasm
        // memory the wasm-bindgen accessors view, and a caller holding
        // on to either Uint8Array past that point would read freed
        // memory.
        return {
          publicKey: pair.publicKey.slice(),
          secretKey: pair.secretKey.slice(),
        };
      } finally {
        pair.free();
      }
    },

    async sign(suite, secretKey, msg, ctx) {
      const raw = await loadOnce();
      return raw.sign(suite, secretKey, msg, ctx);
    },

    async signDeterministic(suite, secretKey, msg, ctx, nonce) {
      const raw = await loadOnce();
      return raw.signDeterministic(suite, secretKey, msg, ctx, nonce);
    },

    async verify(suite, publicKey, msg, ctx, sig) {
      const raw = await loadOnce();
      return raw.verify(suite, publicKey, msg, ctx, sig);
    },

    async verifyWithStoredPublicKey(suite, storedPublicKey, pqVerifyKey, msg, ctx, sig) {
      const raw = await loadOnce();
      return raw.verifyWithStoredPublicKey(suite, storedPublicKey, pqVerifyKey, msg, ctx, sig);
    },

    async publicKeyLen(suite) {
      const raw = await loadOnce();
      return raw.publicKeyLen(suite);
    },

    async secretKeyLen(suite) {
      const raw = await loadOnce();
      return raw.secretKeyLen(suite);
    },

    async signatureLen(suite) {
      const raw = await loadOnce();
      return raw.signatureLen(suite);
    },

    async storedPublicKeyLen(suite) {
      const raw = await loadOnce();
      return raw.storedPublicKeyLen(suite);
    },

    async profileName() {
      const raw = await loadOnce();
      return raw.profileName();
    },
  };
}
