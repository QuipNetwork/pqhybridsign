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

/**
 * A keypair: a secret key and its matching public key. `keygenFromSeed`
 * returns it for H1 through H4; `keygenStatefulFromSeed` returns it for H5
 * and H6, where `secretKey` is the exported stateful blob.
 */
export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * A durable record of a stateful key's consumed one-time leaves and of the
 * one key those leaves belong to. The caller implements it over storage that
 * survives a restart; `signStateful` drives it.
 *
 * Every method is **synchronous**, because `signStateful` calls `commit` and
 * must see it return before it builds the signature (the
 * persist-before-release ordering). `commit` MUST NOT return until the leaf
 * is durably recorded -- under Node, `fs.writeFileSync` then `fs.fsyncSync`.
 * A method that resolves a promise later cannot honour that ordering and MUST
 * NOT be used. This is the same contract the C and Python bindings' journals
 * carry; see the crate documentation.
 */
export interface LeafJournal {
  /**
   * Durably record that `leaf` is consumed. Throw to report the write did
   * not happen; the leaf may then be treated as still unused.
   */
  commit(leaf: number): void;
  /** The next unused leaf, as last committed. `0` for a fresh journal. */
  nextLeaf(): number;
  /**
   * The 32-byte identity of the key this journal belongs to, or `null` if it
   * has never been bound. MUST survive a restart, and MUST NOT report `null`
   * when the durable read failed (fail the read instead): `null` is what
   * `adoptKey` treats as an invitation to bind.
   */
  boundKey(): Uint8Array | null;
  /** Durably record that this journal belongs to `identity`. Throw on failure. */
  bindKey(identity: Uint8Array): void;
}

/**
 * A durable record of a stateful key's few-time stateless budget
 * (`signStateless`, SHRINCS specification section 21). Keyed by the 32-byte
 * budget key `signStateless` derives from the secret key, so one store serves
 * every key a process holds. Synchronous, on the same terms as
 * {@link LeafJournal}: `record` must be durable before it returns.
 */
export interface StatelessBudgetStore {
  /** Units already spent for `key`, or `null` if this key was never tracked. */
  consumed(key: Uint8Array): number | null;
  /** Durably record `count` units spent for `key`. Throw on failure. */
  record(key: Uint8Array, count: number): void;
}

/**
 * The result of `signStateful`: the signature and the advanced secret key
 * blob the caller MUST persist in place of the blob passed in, before relying
 * on `signature`.
 */
export interface SignStatefulResult {
  signature: Uint8Array;
  nextSecretKey: Uint8Array;
}

/**
 * The wasm-bindgen `KeyPair` class as `keygenFromSeed` and
 * `keygenStatefulFromSeed` on the raw module return it: a disposable handle
 * over wasm-owned memory, not a plain object. See
 * `npm/types/pqhybridsign_wasm.{node,web}.d.ts`.
 */
export interface RawKeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
  free(): void;
}

/**
 * The wasm-bindgen `SignStatefulResult` class as `signStateful` on the raw
 * module returns it: a disposable handle over wasm-owned memory, freed after
 * its two fields are copied out. See `npm/types/pqhybridsign_wasm.{node,web}.d.ts`.
 */
export interface RawSignStatefulResult {
  readonly signature: Uint8Array;
  readonly nextSecretKey: Uint8Array;
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
  keygenStatefulFromSeed(
    suite: string,
    seed: Uint8Array,
    maxStatefulSignatures: number,
  ): RawKeyPair;
  keyIdentity(suite: string, publicKey: Uint8Array): Uint8Array;
  keyIdentityFromSecretKey(suite: string, secretKey: Uint8Array): Uint8Array;
  adoptKey(journal: LeafJournal, identity: Uint8Array): void;
  signStateful(
    suite: string,
    secretKey: Uint8Array,
    journal: LeafJournal,
    msg: Uint8Array,
    ctx: Uint8Array,
  ): RawSignStatefulResult;
  signStateless(
    suite: string,
    secretKey: Uint8Array,
    budget: StatelessBudgetStore,
    msg: Uint8Array,
    ctx: Uint8Array,
  ): Uint8Array;
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
 * H1 through H4 are stateless: `keygenFromSeed`, `sign` and
 * `signDeterministic` handle them, and reject H5 and H6, because a
 * stateless-looking call must never silently spend a one-time leaf. H5 and
 * H6 are stateful: `keygenStatefulFromSeed`, `signStateful`, `signStateless`,
 * `adoptKey`, `keyIdentity` and `keyIdentityFromSecretKey` handle them, and
 * reject H1 through H4. `verify`, `verifyWithStoredPublicKey` and the four
 * length accessors span all six suites. Each method resolves or rejects
 * exactly as the underlying wasm-bindgen export would return or throw.
 *
 * The stateful signing methods are `async` only because loading the wasm
 * module is; the {@link LeafJournal} and {@link StatelessBudgetStore} a
 * caller passes have synchronous methods (see those types).
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
  keygenStatefulFromSeed(
    suite: Suite,
    seed: Uint8Array,
    maxStatefulSignatures: number,
  ): Promise<KeyPair>;
  keyIdentity(suite: Suite, publicKey: Uint8Array): Promise<Uint8Array>;
  keyIdentityFromSecretKey(suite: Suite, secretKey: Uint8Array): Promise<Uint8Array>;
  adoptKey(journal: LeafJournal, identity: Uint8Array): Promise<void>;
  signStateful(
    suite: Suite,
    secretKey: Uint8Array,
    journal: LeafJournal,
    msg: Uint8Array,
    ctx: Uint8Array,
  ): Promise<SignStatefulResult>;
  signStateless(
    suite: Suite,
    secretKey: Uint8Array,
    budget: StatelessBudgetStore,
    msg: Uint8Array,
    ctx: Uint8Array,
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

    async keygenStatefulFromSeed(suite, seed, maxStatefulSignatures) {
      const raw = await loadOnce();
      const pair = raw.keygenStatefulFromSeed(suite, seed, maxStatefulSignatures);
      try {
        // Copy both fields out before free(), as keygenFromSeed does.
        return {
          publicKey: pair.publicKey.slice(),
          secretKey: pair.secretKey.slice(),
        };
      } finally {
        pair.free();
      }
    },

    async keyIdentity(suite, publicKey) {
      const raw = await loadOnce();
      return raw.keyIdentity(suite, publicKey);
    },

    async keyIdentityFromSecretKey(suite, secretKey) {
      const raw = await loadOnce();
      return raw.keyIdentityFromSecretKey(suite, secretKey);
    },

    async adoptKey(journal, identity) {
      const raw = await loadOnce();
      raw.adoptKey(journal, identity);
    },

    async signStateful(suite, secretKey, journal, msg, ctx) {
      const raw = await loadOnce();
      const result = raw.signStateful(suite, secretKey, journal, msg, ctx);
      try {
        // Copy both fields out before free(): nextSecretKey especially must
        // outlive the wasm handle so the caller can persist it.
        return {
          signature: result.signature.slice(),
          nextSecretKey: result.nextSecretKey.slice(),
        };
      } finally {
        result.free();
      }
    },

    async signStateless(suite, secretKey, budget, msg, ctx) {
      const raw = await loadOnce();
      return raw.signStateless(suite, secretKey, budget, msg, ctx);
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
