// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference lib="dom" />
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
export type Suite =
  | "ED-ML-44"
  | "ED-FN-512"
  | "SR-ML-44"
  | "SR-FN-512"
  | "ED-SH"
  | "SR-SH";

/**
 * A keypair: a secret key and its matching public key. `keygenFromSeed`
 * returns it for ED-ML-44 through SR-FN-512; `keygenStatefulFromSeed`
 * returns it for ED-SH and SR-SH, where `secretKey` is the exported
 * stateful blob.
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
 * An imported stateful secret key, held across signing calls.
 *
 * `signStateful` on the module-level API imports the exported blob on
 * every call. That import re-derives the hypertree root, which at the
 * 128s profiles costs about 47 seconds. A handle pays it once, at
 * {@link PqHybridSignApi.openStatefulKey}.
 *
 * Call {@link free} when finished. wasm-bindgen registers every handle
 * with a `FinalizationRegistry` that calls the free function when the
 * wrapper becomes unreachable, but that release is not under the
 * caller's control: it may happen at any garbage collection, and it may
 * never happen at all. A handle dropped without `free()` cannot be
 * relied on to release its secret key material.
 *
 * The durability contract is unchanged. After every {@link signStateful}
 * call, including one that rejected with an ordinary error, call
 * {@link export} and persist the result before relying on the signature.
 *
 * **A {@link PqHybridSignPanic} is the one rejection that instruction does
 * not cover.** It means the wasm instance behind this handle trapped, and
 * this package's own trap documentation says a host cannot assume such an
 * instance is sound. Once any method here rejects with a
 * {@link PqHybridSignPanic}, this handle is poisoned: every later call on
 * it, including {@link export} and {@link free}, rejects or throws the same
 * {@link PqHybridSignPanic} instead of touching the dead instance, so a
 * caller cannot accidentally export and persist bytes the trapped instance
 * produced. There is no advanced key to recover from a poisoned handle;
 * the caller's leaf journal is the only durable record of which leaf, if
 * any, was spent before the trap.
 */
export interface StatefulKeyHandle {
  keyIdentity(): Promise<Uint8Array>;
  export(): Promise<Uint8Array>;
  signStateful(journal: LeafJournal, msg: Uint8Array, ctx: Uint8Array): Promise<Uint8Array>;
  signStateless(
    budget: StatelessBudgetStore,
    msg: Uint8Array,
    ctx: Uint8Array,
  ): Promise<Uint8Array>;
  free(): void;
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
 * A SHRINCS key dedicated to VRF evaluation for a stateful suite (`"ED-SH"`
 * or `"SR-SH"`), held across calls. Returned by `deriveVrfStatelessKey`.
 *
 * This key is disjoint from the identity key that carries an account's
 * rotation and recovery authority: it is derived under a label separate from
 * the identity key's, so the two never collide, and it has no leaf counter to
 * fork -- {@link prove} draws only on the few-time stateless budget the
 * caller's `budget` tracks. It cannot be exported to bytes; it lives only in
 * wasm memory for the life of the handle.
 *
 * Call {@link free} when finished. wasm-bindgen registers every handle
 * with a `FinalizationRegistry` that calls the free function when the
 * wrapper becomes unreachable, but that release is not under the
 * caller's control: it may happen at any garbage collection, and it may
 * never happen at all. A handle dropped without `free()` cannot be
 * relied on to release its key material.
 *
 * If {@link prove} ever rejects with a {@link PqHybridSignPanic}, this
 * handle is poisoned on the same terms {@link StatefulKeyHandle} is: the
 * wasm instance it points into trapped and is no longer sound to call, so
 * every later call on it, including {@link free}, rejects or throws that
 * same {@link PqHybridSignPanic} instead of touching the dead instance.
 */
export interface VrfKeyHandle {
  prove(budget: StatelessBudgetStore, input: Uint8Array): Promise<Uint8Array>;
  free(): void;
}

/**
 * The wasm-bindgen `VrfKey` class as `deriveVrfStatelessKey` on the raw
 * module returns it: a disposable handle over wasm-owned memory. See
 * `npm/types/pqhybridsign_wasm.{node,web}.d.ts`.
 */
export interface RawVrfKey {
  prove(budget: StatelessBudgetStore, input: Uint8Array): Uint8Array;
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
 * The wasm-bindgen `StatefulKey` class as `StatefulKey.open` on the raw
 * module returns it: a disposable handle over wasm-owned memory. See
 * `npm/types/pqhybridsign_wasm.{node,web}.d.ts`.
 */
export interface RawStatefulKey {
  keyIdentity(): Uint8Array;
  export(): Uint8Array;
  signStateful(journal: LeafJournal, msg: Uint8Array, ctx: Uint8Array): Uint8Array;
  signStateless(
    budget: StatelessBudgetStore,
    msg: Uint8Array,
    ctx: Uint8Array,
  ): Uint8Array;
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
  StatefulKey: {
    open(suite: string, secretKey: Uint8Array): RawStatefulKey;
  };
  masterSeedFromMnemonic(phrase: string, password?: string | null): Uint8Array;
  deriveHardJunction(parentMaster: Uint8Array, chainCode: Uint8Array): Uint8Array;
  deriveHardJunctionPath(parentMaster: Uint8Array, chainCodes: Uint8Array[]): Uint8Array;
  vrfProofLen(suite: string): number;
  vrfProve(suite: string, secretKey: Uint8Array, input: Uint8Array): Uint8Array;
  vrfProveDeterministic(suite: string, secretKey: Uint8Array, input: Uint8Array): Uint8Array;
  vrfVerify(suite: string, publicKey: Uint8Array, input: Uint8Array, proof: Uint8Array): boolean;
  vrfMakeBytes(
    suite: string,
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    context: Uint8Array,
  ): Uint8Array;
  deriveVrfStatelessKey(
    suite: string,
    master: Uint8Array,
  ): { key: RawVrfKey; publicKey: Uint8Array };
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
 * ED-ML-44 through SR-FN-512 are stateless: `keygenFromSeed`, `sign` and
 * `signDeterministic` handle them, and reject ED-SH and SR-SH, because a
 * stateless-looking call must never silently spend a one-time leaf. ED-SH
 * and SR-SH are stateful: `keygenStatefulFromSeed`, `openStatefulKey`,
 * `signStateful`, `signStateless`, `adoptKey`, `keyIdentity` and
 * `keyIdentityFromSecretKey` handle them, and
 * reject ED-ML-44 through SR-FN-512. `verify`, `verifyWithStoredPublicKey`
 * and the four length accessors span all six suites. Each method resolves
 * or rejects exactly as the underlying wasm-bindgen export would return or
 * throw,
 * except that a WebAssembly trap is rethrown as {@link PqHybridSignPanic}
 * and the cached instance is discarded.
 *
 * `masterSeedFromMnemonic`, `deriveHardJunction` and `deriveHardJunctionPath`
 * derive master seeds from a recovery phrase or an existing seed.
 * `masterSeedFromMnemonic` runs Substrate's derivation, not standard BIP39: a
 * caller that reproduces it with a stock BIP39 library gets a different seed,
 * and therefore a different key. **Deriving one child twice, on two
 * different hosts, is the re-keygen hazard**: `deriveHardJunction` and
 * `deriveHardJunctionPath` are deterministic, so the same parent and the
 * same chain code reach the same child seed and therefore the same stateful
 * tree starting at leaf 1 -- the same failure as importing one key twice.
 * Derive a child once, then persist and restore it; never re-derive one
 * junction on a second host. An empty `chainCodes` array passed to
 * `deriveHardJunctionPath` returns `parentMaster` unchanged -- the identity a
 * path of no junctions should have, not an error -- so a caller whose parsed
 * path came out empty gets the parent key back and must check for that
 * itself.
 *
 * `vrfProofLen`, `vrfProve`, `vrfProveDeterministic`, `vrfVerify` and
 * `vrfMakeBytes` cover the hybrid VRF for ED-ML-44 through SR-FN-512;
 * `vrfProve` and `vrfProveDeterministic` reject ED-SH and SR-SH for the
 * same reason `sign` and `signDeterministic` do, and
 * `deriveVrfStatelessKey` covers those two suites
 * instead, through a dedicated key disjoint from the identity key and a
 * caller-supplied {@link StatelessBudgetStore}.
 * `vrfMakeBytes` verifies the proof first, the same check `vrfVerify`
 * makes, and derives bytes only on success; a proof that does not verify
 * rejects with an `Error` whose message says so.
 *
 * The stateful signing methods are `async` only because loading the wasm
 * module is; the {@link LeafJournal} and {@link StatelessBudgetStore} a
 * caller passes have synchronous methods (see those types).
 */
export interface PqHybridSignApi {
  masterSeedFromMnemonic(phrase: string, password?: string | null): Promise<Uint8Array>;
  deriveHardJunction(parentMaster: Uint8Array, chainCode: Uint8Array): Promise<Uint8Array>;
  deriveHardJunctionPath(parentMaster: Uint8Array, chainCodes: Uint8Array[]): Promise<Uint8Array>;
  /**
   * Length in bytes of a hybrid VRF proof for `suite`.
   *
   * For ED-ML-44 and SR-ML-44 this is exact. For ED-FN-512 and SR-FN-512
   * this is the maximum a delta-length binding can occupy. For ED-SH and
   * SR-SH this is exact. A caller
   * sizing storage from this value must treat it as an upper bound.
   */
  vrfProofLen(suite: Suite): Promise<number>;
  vrfProve(suite: Suite, secretKey: Uint8Array, input: Uint8Array): Promise<Uint8Array>;
  vrfProveDeterministic(
    suite: Suite,
    secretKey: Uint8Array,
    input: Uint8Array,
  ): Promise<Uint8Array>;
  vrfVerify(
    suite: Suite,
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
  ): Promise<boolean>;
  vrfMakeBytes(
    suite: Suite,
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    context: Uint8Array,
  ): Promise<Uint8Array>;
  deriveVrfStatelessKey(
    suite: Suite,
    master: Uint8Array,
  ): Promise<{ key: VrfKeyHandle; publicKey: Uint8Array }>;
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
  openStatefulKey(suite: Suite, secretKey: Uint8Array): Promise<StatefulKeyHandle>;
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
 * A WebAssembly trap that reached the wrapper.
 *
 * `wasm32-unknown-unknown` builds its standard library with
 * `panic = "abort"`. A Rust panic lowers to an `unreachable` instruction
 * and traps the instance, so `catch_unwind` cannot contain it inside the
 * module the way the C ABI's guards do. The trap does reach JavaScript, as
 * a `WebAssembly.RuntimeError`, but so do this package's ordinary
 * failures as plain `Error`s, and nothing in the object graph separates
 * them.
 *
 * Every method of {@link PqHybridSignApi} rethrows a trap as this class,
 * so `instanceof PqHybridSignPanic` distinguishes "the module crashed"
 * from "the call was rejected". The original `RuntimeError` is on
 * {@link cause}.
 *
 * The instance that trapped is discarded. The next call to any method loads a
 * fresh one, so a caller that catches this and retries is calling into a clean
 * module rather than a poisoned one.
 *
 * Under Node this reload is exercised by the package's own test suite. In a
 * browser the loader re-imports the glue under a cache-busting specifier to
 * get a new module record, which is necessary because a second `init()` on the
 * same record returns the instance that already trapped. That browser path is
 * not covered by the test suite, so treat a retry there as best-effort rather
 * than guaranteed.
 *
 * Any state the crashed instance held is gone: a stateful signing call that
 * threw this must be treated as having an unknown outcome, and the caller's
 * leaf journal, not this package, is what says whether a leaf was spent.
 */
export class PqHybridSignPanic extends Error {
  override readonly cause: unknown;

  constructor(cause: unknown) {
    super(
      "the pqhybridsign WebAssembly module trapped and was discarded; " +
        "the next call attempts to load a fresh instance",
    );
    this.name = "PqHybridSignPanic";
    this.cause = cause;
  }
}

/**
 * Build a {@link PqHybridSignApi} over `load`.
 *
 * The first call from any method below invokes `load` and caches the
 * returned promise, so concurrent callers still pay for exactly one
 * load. After a {@link PqHybridSignPanic} the cache is cleared, so the
 * next call invokes `load` again rather than reuse a trapped instance.
 */
export function createApi(load: () => Promise<RawModule>): PqHybridSignApi {
  let modulePromise: Promise<RawModule> | undefined;

  function loadOnce(): Promise<RawModule> {
    if (modulePromise === undefined) {
      modulePromise = load();
    }
    return modulePromise;
  }

  /**
   * Run `call` against a loaded module, converting a trap.
   *
   * A `WebAssembly.RuntimeError` means the instance executed an
   * `unreachable` and is no longer safe to call, so the cached promise is
   * cleared before the error is rethrown as a {@link PqHybridSignPanic}.
   * Every other error is this package's own rejection and passes through
   * untouched.
   */
  async function guard<T>(call: (raw: RawModule) => T | Promise<T>): Promise<T> {
    const raw = await loadOnce();
    try {
      return await call(raw);
    } catch (err) {
      if (err instanceof WebAssembly.RuntimeError) {
        modulePromise = undefined;
        throw new PqHybridSignPanic(err);
      }
      throw err;
    }
  }

  return {
    async masterSeedFromMnemonic(phrase, password) {
      return guard((raw) => raw.masterSeedFromMnemonic(phrase, password));
    },

    async deriveHardJunction(parentMaster, chainCode) {
      return guard((raw) => raw.deriveHardJunction(parentMaster, chainCode));
    },

    async deriveHardJunctionPath(parentMaster, chainCodes) {
      return guard((raw) => raw.deriveHardJunctionPath(parentMaster, chainCodes));
    },

    async vrfProofLen(suite) {
      return guard((raw) => raw.vrfProofLen(suite));
    },

    async vrfProve(suite, secretKey, input) {
      return guard((raw) => raw.vrfProve(suite, secretKey, input));
    },

    async vrfProveDeterministic(suite, secretKey, input) {
      return guard((raw) => raw.vrfProveDeterministic(suite, secretKey, input));
    },

    async vrfVerify(suite, publicKey, input, proof) {
      return guard((raw) => raw.vrfVerify(suite, publicKey, input, proof));
    },

    async vrfMakeBytes(suite, publicKey, input, proof, context) {
      return guard((raw) => raw.vrfMakeBytes(suite, publicKey, input, proof, context));
    },

    async deriveVrfStatelessKey(suite, master) {
      return guard((raw) => {
        const { key: inner, publicKey } = raw.deriveVrfStatelessKey(suite, master);

        // Set the first time any call on this handle traps, and never
        // cleared: a trap invalidates the instance `inner` points into
        // (see the crate documentation), so once this handle has seen one,
        // every later call rejects or throws this same PqHybridSignPanic
        // instead of touching the dead instance.
        let poisoned: PqHybridSignPanic | undefined;

        async function guardHandle<T>(call: () => T | Promise<T>): Promise<T> {
          if (poisoned !== undefined) {
            throw poisoned;
          }
          try {
            return await guard(call);
          } catch (err) {
            if (err instanceof PqHybridSignPanic) {
              poisoned = err;
            }
            throw err;
          }
        }

        return {
          key: {
            async prove(budget, input) {
              return guardHandle(() => inner.prove(budget, input));
            },
            free() {
              // Poisoned already: the underlying instance is gone (guard
              // cleared modulePromise when it first trapped), so there is
              // nothing left to free -- throw the same panic rather than
              // call into the dead instance.
              if (poisoned !== undefined) {
                throw poisoned;
              }
              // free() cannot go through guard/guardHandle: the public
              // signature is synchronous (`free(): void`), not a Promise.
              // Contain the trap here instead, on the same terms guard does.
              try {
                inner.free();
              } catch (err) {
                if (err instanceof WebAssembly.RuntimeError) {
                  modulePromise = undefined;
                  poisoned = new PqHybridSignPanic(err);
                  throw poisoned;
                }
                throw err;
              }
            },
          },
          publicKey,
        };
      });
    },

    async keygenFromSeed(suite, seed) {
      return guard((raw) => {
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
      });
    },

    async sign(suite, secretKey, msg, ctx) {
      return guard((raw) => raw.sign(suite, secretKey, msg, ctx));
    },

    async signDeterministic(suite, secretKey, msg, ctx, nonce) {
      return guard((raw) => raw.signDeterministic(suite, secretKey, msg, ctx, nonce));
    },

    async keygenStatefulFromSeed(suite, seed, maxStatefulSignatures) {
      return guard((raw) => {
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
      });
    },

    async openStatefulKey(suite, secretKey) {
      return guard((raw) => {
        const inner = raw.StatefulKey.open(suite, secretKey);

        // Set the first time any call on this handle traps, and never
        // cleared: a trap invalidates the instance `inner` points into
        // (see the crate documentation), so once this handle has seen one,
        // every later call rejects or throws this same PqHybridSignPanic
        // instead of touching the dead instance -- most importantly
        // `export()`, which must never hand back bytes a trapped instance
        // produced.
        let poisoned: PqHybridSignPanic | undefined;

        async function guardHandle<T>(call: () => T | Promise<T>): Promise<T> {
          if (poisoned !== undefined) {
            throw poisoned;
          }
          try {
            return await guard(call);
          } catch (err) {
            if (err instanceof PqHybridSignPanic) {
              poisoned = err;
            }
            throw err;
          }
        }

        return {
          async keyIdentity() {
            return guardHandle(() => inner.keyIdentity());
          },
          async export() {
            return guardHandle(() => inner.export());
          },
          async signStateful(journal, msg, ctx) {
            return guardHandle(() => inner.signStateful(journal, msg, ctx));
          },
          async signStateless(budget, msg, ctx) {
            return guardHandle(() => inner.signStateless(budget, msg, ctx));
          },
          free() {
            // Poisoned already: the underlying instance is gone (guard
            // cleared modulePromise when it first trapped), so there is
            // nothing left to free -- throw the same panic rather than
            // call into the dead instance.
            if (poisoned !== undefined) {
              throw poisoned;
            }
            // free() cannot go through guard/guardHandle: the public
            // signature is synchronous (`free(): void`), not a Promise.
            // Contain the trap here instead, on the same terms guard does.
            try {
              inner.free();
            } catch (err) {
              if (err instanceof WebAssembly.RuntimeError) {
                modulePromise = undefined;
                poisoned = new PqHybridSignPanic(err);
                throw poisoned;
              }
              throw err;
            }
          },
        };
      });
    },

    async keyIdentity(suite, publicKey) {
      return guard((raw) => raw.keyIdentity(suite, publicKey));
    },

    async keyIdentityFromSecretKey(suite, secretKey) {
      return guard((raw) => raw.keyIdentityFromSecretKey(suite, secretKey));
    },

    async adoptKey(journal, identity) {
      return guard((raw) => raw.adoptKey(journal, identity));
    },

    async signStateful(suite, secretKey, journal, msg, ctx) {
      return guard((raw) => {
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
      });
    },

    async signStateless(suite, secretKey, budget, msg, ctx) {
      return guard((raw) => raw.signStateless(suite, secretKey, budget, msg, ctx));
    },

    async verify(suite, publicKey, msg, ctx, sig) {
      return guard((raw) => raw.verify(suite, publicKey, msg, ctx, sig));
    },

    async verifyWithStoredPublicKey(suite, storedPublicKey, pqVerifyKey, msg, ctx, sig) {
      return guard((raw) =>
        raw.verifyWithStoredPublicKey(suite, storedPublicKey, pqVerifyKey, msg, ctx, sig),
      );
    },

    async publicKeyLen(suite) {
      return guard((raw) => raw.publicKeyLen(suite));
    },

    async secretKeyLen(suite) {
      return guard((raw) => raw.secretKeyLen(suite));
    },

    async signatureLen(suite) {
      return guard((raw) => raw.signatureLen(suite));
    },

    async storedPublicKeyLen(suite) {
      return guard((raw) => raw.storedPublicKeyLen(suite));
    },

    async profileName() {
      return guard((raw) => raw.profileName());
    },
  };
}
