/* tslint:disable */
/* eslint-disable */

/**
 * A keypair: a secret key and its matching public key.
 *
 * Returned by both [`keygenFromSeed`](keygen_from_seed) (H1 through H4)
 * and [`keygenStatefulFromSeed`](keygen_stateful_from_seed) (H5 and H6);
 * for the stateful suites the secret key is the exported blob, still
 * `secretKeyLen(suite)` bytes.
 *
 * A caller must call `free()`, call `[Symbol.dispose]()`, or declare
 * the value with JavaScript `using`. A leaked `KeyPair` keeps its
 * secret-key `Uint8Array` reachable.
 */
export class KeyPair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The composite public key, `pqhybridsign_wasm::publicKeyLen(suite)`
     * bytes.
     */
    publicKey: Uint8Array;
    /**
     * The composite secret key, `pqhybridsign_wasm::secretKeyLen(suite)`
     * bytes.
     */
    secretKey: Uint8Array;
}

/**
 * The result of [`signStateful`](sign_stateful): the signature and the
 * advanced secret key blob the caller must persist.
 *
 * `nextSecretKey` is the exported blob with its leaf counter advanced past
 * the leaf this signature spent. Persist it in place of the blob passed in,
 * before relying on `signature`: signing again with the old blob is refused
 * (the abi's `CountersDiverged`), so a stale blob stops the key rather than
 * reissuing the leaf, and keeping the working blob in step is what lets the
 * key keep signing.
 *
 * A caller must call `free()`, call `[Symbol.dispose]()`, or declare the
 * value with JavaScript `using`. A leaked `SignStatefulResult` keeps its
 * secret-key `Uint8Array` reachable.
 */
export class SignStatefulResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The exported secret key blob with its leaf counter advanced, exactly
     * `secretKeyLen(suite)` bytes. Persist this before using `signature`.
     */
    nextSecretKey: Uint8Array;
    /**
     * The signature, at most `signatureLen(suite)` bytes.
     */
    signature: Uint8Array;
}

/**
 * An imported stateful secret key, held across signing calls.
 *
 * [`sign_stateful`] takes the exported blob and calls
 * `SecretKey::import` every time. `import` re-derives the hypertree
 * root, which at the 128s profiles costs about 47 seconds, the same walk
 * as keygen. A caller that signs more than once pays it more than once.
 * This type pays it exactly once, in [`StatefulKey::open`], and every
 * later signature costs what the in-process Rust API costs.
 *
 * # The durability contract is unchanged
 *
 * The handle advances the key in memory. It does not persist anything.
 * After [`sign_stateful`](Self::sign_stateful) returns, **whether it
 * returned a signature or threw**, this handle holds the advanced key
 * and the caller must [`export`](Self::export) it and persist the result
 * before relying on any signature. The reason is the one
 * [`sign_stateful`] documents: a leaf can be durably committed to the
 * journal and the signature still fail, and a caller whose stored key
 * did not advance with the journal is a caller whose next call is
 * refused for the rest of the key's life.
 *
 * A handle is not a substitute for the journal. The journal is the
 * durable record of spent leaves and the only thing that survives a
 * crash.
 *
 * # `free()` must be called
 *
 * A caller must call `free()`, call `[Symbol.dispose]()`, or declare
 * the value with JavaScript `using`. The key lives in wasm memory, which
 * JavaScript garbage collection does not reach, so a handle that is
 * dropped without `free()` keeps its secret key material alive for the
 * life of the instance.
 *
 * # Only H5 and H6
 *
 * H1 through H4 are stateless and have nothing to hold open;
 * [`open`](Self::open) rejects them.
 */
export class StatefulKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The current exported blob, exactly `secretKeyLen(suite)` bytes.
     *
     * Persist this after every [`sign_stateful`](Self::sign_stateful)
     * call, including one that threw; see the type documentation.
     *
     * # Errors
     *
     * A JavaScript `Error` if the key does not export.
     */
    export(): Uint8Array;
    /**
     * The 32-byte identity of the key this handle holds.
     *
     * The value [`adopt_key`] takes. Derived from the cached post-quantum
     * verify key, which is public; no secret byte reaches it.
     */
    keyIdentity(): Uint8Array;
    /**
     * Import `secret_key` once and hold it.
     *
     * This is the call that costs about 47 seconds at the 128s profiles.
     * Every signature taken through the returned handle costs under 0.01
     * seconds.
     *
     * # Errors
     *
     * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if
     * `secret_key` is not `secretKeyLen(suite)` bytes, or if the blob
     * does not import.
     */
    static open(suite: string, secret_key: Uint8Array): StatefulKey;
    /**
     * Sign `msg` under `ctx`, spending one leaf recorded through
     * `journal`.
     *
     * The handle-held counterpart of [`sign_stateful`]. The signature is
     * returned; the advanced key stays in this handle. **Export and
     * persist it before relying on the signature**, including when this
     * method throws.
     *
     * `journal` is a JavaScript object with the four synchronous methods
     * the crate documentation describes; it must already be bound to
     * this key ([`adopt_key`]).
     *
     * # Errors
     *
     * A JavaScript `Error` if the key's leaf budget is spent
     * (`LeavesExhausted`), if `journal` is not this key's journal
     * (`JournalKeyMismatch`), if the key and journal counters disagree
     * (`CountersDiverged`), or if the journal could not durably commit
     * (`JournalFailed`). Any exception a journal method itself threw is
     * re-thrown unchanged.
     */
    signStateful(journal: any, msg: Uint8Array, ctx: Uint8Array): Uint8Array;
    /**
     * Sign `msg` under `ctx` without spending a leaf, spending one unit
     * of the few-time stateless budget instead.
     *
     * The handle-held counterpart of [`sign_stateless`]. The key is not
     * advanced, so there is nothing new to export afterwards. `budget`
     * is a JavaScript object with synchronous `consumed(key)` and
     * `record(key, count)` methods, and `record` must be durable before
     * it returns, on the same terms `journal.commit` is.
     *
     * # Errors
     *
     * A JavaScript `Error` if the stateless budget is spent
     * (`StatelessBudgetExhausted`), or if the store could not durably
     * record (`BudgetStoreFailed`). Any exception a budget method itself
     * threw is re-thrown unchanged.
     */
    signStateless(budget: any, msg: Uint8Array, ctx: Uint8Array): Uint8Array;
}

/**
 * A SHRINCS key dedicated to VRF evaluation for a stateful suite (`"H5"`
 * or `"H6"`), held across calls.
 *
 * Returned by
 * [`deriveVrfStatelessKey`](derive_vrf_stateless_key). This key is
 * disjoint from the identity key that carries an account's rotation and
 * recovery authority (`pqhs-1l6`): it is derived under a label separate
 * from the identity key's, so the two never collide, and it has no leaf
 * counter to fork -- [`prove`](Self::prove) draws only on the few-time
 * stateless budget the caller's `budget` tracks. It cannot be exported to
 * bytes; it lives only in wasm memory for the life of the handle.
 *
 * # `free()` must be called
 *
 * A caller must call `free()`, call `[Symbol.dispose]()`, or declare the
 * value with JavaScript `using`. The key lives in wasm memory, which
 * JavaScript garbage collection does not reach, so a handle that is
 * dropped without `free()` keeps its key material alive for the life of
 * the instance.
 */
export class VrfKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Evaluate the hybrid VRF, spending one unit of `budget`.
     *
     * `budget` is a JavaScript object with synchronous `consumed(key)`
     * and `record(key, count)` methods, on the same terms
     * [`signStateless`](sign_stateless)'s budget is (see the crate
     * documentation); `record` must be durable before it returns.
     *
     * Returns the proof.
     *
     * # Errors
     *
     * A JavaScript `Error` if the stateless budget is spent
     * (`StatelessBudgetExhausted`), or if the store could not durably
     * record (`BudgetStoreFailed`). Any exception a budget method itself
     * threw is re-thrown unchanged.
     */
    prove(budget: any, input: Uint8Array): Uint8Array;
}

/**
 * Bind `journal` to the key `identity` names, unless it already belongs to a
 * different key.
 *
 * This is the one explicit act that pairs a key with its durable journal,
 * performed once when the journal is created (`identity` comes from
 * [`keyIdentity`](key_identity) or
 * [`keyIdentityFromSecretKey`](key_identity_from_secret_key)).
 * [`signStateful`](sign_stateful) never binds implicitly: pairing a key with
 * a journal that has never seen it is how one key's one-time leaves get
 * spent twice. Idempotent for a journal already bound to `identity`, so a
 * provisioning step is safe to re-run; do not call it on a fresh journal at
 * every process start, which mints a new binding and starts the budget over.
 *
 * `journal` is a JavaScript object with synchronous `boundKey()` and
 * `bindKey(identity)` methods (see the crate documentation).
 *
 * # Errors
 *
 * A JavaScript `Error` if `identity` is not 32 bytes, if `journal` already
 * belongs to another key (the abi's `JournalKeyMismatch`), or if `bindKey`
 * could not durably record the binding. Any exception a journal method
 * itself threw is re-thrown unchanged.
 *
 * A `boundKey()` that throws prevents `bindKey` from being called at all,
 * so a read fault can never replace an existing binding.
 */
export function adoptKey(journal: any, identity: Uint8Array): void;

/**
 * Derive a hard-junction child master seed.
 *
 * # The re-keygen hazard
 *
 * See `pqhybridsign_abi::derive_hard_junction`: derivation is
 * deterministic, so deriving one junction twice, on two different hosts,
 * reaches the same child seed and therefore the same stateful tree
 * starting at leaf 1 -- the same failure as importing one key twice.
 * Derive a child once, then persist and restore it through the
 * validating import path. Never re-derive one junction on a second host.
 *
 * # Errors
 *
 * A JavaScript `Error` if `parentMaster` or `chainCode` is not exactly 32
 * bytes, or if the key derivation function fails.
 */
export function deriveHardJunction(parent_master: Uint8Array, chain_code: Uint8Array): Uint8Array;

/**
 * Apply a sequence of chain codes in order, each child becoming the next
 * parent (`[a, b]` means `deriveHardJunction(deriveHardJunction(parent,
 * a), b)`).
 *
 * **An empty `chainCodes` returns `parentMaster` unchanged.** That is the
 * identity a path of no junctions should have; see
 * `pqhybridsign_abi::derive_hard_junction_path`.
 *
 * See [`deriveHardJunction`](derive_hard_junction) for the re-keygen
 * hazard, which applies to every seed this function returns.
 *
 * # Errors
 *
 * A JavaScript `Error` if `parentMaster` is not exactly 32 bytes, if any
 * element of `chainCodes` is not a 32-byte `Uint8Array` -- naming its
 * index -- or if the key derivation function fails.
 */
export function deriveHardJunctionPath(parent_master: Uint8Array, chain_codes: Array<any>): Uint8Array;

/**
 * Derive a dedicated VRF key for a stateful `suite` (`"H5"` or `"H6"`)
 * from a 32-byte master seed, disjoint from the identity key
 * (`pqhs-1l6`).
 *
 * Returns a plain JavaScript object with two properties: `key`, the
 * [`VrfKey`] handle -- call `free()` on it when finished -- and
 * `publicKey`, the verify-form public key [`vrfVerify`](vrf_verify)
 * checks proofs against.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `master` is
 * not exactly 32 bytes, or if derivation fails.
 */
export function deriveVrfStatelessKey(suite: string, master: Uint8Array): any;

/**
 * The 32-byte identity of the key `public_key` describes, for a stateful
 * `suite` (`"H5"` or `"H6"`).
 *
 * `public_key` is the verify-form public key
 * [`keygenStatefulFromSeed`](keygen_stateful_from_seed) returned. It is
 * public material, so this discloses nothing about the secret key. Pass the
 * result to [`adoptKey`](adopt_key) once, when the key's durable journal is
 * created.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, or if
 * `public_key` is not `publicKeyLen(suite)` bytes.
 */
export function keyIdentity(suite: string, public_key: Uint8Array): Uint8Array;

/**
 * The 32-byte identity of the key an exported secret key blob holds, for a
 * stateful `suite`.
 *
 * The same value [`keyIdentity`](key_identity) returns for the matching
 * public key; it comes from the blob's cached verify key, which is public.
 * This exists for the restart path, which has the blob but may not have kept
 * the public key.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `secret_key`
 * is not `secretKeyLen(suite)` bytes, or if the blob does not import.
 */
export function keyIdentityFromSecretKey(suite: string, secret_key: Uint8Array): Uint8Array;

/**
 * Derive a keypair for `suite` from a 32-byte master seed.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of the four stateless
 * suites, or if `seed` is not exactly 32 bytes.
 */
export function keygenFromSeed(suite: string, seed: Uint8Array): KeyPair;

/**
 * Derive a stateful keypair for `suite` (`"H5"` or `"H6"`) from a 32-byte
 * master seed, with a budget of `max_stateful_signatures` one-time leaves.
 *
 * Returns a [`KeyPair`] whose `secretKey` is the exported blob
 * [`signStateful`](sign_stateful) reads and
 * [`secretKeyLen`](secret_key_len) measures, and whose `publicKey` is the
 * verify-form public key.
 *
 * This does not touch a journal. Before the first
 * [`signStateful`](sign_stateful) call, bind the key's durable journal to it
 * once with [`adoptKey`](adopt_key) over the identity
 * [`keyIdentity`](key_identity) derives from `publicKey`; that binding is
 * what a later restore checks against, and skipping it makes the first
 * signature fail with the abi's `JournalKeyMismatch`.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `seed` is not
 * exactly 32 bytes, or if `max_stateful_signatures` is zero or exceeds the
 * component's leaf capacity limit.
 */
export function keygenStatefulFromSeed(suite: string, seed: Uint8Array, max_stateful_signatures: number): KeyPair;

/**
 * Turn an English BIP39 recovery phrase into a 32-byte master seed.
 *
 * This is Substrate's derivation, not standard BIP39: see
 * `pqhybridsign_abi::master_seed_from_mnemonic` for exactly which KDF runs
 * and over what. `password` defaults to the empty string when omitted.
 *
 * # Errors
 *
 * A JavaScript `Error` if `phrase` is not a valid English BIP39 mnemonic:
 * a wrong word count, an unknown word, or a bad checksum. The three are
 * not distinguished, because telling an attacker which part of a guessed
 * phrase was wrong narrows the search.
 */
export function masterSeedFromMnemonic(phrase: string, password?: string | null): Uint8Array;

/**
 * The SHRINCS profile this build links against, for example
 * `"shrincs-256s"`.
 *
 * See the crate documentation and
 * [`pqhybridsign_abi::profile_name`] for why an integrator must confirm
 * this string matches on every side of an integration before trusting
 * anything on the wire.
 */
export function profileName(): string;

/**
 * Public key length, in bytes, for `suite`.
 *
 * Total over all six suites, matching `pqhybridsign_abi::public_key_len`
 * and the C and Python bindings. For H5 and H6 this is the verify-key
 * form [`keygenStatefulFromSeed`](keygen_stateful_from_seed) writes,
 * larger than the on-storage commitment form
 * [`storedPublicKeyLen`](stored_public_key_len) reports for the same suite
 * because a verifier needs the full verify key, not just a commitment to
 * it.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
 */
export function publicKeyLen(suite: string): number;

/**
 * Secret key length, in bytes, for `suite`.
 *
 * Total over all six suites, matching `pqhybridsign_abi::secret_key_len`
 * and the C and Python bindings. For H1 through H4 this is the raw
 * composite secret key. For H5 and H6 it is the length of the exported
 * blob [`keygenStatefulFromSeed`](keygen_stateful_from_seed) returns and
 * [`signStateful`](sign_stateful) reads and hands forward: the composite
 * secret key plus the leaf counter and the cached verify key, because a
 * stateful secret key is not safe to serialize as raw component bytes
 * alone.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
 */
export function secretKeyLen(suite: string): number;

/**
 * Hedged (randomized) signing for `suite`. Returns the signature.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of the four stateless
 * suites, or if `secret_key` is not exactly
 * `pqhybridsign_wasm::secretKeyLen(suite)` bytes.
 */
export function sign(suite: string, secret_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array;

/**
 * Deterministic signing for `suite`. Returns the signature.
 *
 * See [`pqhybridsign_abi::sign_deterministic`] for which components
 * honour `nonce`; not every suite does.
 *
 * # Errors
 *
 * The same as [`sign`].
 */
export function signDeterministic(suite: string, secret_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, nonce: Uint8Array): Uint8Array;

/**
 * Sign `msg` under `ctx` for a stateful `suite` (`"H5"` or `"H6"`), spending
 * one leaf recorded through `journal`.
 *
 * `secret_key` is the exported blob from
 * [`keygenStatefulFromSeed`](keygen_stateful_from_seed) or a previous call
 * to this function. `journal` is a JavaScript object with the four
 * synchronous methods the crate documentation describes; it must already be
 * bound to this key ([`adoptKey`](adopt_key)), and its `commit` durably
 * records the leaf before this returns any signature.
 *
 * Returns a [`SignStatefulResult`]: the `signature`, and the `nextSecretKey`
 * blob with its leaf counter advanced. **Persist `nextSecretKey` before
 * relying on `signature`.** The journal is the durable record that makes a
 * missed persist fail closed -- signing again with the stale blob is refused
 * (`CountersDiverged`), never a reissued leaf -- while keeping the working
 * blob in step is what lets the key keep signing.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `secret_key`
 * is not `secretKeyLen(suite)` bytes, if the key's leaf budget is spent
 * (`LeavesExhausted`), if `journal` is not this key's journal
 * (`JournalKeyMismatch`), if the key and journal counters disagree
 * (`CountersDiverged`), or if the journal could not durably commit
 * (`JournalFailed`). Any exception a journal method itself threw is
 * re-thrown unchanged. On the abi's `GrindAbort` the leaf is already spent
 * and durably committed to `journal`; the throw carries no advanced blob, so
 * treat the key as stopped and rotate it.
 */
export function signStateful(suite: string, secret_key: Uint8Array, journal: any, msg: Uint8Array, ctx: Uint8Array): SignStatefulResult;

/**
 * Sign `msg` under `ctx` for a stateful `suite` without spending a leaf,
 * spending one unit of the few-time stateless budget instead.
 *
 * Available because H5 and H6 pair their stateful fast path with a stateless
 * few-time path (SHRINCS specification section 21). No leaf is spent and
 * `secret_key` is not advanced, so there is nothing to persist afterward --
 * but the stateless path has a hard bound of its own, `2^20` signatures
 * (`2^18` under the low-budget profile), and `budget` is what holds the key
 * to it. `budget` is a JavaScript object with synchronous `consumed(key)`
 * and `record(key, count)` methods, and `record` must be durable before it
 * returns, on the same terms `journal.commit` is.
 *
 * Returns the signature.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `secret_key`
 * is not `secretKeyLen(suite)` bytes, if the stateless budget is spent
 * (`StatelessBudgetExhausted`), or if the store could not durably record
 * (`BudgetStoreFailed`). Any exception a budget method itself threw is
 * re-thrown unchanged.
 */
export function signStateless(suite: string, secret_key: Uint8Array, budget: any, msg: Uint8Array, ctx: Uint8Array): Uint8Array;

/**
 * Maximum signature length, in bytes, for `suite`. H2, H4, H5 and H6 are
 * variable-length; see [`pqhybridsign_abi::signature_len`] for why each
 * is. Size the buffer you expect a signature to fit in with this value,
 * not the length of any one signature you have already seen.
 *
 * Total over all six suites, matching `pqhybridsign_abi::signature_len`
 * and the C and Python bindings.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
 */
export function signatureLen(suite: string): number;

/**
 * Stored public key length, in bytes, for `suite`: the form a verifier
 * keeps, which is what
 * [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful)
 * and
 * [`verifyWithStoredPublicKeyStateless`](verify_with_stored_public_key_stateless)
 * take as `stored_public_key`.
 *
 * Total over all six suites, matching `pqhybridsign_abi::stored_public_key_len`,
 * the C `pqhs_stored_public_key_len` and the Python `stored_public_key_len`:
 * for H5 and H6 this is the classical public key and a 32-byte commitment
 * to the post-quantum verify key, smaller than
 * [`publicKeyLen`](public_key_len) reports for the same suite because the
 * verify key itself is supplied per signature rather than stored. For H1
 * through H4 the stored and verify forms are the same bytes, so this
 * equals [`publicKeyLen`](public_key_len). Deliberately routed through
 * `any_suite` rather than `stateful_suite`: this is a pure length
 * accessor over public data, not a signing or verification call, so it has
 * no reason to throw for the four suites every other function in this
 * crate supports.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
 */
export function storedPublicKeyLen(suite: string): number;

/**
 * Verify `sig` over `msg` under `ctx` for `suite`, against `public_key`.
 *
 * Total over all six suites, matching `pqhybridsign_abi::verify`. For H5
 * and H6, `public_key` is the whole verify-form public key
 * [`keygenStatefulFromSeed`](keygen_stateful_from_seed) returns, and no
 * commitment is checked because there is nothing to check one against; use
 * this only where that verify key came from a trusted place, and
 * [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful)
 * -- which binds a signer-supplied bundle to a stored commitment --
 * otherwise.
 *
 * For H5 and H6 this accepts only a signature produced by
 * [`signStateful`](sign_stateful), the same behaviour
 * [`verifyStateful`](verify_stateful) gives directly: specification section
 * 20.2 reserves the primary stateless path for rotation and recovery, and
 * an ordinary application message must not verify through it. Call
 * [`verifyStateless`](verify_stateless) for a message deliberately signed
 * on that path.
 *
 * Returns `false`, never throws, for a malformed `public_key` or `sig`;
 * see [`pqhybridsign_abi::verify`] for why a verification failure is
 * never distinguished by cause.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
 */
export function verify(suite: string, public_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean;

/**
 * Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
 * `"H6"`), accepting only a signature produced by
 * [`signStateful`](sign_stateful), against one whole verify-form
 * `public_key`.
 *
 * [`verify`] is the total dispatcher across all six suites and, for H5 and
 * H6, behaves exactly as this function does; call this one directly only
 * where the suite is already known to be H5 or H6. A signature whose wire
 * `PathSelector` names the stateless path is refused before either
 * component signature is checked. Call
 * [`verifyStateless`](verify_stateless) for a message deliberately signed
 * on the stateless path.
 *
 * Returns `false`, never throws, for a malformed `public_key` or `sig`, on
 * the same terms as [`verify`].
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`.
 */
export function verifyStateful(suite: string, public_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean;

/**
 * Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
 * `"H6"`), accepting only a signature produced by
 * [`signStateless`](sign_stateless), against one whole verify-form
 * `public_key`.
 *
 * The mirror image of [`verifyStateful`](verify_stateful). Use this for
 * rotation and recovery authorizations, and for any other message an
 * application has deliberately chosen to sign on the few-time stateless
 * path.
 *
 * # Errors
 *
 * The same as [`verifyStateful`](verify_stateful).
 */
export function verifyStateless(suite: string, public_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean;

/**
 * Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
 * `"H6"`), accepting only a signature produced by
 * [`signStateful`](sign_stateful), against a signer-supplied verify key
 * that must be the one `stored_public_key` commits to.
 *
 * This is the entry point the H5/H6 deployment is built for: the
 * verifier stores the small form (`ClassicalPK || commitment`,
 * [`storedPublicKeyLen`](stored_public_key_len) bytes -- 64 for both
 * suites) and the signer supplies the full 164-byte commitment bundle
 * alongside every signature, because the bundle is too large to keep on
 * an account.
 *
 * `stored_public_key` is trusted and `pq_verify_key` is not. The
 * commitment is recomputed from `pq_verify_key` and matched against the
 * stored one before anything is verified, and the classical public key is
 * taken from `stored_public_key`, so nothing the signer supplied can
 * substitute a key of their own.
 *
 * [`verifyStateful`](verify_stateful) is the other shape: it takes one
 * whole verify-form public key and checks no commitment, because it has
 * nothing to check one against. Use it only where the verify key itself
 * came from a trusted place.
 *
 * A signature whose wire `PathSelector` names the stateless path is
 * refused before either component signature is checked. Call
 * [`verifyWithStoredPublicKeyStateless`](verify_with_stored_public_key_stateless)
 * for a message deliberately signed on that path.
 *
 * Returns `false`, never throws, for a commitment that does not match, a
 * malformed key or a malformed signature -- the same design [`verify`]
 * uses, so a caller cannot learn which check rejected.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`.
 */
export function verifyWithStoredPublicKeyStateful(suite: string, stored_public_key: Uint8Array, pq_verify_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean;

/**
 * Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
 * `"H6"`), accepting only a signature produced by
 * [`signStateless`](sign_stateless), against a signer-supplied verify key
 * that must be the one `stored_public_key` commits to.
 *
 * The mirror image of
 * [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful).
 * Use this for rotation and recovery authorizations, and for any other
 * message an application has deliberately chosen to sign on the few-time
 * stateless path.
 *
 * # Errors
 *
 * The same as
 * [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful).
 */
export function verifyWithStoredPublicKeyStateless(suite: string, stored_public_key: Uint8Array, pq_verify_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean;

/**
 * Derive 32 output bytes from a verified hybrid VRF proof.
 *
 * **Verify the proof first.** [`vrfVerify`](vrf_verify) is what
 * establishes that the pre-output belongs to this key and this input.
 * Deriving bytes from an unverified proof derives bytes from whatever an
 * attacker supplied.
 *
 * `context` separates two uses of one proof: the same proof under two
 * different contexts gives unrelated bytes, so one evaluation can feed
 * two consumers without either learning the other's value early.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`, if
 * `proof` is shorter than the proof header or `publicKey` shorter than
 * the classical public key, or if `publicKey` or the pre-output does not
 * decode.
 */
export function vrfMakeBytes(suite: string, public_key: Uint8Array, input: Uint8Array, proof: Uint8Array, context: Uint8Array): Uint8Array;

/**
 * Length in bytes of a hybrid VRF proof for `suite`. Total over all six
 * suites; see `pqhybridsign_abi::vrf_proof_len` for what this length
 * means for each.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
 */
export function vrfProofLen(suite: string): number;

/**
 * Evaluate the hybrid VRF for a stateless suite. Returns the proof.
 *
 * H1 through H4 only; see the section documentation above for why H5 and
 * H6 have their own entry point.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H4"`, if
 * `suite` is `"H5"` or `"H6"` (naming `deriveVrfStatelessKey` as the entry
 * point to use instead), if `secretKey` is not the suite's secret-key
 * length, or if either component rejects its key.
 */
export function vrfProve(suite: string, secret_key: Uint8Array, input: Uint8Array): Uint8Array;

/**
 * Evaluate the hybrid VRF for a stateless suite with a reproducible
 * classical proof. H1 through H4 only, on the same terms as
 * [`vrfProve`](vrf_prove).
 *
 * # Errors
 *
 * The same as [`vrfProve`](vrf_prove).
 */
export function vrfProveDeterministic(suite: string, secret_key: Uint8Array, input: Uint8Array): Uint8Array;

/**
 * Verify a hybrid VRF proof against `publicKey`. Total over all six
 * suites: verifying never spends anything, so there is nothing to keep
 * apart by statefulness.
 *
 * Returns `false`, never throws, for a malformed `publicKey` or `proof`.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
 */
export function vrfVerify(suite: string, public_key: Uint8Array, input: Uint8Array, proof: Uint8Array): boolean;
