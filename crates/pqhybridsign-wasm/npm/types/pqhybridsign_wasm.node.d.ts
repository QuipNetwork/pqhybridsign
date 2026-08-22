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
