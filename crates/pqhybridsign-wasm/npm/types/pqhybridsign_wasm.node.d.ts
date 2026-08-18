/* tslint:disable */
/* eslint-disable */

/**
 * A stateless keypair: a secret key and its matching public key.
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
 * Derive a keypair for `suite` from a 32-byte master seed.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of the four stateless
 * suites, or if `seed` is not exactly 32 bytes.
 */
export function keygenFromSeed(suite: string, seed: Uint8Array): KeyPair;

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
 * Public key length, in bytes, for one of the four stateless suites.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H1"`, `"H2"`, `"H3"` or
 * `"H4"`.
 */
export function publicKeyLen(suite: string): number;

/**
 * Secret key length, in bytes, for one of the four stateless suites.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H1"`, `"H2"`, `"H3"` or
 * `"H4"`.
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
 * Maximum signature length, in bytes, for one of the four stateless
 * suites. H2 and H4 are variable-length; see
 * [`pqhybridsign_abi::signature_len`] for why. Size the buffer you
 * expect a signature to fit in with this value, not the length of any
 * one signature you have already seen.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H1"`, `"H2"`, `"H3"` or
 * `"H4"`.
 */
export function signatureLen(suite: string): number;

/**
 * Stored public key length, in bytes, for `suite`: the form a verifier
 * keeps, which is what [`verify_with_stored_public_key`] takes as
 * `stored_public_key`.
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
 * Returns `false`, never throws, for a malformed `public_key` or `sig`;
 * see [`pqhybridsign_abi::verify`] for why a verification failure is
 * never distinguished by cause.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not one of the four stateless
 * suites.
 */
export function verify(suite: string, public_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean;

/**
 * Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
 * `"H6"`), against a signer-supplied verify key that must be the one
 * `stored_public_key` commits to.
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
 * [`verify`] is the other shape: it takes one whole verify-form public
 * key and checks no commitment, because it has nothing to check one
 * against. Use it only where the verify key itself came from a trusted
 * place.
 *
 * Returns `false`, never throws, for a commitment that does not match, a
 * malformed key or a malformed signature -- the same design [`verify`]
 * uses, so a caller cannot learn which check rejected.
 *
 * # Errors
 *
 * A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`.
 */
export function verifyWithStoredPublicKey(suite: string, stored_public_key: Uint8Array, pq_verify_key: Uint8Array, msg: Uint8Array, ctx: Uint8Array, sig: Uint8Array): boolean;
