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
