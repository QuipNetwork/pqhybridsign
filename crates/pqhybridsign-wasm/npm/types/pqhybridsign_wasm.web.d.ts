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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_get_keypair_publicKey: (a: number) => any;
    readonly __wbg_get_keypair_secretKey: (a: number) => any;
    readonly __wbg_keypair_free: (a: number, b: number) => void;
    readonly __wbg_set_keypair_publicKey: (a: number, b: any) => void;
    readonly __wbg_set_keypair_secretKey: (a: number, b: any) => void;
    readonly keygenFromSeed: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly profileName: () => [number, number];
    readonly publicKeyLen: (a: number, b: number) => [number, number, number];
    readonly secretKeyLen: (a: number, b: number) => [number, number, number];
    readonly sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly signDeterministic: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly signatureLen: (a: number, b: number) => [number, number, number];
    readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
