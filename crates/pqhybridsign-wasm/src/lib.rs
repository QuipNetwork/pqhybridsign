// SPDX-License-Identifier: AGPL-3.0-or-later
// This crate genuinely forbids `unsafe`. `forbid` is stricter than the
// workspace `[lints.rust] unsafe-code = "deny"` and, unlike `deny`,
// cannot be relaxed by a downstream `#![allow(unsafe_code)]` -- which
// `clippy::allow_attributes` would not flag, because it does not fire on
// crate-scope inner attributes. The `# Panics and instance loss` section
// below names this attribute, so removing it silently falsifies published
// rustdoc.
#![forbid(unsafe_code)]
// Test-only fixtures use `unwrap` freely; test failure is the desired
// outcome of a bad input.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! WebAssembly and npm binding over `pqhybridsign-abi`.
//!
//! # All six suites, stateless and stateful
//!
//! `pqhybridsign-abi` ships six suites. H1 through H4 are stateless:
//! [`sign`] and [`sign_deterministic`] cost nothing but CPU time. H5 and
//! H6 are stateful -- their post-quantum half spends a one-time leaf per
//! signature, and a leaf spent twice is a total loss of that key's
//! post-quantum security. The stateful pair has its own entry points --
//! [`keygen_stateful_from_seed`], [`sign_stateful`], [`sign_stateless`],
//! [`StatefulKey`], [`adopt_key`], [`key_identity`] and
//! [`key_identity_from_secret_key`] --
//! and the stateless functions [`sign`], [`sign_deterministic`] and
//! [`keygen_from_seed`] reject H5 and H6, because a stateless-looking call
//! that silently spent a leaf would be the worst mistake this binding could
//! make.
//!
//! # Why signing H5 and H6 from JavaScript is safe
//!
//! An earlier version of this binding refused to sign H5 or H6 at all. The
//! reasoning was that a JavaScript value holding a live stateful secret key
//! could be captured by `structuredClone`, serialized with `JSON.stringify`,
//! sent through a `MessageChannel`, or aliased to a second variable, and any
//! of those forks the one-time leaf counter exactly as a Rust `Clone` would.
//! That reasoning is about a *held, mutable key object*. The one-shot
//! functions still keep none. [`StatefulKey`] is a held object, but it is a
//! wasm-bindgen wrapper over one Rust value: assignment aliases it,
//! `structuredClone` cannot fork it, and `free()` releases it. The C and
//! Python bindings expose the same handle. It is safe for these reasons:
//!
//! * On the one-shot path a secret key crosses the boundary only as bytes --
//!   the exported blob [`keygen_stateful_from_seed`] returns,
//!   [`sign_stateful`] reads, and [`sign_stateful`] hands forward again as
//!   `nextSecretKey`. There is no counter object for `structuredClone` to
//!   fork on that path: the leaf counter lives inside the blob and inside
//!   the caller's journal.
//! * [`StatefulKey`] wraps one [`pqhybridsign_abi::StatefulKeyHandle`].
//!   JavaScript assignment aliases the wrapper; it does not clone the key.
//!   `structuredClone` and `postMessage` do not reject a wasm-bindgen class
//!   -- the structured clone algorithm clones its own enumerable
//!   properties, here the raw `__wbg_ptr`, into a prototype-less plain
//!   object in the other realm, dropping the class and therefore every
//!   method, including `free()`. That is worse than a rejection, not
//!   better: the clone silently carries a pointer that is meaningless
//!   outside the instance it came from, and there is no method left on it
//!   to catch the misuse. Call `free()` when finished, on the original
//!   handle only. A handle dropped without `free()` keeps its secret key
//!   material alive for the life of the instance.
//! * Durability and fork-detection live in a caller-supplied leaf journal
//!   (see [`pqhybridsign_abi::LeafJournal`]): a small JavaScript object with
//!   four methods that [`sign_stateful`] drives. Before any signature
//!   exists, the journal durably records the leaf about to be spent, and the
//!   journal is bound once to the key's identity ([`adopt_key`]). A blob
//!   restored out of step with its journal, or paired with a journal that is
//!   not its own, is refused -- the abi's `CountersDiverged` or
//!   `JournalKeyMismatch` -- rather than reissuing a leaf a sibling already
//!   spent.
//!
//! The journal is what makes the one residual hazard -- signing again with a
//! *stale* blob -- **fail closed**. Persisting the `nextSecretKey`
//! [`sign_stateful`] returns keeps the caller's working copy in step; the
//! journal is the durable second record that refuses to sign when the caller
//! does not. Reusing a stale blob does not reissue a leaf here: it stops the
//! key, which the operator recovers from by rotating, never by replaying.
//!
//! # The journal's methods are synchronous
//!
//! [`sign_stateful`] and [`StatefulKey::sign_stateful`] call
//! `journal.commit(leaf)` and must see it return
//! before they build the signature -- the persist-before-release ordering
//! `pqhybridsign_abi::sign_stateful` documents. Its four methods
//! (`commit`, `nextLeaf`, `boundKey`, `bindKey`) are therefore ordinary
//! synchronous calls, exactly as the C binding's function pointers and the
//! Python binding's methods are. `commit` MUST NOT return until the leaf is
//! durably recorded -- under Node an `fs.writeFileSync` followed by an
//! `fs.fsyncSync`. A `commit` that resolves a promise later cannot be
//! awaited from inside the synchronous signature call, so it cannot honour
//! that ordering and MUST NOT be used. The npm layer's functions are `async`
//! only because loading the wasm module is (see `npm/src/api.ts`), not
//! because signing awaits anything.
//!
//! # Verifying needs no key and no journal
//!
//! [`verify`], [`verify_stateful`], [`verify_stateless`],
//! [`verify_with_stored_public_key_stateful`],
//! [`verify_with_stored_public_key_stateless`] and [`stored_public_key_len`]
//! neither receive nor return a secret key, so no journal and no
//! durability obligation attaches to them. The `WithStoredPublicKey`
//! functions check an H5 or H6 signature against public data alone;
//! `stored_public_key_len` is a plain length accessor over public data,
//! defined for all six suites, the same as its C and Python counterparts.
//!
//! # Errors
//!
//! Every fallible export throws a JavaScript `Error` carrying the
//! [`pqhybridsign_abi::AbiError`] message. Nothing here returns an
//! integer error code or a Rust `Result` to JavaScript.
//!
//! # Panics and instance loss
//!
//! This module is built for `wasm32-unknown-unknown`, whose standard library
//! uses `panic = "abort"`. A panic there compiles to an `unreachable`
//! instruction, which traps the WebAssembly instance. The host engine
//! surfaces that trap to JavaScript as a `WebAssembly.RuntimeError`, and an
//! ordinary `try`/`catch` around the call does catch it -- but catching it
//! says nothing about whether the instance is safe to call again. A trap is
//! not one of this crate's ordinary thrown `Error` values, and a caller that
//! treats it as one and keeps using the instance is trusting state this
//! crate never vouched for. `catch_unwind` cannot contain a panic on this
//! target -- confirmed directly against the `wasm-bindgen` build this crate
//! ships, not only against a bare `cdylib` -- so this crate does not attempt
//! it: the C ABI's per-entry-point guard has no equivalent here.
//!
//! Every export in this module has been audited for a panic reachable from
//! caller-controlled input, and none was found: `#![forbid(unsafe_code)]`
//! and no `unwrap`/`expect` outside `#[cfg(test)]`; every suite name and
//! length is validated and reported as a thrown `Error` rather than indexed
//! or unwrapped; and every buffer this crate slices with a length read back
//! from elsewhere -- most prominently the signature buffers [`sign`],
//! [`sign_deterministic`], [`sign_stateful`] and [`sign_stateless`] return --
//! is bounds-checked inside `pqhybridsign-abi` before that length is ever
//! used to slice. Ordinary misuse -- a wrong-length key, an unknown suite
//! name, a malformed signature -- returns an error and leaves the instance
//! usable; a panic here would indicate a defect in this crate rather than
//! bad input.
//!
//! A trap skips Rust's normal unwind cleanup, so a host cannot assume the
//! instance's internal state is sound afterward. This crate holds no
//! `static` or thread-local data across calls. Live [`StatefulKey`]
//! instances hold an imported key in wasm memory; a trap invalidates them
//! along with the instance. A trap here cannot leave a lock or half-built
//! value behind for a later call to observe; that says nothing about the
//! wasm allocator or the `wasm-bindgen` runtime the instance also carries,
//! which this crate does not own and cannot vouch for. A host that must
//! survive a panic here should still instantiate the module in a context
//! it can discard and recreate, such as a dedicated worker, rather than
//! rely on the instance remaining usable.
//!
//! The npm package wraps this. Its `createApi` catches a
//! `WebAssembly.RuntimeError`, discards the instance, and rethrows a
//! `PqHybridSignPanic`. A JavaScript caller that reaches this crate through
//! `@quip.network/pqhybridsign` can separate a trap from an ordinary
//! rejection. The next call reloads. It does not reuse the crashed instance.
//! The Node reload is covered by the package test suite. The browser
//! reload re-imports the glue under a cache-busting specifier, because a
//! second `init()` on the same module record returns the instance that
//! already trapped. The suite does not exercise that browser path, so treat
//! a retry there as best-effort rather than guaranteed. A caller that
//! instantiates the `.wasm` file directly gets neither and must treat any
//! `RuntimeError` as fatal to the instance.
//!
//! # Secret key handling
//!
//! Every export that receives or produces secret key bytes, or the
//! master seed, takes or returns them as an owned `Vec<u8>` (a
//! `Uint8Array` on the JavaScript side, always copied across the
//! boundary by `wasm-bindgen`) and [`zeroize`]s its own copy before
//! returning. That covers the memory this crate controls. It cannot
//! zero the `Uint8Array` the caller passed in, or any copy JavaScript
//! itself made of it -- no binding in any language can reach into a
//! garbage-collected heap it does not own. Callers that need that
//! guarantee should drop their reference to the key material as soon as
//! they are done with it.
//!
//! # The SHRINCS profile is fixed at compile time
//!
//! [`profile_name`] reports the SHRINCS profile this build links
//! against. A key, signature or verify key produced by a build against
//! one profile is not interchangeable with a build against another; see
//! [`pqhybridsign_abi::profile_name`] for why.

use std::cell::RefCell;

use js_sys::{Array, Function, Object, Reflect, Uint8Array};
use pqhybridsign_abi::{
    sign_stateful_with_handle, sign_stateless_with_handle, BudgetKey, KeyIdentity, LeafJournal,
    StatefulKeyHandle, StatelessBudgetStore, KEY_IDENTITY_LEN,
};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use zeroize::Zeroize;

/// Parse a suite name into the ABI's [`pqhybridsign_abi::Suite`],
/// restricted to the four stateless suites this binding exposes.
///
/// Returns a plain `String` message rather than a `JsValue` so this
/// function -- and the suite-name validation logic it holds -- can be
/// exercised by ordinary native `cargo test`, which cannot call into
/// `js-sys` (there is no JavaScript engine to call into). Every call
/// site wraps the error with [`js_error`] before it reaches
/// `wasm-bindgen`.
///
/// # Errors
///
/// An error naming H5/H6 explicitly (see the crate documentation for why
/// they are omitted) or listing the valid names for anything else
/// unrecognised.
fn stateless_suite(name: &str) -> Result<pqhybridsign_abi::Suite, String> {
    match name {
        "H1" => Ok(pqhybridsign_abi::Suite::H1),
        "H2" => Ok(pqhybridsign_abi::Suite::H2),
        "H3" => Ok(pqhybridsign_abi::Suite::H3),
        "H4" => Ok(pqhybridsign_abi::Suite::H4),
        "H5" | "H6" => Err(format!(
            "{name} is a stateful suite: this stateless entry point would spend a \
             one-time leaf without recording it, so it is refused. Sign H5/H6 with \
             keygenStatefulFromSeed and signStateful (which take a durable leaf \
             journal), or use signStateless for the few-time stateless path."
        )),
        other => Err(format!(
            "unknown suite \"{other}\"; expected one of H1, H2, H3, H4"
        )),
    }
}

/// Parse a suite name into the ABI's [`pqhybridsign_abi::Suite`], restricted
/// to the four suites [`vrf_prove`] and [`vrf_prove_deterministic`] can
/// prove under.
///
/// H5 and H6 spend one unit of the few-time stateless budget on every VRF
/// evaluation, the same hazard [`stateless_suite`] refuses for signing, and
/// for the same reason: a call that looks free and is not is the worst
/// failure mode this crate could offer. Rejecting here, at the wasm layer,
/// rather than letting the request reach the abi, is what lets the error
/// name the entry point to use instead -- the abi's own
/// `WrongEntryPointForSuite` has no way to know this binding calls that
/// entry point `deriveVrfStatelessKey`.
///
/// # Errors
///
/// An error naming H5/H6 explicitly and the entry point to use instead, or
/// listing the valid names for anything else unrecognised.
fn vrf_stateless_suite(name: &str) -> Result<pqhybridsign_abi::Suite, String> {
    match name {
        "H1" => Ok(pqhybridsign_abi::Suite::H1),
        "H2" => Ok(pqhybridsign_abi::Suite::H2),
        "H3" => Ok(pqhybridsign_abi::Suite::H3),
        "H4" => Ok(pqhybridsign_abi::Suite::H4),
        "H5" | "H6" => Err(format!(
            "{name} is a stateful suite: this entry point would spend one \
             unit of a few-time stateless budget without recording it, so \
             it is refused. Evaluate the VRF for H5/H6 with \
             deriveVrfStatelessKey and the returned key's prove(budget, \
             input), which takes a durable budget store."
        )),
        other => Err(format!(
            "unknown suite \"{other}\"; expected one of H1, H2, H3, H4"
        )),
    }
}

/// Parse a suite name into the ABI's [`pqhybridsign_abi::Suite`], restricted
/// to the two stateful suites.
///
/// Every stateful-only entry point routes through this:
/// [`keygenStatefulFromSeed`](keygen_stateful_from_seed),
/// [`signStateful`](sign_stateful), [`signStateless`](sign_stateless),
/// [`StatefulKey::open`],
/// [`keyIdentity`](key_identity),
/// [`keyIdentityFromSecretKey`](key_identity_from_secret_key),
/// [`verifyStateful`](verify_stateful), [`verifyStateless`](verify_stateless),
/// [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful)
/// and
/// [`verifyWithStoredPublicKeyStateless`](verify_with_stored_public_key_stateless).
/// It is the counterpart of [`stateless_suite`], which rejects H5/H6, and of
/// [`any_suite`], which accepts all six for the length accessors and
/// [`verify`].
///
/// # Errors
///
/// An error listing the valid names for anything other than `"H5"` or
/// `"H6"`, including H1 through H4.
fn stateful_suite(name: &str) -> Result<pqhybridsign_abi::Suite, String> {
    match name {
        "H5" => Ok(pqhybridsign_abi::Suite::H5),
        "H6" => Ok(pqhybridsign_abi::Suite::H6),
        other => Err(format!(
            "unknown or unsupported suite \"{other}\"; expected \"H5\" or \"H6\""
        )),
    }
}

/// Parse a suite name into the ABI's [`pqhybridsign_abi::Suite`], accepting
/// all six suites this crate knows.
///
/// The only parser of the four that is total over every suite name this
/// crate recognises. Every entry point that is genuinely total over all
/// six suites -- a length accessor, [`verify`], or a VRF function that
/// spends nothing regardless of statefulness -- parses through here rather
/// than through [`stateless_suite`], [`stateful_suite`] or
/// [`vrf_stateless_suite`], each of which excludes suites for a reason
/// specific to what it guards: [`stateless_suite`] excludes H5/H6 because
/// signing them would spend an unrecorded leaf,
/// [`vrf_stateless_suite`] excludes them for the matching reason on the
/// VRF's few-time stateless budget, and [`stateful_suite`] exists only
/// because the `WithStoredPublicKey` verify functions are specific to
/// H5/H6. Eight entry points parse through here as of this writing:
/// [`public_key_len`], [`secret_key_len`], [`signature_len`],
/// [`stored_public_key_len`], [`verify`], [`vrf_proof_len`],
/// [`vrf_verify`] and [`vrf_make_bytes`].
///
/// # Errors
///
/// An error naming the six valid suites, for anything else unrecognised.
fn any_suite(name: &str) -> Result<pqhybridsign_abi::Suite, String> {
    match name {
        "H1" => Ok(pqhybridsign_abi::Suite::H1),
        "H2" => Ok(pqhybridsign_abi::Suite::H2),
        "H3" => Ok(pqhybridsign_abi::Suite::H3),
        "H4" => Ok(pqhybridsign_abi::Suite::H4),
        "H5" => Ok(pqhybridsign_abi::Suite::H5),
        "H6" => Ok(pqhybridsign_abi::Suite::H6),
        other => Err(format!(
            "unknown suite \"{other}\"; expected one of H1, H2, H3, H4, H5, H6"
        )),
    }
}

/// Wrap an error message as a thrown JavaScript `Error`.
fn js_error(message: impl core::fmt::Display) -> JsValue {
    JsValue::from(js_sys::Error::new(&message.to_string()))
}

/// Copy `bytes` into a fixed-size array, or report a JavaScript `Error`
/// naming `what` and the length seen if `bytes` is not exactly `N` long.
///
/// Used for the master-seed and chain-code parameters
/// [`master_seed_from_mnemonic`], [`derive_hard_junction`],
/// [`derive_hard_junction_path`] and [`derive_vrf_stateless_key`] take:
/// `pqhybridsign_abi`'s seed and VRF-key-derivation functions take fixed
/// arrays rather than the runtime-checked slices most of this crate's
/// other exports do, so this crate validates the length itself instead of
/// forwarding a mismatch to the abi layer.
fn fixed_bytes<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsValue> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        js_error(format!(
            "{what} must be exactly {N} bytes, got {}",
            bytes.len()
        ))
    })
}

/// The SHRINCS profile this build links against, for example
/// `"shrincs-256s"`.
///
/// See the crate documentation and
/// [`pqhybridsign_abi::profile_name`] for why an integrator must confirm
/// this string matches on every side of an integration before trusting
/// anything on the wire.
#[wasm_bindgen(js_name = profileName)]
#[must_use]
pub fn profile_name() -> String {
    pqhybridsign_abi::profile_name().to_string()
}

/// Public key length, in bytes, for `suite`.
///
/// Total over all six suites, matching `pqhybridsign_abi::public_key_len`
/// and the C and Python bindings. For H5 and H6 this is the verify-key
/// form [`keygenStatefulFromSeed`](keygen_stateful_from_seed) writes,
/// larger than the on-storage commitment form
/// [`storedPublicKeyLen`](stored_public_key_len) reports for the same suite
/// because a verifier needs the full verify key, not just a commitment to
/// it.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
#[wasm_bindgen(js_name = publicKeyLen)]
pub fn public_key_len(suite: &str) -> Result<u32, JsValue> {
    Ok(pqhybridsign_abi::public_key_len(any_suite(suite).map_err(js_error)?) as u32)
}

/// Secret key length, in bytes, for `suite`.
///
/// Total over all six suites, matching `pqhybridsign_abi::secret_key_len`
/// and the C and Python bindings. For H1 through H4 this is the raw
/// composite secret key. For H5 and H6 it is the length of the exported
/// blob [`keygenStatefulFromSeed`](keygen_stateful_from_seed) returns and
/// [`signStateful`](sign_stateful) reads and hands forward: the composite
/// secret key plus the leaf counter and the cached verify key, because a
/// stateful secret key is not safe to serialize as raw component bytes
/// alone.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
#[wasm_bindgen(js_name = secretKeyLen)]
pub fn secret_key_len(suite: &str) -> Result<u32, JsValue> {
    Ok(pqhybridsign_abi::secret_key_len(any_suite(suite).map_err(js_error)?) as u32)
}

/// Maximum signature length, in bytes, for `suite`. H2, H4, H5 and H6 are
/// variable-length; see [`pqhybridsign_abi::signature_len`] for why each
/// is. Size the buffer you expect a signature to fit in with this value,
/// not the length of any one signature you have already seen.
///
/// Total over all six suites, matching `pqhybridsign_abi::signature_len`
/// and the C and Python bindings.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
#[wasm_bindgen(js_name = signatureLen)]
pub fn signature_len(suite: &str) -> Result<u32, JsValue> {
    Ok(pqhybridsign_abi::signature_len(any_suite(suite).map_err(js_error)?) as u32)
}

/// A keypair: a secret key and its matching public key.
///
/// Returned by both [`keygenFromSeed`](keygen_from_seed) (H1 through H4)
/// and [`keygenStatefulFromSeed`](keygen_stateful_from_seed) (H5 and H6);
/// for the stateful suites the secret key is the exported blob, still
/// `secretKeyLen(suite)` bytes.
///
/// A caller must call `free()`, call `[Symbol.dispose]()`, or declare
/// the value with JavaScript `using`. A leaked `KeyPair` keeps its
/// secret-key `Uint8Array` reachable.
#[wasm_bindgen(getter_with_clone)]
pub struct KeyPair {
    /// The composite secret key, `pqhybridsign_wasm::secretKeyLen(suite)`
    /// bytes.
    #[wasm_bindgen(js_name = secretKey)]
    pub secret_key: Uint8Array,
    /// The composite public key, `pqhybridsign_wasm::publicKeyLen(suite)`
    /// bytes.
    #[wasm_bindgen(js_name = publicKey)]
    pub public_key: Uint8Array,
}

/// Derive a keypair for `suite` from a 32-byte master seed.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of the four stateless
/// suites, or if `seed` is not exactly 32 bytes.
#[wasm_bindgen(js_name = keygenFromSeed)]
pub fn keygen_from_seed(suite: &str, seed: Vec<u8>) -> Result<KeyPair, JsValue> {
    let suite = stateless_suite(suite).map_err(js_error)?;
    let mut seed = seed;
    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(suite)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(suite)];

    let result = pqhybridsign_abi::keygen_from_seed(suite, &seed, &mut sk, &mut pk);
    seed.zeroize();

    let pair = result.map(|()| KeyPair {
        secret_key: Uint8Array::from(sk.as_slice()),
        public_key: Uint8Array::from(pk.as_slice()),
    });
    sk.zeroize();

    pair.map_err(js_error)
}

/// Hedged (randomized) signing for `suite`. Returns the signature.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of the four stateless
/// suites, or if `secret_key` is not exactly
/// `pqhybridsign_wasm::secretKeyLen(suite)` bytes.
#[wasm_bindgen]
pub fn sign(
    suite: &str,
    secret_key: Vec<u8>,
    msg: &[u8],
    ctx: &[u8],
) -> Result<Uint8Array, JsValue> {
    let suite = stateless_suite(suite).map_err(js_error)?;
    let mut secret_key = secret_key;
    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];

    let result = pqhybridsign_abi::sign(suite, &secret_key, msg, ctx, &mut OsRng, &mut sig);
    secret_key.zeroize();

    let n = result.map_err(js_error)?;
    Ok(Uint8Array::from(&sig[..n]))
}

/// Deterministic signing for `suite`. Returns the signature.
///
/// See [`pqhybridsign_abi::sign_deterministic`] for which components
/// honour `nonce`; not every suite does.
///
/// # Errors
///
/// The same as [`sign`].
#[wasm_bindgen(js_name = signDeterministic)]
pub fn sign_deterministic(
    suite: &str,
    secret_key: Vec<u8>,
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
) -> Result<Uint8Array, JsValue> {
    let suite = stateless_suite(suite).map_err(js_error)?;
    let mut secret_key = secret_key;
    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];

    let result =
        pqhybridsign_abi::sign_deterministic(suite, &secret_key, msg, ctx, nonce, &mut sig);
    secret_key.zeroize();

    let n = result.map_err(js_error)?;
    Ok(Uint8Array::from(&sig[..n]))
}

/// Verify `sig` over `msg` under `ctx` for `suite`, against `public_key`.
///
/// Total over all six suites, matching `pqhybridsign_abi::verify`. For H5
/// and H6, `public_key` is the whole verify-form public key
/// [`keygenStatefulFromSeed`](keygen_stateful_from_seed) returns, and no
/// commitment is checked because there is nothing to check one against; use
/// this only where that verify key came from a trusted place, and
/// [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful)
/// -- which binds a signer-supplied bundle to a stored commitment --
/// otherwise.
///
/// For H5 and H6 this accepts only a signature produced by
/// [`signStateful`](sign_stateful), the same behaviour
/// [`verifyStateful`](verify_stateful) gives directly: specification section
/// 20.2 reserves the primary stateless path for rotation and recovery, and
/// an ordinary application message must not verify through it. Call
/// [`verifyStateless`](verify_stateless) for a message deliberately signed
/// on that path.
///
/// Returns `false`, never throws, for a malformed `public_key` or `sig`;
/// see [`pqhybridsign_abi::verify`] for why a verification failure is
/// never distinguished by cause.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
#[wasm_bindgen]
pub fn verify(
    suite: &str,
    public_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let suite = any_suite(suite).map_err(js_error)?;
    Ok(pqhybridsign_abi::verify(suite, public_key, msg, ctx, sig))
}

/// Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
/// `"H6"`), accepting only a signature produced by
/// [`signStateful`](sign_stateful), against one whole verify-form
/// `public_key`.
///
/// [`verify`] is the total dispatcher across all six suites and, for H5 and
/// H6, behaves exactly as this function does; call this one directly only
/// where the suite is already known to be H5 or H6. A signature whose wire
/// `PathSelector` names the stateless path is refused before either
/// component signature is checked. Call
/// [`verifyStateless`](verify_stateless) for a message deliberately signed
/// on the stateless path.
///
/// Returns `false`, never throws, for a malformed `public_key` or `sig`, on
/// the same terms as [`verify`].
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`.
#[wasm_bindgen(js_name = verifyStateful)]
pub fn verify_stateful(
    suite: &str,
    public_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    pqhybridsign_abi::verify_stateful(suite, public_key, msg, ctx, sig).map_err(js_error)
}

/// Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
/// `"H6"`), accepting only a signature produced by
/// [`signStateless`](sign_stateless), against one whole verify-form
/// `public_key`.
///
/// The mirror image of [`verifyStateful`](verify_stateful). Use this for
/// rotation and recovery authorizations, and for any other message an
/// application has deliberately chosen to sign on the few-time stateless
/// path.
///
/// # Errors
///
/// The same as [`verifyStateful`](verify_stateful).
#[wasm_bindgen(js_name = verifyStateless)]
pub fn verify_stateless(
    suite: &str,
    public_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    pqhybridsign_abi::verify_stateless(suite, public_key, msg, ctx, sig).map_err(js_error)
}

/// Stored public key length, in bytes, for `suite`: the form a verifier
/// keeps, which is what
/// [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful)
/// and
/// [`verifyWithStoredPublicKeyStateless`](verify_with_stored_public_key_stateless)
/// take as `stored_public_key`.
///
/// Total over all six suites, matching `pqhybridsign_abi::stored_public_key_len`,
/// the C `pqhs_stored_public_key_len` and the Python `stored_public_key_len`:
/// for H5 and H6 this is the classical public key and a 32-byte commitment
/// to the post-quantum verify key, smaller than
/// [`publicKeyLen`](public_key_len) reports for the same suite because the
/// verify key itself is supplied per signature rather than stored. For H1
/// through H4 the stored and verify forms are the same bytes, so this
/// equals [`publicKeyLen`](public_key_len). Deliberately routed through
/// `any_suite` rather than `stateful_suite`: this is a pure length
/// accessor over public data, not a signing or verification call, so it has
/// no reason to throw for the four suites every other function in this
/// crate supports.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
#[wasm_bindgen(js_name = storedPublicKeyLen)]
pub fn stored_public_key_len(suite: &str) -> Result<u32, JsValue> {
    Ok(pqhybridsign_abi::stored_public_key_len(any_suite(suite).map_err(js_error)?) as u32)
}

/// Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
/// `"H6"`), accepting only a signature produced by
/// [`signStateful`](sign_stateful), against a signer-supplied verify key
/// that must be the one `stored_public_key` commits to.
///
/// This is the entry point the H5/H6 deployment is built for: the
/// verifier stores the small form (`ClassicalPK || commitment`,
/// [`storedPublicKeyLen`](stored_public_key_len) bytes -- 64 for both
/// suites) and the signer supplies the full 164-byte commitment bundle
/// alongside every signature, because the bundle is too large to keep on
/// an account.
///
/// `stored_public_key` is trusted and `pq_verify_key` is not. The
/// commitment is recomputed from `pq_verify_key` and matched against the
/// stored one before anything is verified, and the classical public key is
/// taken from `stored_public_key`, so nothing the signer supplied can
/// substitute a key of their own.
///
/// [`verifyStateful`](verify_stateful) is the other shape: it takes one
/// whole verify-form public key and checks no commitment, because it has
/// nothing to check one against. Use it only where the verify key itself
/// came from a trusted place.
///
/// A signature whose wire `PathSelector` names the stateless path is
/// refused before either component signature is checked. Call
/// [`verifyWithStoredPublicKeyStateless`](verify_with_stored_public_key_stateless)
/// for a message deliberately signed on that path.
///
/// Returns `false`, never throws, for a commitment that does not match, a
/// malformed key or a malformed signature -- the same design [`verify`]
/// uses, so a caller cannot learn which check rejected.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`.
#[wasm_bindgen(js_name = verifyWithStoredPublicKeyStateful)]
pub fn verify_with_stored_public_key_stateful(
    suite: &str,
    stored_public_key: &[u8],
    pq_verify_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    pqhybridsign_abi::verify_with_stored_public_key_stateful(
        suite,
        stored_public_key,
        pq_verify_key,
        msg,
        ctx,
        sig,
    )
    .map_err(js_error)
}

/// Verify `sig` over `msg` under `ctx` for a stateful suite (`"H5"` or
/// `"H6"`), accepting only a signature produced by
/// [`signStateless`](sign_stateless), against a signer-supplied verify key
/// that must be the one `stored_public_key` commits to.
///
/// The mirror image of
/// [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful).
/// Use this for rotation and recovery authorizations, and for any other
/// message an application has deliberately chosen to sign on the few-time
/// stateless path.
///
/// # Errors
///
/// The same as
/// [`verifyWithStoredPublicKeyStateful`](verify_with_stored_public_key_stateful).
#[wasm_bindgen(js_name = verifyWithStoredPublicKeyStateless)]
pub fn verify_with_stored_public_key_stateless(
    suite: &str,
    stored_public_key: &[u8],
    pq_verify_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    pqhybridsign_abi::verify_with_stored_public_key_stateless(
        suite,
        stored_public_key,
        pq_verify_key,
        msg,
        ctx,
        sig,
    )
    .map_err(js_error)
}

// ---- Stateful suites (H5, H6): the leaf journal and budget bridges ----
//
// `pqhybridsign_abi::sign_stateful` and `sign_stateless` do no I/O. Durability
// and fork-detection are the caller's, supplied through a `LeafJournal` and a
// `StatelessBudgetStore`. These two adapters wrap a JavaScript object as
// each, calling its methods synchronously -- the same shape the C binding's
// `PqhsLeafJournal` function pointers and the Python binding's `PyJournal`
// take, and safe under `#![forbid(unsafe_code)]` because every call goes
// through `js_sys::Reflect` and `js_sys::Function`, never a raw import.

/// Marker: a journal or budget callback threw or reported failure. The
/// JavaScript exception itself, when there was one, is captured on the
/// adapter and re-thrown by the WASM entry point; this only tells the abi
/// layer the write did not happen, which it maps to `AbiError::JournalFailed`
/// or `AbiError::BudgetStoreFailed`.
#[derive(Debug)]
struct CallbackFailed;

/// Look up `name` on `obj` and require it to be callable.
fn method(obj: &JsValue, name: &str) -> Result<Function, JsValue> {
    Reflect::get(obj, &JsValue::from_str(name))?
        .dyn_into::<Function>()
        .map_err(|_| js_error(format!("the object passed has no callable {name}() method")))
}

/// Fetch method `name` from `obj` and call it with no arguments.
fn call0(obj: &JsValue, name: &str) -> Result<JsValue, JsValue> {
    method(obj, name)?.call0(obj)
}

/// Fetch method `name` from `obj` and call it with one argument.
fn call1(obj: &JsValue, name: &str, a: &JsValue) -> Result<JsValue, JsValue> {
    method(obj, name)?.call1(obj, a)
}

/// Fetch method `name` from `obj` and call it with two arguments.
fn call2(obj: &JsValue, name: &str, a: &JsValue, b: &JsValue) -> Result<JsValue, JsValue> {
    method(obj, name)?.call2(obj, a, b)
}

/// Read a JavaScript number as a `u32`, or `None` if it is not a
/// non-negative integer within range.
fn js_to_u32(value: &JsValue) -> Option<u32> {
    let n = value.as_f64()?;
    // `fract() == 0.0` is false for NaN and the infinities, so it rules out
    // every non-integer before the range check runs.
    if n.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&n) {
        Some(n as u32)
    } else {
        None
    }
}

/// Read a JavaScript number as a `u64`, or `None` if it is not a
/// non-negative integer a `f64` represents exactly (below 2^53).
fn js_to_u64(value: &JsValue) -> Option<u64> {
    let n = value.as_f64()?;
    // 2^53 - 1 is the largest integer f64 represents without gaps; a
    // few-time budget count (bounded by 2^20) never approaches it, so a
    // value above is a caller error.
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    // `fract() == 0.0` is false for NaN and the infinities, so it rules out
    // every non-integer before the range check runs.
    if n.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&n) {
        Some(n as u64)
    } else {
        None
    }
}

/// Read a 32-byte `Uint8Array` as a [`KeyIdentity`], or `None` if `value` is
/// not a `Uint8Array` of exactly `KEY_IDENTITY_LEN` bytes.
fn js_to_key_identity(value: &JsValue) -> Option<KeyIdentity> {
    let arr = value.dyn_ref::<Uint8Array>()?;
    if arr.length() as usize != KEY_IDENTITY_LEN {
        return None;
    }
    let mut bytes = [0u8; KEY_IDENTITY_LEN];
    arr.copy_to(&mut bytes);
    Some(KeyIdentity::from_bytes(bytes))
}

/// A [`LeafJournal`] backed by a JavaScript object exposing synchronous
/// `commit(leaf)`, `nextLeaf()`, `boundKey()` and `bindKey(identity)`
/// methods.
///
/// A `LeafJournal` method has no `Result` return for `next_leaf`/`bound_key`,
/// so a JavaScript exception thrown from either is captured in `error` and
/// reported as the fail-closed value (`u32::MAX` or `None`); the WASM entry
/// point re-throws it in preference to whatever the abi reported.
///
/// `bound_key` is memoized in `bound_key_cache`: the first call reaches
/// `boundKey()`, and every later call on the same `JsJournal` returns the
/// cached answer without calling back into JavaScript. A caller that needs
/// a read fault to be visible before the ABI's own read -- see `adoptKey`
/// below -- gets that only if a transient fault has exactly one place to
/// land; two independent calls into the same JavaScript method would give
/// it two, and a fault that lands on the second would go unnoticed by a
/// guard checked after the first.
///
/// `bind_key` clears `bound_key_cache` on success, so a `bound_key` read
/// after a `bind_key` write on the same instance sees the new binding rather
/// than a `None` cached from before it. No current caller reads
/// `bound_key` again after `bind_key` on one `JsJournal` -- `adopt_key`
/// reads it once, before its own single call to `bind_key`, and
/// `sign_stateful` never calls `bind_key` at all -- but the type does not
/// enforce that ordering, and a future entry point that adopts and then
/// re-reads must not see a stale `None`: that is exactly the never-bound
/// condition `JournalKeyMismatch` exists to catch. Any method added to this
/// `impl` that writes through to JavaScript must maintain this invariant.
struct JsJournal<'a> {
    obj: &'a JsValue,
    error: RefCell<Option<JsValue>>,
    bound_key_cache: RefCell<Option<Option<KeyIdentity>>>,
}

impl<'a> JsJournal<'a> {
    fn new(obj: &'a JsValue) -> Self {
        Self {
            obj,
            error: RefCell::new(None),
            bound_key_cache: RefCell::new(None),
        }
    }

    fn record_error(&self, err: JsValue) {
        *self.error.borrow_mut() = Some(err);
    }

    fn take_error(&self) -> Option<JsValue> {
        self.error.borrow_mut().take()
    }
}

impl LeafJournal for JsJournal<'_> {
    type Error = CallbackFailed;

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        match call1(self.obj, "commit", &JsValue::from_f64(f64::from(leaf))) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.record_error(err);
                Err(CallbackFailed)
            }
        }
    }

    fn next_leaf(&self) -> u32 {
        match call0(self.obj, "nextLeaf") {
            Ok(value) => js_to_u32(&value).unwrap_or_else(|| {
                self.record_error(js_error(
                    "nextLeaf() must return a non-negative integer that fits in a u32",
                ));
                u32::MAX
            }),
            Err(err) => {
                self.record_error(err);
                u32::MAX
            }
        }
    }

    /// Memoized (see `bound_key_cache` on the struct): `boundKey()` is
    /// called at most once per `JsJournal` between calls to `bind_key`,
    /// however many times this method is called. `bind_key` clears the
    /// cache on success, so a call after a successful bind reaches
    /// `boundKey()` again rather than returning a stale answer.
    fn bound_key(&self) -> Option<KeyIdentity> {
        if let Some(cached) = *self.bound_key_cache.borrow() {
            return cached;
        }
        let result = match call0(self.obj, "boundKey") {
            Ok(value) if value.is_null() || value.is_undefined() => None,
            Ok(value) => match js_to_key_identity(&value) {
                Some(identity) => Some(identity),
                None => {
                    self.record_error(js_error(
                        "boundKey() must return a 32-byte Uint8Array or null",
                    ));
                    None
                }
            },
            Err(err) => {
                self.record_error(err);
                None
            }
        };
        *self.bound_key_cache.borrow_mut() = Some(result);
        result
    }

    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        let arg = Uint8Array::from(&key.as_bytes()[..]);
        match call1(self.obj, "bindKey", arg.as_ref()) {
            Ok(_) => {
                // Invalidate `bound_key_cache`: a stale `None` cached from a
                // read before this write would read back as never-bound,
                // which is the exact condition `JournalKeyMismatch` exists
                // to catch. The next `bound_key()` call re-reads `boundKey()`.
                *self.bound_key_cache.borrow_mut() = None;
                Ok(())
            }
            Err(err) => {
                self.record_error(err);
                Err(CallbackFailed)
            }
        }
    }
}

/// A [`StatelessBudgetStore`] backed by a JavaScript object exposing
/// synchronous `consumed(key)` and `record(key, count)` methods.
///
/// The stateless counterpart of [`JsJournal`]. `consumed` has no `Result`
/// return, so a JavaScript exception there is captured and reported as `None`
/// (never tracked, a full budget); the WASM entry point re-throws it in
/// preference to the abi's code, because a broken read reported as `None`
/// would otherwise look like a fresh key.
struct JsBudget<'a> {
    obj: &'a JsValue,
    error: RefCell<Option<JsValue>>,
}

impl<'a> JsBudget<'a> {
    fn new(obj: &'a JsValue) -> Self {
        Self {
            obj,
            error: RefCell::new(None),
        }
    }

    fn record_error(&self, err: JsValue) {
        *self.error.borrow_mut() = Some(err);
    }

    fn take_error(&self) -> Option<JsValue> {
        self.error.borrow_mut().take()
    }
}

impl StatelessBudgetStore for JsBudget<'_> {
    type Error = CallbackFailed;

    fn consumed(&self, key: &BudgetKey) -> Option<u64> {
        let arg = Uint8Array::from(&key.as_bytes()[..]);
        let value = match call1(self.obj, "consumed", arg.as_ref()) {
            Ok(value) => value,
            Err(err) => {
                self.record_error(err);
                return None;
            }
        };
        if value.is_null() || value.is_undefined() {
            return None;
        }
        match js_to_u64(&value) {
            Some(count) => Some(count),
            None => {
                self.record_error(js_error(
                    "consumed() must return a non-negative integer or null",
                ));
                None
            }
        }
    }

    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
        let key_arg = Uint8Array::from(&key.as_bytes()[..]);
        // A few-time budget count is bounded by 2^20 (specification section
        // 21), far below 2^53, so a f64 carries it exactly.
        let count_arg = JsValue::from_f64(count as f64);
        match call2(self.obj, "record", key_arg.as_ref(), &count_arg) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.record_error(err);
                Err(CallbackFailed)
            }
        }
    }
}

/// The result of [`signStateful`](sign_stateful): the signature and the
/// advanced secret key blob the caller must persist.
///
/// `nextSecretKey` is the exported blob with its leaf counter advanced past
/// the leaf this signature spent. Persist it in place of the blob passed in,
/// before relying on `signature`: signing again with the old blob is refused
/// (the abi's `CountersDiverged`), so a stale blob stops the key rather than
/// reissuing the leaf, and keeping the working blob in step is what lets the
/// key keep signing.
///
/// A caller must call `free()`, call `[Symbol.dispose]()`, or declare the
/// value with JavaScript `using`. A leaked `SignStatefulResult` keeps its
/// secret-key `Uint8Array` reachable.
#[wasm_bindgen(getter_with_clone)]
pub struct SignStatefulResult {
    /// The signature, at most `signatureLen(suite)` bytes.
    #[wasm_bindgen(js_name = signature)]
    pub signature: Uint8Array,
    /// The exported secret key blob with its leaf counter advanced, exactly
    /// `secretKeyLen(suite)` bytes. Persist this before using `signature`.
    #[wasm_bindgen(js_name = nextSecretKey)]
    pub next_secret_key: Uint8Array,
}

/// Derive a stateful keypair for `suite` (`"H5"` or `"H6"`) from a 32-byte
/// master seed, with a budget of `max_stateful_signatures` one-time leaves.
///
/// Returns a [`KeyPair`] whose `secretKey` is the exported blob
/// [`signStateful`](sign_stateful) reads and
/// [`secretKeyLen`](secret_key_len) measures, and whose `publicKey` is the
/// verify-form public key.
///
/// This does not touch a journal. Before the first
/// [`signStateful`](sign_stateful) call, bind the key's durable journal to it
/// once with [`adoptKey`](adopt_key) over the identity
/// [`keyIdentity`](key_identity) derives from `publicKey`; that binding is
/// what a later restore checks against, and skipping it makes the first
/// signature fail with the abi's `JournalKeyMismatch`.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `seed` is not
/// exactly 32 bytes, or if `max_stateful_signatures` is zero or exceeds the
/// component's leaf capacity limit.
#[wasm_bindgen(js_name = keygenStatefulFromSeed)]
pub fn keygen_stateful_from_seed(
    suite: &str,
    seed: Vec<u8>,
    max_stateful_signatures: u32,
) -> Result<KeyPair, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    let mut seed = seed;
    let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(suite)];
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(suite)];

    let result = pqhybridsign_abi::keygen_stateful_from_seed(
        suite,
        &seed,
        max_stateful_signatures,
        &mut sk,
        &mut pk,
    );
    seed.zeroize();

    let pair = result.map(|()| KeyPair {
        secret_key: Uint8Array::from(sk.as_slice()),
        public_key: Uint8Array::from(pk.as_slice()),
    });
    sk.zeroize();

    pair.map_err(js_error)
}

/// The 32-byte identity of the key `public_key` describes, for a stateful
/// `suite` (`"H5"` or `"H6"`).
///
/// `public_key` is the verify-form public key
/// [`keygenStatefulFromSeed`](keygen_stateful_from_seed) returned. It is
/// public material, so this discloses nothing about the secret key. Pass the
/// result to [`adoptKey`](adopt_key) once, when the key's durable journal is
/// created.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, or if
/// `public_key` is not `publicKeyLen(suite)` bytes.
#[wasm_bindgen(js_name = keyIdentity)]
pub fn key_identity(suite: &str, public_key: &[u8]) -> Result<Uint8Array, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    let identity = pqhybridsign_abi::key_identity(suite, public_key).map_err(js_error)?;
    Ok(Uint8Array::from(&identity.as_bytes()[..]))
}

/// The 32-byte identity of the key an exported secret key blob holds, for a
/// stateful `suite`.
///
/// The same value [`keyIdentity`](key_identity) returns for the matching
/// public key; it comes from the blob's cached verify key, which is public.
/// This exists for the restart path, which has the blob but may not have kept
/// the public key.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `secret_key`
/// is not `secretKeyLen(suite)` bytes, or if the blob does not import.
#[wasm_bindgen(js_name = keyIdentityFromSecretKey)]
pub fn key_identity_from_secret_key(
    suite: &str,
    secret_key: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    let mut secret_key = secret_key;
    let identity = pqhybridsign_abi::key_identity_from_secret_key(suite, &secret_key);
    secret_key.zeroize();
    let identity = identity.map_err(js_error)?;
    Ok(Uint8Array::from(&identity.as_bytes()[..]))
}

/// Bind `journal` to the key `identity` names, unless it already belongs to a
/// different key.
///
/// This is the one explicit act that pairs a key with its durable journal,
/// performed once when the journal is created (`identity` comes from
/// [`keyIdentity`](key_identity) or
/// [`keyIdentityFromSecretKey`](key_identity_from_secret_key)).
/// [`signStateful`](sign_stateful) never binds implicitly: pairing a key with
/// a journal that has never seen it is how one key's one-time leaves get
/// spent twice. Idempotent for a journal already bound to `identity`, so a
/// provisioning step is safe to re-run; do not call it on a fresh journal at
/// every process start, which mints a new binding and starts the budget over.
///
/// `journal` is a JavaScript object with synchronous `boundKey()` and
/// `bindKey(identity)` methods (see the crate documentation).
///
/// # Errors
///
/// A JavaScript `Error` if `identity` is not 32 bytes, if `journal` already
/// belongs to another key (the abi's `JournalKeyMismatch`), or if `bindKey`
/// could not durably record the binding. Any exception a journal method
/// itself threw is re-thrown unchanged.
///
/// A `boundKey()` that throws prevents `bindKey` from being called at all,
/// so a read fault can never replace an existing binding.
#[wasm_bindgen(js_name = adoptKey)]
pub fn adopt_key(journal: &JsValue, identity: &[u8]) -> Result<(), JsValue> {
    let bytes = <[u8; KEY_IDENTITY_LEN]>::try_from(identity)
        .map_err(|_| js_error(pqhybridsign_abi::AbiError::BadLength))?;
    let mut journal = JsJournal::new(journal);
    // Read the binding once, and surface a read fault, before anything can
    // write. The bridge reports a throwing `boundKey` to the abi as `None`,
    // which the abi reads as never-bound: it would call `bindKey` and only
    // then let the deferred exception surface. Against an already-bound
    // journal whose `bindKey` is not write-once, that silently replaces the
    // binding, which is what the JournalKeyMismatch guard exists to prevent.
    let _ = journal.bound_key();
    if let Some(err) = journal.take_error() {
        return Err(err);
    }
    let result = pqhybridsign_abi::adopt_key(&mut journal, KeyIdentity::from_bytes(bytes));
    if let Some(err) = journal.take_error() {
        return Err(err);
    }
    result.map_err(js_error)
}

/// Sign `msg` under `ctx` for a stateful `suite` (`"H5"` or `"H6"`), spending
/// one leaf recorded through `journal`.
///
/// `secret_key` is the exported blob from
/// [`keygenStatefulFromSeed`](keygen_stateful_from_seed) or a previous call
/// to this function. `journal` is a JavaScript object with the four
/// synchronous methods the crate documentation describes; it must already be
/// bound to this key ([`adoptKey`](adopt_key)), and its `commit` durably
/// records the leaf before this returns any signature.
///
/// Returns a [`SignStatefulResult`]: the `signature`, and the `nextSecretKey`
/// blob with its leaf counter advanced. **Persist `nextSecretKey` before
/// relying on `signature`.** The journal is the durable record that makes a
/// missed persist fail closed -- signing again with the stale blob is refused
/// (`CountersDiverged`), never a reissued leaf -- while keeping the working
/// blob in step is what lets the key keep signing.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `secret_key`
/// is not `secretKeyLen(suite)` bytes, if the key's leaf budget is spent
/// (`LeavesExhausted`), if `journal` is not this key's journal
/// (`JournalKeyMismatch`), if the key and journal counters disagree
/// (`CountersDiverged`), or if the journal could not durably commit
/// (`JournalFailed`). Any exception a journal method itself threw is
/// re-thrown unchanged. On the abi's `GrindAbort` the leaf is already spent
/// and durably committed to `journal`; the throw carries no advanced blob, so
/// treat the key as stopped and rotate it.
#[wasm_bindgen(js_name = signStateful)]
pub fn sign_stateful(
    suite: &str,
    secret_key: Vec<u8>,
    journal: &JsValue,
    msg: &[u8],
    ctx: &[u8],
) -> Result<SignStatefulResult, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    let mut secret_key = secret_key;
    let mut sk_out = vec![0u8; pqhybridsign_abi::secret_key_len(suite)];
    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];
    let mut journal = JsJournal::new(journal);

    let result = pqhybridsign_abi::sign_stateful(
        suite,
        &secret_key,
        &mut journal,
        msg,
        ctx,
        &mut sk_out,
        &mut sig,
    );
    secret_key.zeroize();

    // A JavaScript exception a journal method threw wins over the abi's flat
    // code, exactly as in the Python binding: the abi reports `JournalFailed`
    // where the caller's own error is more specific.
    if let Some(err) = journal.take_error() {
        sk_out.zeroize();
        return Err(err);
    }

    let outcome = match result {
        Ok(n) => Ok(SignStatefulResult {
            signature: Uint8Array::from(&sig[..n]),
            next_secret_key: Uint8Array::from(sk_out.as_slice()),
        }),
        Err(e) => Err(js_error(e)),
    };
    sk_out.zeroize();
    outcome
}

/// Sign `msg` under `ctx` for a stateful `suite` without spending a leaf,
/// spending one unit of the few-time stateless budget instead.
///
/// Available because H5 and H6 pair their stateful fast path with a stateless
/// few-time path (SHRINCS specification section 21). No leaf is spent and
/// `secret_key` is not advanced, so there is nothing to persist afterward --
/// but the stateless path has a hard bound of its own, `2^20` signatures
/// (`2^18` under the low-budget profile), and `budget` is what holds the key
/// to it. `budget` is a JavaScript object with synchronous `consumed(key)`
/// and `record(key, count)` methods, and `record` must be durable before it
/// returns, on the same terms `journal.commit` is.
///
/// Returns the signature.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `secret_key`
/// is not `secretKeyLen(suite)` bytes, if the stateless budget is spent
/// (`StatelessBudgetExhausted`), or if the store could not durably record
/// (`BudgetStoreFailed`). Any exception a budget method itself threw is
/// re-thrown unchanged.
#[wasm_bindgen(js_name = signStateless)]
pub fn sign_stateless(
    suite: &str,
    secret_key: Vec<u8>,
    budget: &JsValue,
    msg: &[u8],
    ctx: &[u8],
) -> Result<Uint8Array, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    let mut secret_key = secret_key;
    let mut sig = vec![0u8; pqhybridsign_abi::signature_len(suite)];
    let mut budget = JsBudget::new(budget);

    let result =
        pqhybridsign_abi::sign_stateless(suite, &secret_key, &mut budget, msg, ctx, &mut sig);
    secret_key.zeroize();

    if let Some(err) = budget.take_error() {
        return Err(err);
    }
    let n = result.map_err(js_error)?;
    Ok(Uint8Array::from(&sig[..n]))
}

/// An imported stateful secret key, held across signing calls.
///
/// [`sign_stateful`] takes the exported blob and calls
/// `SecretKey::import` every time. `import` re-derives the hypertree
/// root, which at the 128s profiles costs about 47 seconds, the same walk
/// as keygen. A caller that signs more than once pays it more than once.
/// This type pays it exactly once, in [`StatefulKey::open`], and every
/// later signature costs what the in-process Rust API costs.
///
/// # The durability contract is unchanged
///
/// The handle advances the key in memory. It does not persist anything.
/// After [`sign_stateful`](Self::sign_stateful) returns, **whether it
/// returned a signature or threw**, this handle holds the advanced key
/// and the caller must [`export`](Self::export) it and persist the result
/// before relying on any signature. The reason is the one
/// [`sign_stateful`] documents: a leaf can be durably committed to the
/// journal and the signature still fail, and a caller whose stored key
/// did not advance with the journal is a caller whose next call is
/// refused for the rest of the key's life.
///
/// A handle is not a substitute for the journal. The journal is the
/// durable record of spent leaves and the only thing that survives a
/// crash.
///
/// # `free()` must be called
///
/// A caller must call `free()`, call `[Symbol.dispose]()`, or declare
/// the value with JavaScript `using`. The key lives in wasm memory, which
/// JavaScript garbage collection does not reach, so a handle that is
/// dropped without `free()` keeps its secret key material alive for the
/// life of the instance.
///
/// # Only H5 and H6
///
/// H1 through H4 are stateless and have nothing to hold open;
/// [`open`](Self::open) rejects them.
#[wasm_bindgen]
pub struct StatefulKey {
    inner: StatefulKeyHandle,
}

#[wasm_bindgen]
impl StatefulKey {
    /// Import `secret_key` once and hold it.
    ///
    /// This is the call that costs about 47 seconds at the 128s profiles.
    /// Every signature taken through the returned handle costs under 0.01
    /// seconds.
    ///
    /// # Errors
    ///
    /// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if
    /// `secret_key` is not `secretKeyLen(suite)` bytes, or if the blob
    /// does not import.
    pub fn open(suite: &str, secret_key: Vec<u8>) -> Result<Self, JsValue> {
        let suite = stateful_suite(suite).map_err(js_error)?;
        let mut secret_key = secret_key;
        let result = StatefulKeyHandle::open(suite, &secret_key).map(|inner| Self { inner });
        secret_key.zeroize();
        result.map_err(js_error)
    }

    /// The 32-byte identity of the key this handle holds.
    ///
    /// The value [`adopt_key`] takes. Derived from the cached post-quantum
    /// verify key, which is public; no secret byte reaches it.
    #[wasm_bindgen(js_name = keyIdentity)]
    #[must_use]
    pub fn key_identity(&self) -> Uint8Array {
        let identity = self.inner.key_identity();
        Uint8Array::from(&identity.as_bytes()[..])
    }

    /// The current exported blob, exactly `secretKeyLen(suite)` bytes.
    ///
    /// Persist this after every [`sign_stateful`](Self::sign_stateful)
    /// call, including one that threw; see the type documentation.
    ///
    /// # Errors
    ///
    /// A JavaScript `Error` if the key does not export.
    pub fn export(&self) -> Result<Uint8Array, JsValue> {
        let mut sk_out = vec![0u8; pqhybridsign_abi::secret_key_len(self.inner.suite())];
        let result = self.inner.export(&mut sk_out);
        match result {
            Ok(n) => {
                let out = Uint8Array::from(&sk_out[..n]);
                sk_out.zeroize();
                Ok(out)
            }
            Err(e) => {
                sk_out.zeroize();
                Err(js_error(e))
            }
        }
    }

    /// Sign `msg` under `ctx`, spending one leaf recorded through
    /// `journal`.
    ///
    /// The handle-held counterpart of [`sign_stateful`]. The signature is
    /// returned; the advanced key stays in this handle. **Export and
    /// persist it before relying on the signature**, including when this
    /// method throws.
    ///
    /// `journal` is a JavaScript object with the four synchronous methods
    /// the crate documentation describes; it must already be bound to
    /// this key ([`adopt_key`]).
    ///
    /// # Errors
    ///
    /// A JavaScript `Error` if the key's leaf budget is spent
    /// (`LeavesExhausted`), if `journal` is not this key's journal
    /// (`JournalKeyMismatch`), if the key and journal counters disagree
    /// (`CountersDiverged`), or if the journal could not durably commit
    /// (`JournalFailed`). Any exception a journal method itself threw is
    /// re-thrown unchanged.
    #[wasm_bindgen(js_name = signStateful)]
    pub fn sign_stateful(
        &mut self,
        journal: &JsValue,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<Uint8Array, JsValue> {
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(self.inner.suite())];
        let mut journal = JsJournal::new(journal);

        let result = sign_stateful_with_handle(&mut self.inner, &mut journal, msg, ctx, &mut sig);

        if let Some(err) = journal.take_error() {
            return Err(err);
        }

        let n = result.map_err(js_error)?;
        Ok(Uint8Array::from(&sig[..n]))
    }

    /// Sign `msg` under `ctx` without spending a leaf, spending one unit
    /// of the few-time stateless budget instead.
    ///
    /// The handle-held counterpart of [`sign_stateless`]. The key is not
    /// advanced, so there is nothing new to export afterwards. `budget`
    /// is a JavaScript object with synchronous `consumed(key)` and
    /// `record(key, count)` methods, and `record` must be durable before
    /// it returns, on the same terms `journal.commit` is.
    ///
    /// # Errors
    ///
    /// A JavaScript `Error` if the stateless budget is spent
    /// (`StatelessBudgetExhausted`), or if the store could not durably
    /// record (`BudgetStoreFailed`). Any exception a budget method itself
    /// threw is re-thrown unchanged.
    #[wasm_bindgen(js_name = signStateless)]
    pub fn sign_stateless(
        &self,
        budget: &JsValue,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<Uint8Array, JsValue> {
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(self.inner.suite())];
        let mut budget = JsBudget::new(budget);

        let result = sign_stateless_with_handle(&self.inner, &mut budget, msg, ctx, &mut sig);

        if let Some(err) = budget.take_error() {
            return Err(err);
        }

        let n = result.map_err(js_error)?;
        Ok(Uint8Array::from(&sig[..n]))
    }
}

// ---- Master seed derivation: recovery phrases and hard junctions ----

/// Turn an English BIP39 recovery phrase into a 32-byte master seed.
///
/// This is Substrate's derivation, not standard BIP39: see
/// `pqhybridsign_abi::master_seed_from_mnemonic` for exactly which KDF runs
/// and over what. `password` defaults to the empty string when omitted.
///
/// # Errors
///
/// A JavaScript `Error` if `phrase` is not a valid English BIP39 mnemonic:
/// a wrong word count, an unknown word, or a bad checksum. The three are
/// not distinguished, because telling an attacker which part of a guessed
/// phrase was wrong narrows the search.
#[wasm_bindgen(js_name = masterSeedFromMnemonic)]
pub fn master_seed_from_mnemonic(
    phrase: &str,
    password: Option<String>,
) -> Result<Uint8Array, JsValue> {
    let mut out = [0u8; pqhybridsign_abi::MASTER_SEED_LEN];
    let result = pqhybridsign_abi::master_seed_from_mnemonic(phrase, password.as_deref(), &mut out);
    let out_value = result.map(|()| Uint8Array::from(&out[..]));
    out.zeroize();
    out_value.map_err(js_error)
}

/// Derive a hard-junction child master seed.
///
/// # The re-keygen hazard
///
/// See `pqhybridsign_abi::derive_hard_junction`: derivation is
/// deterministic, so deriving one junction twice, on two different hosts,
/// reaches the same child seed and therefore the same stateful tree
/// starting at leaf 1 -- the same failure as importing one key twice.
/// Derive a child once, then persist and restore it through the
/// validating import path. Never re-derive one junction on a second host.
///
/// # Errors
///
/// A JavaScript `Error` if `parentMaster` or `chainCode` is not exactly 32
/// bytes, or if the key derivation function fails.
#[wasm_bindgen(js_name = deriveHardJunction)]
pub fn derive_hard_junction(
    parent_master: &[u8],
    chain_code: &[u8],
) -> Result<Uint8Array, JsValue> {
    let parent: [u8; pqhybridsign_abi::MASTER_SEED_LEN] =
        fixed_bytes(parent_master, "parentMaster")?;
    let code: [u8; pqhybridsign_abi::CHAIN_CODE_LEN] = fixed_bytes(chain_code, "chainCode")?;
    let mut out = [0u8; pqhybridsign_abi::MASTER_SEED_LEN];
    let result = pqhybridsign_abi::derive_hard_junction(&parent, &code, &mut out);
    let out_value = result.map(|()| Uint8Array::from(&out[..]));
    out.zeroize();
    out_value.map_err(js_error)
}

/// Read one 32-byte chain code out of `chainCodes[index]`, for
/// [`derive_hard_junction_path`]. The error names `index`, so a caller can
/// tell which element of the array was wrong.
fn chain_code_at(
    value: &JsValue,
    index: usize,
) -> Result<[u8; pqhybridsign_abi::CHAIN_CODE_LEN], JsValue> {
    let arr = value.dyn_ref::<Uint8Array>().ok_or_else(|| {
        js_error(format!(
            "chainCodes: element at index {index} must be a Uint8Array"
        ))
    })?;
    let len = arr.length() as usize;
    if len != pqhybridsign_abi::CHAIN_CODE_LEN {
        return Err(js_error(format!(
            "chainCodes: element at index {index} must be exactly {} bytes, got {len}",
            pqhybridsign_abi::CHAIN_CODE_LEN
        )));
    }
    let mut bytes = [0u8; pqhybridsign_abi::CHAIN_CODE_LEN];
    arr.copy_to(&mut bytes);
    Ok(bytes)
}

/// Apply a sequence of chain codes in order, each child becoming the next
/// parent (`[a, b]` means `deriveHardJunction(deriveHardJunction(parent,
/// a), b)`).
///
/// **An empty `chainCodes` returns `parentMaster` unchanged.** That is the
/// identity a path of no junctions should have; see
/// `pqhybridsign_abi::derive_hard_junction_path`.
///
/// See [`deriveHardJunction`](derive_hard_junction) for the re-keygen
/// hazard, which applies to every seed this function returns.
///
/// # Errors
///
/// A JavaScript `Error` if `parentMaster` is not exactly 32 bytes, if any
/// element of `chainCodes` is not a 32-byte `Uint8Array` -- naming its
/// index -- or if the key derivation function fails.
#[wasm_bindgen(js_name = deriveHardJunctionPath)]
pub fn derive_hard_junction_path(
    parent_master: &[u8],
    chain_codes: Array,
) -> Result<Uint8Array, JsValue> {
    let parent: [u8; pqhybridsign_abi::MASTER_SEED_LEN] =
        fixed_bytes(parent_master, "parentMaster")?;
    let mut codes = Vec::with_capacity(chain_codes.length() as usize);
    for (index, value) in chain_codes.iter().enumerate() {
        codes.push(chain_code_at(&value, index)?);
    }
    let mut out = [0u8; pqhybridsign_abi::MASTER_SEED_LEN];
    let result = pqhybridsign_abi::derive_hard_junction_path(&parent, &codes, &mut out);
    let out_value = result.map(|()| Uint8Array::from(&out[..]));
    out.zeroize();
    out_value.map_err(js_error)
}

// ---- The hybrid verifiable random function ----
//
// H1 through H4 prove through `vrfProve`/`vrfProveDeterministic`, which
// reject H5 and H6 -- proving under those suites spends one unit of a
// few-time stateless budget on every evaluation, the same hazard
// `sign`/`signDeterministic` refuse for signing, and for the same reason:
// a call that looks free and is not is the worst failure mode this crate
// could offer. `deriveVrfStatelessKey` and `VrfKey.prove` cover H5 and H6
// through a dedicated key and a caller-supplied budget store, on the same
// bridge `sign_stateless` uses. `vrfProofLen`, `vrfVerify` and
// `vrfMakeBytes` span all six suites: verifying and measuring a length
// spend nothing.

/// Length in bytes of a hybrid VRF proof for `suite`. Total over all six
/// suites; see `pqhybridsign_abi::vrf_proof_len` for what this length
/// means for each.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
#[wasm_bindgen(js_name = vrfProofLen)]
pub fn vrf_proof_len(suite: &str) -> Result<u32, JsValue> {
    let suite = any_suite(suite).map_err(js_error)?;
    Ok(pqhybridsign_abi::vrf_proof_len(suite).map_err(js_error)? as u32)
}

/// Evaluate the hybrid VRF for a stateless suite. Returns the proof.
///
/// H1 through H4 only; see the section documentation above for why H5 and
/// H6 have their own entry point.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H4"`, if
/// `suite` is `"H5"` or `"H6"` (naming `deriveVrfStatelessKey` as the entry
/// point to use instead), if `secretKey` is not the suite's secret-key
/// length, or if either component rejects its key.
#[wasm_bindgen(js_name = vrfProve)]
pub fn vrf_prove(suite: &str, secret_key: Vec<u8>, input: &[u8]) -> Result<Uint8Array, JsValue> {
    let suite = vrf_stateless_suite(suite).map_err(js_error)?;
    let mut secret_key = secret_key;
    let mut proof = vec![0u8; pqhybridsign_abi::vrf_proof_len(suite).map_err(js_error)?];

    let result = pqhybridsign_abi::vrf_prove(suite, &secret_key, input, &mut OsRng, &mut proof);
    secret_key.zeroize();

    let n = result.map_err(js_error)?;
    Ok(Uint8Array::from(&proof[..n]))
}

/// Evaluate the hybrid VRF for a stateless suite with a reproducible
/// classical proof. H1 through H4 only, on the same terms as
/// [`vrfProve`](vrf_prove).
///
/// # Errors
///
/// The same as [`vrfProve`](vrf_prove).
#[wasm_bindgen(js_name = vrfProveDeterministic)]
pub fn vrf_prove_deterministic(
    suite: &str,
    secret_key: Vec<u8>,
    input: &[u8],
) -> Result<Uint8Array, JsValue> {
    let suite = vrf_stateless_suite(suite).map_err(js_error)?;
    let mut secret_key = secret_key;
    let mut proof = vec![0u8; pqhybridsign_abi::vrf_proof_len(suite).map_err(js_error)?];

    let result = pqhybridsign_abi::vrf_prove_deterministic(suite, &secret_key, input, &mut proof);
    secret_key.zeroize();

    let n = result.map_err(js_error)?;
    Ok(Uint8Array::from(&proof[..n]))
}

/// Verify a hybrid VRF proof against `publicKey`. Total over all six
/// suites: verifying never spends anything, so there is nothing to keep
/// apart by statefulness.
///
/// Returns `false`, never throws, for a malformed `publicKey` or `proof`.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`.
#[wasm_bindgen(js_name = vrfVerify)]
pub fn vrf_verify(
    suite: &str,
    public_key: &[u8],
    input: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let suite = any_suite(suite).map_err(js_error)?;
    Ok(pqhybridsign_abi::vrf_verify(
        suite, public_key, input, proof,
    ))
}

/// Derive 32 output bytes from a verified hybrid VRF proof.
///
/// **Verify the proof first.** [`vrfVerify`](vrf_verify) is what
/// establishes that the pre-output belongs to this key and this input.
/// Deriving bytes from an unverified proof derives bytes from whatever an
/// attacker supplied.
///
/// `context` separates two uses of one proof: the same proof under two
/// different contexts gives unrelated bytes, so one evaluation can feed
/// two consumers without either learning the other's value early.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of `"H1"` through `"H6"`, if
/// `proof` is shorter than the proof header or `publicKey` shorter than
/// the classical public key, or if `publicKey` or the pre-output does not
/// decode.
#[wasm_bindgen(js_name = vrfMakeBytes)]
pub fn vrf_make_bytes(
    suite: &str,
    public_key: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<Uint8Array, JsValue> {
    let suite = any_suite(suite).map_err(js_error)?;
    let mut out = [0u8; pqhybridsign_abi::VRF_OUTPUT_LEN];
    pqhybridsign_abi::vrf_make_bytes(suite, public_key, input, proof, context, &mut out)
        .map_err(js_error)?;
    Ok(Uint8Array::from(&out[..]))
}

/// A SHRINCS key dedicated to VRF evaluation for a stateful suite (`"H5"`
/// or `"H6"`), held across calls.
///
/// Returned by
/// [`deriveVrfStatelessKey`](derive_vrf_stateless_key). This key is
/// disjoint from the identity key that carries an account's rotation and
/// recovery authority (`pqhs-1l6`): it is derived under a label separate
/// from the identity key's, so the two never collide, and it has no leaf
/// counter to fork -- [`prove`](Self::prove) draws only on the few-time
/// stateless budget the caller's `budget` tracks. It cannot be exported to
/// bytes; it lives only in wasm memory for the life of the handle.
///
/// # `free()` must be called
///
/// A caller must call `free()`, call `[Symbol.dispose]()`, or declare the
/// value with JavaScript `using`. The key lives in wasm memory, which
/// JavaScript garbage collection does not reach, so a handle that is
/// dropped without `free()` keeps its key material alive for the life of
/// the instance.
#[wasm_bindgen]
pub struct VrfKey {
    inner: pqhybridsign_abi::VrfStatelessKey,
}

#[wasm_bindgen]
impl VrfKey {
    /// Evaluate the hybrid VRF, spending one unit of `budget`.
    ///
    /// `budget` is a JavaScript object with synchronous `consumed(key)`
    /// and `record(key, count)` methods, on the same terms
    /// [`signStateless`](sign_stateless)'s budget is (see the crate
    /// documentation); `record` must be durable before it returns.
    ///
    /// Returns the proof.
    ///
    /// # Errors
    ///
    /// A JavaScript `Error` if the stateless budget is spent
    /// (`StatelessBudgetExhausted`), or if the store could not durably
    /// record (`BudgetStoreFailed`). Any exception a budget method itself
    /// threw is re-thrown unchanged.
    pub fn prove(&self, budget: &JsValue, input: &[u8]) -> Result<Uint8Array, JsValue> {
        let mut proof =
            vec![0u8; pqhybridsign_abi::vrf_proof_len(self.inner.suite()).map_err(js_error)?];
        let mut budget = JsBudget::new(budget);

        let result = pqhybridsign_abi::vrf_prove_stateless(
            &self.inner,
            &mut budget,
            input,
            &mut OsRng,
            &mut proof,
        );

        if let Some(err) = budget.take_error() {
            return Err(err);
        }
        let n = result.map_err(js_error)?;
        Ok(Uint8Array::from(&proof[..n]))
    }
}

/// Derive a dedicated VRF key for a stateful `suite` (`"H5"` or `"H6"`)
/// from a 32-byte master seed, disjoint from the identity key
/// (`pqhs-1l6`).
///
/// Returns a plain JavaScript object with two properties: `key`, the
/// [`VrfKey`] handle -- call `free()` on it when finished -- and
/// `publicKey`, the verify-form public key [`vrfVerify`](vrf_verify)
/// checks proofs against.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`, if `master` is
/// not exactly 32 bytes, or if derivation fails.
#[wasm_bindgen(js_name = deriveVrfStatelessKey)]
pub fn derive_vrf_stateless_key(suite: &str, master: &[u8]) -> Result<JsValue, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    let mut master: [u8; pqhybridsign_abi::MASTER_SEED_LEN] = fixed_bytes(master, "master")?;
    let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(suite)];

    let result = pqhybridsign_abi::VrfStatelessKey::derive(suite, &master, &mut pk);
    master.zeroize();

    let inner = result.map_err(js_error)?;
    let key = VrfKey { inner };

    let out = Object::new();
    Reflect::set(&out, &JsValue::from_str("key"), &JsValue::from(key))?;
    Reflect::set(
        &out,
        &JsValue::from_str("publicKey"),
        &Uint8Array::from(pk.as_slice()),
    )?;
    Ok(out.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateless_suite_accepts_h1_through_h4() {
        assert_eq!(stateless_suite("H1").unwrap(), pqhybridsign_abi::Suite::H1);
        assert_eq!(stateless_suite("H2").unwrap(), pqhybridsign_abi::Suite::H2);
        assert_eq!(stateless_suite("H3").unwrap(), pqhybridsign_abi::Suite::H3);
        assert_eq!(stateless_suite("H4").unwrap(), pqhybridsign_abi::Suite::H4);
    }

    #[test]
    fn stateless_suite_rejects_h5_h6_and_unknown_names() {
        assert!(stateless_suite("H5").is_err());
        assert!(stateless_suite("H6").is_err());
        assert!(stateless_suite("H7").is_err());
        assert!(stateless_suite("").is_err());
    }

    #[test]
    fn stateful_suite_accepts_h5_and_h6() {
        assert_eq!(stateful_suite("H5").unwrap(), pqhybridsign_abi::Suite::H5);
        assert_eq!(stateful_suite("H6").unwrap(), pqhybridsign_abi::Suite::H6);
    }

    #[test]
    fn stateful_suite_rejects_h1_through_h4_and_unknown_names() {
        assert!(stateful_suite("H1").is_err());
        assert!(stateful_suite("H2").is_err());
        assert!(stateful_suite("H3").is_err());
        assert!(stateful_suite("H4").is_err());
        assert!(stateful_suite("H7").is_err());
        assert!(stateful_suite("").is_err());
    }

    #[test]
    fn any_suite_accepts_all_six() {
        assert_eq!(any_suite("H1").unwrap(), pqhybridsign_abi::Suite::H1);
        assert_eq!(any_suite("H2").unwrap(), pqhybridsign_abi::Suite::H2);
        assert_eq!(any_suite("H3").unwrap(), pqhybridsign_abi::Suite::H3);
        assert_eq!(any_suite("H4").unwrap(), pqhybridsign_abi::Suite::H4);
        assert_eq!(any_suite("H5").unwrap(), pqhybridsign_abi::Suite::H5);
        assert_eq!(any_suite("H6").unwrap(), pqhybridsign_abi::Suite::H6);
    }

    #[test]
    fn any_suite_rejects_unknown_names() {
        assert!(any_suite("H7").is_err());
        assert!(any_suite("").is_err());
    }
}

/// Tests that call into a real JavaScript object through `JsJournal`.
///
/// `js_sys`'s wasm-bindgen imports panic with "cannot call wasm-bindgen
/// imported functions on non-wasm targets" outside `wasm32`, so this module
/// only compiles for that target and only runs under `wasm-bindgen-test`,
/// against Node by default:
///
/// ```text
/// CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
///   cargo test -p pqhybridsign-wasm --target wasm32-unknown-unknown --lib
/// ```
///
/// Never runs under plain `cargo test`, and the installed
/// `wasm-bindgen-test-runner` must match this crate's `wasm-bindgen` version
/// exactly (`cargo install wasm-bindgen-cli --version <version> --locked`).
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    /// A `bound_key()` read cached before a successful `bind_key()` must not
    /// be handed back after it: that cached `None` reads as never-bound,
    /// which is the exact condition `JournalKeyMismatch` exists to catch.
    /// No current entry point re-reads `bound_key()` after `bind_key()` on
    /// one `JsJournal` (`adopt_key` reads it once, before its own single
    /// `bind_key` call, and `sign_stateful` never calls `bind_key` at all),
    /// so this constructs the sequence directly against a real JavaScript
    /// object instead of going through an entry point.
    #[wasm_bindgen_test]
    fn bind_key_invalidates_the_bound_key_cache() {
        // `js_sys::eval` here runs a fixed, hardcoded source string compiled
        // into this test binary, not any externally supplied or runtime-built
        // text; it stands in for a JavaScript-authored journal object, which
        // is exactly what `JsJournal` wraps in production. No untrusted input
        // reaches it.
        let obj = js_sys::eval(
            "(function () {
                let bound = null;
                return {
                    boundKey: function () { return bound; },
                    bindKey: function (k) { bound = new Uint8Array(k); },
                };
            })()",
        )
        .expect("eval the fake journal object");

        let mut journal = JsJournal::new(&obj);

        // Populate the cache with the pre-bind answer.
        assert_eq!(journal.bound_key(), None, "a fresh journal owns no key");

        let key = KeyIdentity::from_bytes([7u8; KEY_IDENTITY_LEN]);
        journal.bind_key(key).expect("bind_key");

        assert_eq!(
            journal.bound_key(),
            Some(key),
            "bound_key() after bind_key() must reflect the new binding, not \
             the None cached from before it"
        );
    }
}
