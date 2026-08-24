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
//! [`adopt_key`], [`key_identity`] and [`key_identity_from_secret_key`] --
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
//! That reasoning is about a *held, mutable key object*. This binding keeps
//! none, and neither do the C and Python bindings whose functional shape it
//! mirrors. It is safe for the same reasons they are:
//!
//! * A secret key crosses the boundary only as bytes -- the exported blob
//!   [`keygen_stateful_from_seed`] returns, [`sign_stateful`] reads, and
//!   [`sign_stateful`] hands forward again as `nextSecretKey`. There is no
//!   counter object for `structuredClone` to fork, because there is no
//!   object: the leaf counter lives inside the blob and inside the caller's
//!   journal, never in a handle this binding hands out.
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
//! [`sign_stateful`] calls `journal.commit(leaf)` and must see it return
//! before it builds the signature -- the persist-before-release ordering
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
//! instance's internal state is sound afterward. This crate holds no state
//! of its own across calls -- every export is a plain function over its
//! arguments, with no `static` or thread-local data -- so a trap here
//! cannot leave one of this crate's own locks or half-built values behind
//! for a later call to observe; that says nothing about the wasm allocator
//! or the `wasm-bindgen` runtime the instance also carries, which this
//! crate does not own and cannot vouch for. A host that must survive a
//! panic here should still instantiate the module in a context it can
//! discard and recreate, such as a dedicated worker, rather than rely on
//! the instance remaining usable.
//!
//! The npm package wraps this. Its `createApi` catches a
//! `WebAssembly.RuntimeError`, discards the instance, and rethrows a
//! `PqHybridSignPanic`, so a JavaScript caller reaching this crate through
//! `@quip.network/pqhybridsign` can separate a trap from an ordinary
//! rejection and does not keep calling a crashed instance. A caller that
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

use js_sys::{Function, Reflect, Uint8Array};
use pqhybridsign_abi::{
    BudgetKey, KeyIdentity, LeafJournal, StatelessBudgetStore, KEY_IDENTITY_LEN,
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
/// to the two stateful suites.
///
/// Every stateful-only entry point routes through this:
/// [`keygenStatefulFromSeed`](keygen_stateful_from_seed),
/// [`signStateful`](sign_stateful), [`signStateless`](sign_stateless),
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
/// The only parser of the three that is total over every suite name this
/// crate recognises. [`stored_public_key_len`] is the one export that needs
/// it: it is a pure length accessor over public data, defined for every
/// suite (`pqhybridsign_abi::stored_public_key_len` is total), so it must
/// not throw for the four suites this binding's other functions actually
/// sign and verify with. Compare [`stateless_suite`], which excludes H5/H6
/// for a reason specific to *signing*, and [`stateful_suite`], which exists
/// only because the `WithStoredPublicKey` verify functions are specific to
/// H5/H6.
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
