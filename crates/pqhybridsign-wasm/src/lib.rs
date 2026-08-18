// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! WebAssembly and npm binding over `pqhybridsign-abi`.
//!
//! # Only the stateless suites are exposed
//!
//! `pqhybridsign-abi` ships six suites. H1 through H4 are stateless:
//! signing costs nothing but CPU time. H5 and H6 are stateful -- their
//! post-quantum half spends a one-time leaf per signature, and a secret
//! key that is copied without advancing both copies together reuses a
//! leaf, which is a total loss of that key's post-quantum security. The
//! generic Rust API enforces this by making the stateful secret key type
//! non-`Clone`.
//!
//! A JavaScript value has no such guarantee. Any object this binding
//! handed back to represent a stateful key -- however it tried to hide
//! the leaf counter -- could be captured by `structuredClone`, serialized
//! with `JSON.stringify`, sent through a `MessageChannel`, or simply
//! assigned to a second variable and used from both call sites. Any of
//! those forks the leaf counter exactly as a Rust `Clone` would, and
//! nothing in this binding could detect or prevent it after the fact.
//!
//! Rather than ship a stateful signing call whose safety depends on every
//! caller manually promising not to do any of that, this binding exposes
//! **no stateful signing entry point**. An integrator who needs the
//! stateful suites' signing path should drive them from the C ABI or
//! Python binding, where the secret key type's language-native copy
//! semantics can be made to reject cloning outright, or from Rust
//! directly.
//!
//! [`verify_with_stored_public_key`] and [`stored_public_key_len`] are the
//! two exceptions. Neither receives, holds or returns a stateful secret
//! key, so the structured-clone hazard above does not apply to either.
//! `verify_with_stored_public_key` checks an H5 or H6 signature against
//! public data alone. `stored_public_key_len` is a plain length accessor
//! over public data, defined for all six suites, the same as its C and
//! Python counterparts. Every other export throws a JavaScript `Error` for
//! `"H5"` or `"H6"` -- not only the ones that sign or hold key material,
//! but the length accessors and `verify` as well.
//!
//! # Errors
//!
//! Every fallible export throws a JavaScript `Error` carrying the
//! [`pqhybridsign_abi::AbiError`] message. Nothing here returns an
//! integer error code or a Rust `Result` to JavaScript.
//!
//! # No panics
//!
//! `#![forbid(unsafe_code)]` and no `unwrap`/`expect` outside
//! `#[cfg(test)]`: a panic unwinding across the WebAssembly boundary is
//! undefined behaviour, and every export here is written to be called
//! from JavaScript.
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

use js_sys::Uint8Array;
use rand_core::OsRng;
use wasm_bindgen::prelude::*;
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
            "{name} is a stateful suite and is not exposed by pqhybridsign-wasm: a \
             JavaScript object can be structured-cloned, which would fork the \
             one-time leaf counter and destroy the key's post-quantum security. \
             Use the C ABI or Python binding for H5/H6, or drive pqhybridsign \
             directly from Rust."
        )),
        other => Err(format!(
            "unknown suite \"{other}\"; expected one of H1, H2, H3, H4"
        )),
    }
}

/// Parse a suite name into the ABI's [`pqhybridsign_abi::Suite`],
/// restricted to the two stateful suites [`verify_with_stored_public_key`]
/// and [`stored_public_key_len`] serve.
///
/// Deliberately separate from [`stateless_suite`]: that function's H5/H6
/// refusal is about the structured-clone hazard a stateful *secret key*
/// carries, which these two functions never touch (see the crate
/// documentation).
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
/// only because [`verify_with_stored_public_key`] is specific to H5/H6.
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

/// Public key length, in bytes, for one of the four stateless suites.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H1"`, `"H2"`, `"H3"` or
/// `"H4"`.
#[wasm_bindgen(js_name = publicKeyLen)]
pub fn public_key_len(suite: &str) -> Result<u32, JsValue> {
    Ok(pqhybridsign_abi::public_key_len(stateless_suite(suite).map_err(js_error)?) as u32)
}

/// Secret key length, in bytes, for one of the four stateless suites.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H1"`, `"H2"`, `"H3"` or
/// `"H4"`.
#[wasm_bindgen(js_name = secretKeyLen)]
pub fn secret_key_len(suite: &str) -> Result<u32, JsValue> {
    Ok(pqhybridsign_abi::secret_key_len(stateless_suite(suite).map_err(js_error)?) as u32)
}

/// Maximum signature length, in bytes, for one of the four stateless
/// suites. H2 and H4 are variable-length; see
/// [`pqhybridsign_abi::signature_len`] for why. Size the buffer you
/// expect a signature to fit in with this value, not the length of any
/// one signature you have already seen.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H1"`, `"H2"`, `"H3"` or
/// `"H4"`.
#[wasm_bindgen(js_name = signatureLen)]
pub fn signature_len(suite: &str) -> Result<u32, JsValue> {
    Ok(pqhybridsign_abi::signature_len(stateless_suite(suite).map_err(js_error)?) as u32)
}

/// A stateless keypair: a secret key and its matching public key.
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
/// Returns `false`, never throws, for a malformed `public_key` or `sig`;
/// see [`pqhybridsign_abi::verify`] for why a verification failure is
/// never distinguished by cause.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not one of the four stateless
/// suites.
#[wasm_bindgen]
pub fn verify(
    suite: &str,
    public_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let suite = stateless_suite(suite).map_err(js_error)?;
    Ok(pqhybridsign_abi::verify(suite, public_key, msg, ctx, sig))
}

/// Stored public key length, in bytes, for `suite`: the form a verifier
/// keeps, which is what [`verify_with_stored_public_key`] takes as
/// `stored_public_key`.
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
/// `"H6"`), against a signer-supplied verify key that must be the one
/// `stored_public_key` commits to.
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
/// [`verify`] is the other shape: it takes one whole verify-form public
/// key and checks no commitment, because it has nothing to check one
/// against. Use it only where the verify key itself came from a trusted
/// place.
///
/// Returns `false`, never throws, for a commitment that does not match, a
/// malformed key or a malformed signature -- the same design [`verify`]
/// uses, so a caller cannot learn which check rejected.
///
/// # Errors
///
/// A JavaScript `Error` if `suite` is not `"H5"` or `"H6"`.
#[wasm_bindgen(js_name = verifyWithStoredPublicKey)]
pub fn verify_with_stored_public_key(
    suite: &str,
    stored_public_key: &[u8],
    pq_verify_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let suite = stateful_suite(suite).map_err(js_error)?;
    pqhybridsign_abi::verify_with_stored_public_key(
        suite,
        stored_public_key,
        pq_verify_key,
        msg,
        ctx,
        sig,
    )
    .map_err(js_error)
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
