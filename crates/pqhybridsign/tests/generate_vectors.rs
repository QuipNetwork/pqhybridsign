// Integration test binary: `cfg(test)` is always true here. `unwrap`/
// `expect`/`panic` are the normal way a test fails; the `hybrid_suite!`
// family of macros generates undocumented, unconditionally `pub` fixture
// structs, which is fine for a binary with no public API of its own.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        missing_docs,
        unreachable_pub
    )
)]
// Generator for the checked-in golden vectors. These tests are ignored by
// default: run them explicitly and capture the output into
// tests/vectors/*.json only when a format change is intended.
#[path = "support/mod.rs"]
mod support;

use pqhybridsign::classical::Ed25519;
use pqhybridsign::composite::{keypair_from_seed, sign_deterministic};
use pqhybridsign::{
    component::ClassicalScheme,
    composite_delta,
    suite::{DeltaSuite, Suite},
};
use pqhybridsign::{H1, H2, H3, H4};
use support::{strict, weak_classical_forgery};

fn emit<S: Suite>(name: &str) {
    let master = [0x2au8; 32];
    let (ctx, msg, nonce) = (
        b"quip-testnet".as_slice(),
        b"golden vector".as_slice(),
        b"nonce-0".as_slice(),
    );
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    keypair_from_seed::<S>(&master, &mut sk, &mut pk).expect("keygen");
    let mut sig = vec![0u8; S::SIGNATURE_LEN];
    sign_deterministic::<S>(&sk, msg, ctx, nonce, &mut sig).expect("sign");
    println!("{{");
    println!("  \"suite\": \"{name}\",");
    println!("  \"label_hex\": \"{}\",", hex::encode(S::LABEL));
    println!("  \"hkdf_info_includes_label_null_byte\": true,");
    println!("  \"master_seed_hex\": \"{}\",", hex::encode(master));
    println!("  \"ctx_hex\": \"{}\",", hex::encode(ctx));
    println!("  \"msg_hex\": \"{}\",", hex::encode(msg));
    println!("  \"nonce_hex\": \"{}\",", hex::encode(nonce));
    println!("  \"public_key_hex\": \"{}\",", hex::encode(&pk));
    println!("  \"signature_hex\": \"{}\"", hex::encode(&sig));
    println!("}}");
}

/// Same shape as [`emit`], for a [`DeltaSuite`] (H2, H4), whose signature
/// length is not known ahead of signing.
fn emit_delta<S: DeltaSuite>(name: &str) {
    let master = [0x2au8; 32];
    let (ctx, msg, nonce) = (
        b"quip-testnet".as_slice(),
        b"golden vector".as_slice(),
        b"nonce-0".as_slice(),
    );
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<S>(&master, &mut sk, &mut pk).expect("keygen");
    let mut sig = vec![0u8; S::MAX_SIGNATURE_LEN];
    let written =
        composite_delta::sign_deterministic::<S>(&sk, msg, ctx, nonce, &mut sig).expect("sign");
    sig.truncate(written);
    println!("{{");
    println!("  \"suite\": \"{name}\",");
    println!("  \"label_hex\": \"{}\",", hex::encode(S::LABEL));
    println!("  \"hkdf_info_includes_label_null_byte\": true,");
    println!("  \"master_seed_hex\": \"{}\",", hex::encode(master));
    println!("  \"ctx_hex\": \"{}\",", hex::encode(ctx));
    println!("  \"msg_hex\": \"{}\",", hex::encode(msg));
    println!("  \"nonce_hex\": \"{}\",", hex::encode(nonce));
    println!("  \"public_key_hex\": \"{}\",", hex::encode(&pk));
    println!("  \"signature_hex\": \"{}\"", hex::encode(&sig));
    println!("}}");
}

#[test]
#[ignore = "generator, run explicitly with --ignored"]
fn generate_h1() {
    emit::<H1>("H1");
}

#[test]
#[ignore = "generator, run explicitly with --ignored"]
fn generate_h3() {
    emit::<H3>("H3");
}

#[test]
#[ignore = "generator, run explicitly with --ignored"]
fn generate_h2() {
    emit_delta::<H2>("H2");
}

#[test]
#[ignore = "generator, run explicitly with --ignored"]
fn generate_h4() {
    emit_delta::<H4>("H4");
}

const ED25519_LABEL: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

/// Emit one ZIP-215/strict-RFC-8032 divergence vector for `msg`, and verify
/// as it is generated that: `ed25519-zebra` accepts it (matching this
/// crate's own `Ed25519::verify`), the cofactorless equation fails on this
/// concrete message (not merely on average), and it is rejected for a
/// small-order reason too. A vector that fails any of these checks would
/// not demonstrate the divergence `tests/ed25519_strict.rs` pins, so this
/// panics rather than emit a vector that does not hold up.
fn emit_zip215_negative(description: &str, msg: &[u8]) {
    let (pk, sig) = weak_classical_forgery();

    let zebra_accepts = bool::from(Ed25519::verify(&pk, msg, ED25519_LABEL, &sig));
    assert!(
        zebra_accepts,
        "{description}: expected ed25519-zebra (ZIP-215) to accept this vector"
    );

    let outcome = strict::check(&pk, msg, &sig);
    assert!(
        outcome.decodes && outcome.canonical,
        "{description}: the forged key and R must themselves decode and be canonically encoded, \
         so the divergence below is not an artifact of a malformed vector: {outcome:?}"
    );
    assert!(
        outcome.cofactored_holds,
        "{description}: expected the cofactored equation (what ed25519-zebra checks) to hold: {outcome:?}"
    );
    assert!(
        !outcome.cofactorless_holds,
        "{description}: expected the cofactorless equation to fail for this concrete message; \
         pick a different message (this one landed in the ~1/8 case where it accidentally holds)"
    );
    assert!(
        outcome.small_order,
        "{description}: expected the forged key/R to be small-order"
    );
    assert!(
        !outcome.strict_accepts(),
        "{description}: expected the full strict verdict to reject this vector: {outcome:?}"
    );

    println!("  {{");
    println!("    \"description\": {description:?},");
    println!("    \"public_key_hex\": \"{}\",", hex::encode(pk));
    println!("    \"msg_hex\": \"{}\",", hex::encode(msg));
    println!("    \"signature_hex\": \"{}\"", hex::encode(sig));
    println!("  }}");
}

/// Generator for `tests/vectors/ed25519_zip215_negative.json`. Ignored by
/// default: run explicitly and capture the output when the vectors need
/// regenerating (for example, after a `curve25519-dalek`/`ed25519-zebra`
/// upgrade makes `zip215_negative_vectors_diverge_from_strict_rfc8032`
/// report the pinned vectors as stale).
///
/// Each vector uses the same order-8 forged public key (see
/// `weak_classical_forgery`) with a different message, since the forgery is
/// valid under ed25519-zebra for every message by construction; the
/// messages only need to differ enough that the cofactorless equation does
/// not accidentally hold (checked above, at generation time).
#[test]
#[ignore = "generator, run explicitly with --ignored"]
fn generate_ed25519_zip215_negative() {
    println!("[");
    emit_zip215_negative(
        "order-8 ed25519 public key, R=identity, s=0: accepted by ed25519-zebra for any \
         message; fails the strict cofactorless equation and the small-order screen",
        b"ZIP-215 negative vector 1",
    );
    println!(",");
    emit_zip215_negative(
        "same order-8 forgery, a different message, to show the divergence is not tied to \
         one specific message",
        b"ZIP-215 negative vector 2",
    );
    println!(",");
    emit_zip215_negative(
        "same order-8 forgery, a third message",
        b"ZIP-215 negative vector 3",
    );
    println!("]");
}
