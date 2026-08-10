// Generator for the checked-in golden vectors. These tests are ignored by
// default: run them explicitly and capture the output into
// tests/vectors/*.json only when a format change is intended.
use pqhybridsign::{H1, H3};
use pqhybridsign_core::composite::{keypair_from_seed, sign_deterministic};
use pqhybridsign_core::Suite;

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
