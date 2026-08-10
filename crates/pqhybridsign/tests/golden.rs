// Golden vectors: these pin the wire format. A change to the suite label,
// the `M'` message binding, the HKDF derivation or the signature layout
// breaks these tests instead of silently producing a new format.
use pqhybridsign::{H1, H3};
use pqhybridsign_core::composite::{keypair_from_seed, sign_deterministic, verify};
use pqhybridsign_core::Suite;

#[derive(serde::Deserialize)]
struct Vector {
    suite: String,
    label_hex: String,
    hkdf_info_includes_label_null_byte: bool,
    master_seed_hex: String,
    ctx_hex: String,
    msg_hex: String,
    nonce_hex: String,
    public_key_hex: String,
    signature_hex: String,
}

fn check<S: Suite>(v: &Vector) {
    let master: [u8; 32] = hex::decode(&v.master_seed_hex)
        .expect("seed")
        .try_into()
        .expect("32 bytes");
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    keypair_from_seed::<S>(&master, &mut sk, &mut pk).expect("keygen");
    assert_eq!(
        hex::encode(&pk),
        v.public_key_hex,
        "{} public key drifted",
        v.suite
    );

    assert_eq!(
        hex::encode(S::LABEL),
        v.label_hex,
        "{} label drifted",
        v.suite
    );
    // The registry label is null terminated, and the terminator is part of
    // the bytes that go into `M'` and into the HKDF info string.
    let label = hex::decode(&v.label_hex).expect("label");
    assert_eq!(label.len(), 26, "{} label must be 26 bytes", v.suite);
    assert_eq!(
        label.last(),
        Some(&0u8),
        "{} label must end in a null byte",
        v.suite
    );
    // Specification section 9 is ambiguous about whether the null byte
    // belongs inside the HKDF info string. This crate pins the reading that
    // it does, which differs from the deployed quip-crypto-primitives.
    assert!(
        v.hkdf_info_includes_label_null_byte,
        "this crate pins the null byte inside info"
    );

    let ctx = hex::decode(&v.ctx_hex).expect("ctx");
    let msg = hex::decode(&v.msg_hex).expect("msg");
    let nonce = hex::decode(&v.nonce_hex).expect("nonce");
    let mut sig = vec![0u8; S::SIGNATURE_LEN];
    sign_deterministic::<S>(&sk, &msg, &ctx, &nonce, &mut sig).expect("sign");
    assert_eq!(
        hex::encode(&sig),
        v.signature_hex,
        "{} signature drifted",
        v.suite
    );
    assert!(verify::<S>(&pk, &msg, &ctx, &sig));
}

#[test]
fn h1_matches_the_golden_vector() {
    let v: Vector = serde_json::from_str(include_str!("vectors/h1.json")).expect("parse");
    assert_eq!(v.suite, "H1");
    check::<H1>(&v);
}

#[test]
fn h3_matches_the_golden_vector() {
    let v: Vector = serde_json::from_str(include_str!("vectors/h3.json")).expect("parse");
    assert_eq!(v.suite, "H3");
    check::<H3>(&v);
}
