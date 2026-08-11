// SPDX-License-Identifier: AGPL-3.0-or-later
//! Generator for the checked-in stateful golden vectors
//! (`tests/vectors/h5.json`, `tests/vectors/h6.json`). Ignored by default:
//! run explicitly and capture the output only when a format change is
//! intended.
//!
//! One keypair per suite, `maxSignatures = 4`, shared between the stateful
//! and the stateless vectors: `sign_stateless` takes `&SecretKey`, so it
//! costs nothing extra to reuse the key that the stateful signatures already
//! advanced through all four leaves.
//!
//! Leaves 1, 2 and 4 are recorded; leaf 3 is spent (state must advance
//! through it to reach leaf 4) but its signature is not checked, so it is
//! not persisted.
use pqhybridsign_core::stateful::{LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign_core::{PqStatefulScheme, StatefulSuite};
use pqhybridsign_shrincs::{keygen, ShrincsScheme, H5, H6};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default, Clone)]
struct MemoryJournal {
    committed: Rc<RefCell<Vec<u32>>>,
}

impl LeafJournal for MemoryJournal {
    type Error = core::convert::Infallible;

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.committed.borrow_mut().push(leaf);
        Ok(())
    }

    fn next_leaf(&self) -> u32 {
        self.committed
            .borrow()
            .iter()
            .copied()
            .max()
            .map_or(0, |m| m + 1)
    }
}

const MAX_SIGNATURES: u32 = 4;
const STATEFUL_CTX: &[u8] = b"golden-stateful";
const STATELESS_CTX: &[u8] = b"golden-stateless";
const FILLER_MSG: &[u8] = b"golden leaf 3 (unchecked filler)";
const STATELESS_MSG: &[u8] = b"golden stateless message";

fn leaf_msg(leaf: u32) -> Vec<u8> {
    format!("golden leaf {leaf}").into_bytes()
}

fn emit<S>(name: &str, master: [u8; 32])
where
    S: StatefulSuite<Pq = ShrincsScheme>
        + StatefulHybridSignatureScheme<
            Signature = Vec<u8>,
            SecretKey = pqhybridsign_shrincs::SecretKey<S>,
            PublicKey = pqhybridsign_shrincs::PublicKey<S>,
        >,
{
    let (mut sk, pk) = keygen::<S>(&master, MAX_SIGNATURES).expect("keygen");
    let mut journal = MemoryJournal::default();

    let msg1 = leaf_msg(1);
    let sig1 = S::sign_stateful(&mut sk, &mut journal, &msg1, STATEFUL_CTX).expect("leaf 1");
    let msg2 = leaf_msg(2);
    let sig2 = S::sign_stateful(&mut sk, &mut journal, &msg2, STATEFUL_CTX).expect("leaf 2");
    let _ =
        S::sign_stateful(&mut sk, &mut journal, FILLER_MSG, STATEFUL_CTX).expect("leaf 3 filler");
    let msg4 = leaf_msg(4);
    let sig4 = S::sign_stateful(&mut sk, &mut journal, &msg4, STATEFUL_CTX).expect("leaf 4");

    let stateless_a =
        S::sign_stateless(&sk, STATELESS_MSG, STATELESS_CTX).expect("stateless resign a");
    let stateless_b =
        S::sign_stateless(&sk, STATELESS_MSG, STATELESS_CTX).expect("stateless resign b");
    assert_eq!(
        stateless_a, stateless_b,
        "the generator itself must observe the byte-identical resign it is pinning"
    );
    assert!(S::verify(&pk, STATELESS_MSG, STATELESS_CTX, &stateless_a));

    let classical_pk_len = pk.classical().len();
    let commitment = &pk.pq_verify_key()[68..100];
    let mut stored_public_key = Vec::with_capacity(classical_pk_len + 32);
    stored_public_key.extend_from_slice(pk.classical());
    stored_public_key.extend_from_slice(commitment);

    println!("{{");
    println!("  \"suite\": \"{name}\",");
    println!("  \"label_hex\": \"{}\",", hex::encode(S::LABEL));
    println!("  \"hkdf_info_includes_label_null_byte\": true,");
    println!(
        "  \"profile_name\": \"{}\",",
        <S::Pq as PqStatefulScheme>::NAME
    );
    println!("  \"max_signatures\": {MAX_SIGNATURES},");
    println!("  \"master_seed_hex\": \"{}\",", hex::encode(master));
    println!(
        "  \"stored_public_key_hex\": \"{}\",",
        hex::encode(&stored_public_key)
    );
    println!("  \"ctx_hex\": \"{}\",", hex::encode(STATEFUL_CTX));
    println!("  \"filler_msg_hex\": \"{}\",", hex::encode(FILLER_MSG));
    println!("  \"stateful_vectors\": [");
    println!("    {{");
    println!("      \"leaf_index\": 1,");
    println!("      \"msg_hex\": \"{}\",", hex::encode(&msg1));
    println!("      \"signature_hex\": \"{}\"", hex::encode(&sig1));
    println!("    }},");
    println!("    {{");
    println!("      \"leaf_index\": 2,");
    println!("      \"msg_hex\": \"{}\",", hex::encode(&msg2));
    println!("      \"signature_hex\": \"{}\"", hex::encode(&sig2));
    println!("    }},");
    println!("    {{");
    println!("      \"leaf_index\": 4,");
    println!("      \"msg_hex\": \"{}\",", hex::encode(&msg4));
    println!("      \"signature_hex\": \"{}\"", hex::encode(&sig4));
    println!("    }}");
    println!("  ],");
    println!(
        "  \"stateless_ctx_hex\": \"{}\",",
        hex::encode(STATELESS_CTX)
    );
    println!(
        "  \"stateless_msg_hex\": \"{}\",",
        hex::encode(STATELESS_MSG)
    );
    println!(
        "  \"stateless_signature_hex\": \"{}\",",
        hex::encode(&stateless_a)
    );
    println!(
        "  \"stateless_resign_signature_hex\": \"{}\"",
        hex::encode(&stateless_b)
    );
    println!("}}");
}

#[test]
#[ignore = "generator, run explicitly with --ignored --nocapture"]
fn generate_h5() {
    emit::<H5>("H5", [0x50u8; 32]);
}

#[test]
#[ignore = "generator, run explicitly with --ignored --nocapture"]
fn generate_h6() {
    emit::<H6>("H6", [0x60u8; 32]);
}
