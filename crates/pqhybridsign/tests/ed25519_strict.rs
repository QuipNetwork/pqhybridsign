// SPDX-License-Identifier: AGPL-3.0-or-later
//! ed25519 strict RFC 8032 checks. Need std (curve25519-dalek, getrandom, alloc).
#![cfg(feature = "std")]
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
//! Strict RFC 8032 ed25519 verification tests, checked independently of
//! `ed25519-zebra`.
//!
//! This crate's ed25519 component signs per RFC 8032 and verifies per
//! [ZIP-215] (`ed25519-zebra`). See the rustdoc on
//! `pqhybridsign::classical::Ed25519` for what that means and why. This file
//! carries the evidence for both halves of that claim, and it draws a hard
//! line between two kinds of test:
//!
//! * **Hard failures** (`mod own_outputs`, below): this crate's own signing
//!   procedure produces canonical, non-small-order points and satisfies the
//!   strict (cofactorless) verification equation, on top of satisfying
//!   `ed25519-zebra`. That property is fully under this crate's control --
//!   `derive` and `sign_deterministic` either keep producing strict-valid
//!   output or they do not -- so a regression here is a real bug, and these
//!   tests use ordinary `assert!` and are expected to fail the build if they
//!   ever fail.
//! * **Advisory warnings** (the rest of this file): whether a *given
//!   adversarial* triple is accepted by `ed25519-zebra` and rejected by a
//!   strict verifier is a property of `ed25519-zebra` and `curve25519-dalek`
//!   internals that this crate does not own, and a dependency version bump
//!   could shift it. These tests assert only that the pinned vectors parse;
//!   the divergence verdict itself is reported, never asserted on. A
//!   dependency upgrade that narrows or widens the ZIP-215/strict gap cannot
//!   break the build here -- it can only change what gets printed.
//!
//!   Rust's test harness captures stdout *and* stderr for a passing test by
//!   default (verified empirically against this toolchain), so a plain
//!   `eprintln!` is invisible in a plain `cargo test` run. `support::warn`
//!   works around that by writing straight to file descriptor 2 through
//!   `/dev/stderr`, bypassing the harness's redirect, so these warnings
//!   reach the terminal on a plain `cargo test` with no extra flag on Linux
//!   and macOS (falling back to a captured `eprintln!`, needing
//!   `--nocapture`, on platforms without `/dev/stderr`). See
//!   `tests/support/mod.rs` for the mechanism.
//!
//! [ZIP-215]: https://zips.z.cash/zip-0215

#[path = "support/mod.rs"]
mod support;

use curve25519_dalek::edwards::CompressedEdwardsY;
use pqhybridsign::classical::Ed25519;
use pqhybridsign::EdMl44;
use pqhybridsign::{component::ClassicalScheme, composite, suite::Suite};
use support::{strict, warn, weak_classical_forgery};

const LABEL: &[u8] = b"hybrid-ed25519-mldsa44-v1\0";

fn keypair(seed: u8) -> ([u8; 64], [u8; 32]) {
    let (mut sk, mut pk) = ([0u8; 64], [0u8; 32]);
    Ed25519::derive(&[seed; 32], &mut sk, &mut pk).expect("derive");
    (sk, pk)
}

/// Hard-failing tests: this crate's own ed25519 output must stay valid under
/// both ZIP-215 and strict RFC 8032, for every seed and message tried.
mod own_outputs {
    use super::*;

    #[test]
    fn our_signatures_are_strict_rfc8032_valid() {
        for seed in 0u8..8 {
            let (sk, pk) = keypair(seed);
            let mut sig = [0u8; 64];
            Ed25519::sign_deterministic(&sk, b"strict rfc8032 check", b"nonce", LABEL, &mut sig)
                .expect("sign");

            assert!(
                bool::from(Ed25519::verify(&pk, b"strict rfc8032 check", LABEL, &sig)),
                "seed {seed}: ed25519-zebra (ZIP-215) must accept our own output",
            );

            let outcome = strict::check(&pk, b"strict rfc8032 check", &sig);
            assert!(
                outcome.strict_accepts(),
                "seed {seed}: our own signature must also be strict-RFC-8032-valid: {outcome:?}",
            );
        }
    }

    #[test]
    fn our_public_keys_are_canonical_and_not_small_order() {
        for seed in 0u8..8 {
            let (_, pk) = keypair(seed);
            assert!(
                strict::is_canonical_y(&pk),
                "seed {seed}: derived public key must be canonically encoded",
            );
            let point = CompressedEdwardsY(pk)
                .decompress()
                .expect("derived public key must decode");
            assert!(
                !point.is_small_order(),
                "seed {seed}: derived public key must not be small-order",
            );
        }
    }

    /// The checked-in golden vectors are this crate's own pinned output, so
    /// they belong to the hard-failing class: a golden ed25519 half that
    /// stops satisfying the strict equation means the signing path
    /// regressed, not that some third-party verifier changed its mind.
    ///
    /// Covers EdMl44 and EdFn512, the two ed25519-based suites. The ed25519
    /// component signs `M'`, which the composite layer builds, so the
    /// strict check runs against `M'` and not against the bare message.
    #[test]
    fn golden_vector_ed25519_halves_are_strict_valid() {
        use pqhybridsign::EdFn512;
        use pqhybridsign::{message, suite::DeltaSuite};

        #[derive(serde::Deserialize)]
        struct Vector {
            ctx_hex: String,
            msg_hex: String,
            public_key_hex: String,
            signature_hex: String,
        }

        fn check(label: &[u8], json: &str, case: &str) {
            let v: Vector = serde_json::from_str(json).expect("golden vector must parse");
            let pk = hex::decode(&v.public_key_hex).expect("pk hex");
            let sig = hex::decode(&v.signature_hex).expect("sig hex");
            let ctx = hex::decode(&v.ctx_hex).expect("ctx hex");
            let msg = hex::decode(&v.msg_hex).expect("msg hex");
            let m_prime = message::m_prime(label, &ctx, &msg).expect("M'");

            // Classical-first serialization: the ed25519 half is the leading
            // 32 bytes of the composite public key and the leading 64 of the
            // composite signature.
            let a: [u8; 32] = pk[..32].try_into().expect("32-byte classical public key");
            let s: [u8; 64] = sig[..64].try_into().expect("64-byte classical signature");

            let outcome = strict::check(&a, &m_prime, &s);
            assert!(
                outcome.strict_accepts(),
                "{case}: pinned golden ed25519 half must be strict-RFC-8032-valid: {outcome:?}",
            );
        }

        check(
            EdMl44::LABEL,
            include_str!("vectors/h1.json"),
            "EdMl44 golden",
        );
        check(
            EdFn512::LABEL,
            include_str!("vectors/h2.json"),
            "EdFn512 golden",
        );
    }
}

#[derive(serde::Deserialize)]
struct NegativeVector {
    description: String,
    public_key_hex: String,
    msg_hex: String,
    signature_hex: String,
}

fn parse_vector(v: &NegativeVector) -> ([u8; 32], Vec<u8>, [u8; 64]) {
    let pk: [u8; 32] = hex::decode(&v.public_key_hex)
        .expect("pk hex")
        .try_into()
        .expect("32 bytes");
    let msg = hex::decode(&v.msg_hex).expect("msg hex");
    let sig: [u8; 64] = hex::decode(&v.signature_hex)
        .expect("sig hex")
        .try_into()
        .expect("64 bytes");
    (pk, msg, sig)
}

/// Advisory: the pinned negative vectors currently show a ZIP-215 / strict
/// RFC 8032 divergence. This test always passes -- see the module doc for
/// why -- but prints, per vector, exactly what diverged and what a
/// consuming application should take away from it. See `support::warn` for
/// how that reaches the terminal without `--nocapture`.
#[test]
fn zip215_negative_vectors_diverge_from_strict_rfc8032() {
    let vectors: Vec<NegativeVector> =
        serde_json::from_str(include_str!("vectors/ed25519_zip215_negative.json"))
            .expect("vectors must parse as JSON");
    assert_eq!(
        vectors.len(),
        3,
        "expected exactly 3 pinned ZIP-215/strict-RFC-8032 divergence vectors"
    );

    for v in &vectors {
        let (pk, msg, sig) = parse_vector(v);
        let zebra_accepts = bool::from(Ed25519::verify(&pk, &msg, LABEL, &sig));
        let outcome = strict::check(&pk, &msg, &sig);

        if zebra_accepts && !outcome.strict_accepts() {
            warn(&format!(
                "WARNING [ed25519 ZIP-215 / strict RFC 8032 divergence]\n\
                 \x20 what: {desc}\n\
                 \x20 vector: pk={pk_hex} msg={msg_hex} sig={sig_hex}\n\
                 \x20 this crate's `Ed25519::verify` (ed25519-zebra, ZIP-215): ACCEPTS\n\
                 \x20 strict RFC 8032 (canonical encoding, non-small-order, cofactorless equation): REJECTS\n\
                 \x20 breakdown: canonical={canonical} small_order={small_order} \
                 cofactorless_equation_holds={cofactorless} cofactored_equation_holds={cofactored}\n\
                 \x20 not just an order screen: even a verifier with no small-order check at all \
                 (Go's crypto/ed25519 has none) would still reject this vector, because \
                 cofactorless_equation_holds=false on its own.\n\
                 \x20 consequence: a peer verifying the same bytes with ed25519-dalek's `verify_strict`, \
                 Go's `crypto/ed25519`, or a common Solidity ed25519 port reaches the OPPOSITE verdict. \
                 In a system where independent parties must agree on validity (an on-chain registry, a \
                 consensus protocol), that disagreement is a chain split, not a rejected transaction.",
                desc = v.description,
                pk_hex = v.public_key_hex,
                msg_hex = v.msg_hex,
                sig_hex = v.signature_hex,
                canonical = outcome.canonical,
                small_order = outcome.small_order,
                cofactorless = outcome.cofactorless_holds,
                cofactored = outcome.cofactored_holds,
            ));
        } else {
            warn(&format!(
                "WARNING [ed25519 ZIP-215/strict-RFC-8032 divergence vector is stale]\n\
                 \x20 what: {desc}\n\
                 \x20 this vector no longer demonstrates the expected divergence \
                 (zebra_accepts={zebra_accepts}, strict_accepts={strict_accepts}). A dependency \
                 upgrade likely changed `ed25519-zebra` or `curve25519-dalek` decoding/acceptance \
                 behavior. Regenerate tests/vectors/ed25519_zip215_negative.json: \
                 `cargo test -p pqhybridsign --test generate_vectors -- --ignored --nocapture`.",
                desc = v.description,
                zebra_accepts = zebra_accepts,
                strict_accepts = outcome.strict_accepts(),
            ));
        }
    }
}

/// Shows the ZIP-215 / strict RFC 8032 divergence survives composition to
/// the EdMl44 (ed25519 + ML-DSA-44) composite level, not just the ed25519
/// component in isolation.
///
/// Advisory, for the same reason as `zip215_negative_vectors_diverge_from_strict_rfc8032`:
/// it depends on `ed25519-zebra` acceptance behavior this crate does not
/// own.
#[test]
fn a_low_order_ed25519_half_splits_h1_verification() {
    let master = [0x7bu8; 32];
    let mut sk = vec![0u8; EdMl44::SECRET_KEY_LEN];
    let mut pk = vec![0u8; EdMl44::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<EdMl44>(&master, &mut sk, &mut pk).expect("keygen");

    let msg = b"EdMl44 composite ZIP-215 divergence probe";
    let ctx = b"";
    let mut sig = vec![0u8; EdMl44::SIGNATURE_LEN];
    composite::sign_deterministic::<EdMl44>(&sk, msg, ctx, b"nonce", &mut sig).expect("sign");

    // Splice the weak classical forgery in for the real ed25519 half. The
    // post-quantum half stays an honest ML-DSA-44 signature over the same
    // M'; composite verification is `classical_ok & pq_ok`, so this alone
    // decides whether the whole composite verifies.
    let (weak_pk, weak_sig) = weak_classical_forgery();
    let c_pk_len = <<EdMl44 as Suite>::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
    let split = EdMl44::SPLIT;
    pk[..c_pk_len].copy_from_slice(&weak_pk);
    sig[..split].copy_from_slice(&weak_sig);

    let composite_accepts = composite::verify::<EdMl44>(&pk, msg, ctx, &sig);
    // `weak_classical_forgery` accepts under ed25519-zebra for every
    // message by construction (see its doc comment), so its strict verdict
    // does not depend on which message the composite layer actually signed.
    let classical_outcome = strict::check(&weak_pk, msg, &weak_sig);
    let a_strict_composite_would_reject = !classical_outcome.strict_accepts();

    if composite_accepts && a_strict_composite_would_reject {
        warn(&format!(
            "WARNING [ZIP-215 divergence survives EdMl44 composition]\n\
             \x20 an EdMl44 (ed25519 + ML-DSA-44) composite signature whose classical half is a ZIP-215-only \
             forgery -- an order-8 public key with no discoverable secret key -- verifies successfully \
             end to end, because EdMl44 verification is `classical_ok & pq_ok` and the post-quantum half is \
             an honestly produced ML-DSA-44 signature.\n\
             \x20 a strict classical verifier rejects that same classical half (small_order={small_order}, \
             cofactorless_equation_holds={cofactorless}), and so would reject the whole composite.\n\
             \x20 consequence: two conforming EdMl44 verifiers -- one using this crate, one substituting a \
             strict verifier for the classical half -- disagree about the exact same composite signature \
             bytes.",
            small_order = classical_outcome.small_order,
            cofactorless = classical_outcome.cofactorless_holds,
        ));
    } else {
        warn(&format!(
            "WARNING [EdMl44 composition divergence vector is stale]\n\
             \x20 composite_accepts={composite_accepts}, strict_would_reject={a_strict_composite_would_reject}; \
             the forgery no longer demonstrates the expected divergence at the EdMl44 composite level.",
        ));
    }
}
