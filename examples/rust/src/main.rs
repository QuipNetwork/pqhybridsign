// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sign/verify roundtrip example for EdMl44 through SrFn512, built against the
//! published `pqhybridsign` crate from crates.io.
//!
//! For each suite: derive a keypair from a fixed seed, sign a message
//! deterministically, verify the signature, tamper one message byte, and
//! confirm verification then fails. Every seed and nonce is a fixed
//! constant, so the run needs no random number generator and is
//! byte-for-byte repeatable.
//!
//! EdMl44 and SrMl44 are fixed-offset suites (`pqhybridsign::composite`); EdFn512
//! and SrFn512 are delta-length suites (`pqhybridsign::composite_delta`),
//! since their FN-DSA-512 half has a variable-length signature.

use pqhybridsign::{EdMl44, EdFn512, SrMl44, SrFn512};
use pqhybridsign::composite;
use pqhybridsign::composite_delta;
use pqhybridsign::suite::{DeltaSuite, Suite};
use std::process::ExitCode;

/// Application context bound into every signature.
const CTX: &[u8] = b"pqhybridsign-example-ctx";
/// Fixed nonce for deterministic signing. Not every component honours it
/// (see `composite::sign_deterministic`'s documentation), but it removes
/// any dependency on a random number generator for this example.
const NONCE: &[u8] = b"pqhybridsign-example-nonce";
/// Message signed by every suite in this example.
const MESSAGE: &[u8] = b"pqhybridsign roundtrip message";

/// One fixed 32-byte master seed per suite, so a suite's keypair never
/// depends on another suite's.
fn seed_for(suite_byte: u8) -> [u8; 32] {
    [suite_byte; 32]
}

/// Flip the first byte of `msg`, producing the tampered message this
/// example verifies against.
fn tamper(msg: &[u8]) -> Vec<u8> {
    let mut tampered = msg.to_vec();
    tampered[0] ^= 0x01;
    tampered
}

/// Roundtrip a fixed-offset suite (EdMl44, SrMl44): keygen, sign, verify true,
/// tamper, verify false.
fn check_fixed<S: Suite>(name: &str, seed_byte: u8) -> Result<(), String> {
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<S>(&seed_for(seed_byte), &mut sk, &mut pk)
        .map_err(|e| format!("{name}: keygen failed: {e:?}"))?;

    let mut sig = vec![0u8; S::SIGNATURE_LEN];
    composite::sign_deterministic::<S>(&sk, MESSAGE, CTX, NONCE, &mut sig)
        .map_err(|e| format!("{name}: sign failed: {e:?}"))?;

    if !composite::verify::<S>(&pk, MESSAGE, CTX, &sig) {
        return Err(format!(
            "{name}: verify of the untampered signature returned false"
        ));
    }

    let tampered = tamper(MESSAGE);
    if composite::verify::<S>(&pk, &tampered, CTX, &sig) {
        return Err(format!(
            "{name}: verify of the tampered message returned true"
        ));
    }

    println!("{name}: keygen, sign, verify true, tamper, verify false -- OK");
    Ok(())
}

/// Roundtrip a delta-length suite (EdFn512, SrFn512): keygen, sign, verify true,
/// tamper, verify false.
fn check_delta<S: DeltaSuite>(name: &str, seed_byte: u8) -> Result<(), String> {
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<S>(&seed_for(seed_byte), &mut sk, &mut pk)
        .map_err(|e| format!("{name}: keygen failed: {e:?}"))?;

    let mut sig_buf = vec![0u8; S::MAX_SIGNATURE_LEN];
    let sig_len = composite_delta::sign_deterministic::<S>(&sk, MESSAGE, CTX, NONCE, &mut sig_buf)
        .map_err(|e| format!("{name}: sign failed: {e:?}"))?;
    let sig = &sig_buf[..sig_len];

    if !composite_delta::verify::<S>(&pk, MESSAGE, CTX, sig) {
        return Err(format!(
            "{name}: verify of the untampered signature returned false"
        ));
    }

    let tampered = tamper(MESSAGE);
    if composite_delta::verify::<S>(&pk, &tampered, CTX, sig) {
        return Err(format!(
            "{name}: verify of the tampered message returned true"
        ));
    }

    println!("{name}: keygen, sign, verify true, tamper, verify false -- OK");
    Ok(())
}

fn main() -> ExitCode {
    let checks: [fn() -> Result<(), String>; 4] = [
        || check_fixed::<EdMl44>("EdMl44", 1),
        || check_delta::<EdFn512>("EdFn512", 2),
        || check_fixed::<SrMl44>("SrMl44", 3),
        || check_delta::<SrFn512>("SrFn512", 4),
    ];

    for check in checks {
        if let Err(message) = check() {
            eprintln!("error: {message}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}
