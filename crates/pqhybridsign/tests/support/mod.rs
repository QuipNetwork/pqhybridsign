// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared support for the ZIP-215 / strict RFC 8032 tests and their vector
//! generator.
//!
//! Not a Cargo test target itself: it lives under `tests/support/` rather
//! than directly in `tests/`, which is what keeps Cargo's default test
//! discovery (`tests/*.rs`) from picking it up as its own binary. Both
//! `tests/ed25519_strict.rs` and `tests/generate_vectors.rs` pull it in with
//! `#[path = "support/mod.rs"] mod support;` so the strict verifier and the
//! forgery construction have exactly one definition each.

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

/// Print a warning so a human running plain `cargo test` sees it, with no
/// `--nocapture` flag required.
///
/// `cargo test` captures both stdout and stderr for a passing test and
/// discards the capture -- `eprintln!` alone is invisible here (verified
/// empirically against this toolchain: a plain `cargo test -p pqhybridsign
/// --test ed25519_strict` run shows none of this crate's warning text,
/// while `--nocapture` shows all of it). The capture works by redirecting
/// the *Rust-level* `io::stdout`/`io::stderr` writers that `println!` and
/// `eprintln!` go through; it does not touch the process's real file
/// descriptor 2. Opening `/dev/stderr` -- a live alias for that fd on every
/// platform this crate ships tests on (Linux, macOS) -- and writing to it
/// directly goes around the redirect, so the warning reaches the terminal
/// (or whatever stderr is piped to) regardless of capture.
///
/// Falls back to `eprintln!` if `/dev/stderr` cannot be opened, which
/// covers platforms without it (Windows) at the cost of needing
/// `--nocapture` there. That fallback trades total silence for partial
/// visibility; it does not change what gets asserted, since these warnings
/// never gate test pass/fail either way.
///
/// `#[allow(dead_code)]`: `#[path = "support/mod.rs"]` compiles a separate
/// copy of this module into each test binary that includes it.
/// `tests/generate_vectors.rs` includes it for `strict`/`weak_classical_forgery`
/// but never emits a warning itself, so its copy never calls this function;
/// `tests/ed25519_strict.rs`'s copy does. `-D warnings` sees each copy in
/// isolation.
#[allow(dead_code)]
pub fn warn(message: &str) {
    use std::io::Write;
    match std::fs::OpenOptions::new().write(true).open("/dev/stderr") {
        Ok(mut stderr) => {
            // Best-effort: a broken pipe on the other end of stderr is not
            // something a diagnostic warning should turn into a panic over.
            let _ = writeln!(stderr, "{message}");
        }
        Err(_) => eprintln!("{message}"),
    }
}

/// A from-scratch RFC 8032 5.1.7 verifier, built directly on
/// `curve25519-dalek` so it shares no code path with `ed25519-zebra`.
///
/// "Strict" here is the union of checks enforced by the strictest widely
/// deployed verifiers (`ed25519-dalek`'s `verify_strict`, Go's
/// `crypto/ed25519`, common Solidity ports), not a single RFC 8032
/// requirement:
///
/// * `s` and the `A`/`R` encodings must be canonical (RFC 8032 section
///   5.1.3: "If the resulting value is >= p, decoding fails"). ZIP-215
///   explicitly requires accepting the non-canonical encodings this rejects.
/// * `A` and `R` must not be small-order. Neither RFC 8032 nor ZIP-215
///   requires this; it is `ed25519-dalek`'s `verify_strict` convention,
///   included because it is the check that closes the "one signature valid
///   for almost every message" hazard a small-order `A` opens up.
/// * The verification equation is the cofactorless `[s]B = R + [k]A`. RFC
///   8032 5.1.7 permits this explicitly ("It's sufficient, but not
///   required, to instead check `[S]B = R + [k]A'`"), so using it is not
///   itself an RFC 8032 violation -- ZIP-215's departure from RFC 8032 is
///   the encoding-acceptance rule above, not the choice of equation.
pub mod strict {
    use super::*;

    /// Every signal this module can observe about one `(pk, msg, sig)`
    /// triple. Kept public and inspectable (rather than collapsed straight
    /// to a bool) so callers can report *which* strict check a vector fails,
    /// not just that one did.
    #[derive(Debug, Clone, Copy)]
    pub struct Outcome {
        /// `s`, `A` and `R` all decoded as valid curve points / a
        /// reduced scalar.
        pub decodes: bool,
        /// `A` and `R` were both canonically encoded (RFC 8032 5.1.3).
        pub canonical: bool,
        /// `A` or `R` is small-order.
        pub small_order: bool,
        /// The cofactorless equation `[s]B = R + [k]A` holds.
        pub cofactorless_holds: bool,
        /// The cofactored equation `[8][s]B = [8]R + [8][k]A` holds -- the
        /// same check `ed25519-zebra` performs. Carried here purely for
        /// diagnostic output: it explains *why* `ed25519-zebra` accepted a
        /// vector this module rejects.
        pub cofactored_holds: bool,
    }

    impl Outcome {
        fn rejected() -> Self {
            Outcome {
                decodes: false,
                canonical: false,
                small_order: false,
                cofactorless_holds: false,
                cofactored_holds: false,
            }
        }

        /// The full strict-RFC-8032 verdict: every check above must pass.
        pub fn strict_accepts(&self) -> bool {
            self.decodes && self.canonical && !self.small_order && self.cofactorless_holds
        }
    }

    /// RFC 8032 5.1.3 canonicality: the y-coordinate encoding must be less
    /// than `p = 2^255 - 19`. `curve25519-dalek`'s field-element decoding
    /// reduces mod `p` unconditionally (that is what lets `ed25519-zebra`
    /// accept ZIP-215's non-canonical encodings), so it cannot answer this
    /// on its own. Decompressing and recompressing does: `compress()`
    /// always emits the canonical, minimal encoding, so the round trip
    /// changes the bytes if and only if the input was non-canonical.
    pub fn is_canonical_y(bytes: &[u8; 32]) -> bool {
        match CompressedEdwardsY(*bytes).decompress() {
            Some(point) => point.compress().to_bytes() == *bytes,
            None => false,
        }
    }

    /// Check `(pk, msg, sig)` against every strict criterion and report each
    /// signal independently.
    #[allow(non_snake_case)]
    pub fn check(pk_bytes: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Outcome {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&sig[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig[32..]);

        let s: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
        let A = CompressedEdwardsY(*pk_bytes).decompress();
        let R = CompressedEdwardsY(r_bytes).decompress();

        let (Some(s), Some(A), Some(R)) = (s, A, R) else {
            return Outcome::rejected();
        };

        let canonical = is_canonical_y(pk_bytes) && is_canonical_y(&r_bytes);
        let small_order = A.is_small_order() || R.is_small_order();

        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(pk_bytes);
        h.update(msg);
        let k = Scalar::from_hash(h);

        // R' = [s]B - [k]A. The cofactorless check is R == R'; the
        // cofactored check `ed25519-zebra` performs is [8](R - R') == O.
        let R_prime = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-A), &s);
        let cofactorless_holds = R == R_prime;
        let cofactored_holds = (R - R_prime).mul_by_cofactor() == EdwardsPoint::identity();

        Outcome {
            decodes: true,
            canonical,
            small_order,
            cofactorless_holds,
            cofactored_holds,
        }
    }
}

/// An order-8 point from `curve25519-dalek`'s 8-torsion subgroup. Order
/// exactly 8 (not 1, 2 or 4) so the "generic message" argument in
/// [`weak_classical_forgery`] is as strong as possible: the cofactorless
/// equation only accidentally holds for 1 in 8 hash outputs, versus 1 in 2
/// for an order-2 point.
fn order_8_torsion_point() -> EdwardsPoint {
    for point in EIGHT_TORSION {
        let doubled = point * Scalar::from(2u64);
        let quadrupled = doubled * Scalar::from(2u64);
        if quadrupled != EdwardsPoint::identity() {
            return point;
        }
    }
    panic!("curve25519-dalek's EIGHT_TORSION has no order-8 element");
}

/// A public key with no discoverable secret key, and a signature that
/// `ed25519-zebra` accepts under it for *every* message.
///
/// `A` is an order-8 point, so `[8]A = O` regardless of the scalar it is
/// multiplied by. Fixing `R` to the identity and `s` to zero makes
/// `ed25519-zebra`'s check `[8](R - ([s]B - [k]A)) == O` reduce to
/// `[8]([k]A) == O`, which holds for every `k` -- and therefore for every
/// message, since `k` is a hash that includes the message. This is the
/// mechanism behind `ed25519-dalek`'s documented "weak public key... valid
/// for almost every message" hazard (see `VerifyingKey::is_weak`).
pub fn weak_classical_forgery() -> ([u8; 32], [u8; 64]) {
    let a = order_8_torsion_point();
    let pk = a.compress().to_bytes();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(CompressedEdwardsY::identity().as_bytes());
    // sig[32..] stays zero: s = 0, which is a canonical scalar encoding.
    (pk, sig)
}
