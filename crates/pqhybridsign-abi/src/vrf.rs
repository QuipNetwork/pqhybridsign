// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hybrid verifiable random function, dispatched by suite.
//!
//! The core VRF lives in `pqhybridsign::vrf` behind the `vrf` feature. It
//! has three function families, one for each shape of post-quantum
//! binding:
//!
//! - `vrf::sign`, `sign_deterministic`, `verify`, `make_bytes`,
//!   `proof_len` for a fixed-length binding. H1 and H3.
//! - `vrf::sign_delta`, `sign_delta_deterministic`, `verify_delta`,
//!   `make_bytes_delta`, `max_proof_len_delta` for a delta-length
//!   binding. H2 and H4.
//! - `vrf::sign_stateless`, `verify_stateless`, `make_bytes_stateless`,
//!   `proof_len_stateless`, `derive_stateless_key` for the stateful
//!   suites. H5 and H6.
//!
//! [`vrf_proof_len`], [`vrf_verify`] and [`vrf_make_bytes`] span all six
//! suites and dispatch internally. Every suite supports the mechanism.
//!
//! Proving splits, and the split follows the house pattern rather than
//! inventing a new one. [`crate::sign`] covers H1 through H4 and rejects
//! H5 and H6 with [`AbiError::WrongEntryPointForSuite`], because a
//! stateless-looking call that silently spent state is the worst failure
//! this crate could offer. VRF proving has exactly that shape: H1 through
//! H4 spend nothing, while H5 and H6 spend one unit of the few-time
//! stateless budget and need a durable store to record it. So
//! [`vrf_prove`] and [`vrf_prove_deterministic`] cover H1 through H4 and
//! reject H5 and H6, and [`vrf_prove_stateless`] covers H5 and H6 through
//! a key handle and a budget store.
//!
//! H5 and H6 also need a key that is not the identity key. `pqhs-1l6`
//! settled that: `vrf::derive_stateless_key` derives a SHRINCS key
//! disjoint from the rotation and recovery identity key, under a separate
//! label. The core type is `DedicatedVrfKey<S>`, which cannot be exported
//! to bytes, so a binding must hold it. [`VrfStatelessKey`] is that
//! holder, built the same way [`crate::StatefulKeyHandle`] is.

use pqhybridsign::budget::StatelessBudgetStore;
use pqhybridsign::shrincs::{H5, H6};
use pqhybridsign::stateful_composite::SecretKey;
use pqhybridsign::suite::{DeltaSuite, StatefulSuite, Suite as CoreSuite};
use pqhybridsign::vrf::{self, ClassicalVrf, DedicatedVrfKey};
use pqhybridsign::{H1, H2, H3, H4};

use crate::error::AbiError;
use crate::seed::MASTER_SEED_LEN;
use crate::suite::Suite;

/// Length in bytes of the output [`vrf_make_bytes`] writes.
///
/// Fixed at 32. The core `pqhybridsign::vrf::make_bytes` is generic over
/// the output buffer; this crate pins 32 bytes so every binding's buffer
/// arithmetic is constant.
pub const VRF_OUTPUT_LEN: usize = 32;

/// Length in bytes of a hybrid VRF proof for `suite`.
///
/// For H1 and H3 this is exact. For H2 and H4 this is the maximum a
/// delta-length binding can occupy. For H5 and H6 this is exact: the
/// stateless SHRINCS binding has a fixed length.
pub fn vrf_proof_len(suite: Suite) -> Result<usize, AbiError> {
    match suite {
        Suite::H1 => Ok(proof_len_fixed::<H1>()),
        Suite::H3 => Ok(proof_len_fixed::<H3>()),
        Suite::H2 => Ok(proof_len_delta::<H2>()),
        Suite::H4 => Ok(proof_len_delta::<H4>()),
        Suite::H5 => Ok(proof_len_stateless_suite::<H5>()),
        Suite::H6 => Ok(proof_len_stateless_suite::<H6>()),
    }
}

fn proof_len_fixed<S: CoreSuite>() -> usize
where
    S::Classical: ClassicalVrf,
{
    vrf::proof_len::<S>()
}

fn proof_len_delta<S: DeltaSuite>() -> usize
where
    S::Classical: ClassicalVrf,
{
    vrf::max_proof_len_delta::<S>()
}

fn proof_len_stateless_suite<S: StatefulSuite>() -> usize
where
    S::Classical: ClassicalVrf,
{
    vrf::proof_len_stateless::<S>()
}

/// Evaluate the hybrid VRF.
///
/// `rng` cannot move the output. Whatever it supplies, two evaluations of
/// one input under one key give the same [`vrf_make_bytes`] result, so a
/// prover cannot re-roll for a better value. That is the property the
/// construction rests on and it holds for every suite.
///
/// Whether `rng` is used at all depends on the classical half. The sr25519
/// suites (H3, H4) hedge the classical proof's nonce with it, so two
/// evaluations produce different proof bytes. The ed25519 suites (H1, H2)
/// ignore it: RFC 9381 section 5.4.2.2 derives the ECVRF nonce from the
/// secret key and the input, so their proofs are deterministic and
/// [`vrf_prove_deterministic`] returns the identical bytes. Pass an `rng`
/// regardless -- which suites use it is not part of this API's contract.
///
/// H1 through H4 only. H5 and H6 spend one unit of a few-time stateless
/// budget on every evaluation and need a durable store to record it, so
/// they have their own entry point, [`vrf_prove_stateless`], for the same
/// reason [`crate::sign`] refuses them: a call that looks free and is not
/// is the worst failure mode this crate could offer.
///
/// Returns the number of bytes written into `proof_out`, which is
/// [`vrf_proof_len`] for this suite. A larger buffer is accepted and only
/// that prefix is written.
///
/// # Errors
///
/// [`AbiError::WrongEntryPointForSuite`] for H5 and H6.
/// [`AbiError::OutputBufferTooSmall`] if `proof_out` is shorter than
/// [`vrf_proof_len`]. [`AbiError::BadLength`] if `sk` is not the suite's
/// secret-key length. [`AbiError::ComponentFailure`] if either component
/// rejects its key.
pub fn vrf_prove(
    suite: Suite,
    sk: &[u8],
    input: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    proof_out: &mut [u8],
) -> Result<usize, AbiError> {
    match suite {
        Suite::H1 => prove_fixed::<H1>(sk, input, rng, proof_out),
        Suite::H3 => prove_fixed::<H3>(sk, input, rng, proof_out),
        Suite::H2 => prove_delta::<H2>(sk, input, rng, proof_out),
        Suite::H4 => prove_delta::<H4>(sk, input, rng, proof_out),
        Suite::H5 | Suite::H6 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn prove_fixed<S: CoreSuite>(
    sk: &[u8],
    input: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    proof_out: &mut [u8],
) -> Result<usize, AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::sign::<S>(sk, input, rng, proof_out)?)
}

fn prove_delta<S: DeltaSuite>(
    sk: &[u8],
    input: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    proof_out: &mut [u8],
) -> Result<usize, AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::sign_delta::<S>(sk, input, rng, proof_out)?)
}

/// Evaluate the hybrid VRF with a reproducible classical proof.
///
/// H1 through H4 only, on the same terms as [`vrf_prove`]: H5 and H6
/// spend a few-time budget unit and prove through
/// [`vrf_prove_stateless`].
///
/// Returns the number of bytes written into `proof_out`.
///
/// # Errors
///
/// The same as [`vrf_prove`].
pub fn vrf_prove_deterministic(
    suite: Suite,
    sk: &[u8],
    input: &[u8],
    proof_out: &mut [u8],
) -> Result<usize, AbiError> {
    match suite {
        Suite::H1 => prove_fixed_deterministic::<H1>(sk, input, proof_out),
        Suite::H3 => prove_fixed_deterministic::<H3>(sk, input, proof_out),
        Suite::H2 => prove_delta_deterministic::<H2>(sk, input, proof_out),
        Suite::H4 => prove_delta_deterministic::<H4>(sk, input, proof_out),
        Suite::H5 | Suite::H6 => Err(AbiError::WrongEntryPointForSuite),
    }
}

fn prove_fixed_deterministic<S: CoreSuite>(
    sk: &[u8],
    input: &[u8],
    proof_out: &mut [u8],
) -> Result<usize, AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::sign_deterministic::<S>(sk, input, proof_out)?)
}

fn prove_delta_deterministic<S: DeltaSuite>(
    sk: &[u8],
    input: &[u8],
    proof_out: &mut [u8],
) -> Result<usize, AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::sign_delta_deterministic::<S>(sk, input, proof_out)?)
}

/// Verify a hybrid VRF proof. Both halves must accept.
///
/// Covers all six suites: verifying never spends anything, so there is
/// nothing to keep apart by statefulness.
///
/// Returns `false`, never an error, for a malformed `pk` or `proof`.
#[must_use]
pub fn vrf_verify(suite: Suite, pk: &[u8], input: &[u8], proof: &[u8]) -> bool {
    match suite {
        Suite::H1 => vrf::verify::<H1>(pk, input, proof),
        Suite::H3 => vrf::verify::<H3>(pk, input, proof),
        Suite::H2 => vrf::verify_delta::<H2>(pk, input, proof),
        Suite::H4 => vrf::verify_delta::<H4>(pk, input, proof),
        Suite::H5 => vrf::verify_stateless::<H5>(pk, input, proof),
        Suite::H6 => vrf::verify_stateless::<H6>(pk, input, proof),
    }
}

/// Derive [`VRF_OUTPUT_LEN`] output bytes from a verified proof.
///
/// **Verify the proof first.** [`vrf_verify`] is what establishes that the
/// pre-output belongs to this key and this input. Deriving bytes from an
/// unverified proof derives bytes from whatever an attacker supplied.
///
/// `context` separates two uses of one proof: the same proof under
/// `b"leadership"` and `b"randomness"` gives unrelated bytes, so one
/// evaluation can feed two consumers without either learning the other's
/// value early.
///
/// The width is fixed at 32 bytes. The core `pqhybridsign::vrf::make_bytes`
/// is generic over the output buffer and a Rust caller can ask for another
/// width; no C, Python or JavaScript caller has needed one, and a fixed
/// width keeps every binding's buffer arithmetic constant.
///
/// # Errors
///
/// [`AbiError::BadLength`] if `proof` is shorter than the proof header or
/// `pk` shorter than the classical public key.
/// [`AbiError::ComponentFailure`] if the public key or the pre-output does
/// not decode.
pub fn vrf_make_bytes(
    suite: Suite,
    pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
    out: &mut [u8; VRF_OUTPUT_LEN],
) -> Result<(), AbiError> {
    *out = match suite {
        Suite::H1 => make_bytes_fixed::<H1>(pk, input, proof, context)?,
        Suite::H3 => make_bytes_fixed::<H3>(pk, input, proof, context)?,
        Suite::H2 => make_bytes_delta::<H2>(pk, input, proof, context)?,
        Suite::H4 => make_bytes_delta::<H4>(pk, input, proof, context)?,
        Suite::H5 => make_bytes_stateless_suite::<H5>(pk, input, proof, context)?,
        Suite::H6 => make_bytes_stateless_suite::<H6>(pk, input, proof, context)?,
    };
    Ok(())
}

fn make_bytes_fixed<S: CoreSuite>(
    pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<[u8; VRF_OUTPUT_LEN], AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::make_bytes::<S, [u8; VRF_OUTPUT_LEN]>(
        pk, input, proof, context,
    )?)
}

fn make_bytes_delta<S: DeltaSuite>(
    pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<[u8; VRF_OUTPUT_LEN], AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::make_bytes_delta::<S, [u8; VRF_OUTPUT_LEN]>(
        pk, input, proof, context,
    )?)
}

fn make_bytes_stateless_suite<S: StatefulSuite>(
    pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<[u8; VRF_OUTPUT_LEN], AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::make_bytes_stateless::<S, [u8; VRF_OUTPUT_LEN]>(
        pk, input, proof, context,
    )?)
}

/// A SHRINCS key dedicated to VRF evaluation, held across calls.
///
/// H5 and H6 evaluate the VRF through their post-quantum half's few-time
/// stateless path, which draws on a budget shared with rotation and
/// recovery. The key that carries an identity's rotation and recovery
/// authority must not also spend that budget on VRF evaluations, so this
/// type holds a **separate** key.
///
/// [`VrfStatelessKey::derive`] is the way to get one: it derives from the
/// master seed under a label disjoint from the identity key's, so the two
/// never collide. [`VrfStatelessKey::adopt_unchecked`] takes a key the
/// caller supplies and asserts, without checking, that it is not the
/// identity key. The name says so because a reviewer reading that call is
/// being told to verify the provenance.
///
/// The key lives only in memory. There is no export: a dedicated VRF key
/// is derived from the master seed when it is needed, not stored.
pub struct VrfStatelessKey {
    inner: Inner,
}

enum Inner {
    H5(DedicatedVrfKey<H5>),
    H6(DedicatedVrfKey<H6>),
}

impl VrfStatelessKey {
    /// Derive a dedicated VRF key from `master`, writing its public key
    /// into `pk_out`.
    ///
    /// `pk_out` must be exactly [`crate::public_key_len`] bytes for
    /// `suite`. The derivation uses a label disjoint from the identity
    /// key's, so the two keys never collide.
    ///
    /// # Errors
    ///
    /// [`AbiError::WrongEntryPointForSuite`] for H1-H4.
    /// [`AbiError::BadLength`] if `pk_out` is not
    /// [`crate::public_key_len`] bytes for `suite`.
    /// [`AbiError::ComponentFailure`] if derivation fails.
    pub fn derive(
        suite: Suite,
        master: &[u8; MASTER_SEED_LEN],
        pk_out: &mut [u8],
    ) -> Result<Self, AbiError> {
        match suite {
            Suite::H5 => Ok(Self {
                inner: Inner::H5(derive_suite::<H5>(master, pk_out)?),
            }),
            Suite::H6 => Ok(Self {
                inner: Inner::H6(derive_suite::<H6>(master, pk_out)?),
            }),
            Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
        }
    }

    /// Treat `sk` as a key dedicated to VRF evaluation.
    ///
    /// The caller asserts that `sk` is not the key that carries this
    /// identity's rotation and recovery authority. Nothing here checks
    /// that, which is why the name says so.
    ///
    /// `sk` is an exported stateful secret-key blob of
    /// [`crate::secret_key_len`] bytes for `suite`. Use [`Self::derive`]
    /// wherever the key can be derived from a master seed.
    ///
    /// # Errors
    ///
    /// [`AbiError::WrongEntryPointForSuite`] for H1-H4.
    /// [`AbiError::BadLength`] if `sk` is not [`crate::secret_key_len`]
    /// bytes for `suite`. [`AbiError::ComponentFailure`] if the blob does
    /// not import.
    pub fn adopt_unchecked(suite: Suite, sk: &[u8]) -> Result<Self, AbiError> {
        match suite {
            Suite::H5 => Ok(Self {
                inner: Inner::H5(DedicatedVrfKey::adopt_unchecked(import_checked::<H5>(sk)?)),
            }),
            Suite::H6 => Ok(Self {
                inner: Inner::H6(DedicatedVrfKey::adopt_unchecked(import_checked::<H6>(sk)?)),
            }),
            Suite::H1 | Suite::H2 | Suite::H3 | Suite::H4 => Err(AbiError::WrongEntryPointForSuite),
        }
    }

    /// The suite this key was derived or adopted for.
    #[must_use]
    pub fn suite(&self) -> Suite {
        match self.inner {
            Inner::H5(_) => Suite::H5,
            Inner::H6(_) => Suite::H6,
        }
    }
}

fn derive_suite<S: StatefulSuite>(
    master: &[u8; MASTER_SEED_LEN],
    pk_out: &mut [u8],
) -> Result<DedicatedVrfKey<S>, AbiError>
where
    S::Classical: ClassicalVrf,
{
    let (key, pk) = vrf::derive_stateless_key::<S>(master)?;
    write_exact(pk_out, pk.as_ref())?;
    Ok(key)
}

fn import_checked<S: StatefulSuite>(sk: &[u8]) -> Result<SecretKey<S>, AbiError> {
    if sk.len() != SecretKey::<S>::exported_len() {
        return Err(AbiError::BadLength);
    }
    Ok(SecretKey::<S>::import(sk)?)
}

fn write_exact(out: &mut [u8], src: &[u8]) -> Result<(), AbiError> {
    if out.len() != src.len() {
        return Err(AbiError::BadLength);
    }
    out.copy_from_slice(src);
    Ok(())
}

/// Evaluate the hybrid VRF under H5 or H6, spending one unit of the
/// few-time stateless budget.
///
/// [`vrf_prove`] refuses these suites because a call that looks free and
/// is not is the worst failure mode this crate could offer. This entry
/// point takes the dedicated key and the durable store the spend needs.
///
/// Returns the number of bytes written into `proof_out`.
///
/// # Errors
///
/// [`AbiError::StatelessBudgetExhausted`] if this key's few-time budget
/// is spent. [`AbiError::BudgetStoreFailed`] if the store could not
/// durably record the spend. [`AbiError::OutputBufferTooSmall`] if
/// `proof_out` is shorter than [`vrf_proof_len`].
/// [`AbiError::ComponentFailure`] if a component rejects its key.
pub fn vrf_prove_stateless(
    key: &VrfStatelessKey,
    budget: &mut impl StatelessBudgetStore,
    input: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    proof_out: &mut [u8],
) -> Result<usize, AbiError> {
    match &key.inner {
        Inner::H5(sk) => prove_stateless_suite(sk, budget, input, rng, proof_out),
        Inner::H6(sk) => prove_stateless_suite(sk, budget, input, rng, proof_out),
    }
}

fn prove_stateless_suite<S: StatefulSuite>(
    sk: &DedicatedVrfKey<S>,
    budget: &mut impl StatelessBudgetStore,
    input: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    proof_out: &mut [u8],
) -> Result<usize, AbiError>
where
    S::Classical: ClassicalVrf,
{
    Ok(vrf::sign_stateless(sk, budget, input, rng, proof_out)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keygen_from_seed, public_key_len, secret_key_len, AbiError, BudgetKey,
        StatelessBudgetStore, Suite,
    };
    use pqhybridsign::component::ClassicalScheme;
    use rand_core::OsRng;
    use std::collections::HashMap;

    const INPUT: &[u8] = b"epoch-7/slot-42/randomness";
    const OTHER: &[u8] = b"epoch-7/slot-43/randomness";
    const OUT_CTX: &[u8] = b"leadership-score";

    const STATELESS: [Suite; 4] = [Suite::H1, Suite::H2, Suite::H3, Suite::H4];

    /// An in-memory [`StatelessBudgetStore`]. Not durable: these tests
    /// exercise whether the count is consulted, not persistence.
    #[derive(Default)]
    struct MemoryBudget {
        entries: HashMap<BudgetKey, u64>,
        /// When set, [`StatelessBudgetStore::consumed`] reports this count
        /// for every key. A `HashMap` cannot pre-load a [`BudgetKey`] that
        /// has not been seen, so [`Self::exhausted`] uses this floor.
        floor: Option<u64>,
    }

    impl MemoryBudget {
        /// Pre-load the maximum: every key reports as fully spent.
        fn exhausted() -> Self {
            Self {
                entries: HashMap::new(),
                floor: Some(u64::MAX),
            }
        }
    }

    impl StatelessBudgetStore for MemoryBudget {
        type Error = core::convert::Infallible;

        fn consumed(&self, key: &BudgetKey) -> Option<u64> {
            self.entries.get(key).copied().or(self.floor)
        }

        fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
            self.entries.insert(*key, count);
            Ok(())
        }
    }

    fn keypair(suite: Suite) -> (Vec<u8>, Vec<u8>) {
        let mut sk = vec![0u8; secret_key_len(suite)];
        let mut pk = vec![0u8; public_key_len(suite)];
        keygen_from_seed(suite, &[11u8; 32], &mut sk, &mut pk).unwrap();
        (sk, pk)
    }

    #[test]
    fn every_stateless_suite_proves_and_verifies() {
        for suite in STATELESS {
            let (sk, pk) = keypair(suite);
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut proof).unwrap();
            assert!(
                vrf_verify(suite, &pk, INPUT, &proof[..n]),
                "{suite:?} failed to verify"
            );
        }
    }

    #[test]
    fn a_proof_does_not_verify_against_another_input() {
        for suite in STATELESS {
            let (sk, pk) = keypair(suite);
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut proof).unwrap();
            assert!(
                !vrf_verify(suite, &pk, OTHER, &proof[..n]),
                "{suite:?} verified a wrong input"
            );
        }
    }

    #[test]
    fn a_tampered_proof_does_not_verify() {
        for suite in STATELESS {
            let (sk, pk) = keypair(suite);
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut proof).unwrap();
            proof[0] ^= 0x01;
            assert!(
                !vrf_verify(suite, &pk, INPUT, &proof[..n]),
                "{suite:?} verified a tampered proof"
            );
        }
    }

    #[test]
    fn the_output_does_not_move_with_the_nonce() {
        // The property the construction rests on: a prover cannot re-roll for a
        // better value. Asserting only that the outputs match would also pass if
        // nothing were ever hedged, so the sr25519 suites additionally assert
        // that the proof bytes DID differ -- that is what makes the stable
        // output meaningful rather than trivial.
        //
        // H1/H2 are ed25519: RFC 9381 derives the ECVRF nonce from the key and
        // input, so their proofs are deterministic and must NOT be asserted to
        // differ.
        const HEDGED: [Suite; 2] = [Suite::H3, Suite::H4];
        const DETERMINISTIC: [Suite; 2] = [Suite::H1, Suite::H2];

        for suite in STATELESS {
            let (sk, pk) = keypair(suite);
            let mut a = vec![0u8; vrf_proof_len(suite).unwrap()];
            let mut b = vec![0u8; vrf_proof_len(suite).unwrap()];
            let na = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut a).unwrap();
            let nb = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut b).unwrap();

            let mut out_a = [0u8; VRF_OUTPUT_LEN];
            let mut out_b = [0u8; VRF_OUTPUT_LEN];
            vrf_make_bytes(suite, &pk, INPUT, &a[..na], OUT_CTX, &mut out_a).unwrap();
            vrf_make_bytes(suite, &pk, INPUT, &b[..nb], OUT_CTX, &mut out_b).unwrap();
            assert_eq!(out_a, out_b, "{suite:?} output moved with the nonce");

            if HEDGED.contains(&suite) {
                assert_ne!(
                    a[..na],
                    b[..nb],
                    "{suite:?} hedges its nonce, so two proofs must differ"
                );
            }
            if DETERMINISTIC.contains(&suite) {
                assert_eq!(
                    a[..na],
                    b[..nb],
                    "{suite:?} ignores the rng, so two proofs must be identical"
                );
            }
        }
    }

    #[test]
    fn a_deterministic_proof_repeats_byte_for_byte() {
        for suite in STATELESS {
            let (sk, _pk) = keypair(suite);
            let mut a = vec![0u8; vrf_proof_len(suite).unwrap()];
            let mut b = vec![0u8; vrf_proof_len(suite).unwrap()];
            let na = vrf_prove_deterministic(suite, &sk, INPUT, &mut a).unwrap();
            let nb = vrf_prove_deterministic(suite, &sk, INPUT, &mut b).unwrap();
            assert_eq!(a[..na], b[..nb], "{suite:?} was not deterministic");
        }
    }

    #[test]
    fn a_different_output_context_gives_different_bytes() {
        let suite = Suite::H3;
        let (sk, pk) = keypair(suite);
        let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
        let n = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut proof).unwrap();

        let mut score = [0u8; VRF_OUTPUT_LEN];
        let mut randomness = [0u8; VRF_OUTPUT_LEN];
        vrf_make_bytes(suite, &pk, INPUT, &proof[..n], b"leadership", &mut score).unwrap();
        vrf_make_bytes(
            suite,
            &pk,
            INPUT,
            &proof[..n],
            b"randomness",
            &mut randomness,
        )
        .unwrap();
        assert_ne!(score, randomness);
    }

    #[test]
    fn proving_rejects_the_stateful_suites() {
        for suite in [Suite::H5, Suite::H6] {
            let mut proof = vec![0u8; 4096];
            assert_eq!(
                vrf_prove(suite, &[0u8; 328], INPUT, &mut OsRng, &mut proof).unwrap_err(),
                AbiError::WrongEntryPointForSuite,
                "{suite:?} was accepted by the stateless prover"
            );
            assert_eq!(
                vrf_prove_deterministic(suite, &[0u8; 328], INPUT, &mut proof).unwrap_err(),
                AbiError::WrongEntryPointForSuite,
                "{suite:?} was accepted by the deterministic stateless prover"
            );
        }
    }

    #[test]
    fn the_stateless_vrf_key_rejects_the_lattice_suites() {
        // The reverse refusal. H1-H4 have no stateful half, so there is no
        // dedicated stateless VRF key to derive or adopt for them.
        for suite in [Suite::H1, Suite::H2, Suite::H3, Suite::H4] {
            let mut pk = vec![0u8; public_key_len(suite)];
            assert_eq!(
                VrfStatelessKey::derive(suite, &[13u8; 32], &mut pk).err(),
                Some(AbiError::WrongEntryPointForSuite),
                "{suite:?} was accepted by derive"
            );
            assert_eq!(
                VrfStatelessKey::adopt_unchecked(suite, &[0u8; 328]).err(),
                Some(AbiError::WrongEntryPointForSuite),
                "{suite:?} was accepted by adopt_unchecked"
            );
        }
    }

    #[test]
    fn a_short_proof_buffer_is_refused() {
        let suite = Suite::H1;
        let (sk, _pk) = keypair(suite);
        let short = vrf_proof_len(suite).unwrap() - 1;
        assert_eq!(
            vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut vec![0u8; short]).unwrap_err(),
            AbiError::OutputBufferTooSmall
        );
    }

    // `derive_stateless_key` runs a real keygen. Fast at profile-256s;
    // about 47 seconds each at a 128s profile. The ABI crate has no
    // `profile-256s` feature to `cfg` on, so these stay `#[ignore]` and
    // the profile-matrix job runs them explicitly.
    #[test]
    #[ignore = "derive_stateless_key runs keygen; 47s at 128s"]
    fn a_derived_stateless_key_proves_and_verifies() {
        for suite in [Suite::H5, Suite::H6] {
            let mut pk = vec![0u8; public_key_len(suite)];
            let key = VrfStatelessKey::derive(suite, &[13u8; 32], &mut pk).unwrap();
            assert_eq!(key.suite(), suite);

            let mut budget = MemoryBudget::default();
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove_stateless(&key, &mut budget, INPUT, &mut OsRng, &mut proof).unwrap();
            assert!(
                vrf_verify(suite, &pk, INPUT, &proof[..n]),
                "{suite:?} failed to verify"
            );
        }
    }

    #[test]
    #[ignore = "derive_stateless_key runs keygen; 47s at 128s"]
    fn the_stateless_vrf_key_is_not_the_identity_key() {
        // pqhs-1l6: the VRF must not draw on the rotation and recovery
        // budget of the identity key. Two keys derived from one master seed
        // under different labels must not collide.
        //
        // The two derivations below also differ in `max_stateful_signatures`
        // (1 for the VRF path, 4 for the identity path), and that parameter
        // alone moves the post-quantum half of the composite public key
        // (StatefulSuite::VERIFY_PUBLIC_KEY_LEN's hypertree-root component
        // depends on it). Asserting on the full public key would therefore
        // pass even with the label separation removed entirely, which was
        // confirmed by running this test with `derive_stateless_vrf_seed`
        // changed to return `*master` unchanged: it passed. Assert on the
        // classical half instead, which `max_stateful_signatures` cannot
        // move: that assertion was confirmed to fail under the same
        // change, and to pass once the change was reverted.
        let suite = Suite::H5;
        let master = [13u8; 32];

        let mut vrf_pk = vec![0u8; public_key_len(suite)];
        let _key = VrfStatelessKey::derive(suite, &master, &mut vrf_pk).unwrap();

        let mut id_sk = vec![0u8; secret_key_len(suite)];
        let mut id_pk = vec![0u8; public_key_len(suite)];
        crate::keygen_stateful_from_seed(suite, &master, 4, &mut id_sk, &mut id_pk).unwrap();

        // `<H5 as StatefulSuite>::Classical::PUBLIC_KEY_LEN`, not a bare
        // number: this is the classical public key's length, which
        // `max_stateful_signatures` does not enter into.
        let classical_len = <<H5 as StatefulSuite>::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
        assert_ne!(
            &vrf_pk[..classical_len],
            &id_pk[..classical_len],
            "the VRF key's classical half collided with the identity key's"
        );
    }

    #[test]
    #[ignore = "derive_stateless_key runs keygen; 47s at 128s"]
    fn a_spent_budget_refuses_a_stateless_proof() {
        let suite = Suite::H5;
        let mut pk = vec![0u8; public_key_len(suite)];
        let key = VrfStatelessKey::derive(suite, &[13u8; 32], &mut pk).unwrap();
        let mut budget = MemoryBudget::exhausted();
        let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
        assert_eq!(
            vrf_prove_stateless(&key, &mut budget, INPUT, &mut OsRng, &mut proof).unwrap_err(),
            AbiError::StatelessBudgetExhausted
        );
    }
}
