// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hybrid verifiable random function, dispatched by suite.
//!
//! The core VRF lives in `pqhybridsign::vrf` behind the `vrf` feature. It
//! has three function families, one for each shape of post-quantum
//! binding:
//!
//! - `vrf::sign`, `sign_deterministic`, `verify`, `make_bytes`,
//!   `proof_len` for a fixed-length binding. EdMl44 and SrMl44.
//! - `vrf::sign_delta`, `sign_delta_deterministic`, `verify_delta`,
//!   `make_bytes_delta`, `max_proof_len_delta` for a delta-length
//!   binding. EdFn512 and SrFn512.
//! - `vrf::sign_stateless`, `verify_stateless`, `make_bytes_stateless`,
//!   `proof_len_stateless`, `derive_stateless_key` for the stateful
//!   suites. EdSh and SrSh.
//!
//! [`vrf_proof_len`], [`vrf_verify`] and [`vrf_make_bytes`] span all six
//! suites and dispatch internally. Every suite supports the mechanism.
//!
//! Proving splits, and the split follows the house pattern rather than
//! inventing a new one. [`crate::sign`] covers EdMl44 through SrFn512 and rejects
//! EdSh and SrSh with [`AbiError::WrongEntryPointForSuite`], because a
//! stateless-looking call that silently spent state is the worst failure
//! this crate could offer. VRF proving has exactly that shape: EdMl44 through
//! SrFn512 spend nothing, while EdSh and SrSh spend one unit of the few-time
//! stateless budget and need a durable store to record it. So
//! [`vrf_prove`] and [`vrf_prove_deterministic`] cover EdMl44 through SrFn512 and
//! reject EdSh and SrSh, and [`vrf_prove_stateless`] covers EdSh and SrSh through
//! a key handle and a budget store.
//!
//! EdSh and SrSh also need a key that is not the identity key. `pqhs-1l6`
//! settled that: `vrf::derive_stateless_key` derives a SHRINCS key
//! disjoint from the rotation and recovery identity key, under a separate
//! label. The core type is `DedicatedVrfKey<S>`, which cannot be exported
//! to bytes, so a binding must hold it. [`VrfStatelessKey`] is that
//! holder, built the same way [`crate::StatefulKeyHandle`] is.

use pqhybridsign::budget::StatelessBudgetStore;
use pqhybridsign::shrincs::{EdSh, SrSh};
use pqhybridsign::stateful_composite::SecretKey;
use pqhybridsign::suite::{DeltaSuite, StatefulSuite, Suite as CoreSuite};
use pqhybridsign::vrf::{self, ClassicalVrf, DedicatedVrfKey};
use pqhybridsign::{EdFn512, EdMl44, SrFn512, SrMl44};

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
/// For EdMl44 and SrMl44 this is exact. For EdFn512 and SrFn512 this is the maximum a
/// delta-length binding can occupy. For EdSh and SrSh this is exact: the
/// stateless SHRINCS binding has a fixed length.
pub fn vrf_proof_len(suite: Suite) -> Result<usize, AbiError> {
    match suite {
        Suite::EdMl44 => Ok(proof_len_fixed::<EdMl44>()),
        Suite::SrMl44 => Ok(proof_len_fixed::<SrMl44>()),
        Suite::EdFn512 => Ok(proof_len_delta::<EdFn512>()),
        Suite::SrFn512 => Ok(proof_len_delta::<SrFn512>()),
        Suite::EdSh => Ok(proof_len_stateless_suite::<EdSh>()),
        Suite::SrSh => Ok(proof_len_stateless_suite::<SrSh>()),
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
/// suites (SrMl44, SrFn512) hedge the classical proof's nonce with it, so two
/// evaluations produce different proof bytes. The ed25519 suites (EdMl44, EdFn512)
/// ignore it: RFC 9381 section 5.4.2.2 derives the ECVRF nonce from the
/// secret key and the input, so their proofs are deterministic and
/// [`vrf_prove_deterministic`] returns the identical bytes. Pass an `rng`
/// regardless -- which suites use it is not part of this API's contract.
///
/// EdMl44 through SrFn512 only. EdSh and SrSh spend one unit of a few-time stateless
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
/// [`AbiError::WrongEntryPointForSuite`] for EdSh and SrSh.
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
        Suite::EdMl44 => prove_fixed::<EdMl44>(sk, input, rng, proof_out),
        Suite::SrMl44 => prove_fixed::<SrMl44>(sk, input, rng, proof_out),
        Suite::EdFn512 => prove_delta::<EdFn512>(sk, input, rng, proof_out),
        Suite::SrFn512 => prove_delta::<SrFn512>(sk, input, rng, proof_out),
        Suite::EdSh | Suite::SrSh => Err(AbiError::WrongEntryPointForSuite),
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
/// EdMl44 through SrFn512 only, on the same terms as [`vrf_prove`]: EdSh and SrSh
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
        Suite::EdMl44 => prove_fixed_deterministic::<EdMl44>(sk, input, proof_out),
        Suite::SrMl44 => prove_fixed_deterministic::<SrMl44>(sk, input, proof_out),
        Suite::EdFn512 => prove_delta_deterministic::<EdFn512>(sk, input, proof_out),
        Suite::SrFn512 => prove_delta_deterministic::<SrFn512>(sk, input, proof_out),
        Suite::EdSh | Suite::SrSh => Err(AbiError::WrongEntryPointForSuite),
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
        Suite::EdMl44 => vrf::verify::<EdMl44>(pk, input, proof),
        Suite::SrMl44 => vrf::verify::<SrMl44>(pk, input, proof),
        Suite::EdFn512 => vrf::verify_delta::<EdFn512>(pk, input, proof),
        Suite::SrFn512 => vrf::verify_delta::<SrFn512>(pk, input, proof),
        Suite::EdSh => vrf::verify_stateless::<EdSh>(pk, input, proof),
        Suite::SrSh => vrf::verify_stateless::<SrSh>(pk, input, proof),
    }
}

/// Derive [`VRF_OUTPUT_LEN`] output bytes from a verified proof.
///
/// This verifies the proof first, the same check [`vrf_verify`] makes, and
/// derives only on success. A caller that already called [`vrf_verify`]
/// pays for the check twice, which is cheap next to deriving consensus
/// bytes from an attacker's proof.
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
/// [`AbiError::BadLength`] if `pk` or `proof` is not the suite's length.
/// [`AbiError::InvalidProof`] if the proof does not verify under `pk` and
/// `input`, including a public key or pre-output that does not decode.
pub fn vrf_make_bytes(
    suite: Suite,
    pk: &[u8],
    input: &[u8],
    proof: &[u8],
    context: &[u8],
    out: &mut [u8; VRF_OUTPUT_LEN],
) -> Result<(), AbiError> {
    *out = match suite {
        Suite::EdMl44 => make_bytes_fixed::<EdMl44>(pk, input, proof, context)?,
        Suite::SrMl44 => make_bytes_fixed::<SrMl44>(pk, input, proof, context)?,
        Suite::EdFn512 => make_bytes_delta::<EdFn512>(pk, input, proof, context)?,
        Suite::SrFn512 => make_bytes_delta::<SrFn512>(pk, input, proof, context)?,
        Suite::EdSh => make_bytes_stateless_suite::<EdSh>(pk, input, proof, context)?,
        Suite::SrSh => make_bytes_stateless_suite::<SrSh>(pk, input, proof, context)?,
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
/// EdSh and SrSh evaluate the VRF through their post-quantum half's few-time
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
    EdSh(DedicatedVrfKey<EdSh>),
    SrSh(DedicatedVrfKey<SrSh>),
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
    /// [`AbiError::WrongEntryPointForSuite`] for EdMl44-SrFn512.
    /// [`AbiError::BadLength`] if `pk_out` is not
    /// [`crate::public_key_len`] bytes for `suite`.
    /// [`AbiError::ComponentFailure`] if derivation fails.
    pub fn derive(
        suite: Suite,
        master: &[u8; MASTER_SEED_LEN],
        pk_out: &mut [u8],
    ) -> Result<Self, AbiError> {
        match suite {
            Suite::EdSh => Ok(Self {
                inner: Inner::EdSh(derive_suite::<EdSh>(master, pk_out)?),
            }),
            Suite::SrSh => Ok(Self {
                inner: Inner::SrSh(derive_suite::<SrSh>(master, pk_out)?),
            }),
            Suite::EdMl44 | Suite::EdFn512 | Suite::SrMl44 | Suite::SrFn512 => {
                Err(AbiError::WrongEntryPointForSuite)
            }
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
    /// [`AbiError::WrongEntryPointForSuite`] for EdMl44-SrFn512.
    /// [`AbiError::BadLength`] if `sk` is not [`crate::secret_key_len`]
    /// bytes for `suite`. [`AbiError::ComponentFailure`] if the blob does
    /// not import.
    pub fn adopt_unchecked(suite: Suite, sk: &[u8]) -> Result<Self, AbiError> {
        match suite {
            Suite::EdSh => Ok(Self {
                inner: Inner::EdSh(DedicatedVrfKey::adopt_unchecked(import_checked::<EdSh>(
                    sk,
                )?)),
            }),
            Suite::SrSh => Ok(Self {
                inner: Inner::SrSh(DedicatedVrfKey::adopt_unchecked(import_checked::<SrSh>(
                    sk,
                )?)),
            }),
            Suite::EdMl44 | Suite::EdFn512 | Suite::SrMl44 | Suite::SrFn512 => {
                Err(AbiError::WrongEntryPointForSuite)
            }
        }
    }

    /// The suite this key was derived or adopted for.
    #[must_use]
    pub fn suite(&self) -> Suite {
        match self.inner {
            Inner::EdSh(_) => Suite::EdSh,
            Inner::SrSh(_) => Suite::SrSh,
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

/// Evaluate the hybrid VRF under EdSh or SrSh, spending one unit of the
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
        Inner::EdSh(sk) => prove_stateless_suite(sk, budget, input, rng, proof_out),
        Inner::SrSh(sk) => prove_stateless_suite(sk, budget, input, rng, proof_out),
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
    use crate::{keygen_from_seed, public_key_len, secret_key_len, AbiError, Suite};
    use pqhybridsign::component::ClassicalScheme;
    use pqhybridsign_test_support::MemoryBudget;
    use rand_core::OsRng;

    const INPUT: &[u8] = b"epoch-7/slot-42/randomness";
    const OTHER: &[u8] = b"epoch-7/slot-43/randomness";
    const OUT_CTX: &[u8] = b"leadership-score";

    const STATELESS: [Suite; 4] = [Suite::EdMl44, Suite::EdFn512, Suite::SrMl44, Suite::SrFn512];

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

    /// QUI-1766: `vrf_make_bytes` verifies before it derives, so a proof
    /// that `vrf_verify` rejects is refused with its own code rather than
    /// turned into output bytes.
    #[test]
    fn make_bytes_refuses_a_tampered_proof() {
        for suite in STATELESS {
            let (sk, pk) = keypair(suite);
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut proof).unwrap();
            proof[n - 1] ^= 0x01;
            let mut out = [0u8; VRF_OUTPUT_LEN];
            assert_eq!(
                vrf_make_bytes(suite, &pk, INPUT, &proof[..n], OUT_CTX, &mut out),
                Err(AbiError::InvalidProof),
                "{suite:?} derived bytes from a tampered proof"
            );
        }
    }

    #[test]
    fn make_bytes_refuses_a_public_key_that_does_not_decode() {
        for suite in STATELESS {
            let (sk, mut pk) = keypair(suite);
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut proof).unwrap();
            pk.fill(0xff);
            let mut out = [0u8; VRF_OUTPUT_LEN];
            assert_eq!(
                vrf_make_bytes(suite, &pk, INPUT, &proof[..n], OUT_CTX, &mut out),
                Err(AbiError::InvalidProof),
                "{suite:?} derived bytes from a public key that does not decode"
            );
        }
    }

    #[test]
    fn make_bytes_refuses_a_pre_output_that_does_not_decode() {
        for suite in STATELESS {
            let (sk, pk) = keypair(suite);
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove(suite, &sk, INPUT, &mut OsRng, &mut proof).unwrap();
            proof[..32].fill(0xff);
            let mut out = [0u8; VRF_OUTPUT_LEN];
            assert_eq!(
                vrf_make_bytes(suite, &pk, INPUT, &proof[..n], OUT_CTX, &mut out),
                Err(AbiError::InvalidProof),
                "{suite:?} derived bytes from a pre-output that does not decode"
            );
        }
    }

    #[test]
    fn make_bytes_refuses_a_proof_for_another_input() {
        for suite in STATELESS {
            let (sk, pk) = keypair(suite);
            let mut proof = vec![0u8; vrf_proof_len(suite).unwrap()];
            let n = vrf_prove(suite, &sk, OTHER, &mut OsRng, &mut proof).unwrap();
            let mut out = [0u8; VRF_OUTPUT_LEN];
            assert_eq!(
                vrf_make_bytes(suite, &pk, INPUT, &proof[..n], OUT_CTX, &mut out),
                Err(AbiError::InvalidProof),
                "{suite:?} derived bytes from another input's proof"
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
        // EdMl44/EdFn512 are ed25519: RFC 9381 derives the ECVRF nonce from the key and
        // input, so their proofs are deterministic and must NOT be asserted to
        // differ.
        const HEDGED: [Suite; 2] = [Suite::SrMl44, Suite::SrFn512];
        const DETERMINISTIC: [Suite; 2] = [Suite::EdMl44, Suite::EdFn512];

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
        let suite = Suite::SrMl44;
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
        for suite in [Suite::EdSh, Suite::SrSh] {
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
        // The reverse refusal. EdMl44-SrFn512 have no stateful half, so there is no
        // dedicated stateless VRF key to derive or adopt for them.
        for suite in [Suite::EdMl44, Suite::EdFn512, Suite::SrMl44, Suite::SrFn512] {
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
        let suite = Suite::EdMl44;
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
        for suite in [Suite::EdSh, Suite::SrSh] {
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
        // (1 for the VRF path, 4 for the identity path). The SHRINCS bundle
        // stores `maxSignatures` verbatim at bundle offset 64
        // (shrincs/bundle.rs:47, written by `write_bundle` from
        // `keygen_from_seed` at shrincs/scheme.rs:162-164), so that field
        // alone moves the post-quantum half of the composite public key --
        // this is established by reading the bundle format, not by running
        // anything. Asserting on the full public key would therefore pass
        // even with the label separation removed entirely, whatever the
        // seed is. Assert on the classical half instead, which
        // `max_stateful_signatures` cannot move: that assertion was
        // confirmed by running this test, with `derive_stateless_vrf_seed`
        // changed to return `*master` unchanged, to fail under the change,
        // and to pass once the change was reverted.
        let suite = Suite::EdSh;
        let master = [13u8; 32];

        let mut vrf_pk = vec![0u8; public_key_len(suite)];
        let _key = VrfStatelessKey::derive(suite, &master, &mut vrf_pk).unwrap();

        let mut id_sk = vec![0u8; secret_key_len(suite)];
        let mut id_pk = vec![0u8; public_key_len(suite)];
        crate::keygen_stateful_from_seed(suite, &master, 4, &mut id_sk, &mut id_pk).unwrap();

        // `<EdSh as StatefulSuite>::Classical::PUBLIC_KEY_LEN`, not a bare
        // number: this is the classical public key's length, which
        // `max_stateful_signatures` does not enter into.
        let classical_len = <<EdSh as StatefulSuite>::Classical as ClassicalScheme>::PUBLIC_KEY_LEN;
        assert_ne!(
            &vrf_pk[..classical_len],
            &id_pk[..classical_len],
            "the VRF key's classical half collided with the identity key's"
        );
    }

    #[test]
    #[ignore = "derive_stateless_key runs keygen; 47s at 128s"]
    fn a_spent_budget_refuses_a_stateless_proof() {
        let suite = Suite::EdSh;
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
