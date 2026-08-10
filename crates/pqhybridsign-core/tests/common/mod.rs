// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stub component implementations shared across integration tests.
#![allow(dead_code)]

use pqhybridsign_core::{ClassicalScheme, PqScheme, Result};
use subtle::Choice;

pub struct Ed25519Stub;
pub struct MlDsaStub;

impl ClassicalScheme for Ed25519Stub {
    const NAME: &'static str = "ed25519";
    const PUBLIC_KEY_LEN: usize = 32;
    const SECRET_KEY_LEN: usize = 64;
    const SIGNATURE_LEN: usize = 64;
    fn derive(_s: &[u8; 32], _sk: &mut [u8], _pk: &mut [u8]) -> Result<()> {
        Ok(())
    }
    fn sign(
        _a: &[u8],
        _b: &[u8],
        _c: &'static [u8],
        _r: &mut impl rand_core::CryptoRngCore,
        _o: &mut [u8],
    ) -> Result<()> {
        Ok(())
    }
    fn sign_deterministic(
        _a: &[u8],
        _b: &[u8],
        _n: &[u8],
        _c: &'static [u8],
        _o: &mut [u8],
    ) -> Result<()> {
        Ok(())
    }
    fn verify(_a: &[u8], _b: &[u8], _c: &'static [u8], _d: &[u8]) -> Choice {
        Choice::from(1u8)
    }
}

impl PqScheme for MlDsaStub {
    const NAME: &'static str = "mldsa44";
    const PUBLIC_KEY_LEN: usize = 1312;
    const SECRET_KEY_LEN: usize = 2560;
    const SIGNATURE_LEN: usize = 2420;
    const SEED_LEN: usize = 32;
    const IS_DETERMINISTIC: bool = true;
    fn derive(_s: &[u8], _sk: &mut [u8], _pk: &mut [u8]) -> Result<()> {
        Ok(())
    }
    fn sign(
        _a: &[u8],
        _b: &[u8],
        _r: &mut impl rand_core::CryptoRngCore,
        _o: &mut [u8],
    ) -> Result<()> {
        Ok(())
    }
    fn sign_deterministic(_a: &[u8], _b: &[u8], _n: &[u8], _o: &mut [u8]) -> Result<()> {
        Ok(())
    }
    fn verify(_a: &[u8], _b: &[u8], _c: &[u8]) -> Choice {
        Choice::from(1u8)
    }
}
