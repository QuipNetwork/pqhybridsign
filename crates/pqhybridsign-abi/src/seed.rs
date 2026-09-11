// SPDX-License-Identifier: AGPL-3.0-or-later
//! Master seed derivation: recovery phrases and hard junctions.

use zeroize::Zeroize;

use crate::error::AbiError;

/// Length of a master seed, in bytes.
pub const MASTER_SEED_LEN: usize = 32;

/// Length of a junction chain code, in bytes.
pub const CHAIN_CODE_LEN: usize = 32;

/// Turn an English BIP39 recovery phrase into a master seed.
///
/// This is Substrate's seed derivation, not standard BIP39: PBKDF2-HMAC-
/// SHA512 runs over the mnemonic's **entropy**, not over the phrase text,
/// salted with `"mnemonic" || password`, for 2048 rounds, and the first 32
/// bytes are the master seed. A caller that reproduces this with a stock
/// BIP39 library gets a different seed and therefore a different key.
///
/// `password` is the empty string when `None`, matching Substrate's
/// `Pair::from_phrase`.
///
/// `out` holds secret material. Wipe it when finished.
///
/// # Errors
///
/// [`AbiError::InvalidMnemonic`] if `phrase` is not a valid English BIP39
/// mnemonic: a wrong word count, an unknown word, or a bad checksum. The
/// three are not distinguished, because telling an attacker which part of
/// a guessed phrase was wrong narrows the search.
pub fn master_seed_from_mnemonic(
    phrase: &str,
    password: Option<&str>,
    out: &mut [u8; MASTER_SEED_LEN],
) -> Result<(), AbiError> {
    let mut seed = pqhybridsign::mnemonic::master_seed_from_mnemonic(phrase, password)?;
    out.copy_from_slice(&seed);
    seed.zeroize();
    Ok(())
}

/// Derive a hard-junction child master seed.
///
/// `[a, b]` in [`derive_hard_junction_path`] means
/// `derive_hard_junction(derive_hard_junction(parent, a), b)`. Order is
/// part of the derivation.
///
/// # The re-keygen hazard
///
/// Derivation is deterministic, so the same parent and the same chain code
/// reach the same child seed on every host that computes it, and therefore
/// the same stateful tree starting at leaf 1. Deriving one child twice on
/// two hosts is the same failure as importing one key twice: both hosts
/// spend leaf 1, and the post-quantum security of that key is gone.
///
/// A derived child must be derived once, then persisted and restored
/// through the validating import path. A key pool spanning several nodes
/// must give each node its own distinct junction. Never re-derive one
/// junction on a second host.
///
/// `out` holds secret material. Wipe it when finished.
///
/// # Errors
///
/// [`AbiError::ComponentFailure`] if the key derivation function fails.
pub fn derive_hard_junction(
    parent_master: &[u8; MASTER_SEED_LEN],
    chain_code: &[u8; CHAIN_CODE_LEN],
    out: &mut [u8; MASTER_SEED_LEN],
) -> Result<(), AbiError> {
    let mut child = pqhybridsign::derive::derive_hard_junction(parent_master, chain_code)?;
    out.copy_from_slice(&child);
    child.zeroize();
    Ok(())
}

/// Apply a sequence of chain codes in order, each child becoming the next
/// parent.
///
/// Every intermediate seed is wiped once the next is derived from it. Only
/// the final seed reaches `out`, and wiping that is the caller's job.
///
/// **An empty `chain_codes` returns `parent_master` unchanged.** That is
/// the identity a path of no junctions should have, and it is a trap for a
/// caller building the path from parsed input: a parse that silently
/// yielded no junctions hands back the parent key rather than failing. A
/// caller that requires at least one junction must check for that itself.
///
/// See [`derive_hard_junction`] for the re-keygen hazard, which applies to
/// every seed this function returns.
///
/// # Errors
///
/// [`AbiError::ComponentFailure`] if the key derivation function fails.
pub fn derive_hard_junction_path(
    parent_master: &[u8; MASTER_SEED_LEN],
    chain_codes: &[[u8; CHAIN_CODE_LEN]],
    out: &mut [u8; MASTER_SEED_LEN],
) -> Result<(), AbiError> {
    let mut child = pqhybridsign::derive::derive_hard_junction_path(parent_master, chain_codes)?;
    out.copy_from_slice(&child);
    child.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The standard all-zero-entropy BIP39 test vector.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about";

    #[test]
    fn a_valid_phrase_produces_a_master_seed() {
        let mut seed = [0u8; MASTER_SEED_LEN];
        master_seed_from_mnemonic(PHRASE, None, &mut seed).unwrap();
        assert_ne!(seed, [0u8; MASTER_SEED_LEN]);

        // Same phrase, same seed. This is the property a recovery flow
        // depends on.
        let mut again = [0u8; MASTER_SEED_LEN];
        master_seed_from_mnemonic(PHRASE, None, &mut again).unwrap();
        assert_eq!(seed, again);
    }

    // `pqhybridsign::mnemonic`'s own `PHRASE_12` golden-vector phrase and
    // expected seed (`crates/pqhybridsign/src/mnemonic.rs`), copied
    // verbatim rather than retyped. That module pins byte-for-byte parity
    // with `quip-validator`'s own `master_seed_from_mnemonic`
    // (crates/transaction-crypto-core/src/lib.rs, on top of substrate-bip39
    // 0.6.1), generated 2026-08-21. `a_valid_phrase_produces_a_master_seed`
    // above only checks shape (non-zero, stable), which a wrapper that
    // mangled its arguments could also satisfy; this pins that this
    // crate's entry point reaches the same derivation. Do not "fix" a
    // failing assertion here by pasting in whatever the code currently
    // returns -- that is exactly the failure mode a pinned vector exists
    // to catch.
    const PHRASE_12: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn a_valid_phrase_matches_the_core_crates_golden_vector() {
        let mut seed = [0u8; MASTER_SEED_LEN];
        master_seed_from_mnemonic(PHRASE_12, None, &mut seed).unwrap();
        assert_eq!(
            hex(&seed),
            "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"
        );
    }

    #[test]
    fn the_abi_agrees_with_the_core_crate() {
        // The wrapper must not transform anything. If it did, a Rust caller
        // and a C caller would derive different keys from one phrase.
        let mut seed = [0u8; MASTER_SEED_LEN];
        master_seed_from_mnemonic(PHRASE, Some("pw"), &mut seed).unwrap();
        let expected =
            pqhybridsign::mnemonic::master_seed_from_mnemonic(PHRASE, Some("pw")).unwrap();
        assert_eq!(seed, expected);
    }

    #[test]
    fn a_password_changes_the_seed() {
        let mut without = [0u8; MASTER_SEED_LEN];
        let mut with = [0u8; MASTER_SEED_LEN];
        master_seed_from_mnemonic(PHRASE, None, &mut without).unwrap();
        master_seed_from_mnemonic(PHRASE, Some("pw"), &mut with).unwrap();
        assert_ne!(without, with);
    }

    #[test]
    fn an_invalid_phrase_is_refused() {
        let mut seed = [0u8; MASTER_SEED_LEN];
        assert_eq!(
            master_seed_from_mnemonic("not a mnemonic at all", None, &mut seed).unwrap_err(),
            AbiError::InvalidMnemonic
        );
    }

    #[test]
    fn a_junction_child_differs_from_its_parent_and_its_sibling() {
        let parent = [3u8; MASTER_SEED_LEN];
        let mut a = [0u8; MASTER_SEED_LEN];
        let mut b = [0u8; MASTER_SEED_LEN];
        derive_hard_junction(&parent, &[1u8; CHAIN_CODE_LEN], &mut a).unwrap();
        derive_hard_junction(&parent, &[2u8; CHAIN_CODE_LEN], &mut b).unwrap();
        assert_ne!(a, parent);
        assert_ne!(a, b);
    }

    #[test]
    fn a_path_applies_its_chain_codes_in_order() {
        let parent = [3u8; MASTER_SEED_LEN];
        let first = [1u8; CHAIN_CODE_LEN];
        let second = [2u8; CHAIN_CODE_LEN];

        let mut stepwise = [0u8; MASTER_SEED_LEN];
        derive_hard_junction(&parent, &first, &mut stepwise).unwrap();
        let intermediate = stepwise;
        derive_hard_junction(&intermediate, &second, &mut stepwise).unwrap();

        let mut path = [0u8; MASTER_SEED_LEN];
        derive_hard_junction_path(&parent, &[first, second], &mut path).unwrap();
        assert_eq!(stepwise, path);

        // Order matters.
        let mut reversed = [0u8; MASTER_SEED_LEN];
        derive_hard_junction_path(&parent, &[second, first], &mut reversed).unwrap();
        assert_ne!(path, reversed);
    }

    #[test]
    fn an_empty_path_returns_the_parent() {
        // Documented, not accidental: a caller that parsed an empty path
        // gets the parent key back rather than an error, and must check for
        // that itself.
        let parent = [3u8; MASTER_SEED_LEN];
        let mut out = [0u8; MASTER_SEED_LEN];
        derive_hard_junction_path(&parent, &[], &mut out).unwrap();
        assert_eq!(out, parent);
    }
}
