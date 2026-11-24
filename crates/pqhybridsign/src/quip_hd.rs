// SPDX-License-Identifier: AGPL-3.0-or-later
//! QUIP HD v1: hardened-only HMAC-SHA512 key derivation from a BIP-39 seed.
//!
//! This is the derivation the QUIP EVM SDK ships (ethereum-sdk
//! `src/v1/shrincs/hd.ts` at `77204ed8`), reproduced byte for byte; the tests
//! below pin its vectors (`hd.test.ts`). It is curve-agnostic: a leaf is a
//! raw 32-byte seed, which a suite then expands with its own key generation.
//!
//! 1. **BIP-39 seed.** Standard BIP-39, unlike the `mnemonic` module: PBKDF2-
//!    HMAC-SHA512 over the normalized phrase *text*, salted with
//!    `"mnemonic" || NFKD(passphrase)`, 2048 rounds, 64 bytes
//!    ([`mnemonic_to_seed`]).
//! 2. **Master.** `I = HMAC-SHA512(key = "QUIP seed", data = seed)`; the key is
//!    `I[0..32]`, the chain code `I[32..64]` ([`master_node`]).
//! 3. **Child, hardened only.** `I = HMAC-SHA512(chain code, 0x00 || key ||
//!    ser32BE(index + 2^31))` for `index` in `[0, 2^31)`
//!    ([`derive_hardened_child`]). There is no range or zero check on the
//!    child key, as in `hd.ts`: a leaf is a seed, not a scalar.
//! 4. **Path.** `m / 0x514E' / algorithm' / network' / account' / index'`
//!    ([`QuipHdPath`]); the leaf is the key at the end of it
//!    ([`derive_quip_seed`]).
//!
//! Every level is an HMAC keyed by a secret chain code, so there is no public
//! derivation and nothing like an xpub.

use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Purpose level: `0x514E`, ASCII "QN" big-endian, the QUIP HD scheme marker.
pub const QUIP_HD_PURPOSE: u32 = 0x514E;

/// The reserved experimental algorithm identifier. Registered identifiers sit
/// below `0x7F00_0000`.
pub const ALGORITHM_EXPERIMENTAL: u32 = 0x7FFF_FFFF;

/// Network level: the QUIP network identifier, 20049 (`0x4E51`). Fixed, so
/// one mnemonic gives the same keys on every chain.
pub const NETWORK_QUIP: u32 = 20_049;

/// The BIP-32 hardened index offset, `2^31`. Every level is hardened.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// The shortest seed [`master_node`] accepts, in bytes (`hd.ts`
/// `MIN_SEED_BYTES`).
pub const MIN_SEED_LEN: usize = 16;

/// HMAC key for the master node.
const MASTER_HMAC_KEY: &[u8] = b"QUIP seed";

/// One node of the derivation tree: a 32-byte key and a 32-byte chain code,
/// both secret, wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HdNode {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl HdNode {
    /// The node's key. At a leaf, this is the derived seed.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// The node's chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Splits `I = HMAC-SHA512(..)` into a node and wipes `I`.
    fn from_hmac(mac: Hmac<Sha512>) -> Self {
        let mut i = mac.finalize().into_bytes();
        let mut node = Self {
            key: [0u8; 32],
            chain_code: [0u8; 32],
        };
        node.key.copy_from_slice(&i[..32]);
        node.chain_code.copy_from_slice(&i[32..]);
        i.as_mut_slice().zeroize();
        node
    }
}

impl fmt::Debug for HdNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HdNode(<secret>)")
    }
}

/// The master node: `I = HMAC-SHA512(key = "QUIP seed", data = seed)`.
///
/// # Errors
///
/// [`Error::HdSeedTooShort`] when `seed` is shorter than [`MIN_SEED_LEN`].
pub fn master_node(seed: &[u8]) -> Result<HdNode> {
    if seed.len() < MIN_SEED_LEN {
        return Err(Error::HdSeedTooShort { actual: seed.len() });
    }
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(MASTER_HMAC_KEY)
        .map_err(|_| Error::ComponentFailure)?;
    mac.update(seed);
    Ok(HdNode::from_hmac(mac))
}

/// The hardened child at `index`:
/// `I = HMAC-SHA512(chain code, 0x00 || key || ser32BE(index + 2^31))`.
///
/// # Errors
///
/// [`Error::HdIndexOutOfRange`] when `index` is `2^31` or more: `index` names
/// the child before the hardened offset is added.
pub fn derive_hardened_child(node: &HdNode, index: u32) -> Result<HdNode> {
    if index >= HARDENED_OFFSET {
        return Err(Error::HdIndexOutOfRange { index });
    }
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&node.chain_code)
        .map_err(|_| Error::ComponentFailure)?;
    mac.update(&[0x00]);
    mac.update(&node.key);
    mac.update(&(index + HARDENED_OFFSET).to_be_bytes());
    Ok(HdNode::from_hmac(mac))
}

/// A QUIP HD path, `m / 0x514E' / algorithm' / network' / account' / index'`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuipHdPath {
    /// The algorithm level.
    pub algorithm: u32,
    /// The network level, normally [`NETWORK_QUIP`].
    pub network: u32,
    /// The account level.
    pub account: u32,
    /// The index level.
    pub index: u32,
}

impl QuipHdPath {
    /// The path for `algorithm` on the QUIP network.
    pub const fn new(algorithm: u32, account: u32, index: u32) -> Self {
        Self {
            algorithm,
            network: NETWORK_QUIP,
            account,
            index,
        }
    }

    /// `hd.ts`'s default path: the experimental algorithm, the QUIP network,
    /// account 0.
    pub const fn experimental(index: u32) -> Self {
        Self::new(ALGORITHM_EXPERIMENTAL, 0, index)
    }

    /// The five levels, in derivation order.
    pub const fn levels(&self) -> [u32; 5] {
        [
            QUIP_HD_PURPOSE,
            self.algorithm,
            self.network,
            self.account,
            self.index,
        ]
    }
}

/// `m/20814'/2147483647'/20049'/0'/0'`, as `hd.ts`'s `quipHdPath` renders it.
impl fmt::Display for QuipHdPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for level in self.levels() {
            write!(f, "/{level}'")?;
        }
        Ok(())
    }
}

/// The 32-byte leaf at `path` under `seed`: walk every level from the
/// master node.
///
/// # Errors
///
/// [`Error::HdSeedTooShort`] for a short seed; [`Error::HdIndexOutOfRange`]
/// for a level of `2^31` or more.
pub fn derive_quip_seed(seed: &[u8], path: &QuipHdPath) -> Result<Zeroizing<[u8; 32]>> {
    let mut node = master_node(seed)?;
    for level in path.levels() {
        node = derive_hardened_child(&node, level)?;
    }
    Ok(Zeroizing::new(node.key))
}

/// Whitespace as JavaScript's `\s` defines it, which `hd.ts` splits on:
/// Unicode `White_Space` without U+0085 (NEXT LINE), plus U+FEFF (the
/// byte-order mark).
fn is_js_whitespace(c: char) -> bool {
    (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}'
}

/// The phrase with surrounding whitespace removed and every inner run of
/// whitespace collapsed to one space, as `hd.ts`'s `normalizeMnemonic`
/// (`trim().replace(/\s+/g, " ")`).
pub fn normalize_mnemonic(phrase: &str) -> String {
    let words: Vec<&str> = phrase
        .split(is_js_whitespace)
        .filter(|w| !w.is_empty())
        .collect();
    words.join(" ")
}

/// Parses the normalized phrase as an English BIP-39 mnemonic.
fn parse_mnemonic(normalized: &str) -> Result<bip39::Mnemonic> {
    // `@scure/bip39` splits the normalized phrase on single spaces only, so a
    // word containing U+0085 (Rust whitespace, not JavaScript's) is not in
    // the wordlist there. `bip39` would split on it; refuse it first.
    if normalized.chars().any(|c| c != ' ' && c.is_whitespace()) {
        return Err(Error::InvalidMnemonic);
    }
    // English words are lowercase ASCII, already NFKD; anything else fails
    // the wordlist, so the NFKD step BIP-39 asks for is a no-op here.
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, normalized)
        .map_err(|_| Error::InvalidMnemonic)
}

/// True when `phrase`, normalized, is a valid English BIP-39 mnemonic: every
/// word in the wordlist, a valid word count and checksum.
pub fn validate_mnemonic(phrase: &str) -> bool {
    parse_mnemonic(&normalize_mnemonic(phrase)).is_ok()
}

/// The standard BIP-39 seed of `phrase` and `passphrase`: PBKDF2-HMAC-SHA512
/// over the normalized phrase, salt `"mnemonic" || NFKD(passphrase)`, 2048
/// rounds, 64 bytes. The phrase is validated first, as `hd.ts` does.
///
/// This is not `mnemonic::master_seed_from_mnemonic`, which hashes
/// the mnemonic's entropy the way Substrate does and keeps 32 bytes. The same
/// phrase gives different seeds through the two.
///
/// Residual: `bip39` normalizes a non-NFKD passphrase into a `String` it does
/// not wipe.
///
/// # Errors
///
/// [`Error::InvalidMnemonic`] when the phrase is not a valid English BIP-39
/// mnemonic.
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    let mut normalized = normalize_mnemonic(phrase);
    let result = parse_mnemonic(&normalized).map(|m| Zeroizing::new(m.to_seed(passphrase)));
    normalized.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `hd.test.ts`: `"a deterministic test seed 32b+.."`.
    const SEED: &[u8] = b"a deterministic test seed 32b+..";

    #[test]
    fn the_path_registry_values_are_pinned() {
        assert_eq!(QUIP_HD_PURPOSE, 0x514e);
        assert_eq!(ALGORITHM_EXPERIMENTAL, 0x7fff_ffff);
        assert_eq!(NETWORK_QUIP, 20049);
        assert_eq!(HARDENED_OFFSET, 0x8000_0000);
    }

    #[test]
    fn the_master_node_is_deterministic_and_splits_key_from_chain_code() {
        let a = master_node(SEED).expect("seed");
        let b = master_node(SEED).expect("seed");
        assert_eq!(a.key(), b.key());
        assert_eq!(a.chain_code(), b.chain_code());
        assert_ne!(a.key(), a.chain_code());
    }

    #[test]
    fn the_master_node_needs_sixteen_bytes() {
        assert_eq!(
            master_node(&[0u8; 15]).err(),
            Some(Error::HdSeedTooShort { actual: 15 })
        );
        assert!(master_node(&[1u8; 16]).is_ok());
    }

    #[test]
    fn hardened_children_are_distinct_deterministic_and_bounded() {
        let node = master_node(SEED).expect("seed");
        let c0 = derive_hardened_child(&node, 0).expect("0");
        let c1 = derive_hardened_child(&node, 1).expect("1");
        assert_ne!(c0.key(), c1.key());
        assert_eq!(
            derive_hardened_child(&node, 7).expect("7").key(),
            derive_hardened_child(&node, 7).expect("7").key()
        );
        assert!(derive_hardened_child(&node, HARDENED_OFFSET - 1).is_ok());
        assert_eq!(
            derive_hardened_child(&node, HARDENED_OFFSET).err(),
            Some(Error::HdIndexOutOfRange {
                index: HARDENED_OFFSET
            })
        );
    }

    #[test]
    fn every_path_level_separates_the_leaf() {
        let leaf = |path: QuipHdPath| derive_quip_seed(SEED, &path).expect("leaf");
        let base = leaf(QuipHdPath::experimental(0));
        let mut account = QuipHdPath::experimental(0);
        account.account = 1;
        let mut network = QuipHdPath::experimental(0);
        network.network = NETWORK_QUIP + 1;
        let mut algorithm = QuipHdPath::experimental(0);
        algorithm.algorithm = 1;
        for other in [QuipHdPath::experimental(1), account, network, algorithm] {
            assert_ne!(*leaf(other), *base, "{other}");
        }
        assert_eq!(
            *leaf(QuipHdPath::new(ALGORITHM_EXPERIMENTAL, 0, 3)),
            *leaf(QuipHdPath::experimental(3))
        );
    }

    #[test]
    fn paths_render_as_in_hd_ts() {
        assert_eq!(
            QuipHdPath::experimental(0).to_string(),
            "m/20814'/2147483647'/20049'/0'/0'"
        );
        let path = QuipHdPath {
            algorithm: 7,
            network: 9,
            account: 2,
            index: 5,
        };
        assert_eq!(path.to_string(), "m/20814'/7'/9'/2'/5'");
    }

    /// `hd.test.ts`, "QUIP HD v1 regression vectors": "never drifts".
    #[test]
    fn the_hd_ts_regression_vectors_reproduce() {
        let seed = b"QUIP HD v1 regression vector seed";
        let leaf =
            |index| hex(&*derive_quip_seed(seed, &QuipHdPath::experimental(index)).expect("leaf"));
        assert_eq!(
            leaf(0),
            "e384e03583d60da36e3fdbad396a0f3a9c98512007bd07999d9f8db870db8bb2"
        );
        assert_eq!(
            leaf(1),
            "afe51b913c23f2baf73026cdc8c6cdf2477a01116e525f30ba0f224a76198700"
        );
        assert_eq!(
            leaf(2_147_483_646),
            "d20cef6c7abf8265603938a64a5028948867107a63f4d9f086aa9cf6f8e475c9"
        );
    }

    /// `hd.test.ts`: "matches the reference BIP-39 vector (Trezor vector 1)".
    #[test]
    fn the_trezor_bip39_vector_reproduces() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase, "TREZOR").expect("valid phrase");
        assert_eq!(
            hex(&*seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn an_invalid_mnemonic_is_rejected() {
        assert!(!validate_mnemonic("abandon abandon abandon"));
        assert_eq!(
            mnemonic_to_seed("abandon abandon abandon", "").err(),
            Some(Error::InvalidMnemonic)
        );
        // Bad checksum: the last word of the Trezor phrase changed.
        assert!(!validate_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        ));
    }

    #[test]
    fn the_passphrase_changes_the_seed() {
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_ne!(
            *mnemonic_to_seed(phrase, "").expect("valid"),
            *mnemonic_to_seed(phrase, "x").expect("valid")
        );
    }

    /// `hd.test.ts`: "tolerates leading, trailing, and doubled whitespace".
    #[test]
    fn surrounding_and_doubled_whitespace_is_tolerated() {
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let dirty =
            " legal  winner thank year wave sausage worth useful legal winner thank yellow\n";
        assert!(validate_mnemonic(dirty));
        assert_eq!(
            *mnemonic_to_seed(dirty, "").expect("valid"),
            *mnemonic_to_seed(phrase, "").expect("valid")
        );
    }

    /// `normalizeMnemonic` splits on JavaScript's `\s`: a byte-order mark and a
    /// no-break space separate words, U+0085 (NEXT LINE) does not.
    #[test]
    fn whitespace_follows_javascript() {
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(normalize_mnemonic(&format!("\u{feff}{phrase}")), phrase);
        assert_eq!(
            normalize_mnemonic(&phrase.replacen(' ', "\u{a0}\u{3000}", 1)),
            phrase
        );
        assert!(!validate_mnemonic(&phrase.replacen(' ', "\u{85}", 1)));
    }

    /// BIP-39 normalizes the passphrase to NFKD, as `@scure/bip39` does: a
    /// precomposed and a decomposed "é" give one seed.
    #[test]
    fn the_passphrase_is_nfkd_normalized() {
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(
            *mnemonic_to_seed(phrase, "caf\u{e9}").expect("valid"),
            *mnemonic_to_seed(phrase, "cafe\u{301}").expect("valid")
        );
    }

    #[test]
    fn a_node_does_not_print_its_secrets() {
        let node = master_node(SEED).expect("seed");
        assert_eq!(format!("{node:?}"), "HdNode(<secret>)");
    }
}
