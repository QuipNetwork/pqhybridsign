// SPDX-License-Identifier: AGPL-3.0-or-later
// Integration test binary: `cfg(test)` is always true here. `unwrap`/
// `expect`/`panic` are the normal way a test fails.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)
)]
#![cfg(feature = "quip-hd")]
//! The QUIP HD golden parity file, `tests/vectors/quip_hd_parity.json`
//! (design note v2.1 §6).
//!
//! One file, generated here, checked by every implementation of the Quip
//! Substrate profile: this crate, the SDK fork, `transaction-crypto-core`,
//! and the wasm (npm) and Python signers. Each case names the layers it
//! applies to:
//!
//! - `quip-hd`: this crate's `hybrid_leaf` / `keypair_from_seed`, given the
//!   case's derivation inputs (`phrase`, `passphrase`, `account`, `index`,
//!   or `raw_seed` and `junction_chain_codes`);
//! - `sdk`: the SDK fork's `Pair::from_string(suri, None)`, which parses
//!   with upstream `AddressUri` (ASCII phrase class), resolves junctions
//!   (design §3, §4) and must reach the same seeds;
//! - `signer`: `transaction-crypto-core` and the browser and Python signers,
//!   which accept the junction-free subset (design §6).
//!
//! Positive cases give, per suite, the 32-byte master seed the SURI selects
//! and the SHA-256 of the public key `keypair_from_seed` makes from it; the
//! first case also carries the full public keys. Negative cases list the
//! layers that must reject the SURI.
//!
//! `generate_quip_hd_parity` (ignored) prints the file:
//! `cargo test -p pqhybridsign --features quip-hd --test quip_hd_parity -- \
//!  --ignored --nocapture generate > tests/vectors/quip_hd_parity.json`.

use std::collections::BTreeMap;

use pqhybridsign::derive::derive_hard_junction;
use pqhybridsign::quip_hd::{hybrid_leaf, HybridSuite};
use pqhybridsign::suite::{DeltaSuite, Suite};
use pqhybridsign::{composite, composite_delta, EdFn512, EdMl44, SrFn512, SrMl44};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// sp-core's `DEV_PHRASE`: an empty SURI phrase means this.
const DEV_PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
/// A phrase with a tab, a no-break space and a trailing newline.
const TAB_NBSP_SURI: &str =
    "legal\twinner thank year wave sausage worth useful legal winner thank\u{a0}yellow\n";
const RAW: &str = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
/// `f(t)` of design §3 for named junctions: `u32::from_le_bytes(
/// blake2_256(SCALE(t))[0..4]) & 0x7FFF_FFFF`. Recomputed independently
/// (Python hashlib.blake2b); claude's R9 script gave the same values.
const F_ALICE: u32 = 910_586_124;
const F_BOB: u32 = 1_714_080_267;
/// A junction name of 64 bytes or more, so its SCALE compact length prefix
/// takes two bytes (`0x1901` for 70 bytes), and `f` of it.
const LONG_PHRASE_JUNCTION: &str =
    "QUIP-HD-parity-phrase-junction-name-that-is-sixty-four-bytes-or-more!!";
const F_LONG_PHRASE_JUNCTION: u32 = 218_918_165;
/// A raw-seed junction name whose SCALE encoding is more than 32 bytes, so
/// upstream `DeriveJunction` uses `blake2_256(SCALE(name))` as its chain
/// code, and that chain code. Both values are recomputed by
/// `scripts/quip-hd-leaf-crosscheck.py` (hashlib.blake2b).
const LONG_RAW_JUNCTION: &str = "QUIP-HD-parity-raw-seed-junction-name";
const LONG_RAW_JUNCTION_CC: &str =
    "138c2ec7d940313a0df3f8c7e81abb307dfc62c6d14e78d8a2815861ed49de92";

const SUITES: [(&str, &str, HybridSuite); 4] = [
    ("H1", "ED-ML-44", HybridSuite::EdMl44),
    ("H2", "ED-FN-512", HybridSuite::EdFn512),
    ("H3", "SR-ML-44", HybridSuite::SrMl44),
    ("H4", "SR-FN-512", HybridSuite::SrFn512),
];

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct ParityFile {
    spec: String,
    layers: BTreeMap<String, String>,
    suites: BTreeMap<String, SuiteInfo>,
    positive: Vec<Positive>,
    negative: Vec<Negative>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct SuiteInfo {
    name: String,
    algorithm: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Positive {
    name: String,
    suri: String,
    scope: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    phrase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    passphrase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    account: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    raw_seed: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    junction_chain_codes: Vec<String>,
    #[serde(default)]
    keys: BTreeMap<String, Key>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Key {
    seed: String,
    public_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    public: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Negative {
    name: String,
    suri: String,
    rejected_by: Vec<String>,
}

fn s(v: &str) -> String {
    v.to_owned()
}

fn scope(layers: &[&str]) -> Vec<String> {
    layers.iter().map(|l| s(l)).collect()
}

fn phrase_case(
    name: &str,
    suri: &str,
    layers: &[&str],
    phrase: &str,
    passphrase: &str,
    account: u32,
    index: u32,
) -> Positive {
    Positive {
        name: s(name),
        suri: s(suri),
        scope: scope(layers),
        phrase: Some(s(phrase)),
        passphrase: Some(s(passphrase)),
        account: Some(account),
        index: Some(index),
        raw_seed: None,
        junction_chain_codes: Vec::new(),
        keys: BTreeMap::new(),
    }
}

/// The chain code of a hard junction as sp-core's `DeriveJunction` builds it
/// for the inputs used here: a numeric `t` is its `u64` SCALE encoding
/// (little-endian), a short name its SCALE `&str` encoding (compact length
/// prefix, then the bytes), zero-padded to 32 bytes. A name whose encoding is
/// longer than 32 bytes is hashed with blake2-256; this crate has no blake2,
/// so the one such name used here carries its precomputed chain code.
fn chain_code(t: &str) -> [u8; 32] {
    let mut cc = [0u8; 32];
    if t == LONG_RAW_JUNCTION {
        hex::decode_to_slice(LONG_RAW_JUNCTION_CC, &mut cc).unwrap();
    } else if let Ok(n) = t.parse::<u64>() {
        cc[..8].copy_from_slice(&n.to_le_bytes());
    } else {
        assert!(t.len() < 32, "only short names are used here");
        cc[0] = u8::try_from(t.len() << 2).unwrap();
        cc[1..=t.len()].copy_from_slice(t.as_bytes());
    }
    cc
}

fn raw_case(name: &str, suri: &str, layers: &[&str], junctions: &[&str]) -> Positive {
    Positive {
        name: s(name),
        suri: s(suri),
        scope: scope(layers),
        phrase: None,
        passphrase: None,
        account: None,
        index: None,
        raw_seed: Some(s(RAW)),
        junction_chain_codes: junctions
            .iter()
            .map(|t| hex::encode(chain_code(t)))
            .collect(),
        keys: BTreeMap::new(),
    }
}

fn positive_inputs() -> Vec<Positive> {
    let both = ["quip-hd", "sdk", "signer"];
    let sdk = ["quip-hd", "sdk"];
    let lib = ["quip-hd"];
    vec![
        phrase_case("bare phrase", LEGAL, &both, LEGAL, "", 0, 0),
        phrase_case(
            "surrounding and doubled spaces",
            "  legal  winner thank year wave sausage worth useful legal winner thank yellow ",
            &both,
            LEGAL,
            "",
            0,
            0,
        ),
        phrase_case(
            "empty password",
            &format!("{LEGAL}///"),
            &both,
            LEGAL,
            "",
            0,
            0,
        ),
        phrase_case(
            "password",
            &format!("{LEGAL}///pw"),
            &both,
            LEGAL,
            "pw",
            0,
            0,
        ),
        phrase_case(
            "NFKD password, precomposed",
            &format!("{LEGAL}///caf\u{e9}"),
            &both,
            LEGAL,
            "caf\u{e9}",
            0,
            0,
        ),
        phrase_case(
            "NFKD password, decomposed",
            &format!("{LEGAL}///cafe\u{301}"),
            &both,
            LEGAL,
            "cafe\u{301}",
            0,
            0,
        ),
        phrase_case(
            "tab, newline and no-break space (library only: not in the ASCII SURI phrase class)",
            TAB_NBSP_SURI,
            &lib,
            LEGAL,
            "",
            0,
            0,
        ),
        phrase_case(
            "NFKD phrase, fi ligature (library only: not in the ASCII SURI phrase class)",
            &DEV_PHRASE.replace("fit", "\u{fb01}t"),
            &lib,
            DEV_PHRASE,
            "",
            0,
            0,
        ),
        phrase_case(
            "junction //0",
            &format!("{LEGAL}//0"),
            &sdk,
            LEGAL,
            "",
            0,
            0,
        ),
        phrase_case(
            "junctions //0//0",
            &format!("{LEGAL}//0//0"),
            &sdk,
            LEGAL,
            "",
            0,
            0,
        ),
        phrase_case(
            "junction //1",
            &format!("{LEGAL}//1"),
            &sdk,
            LEGAL,
            "",
            1,
            0,
        ),
        phrase_case(
            "junctions //1//7",
            &format!("{LEGAL}//1//7"),
            &sdk,
            LEGAL,
            "",
            1,
            7,
        ),
        phrase_case(
            "junction //2147483647, the largest numeric level",
            &format!("{LEGAL}//2147483647"),
            &sdk,
            LEGAL,
            "",
            2_147_483_647,
            0,
        ),
        phrase_case(
            "named junction //Alice",
            &format!("{LEGAL}//Alice"),
            &sdk,
            LEGAL,
            "",
            F_ALICE,
            0,
        ),
        phrase_case(
            "named junctions //Alice//Bob",
            &format!("{LEGAL}//Alice//Bob"),
            &sdk,
            LEGAL,
            "",
            F_ALICE,
            F_BOB,
        ),
        phrase_case(
            "junction and password",
            &format!("{LEGAL}//1///pw"),
            &sdk,
            LEGAL,
            "pw",
            1,
            0,
        ),
        phrase_case(
            "dev phrase //Alice",
            "//Alice",
            &sdk,
            DEV_PHRASE,
            "",
            F_ALICE,
            0,
        ),
        phrase_case("dev phrase (empty SURI)", "", &sdk, DEV_PHRASE, "", 0, 0),
        phrase_case(
            "dev phrase with ///pw",
            "///pw",
            &sdk,
            DEV_PHRASE,
            "pw",
            0,
            0,
        ),
        phrase_case(
            "password containing a slash",
            &format!("{LEGAL}///p/w"),
            &both,
            LEGAL,
            "p/w",
            0,
            0,
        ),
        phrase_case(
            "junction name of 64 bytes or more (two-byte SCALE length)",
            &format!("{LEGAL}//{LONG_PHRASE_JUNCTION}"),
            &sdk,
            LEGAL,
            "",
            F_LONG_PHRASE_JUNCTION,
            0,
        ),
        raw_case("raw seed", &format!("0x{RAW}"), &both, &[]),
        raw_case(
            "raw seed in uppercase hex digits",
            &format!("0x{}", RAW.to_uppercase()),
            &both,
            &[],
        ),
        raw_case(
            "raw seed junction name over 32 encoded bytes (blake2 chain code)",
            &format!("0x{RAW}//{LONG_RAW_JUNCTION}"),
            &sdk,
            &[LONG_RAW_JUNCTION],
        ),
        raw_case(
            "raw seed //1 (HKDF junction)",
            &format!("0x{RAW}//1"),
            &sdk,
            &["1"],
        ),
        raw_case(
            "raw seed //Alice//1 (HKDF junctions)",
            &format!("0x{RAW}//Alice//1"),
            &sdk,
            &["Alice", "1"],
        ),
    ]
}

fn negatives() -> Vec<Negative> {
    let both = ["sdk", "signer"];
    let all = ["quip-hd", "sdk", "signer"];
    let signer = ["signer"];
    let n = |name: &str, suri: String, by: &[&str]| Negative {
        name: s(name),
        suri,
        rejected_by: scope(by),
    };
    vec![
        n("uppercase 0X", format!("0X{RAW}"), &both),
        n("raw seed of 31 bytes", format!("0x{}", &RAW[..62]), &both),
        n("raw seed with an empty ///", format!("0x{RAW}///"), &both),
        n("raw seed with ///pw", format!("0x{RAW}///pw"), &both),
        n("raw seed //01", format!("0x{RAW}//01"), &both),
        n("raw seed //+1", format!("0x{RAW}//+1"), &both),
        n(
            "raw seed //2147483648",
            format!("0x{RAW}//2147483648"),
            &both,
        ),
        n("raw seed soft junction", format!("0x{RAW}/1"), &both),
        n(
            "raw seed third junction",
            format!("0x{RAW}//1//2//3"),
            &both,
        ),
        n(
            "raw seed junction (signers take no junctions)",
            format!("0x{RAW}//1"),
            &signer,
        ),
        n("soft junction", format!("{LEGAL}/soft"), &both),
        n("empty junction", format!("{LEGAL}//"), &both),
        n(
            "dev phrase, empty SURI (signers have no dev phrase)",
            String::new(),
            &signer,
        ),
        n(
            "dev phrase with ///pw (signers have no dev phrase)",
            "///pw".to_owned(),
            &signer,
        ),
        n("third junction", format!("{LEGAL}//1//2//3"), &both),
        n("non-canonical //01", format!("{LEGAL}//01"), &both),
        n("non-canonical //00", format!("{LEGAL}//00"), &both),
        n("plus sign //+1", format!("{LEGAL}//+1"), &both),
        n("//2147483648, 2^31", format!("{LEGAL}//2147483648"), &both),
        n("//4294967296, 2^32", format!("{LEGAL}//4294967296"), &both),
        n(
            "junction (signers take no junctions)",
            format!("{LEGAL}//1"),
            &signer,
        ),
        n(
            "named junction (signers take no junctions)",
            format!("{LEGAL}//Alice"),
            &signer,
        ),
        // The two library-only positives, as SURIs: the SDK's AddressUri phrase
        // class and the signers' grammar are ASCII letters, digits and space, so
        // both layers reject them rather than normalise them into a key.
        n(
            "tab, newline and no-break space between words",
            s(TAB_NBSP_SURI),
            &both,
        ),
        n(
            "fi ligature in the phrase",
            DEV_PHRASE.replace("fit", "\u{fb01}t"),
            &both,
        ),
        n(
            "bad checksum",
            "legal winner thank year wave sausage worth useful legal winner thank legal".to_owned(),
            &all,
        ),
        n(
            "unknown word",
            "legal winner thank year wave sausage worth useful legal winner thank quipq".to_owned(),
            &all,
        ),
    ]
}

fn keypair_public<S: Suite>(seed: &[u8; 32]) -> Vec<u8> {
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    composite::keypair_from_seed::<S>(seed, &mut sk, &mut pk).expect("keypair");
    pk
}

fn keypair_public_delta<S: DeltaSuite>(seed: &[u8; 32]) -> Vec<u8> {
    let mut sk = vec![0u8; S::SECRET_KEY_LEN];
    let mut pk = vec![0u8; S::PUBLIC_KEY_LEN];
    composite_delta::keypair_from_seed::<S>(seed, &mut sk, &mut pk).expect("keypair");
    pk
}

fn public_of(suite: HybridSuite, seed: &[u8; 32]) -> Vec<u8> {
    match suite {
        HybridSuite::EdMl44 => keypair_public::<EdMl44>(seed),
        HybridSuite::SrMl44 => keypair_public::<SrMl44>(seed),
        HybridSuite::EdFn512 => keypair_public_delta::<EdFn512>(seed),
        HybridSuite::SrFn512 => keypair_public_delta::<SrFn512>(seed),
    }
}

/// The seed a positive case selects for `suite`, from its derivation inputs.
fn seed_of(case: &Positive, suite: HybridSuite) -> [u8; 32] {
    if let Some(raw) = &case.raw_seed {
        let mut seed: [u8; 32] = hex::decode(raw).unwrap().try_into().unwrap();
        for cc in &case.junction_chain_codes {
            let cc: [u8; 32] = hex::decode(cc).unwrap().try_into().unwrap();
            seed = derive_hard_junction(&seed, &cc).expect("junction");
        }
        seed
    } else {
        *hybrid_leaf(
            suite,
            case.phrase.as_deref().unwrap(),
            case.passphrase.as_deref().unwrap(),
            case.account.unwrap(),
            case.index.unwrap(),
        )
        .expect("leaf")
    }
}

fn with_keys(mut case: Positive, full_public: bool) -> Positive {
    for (id, _, suite) in SUITES {
        let seed = seed_of(&case, suite);
        let public = public_of(suite, &seed);
        case.keys.insert(
            s(id),
            Key {
                seed: hex::encode(seed),
                public_sha256: hex::encode(Sha256::digest(&public)),
                public: full_public.then(|| hex::encode(&public)),
            },
        );
    }
    case
}

fn generated() -> ParityFile {
    let layers = [
        ("quip-hd", "pqhybridsign quip_hd::hybrid_leaf and keypair_from_seed, from the case's derivation inputs"),
        ("sdk", "SDK fork Pair::from_string(suri, None): AddressUri grammar, at most two hard junctions, strict digits (design v2.1 §3-§4)"),
        ("signer", "transaction-crypto-core and the browser and Python signers: the junction-free subset (design v2.1 §6)"),
    ]
    .into_iter()
    .map(|(k, v)| (s(k), s(v)))
    .collect();
    let suites = SUITES
        .iter()
        .map(|(id, name, suite)| {
            (
                s(id),
                SuiteInfo {
                    name: s(name),
                    algorithm: suite.algorithm(),
                },
            )
        })
        .collect();
    let positive = positive_inputs()
        .into_iter()
        .enumerate()
        .map(|(i, case)| with_keys(case, i == 0))
        .collect();
    ParityFile {
        spec: s("QUIP HD v1, Quip Substrate profile: WP2 batch 1 design note v2.1"),
        layers,
        suites,
        positive,
        negative: negatives(),
    }
}

#[test]
#[ignore = "generator: prints tests/vectors/quip_hd_parity.json"]
fn generate() {
    println!("{}", serde_json::to_string_pretty(&generated()).unwrap());
}

/// The checked-in file is exactly what this crate derives today, so every
/// consumer checks against this crate's derivation.
#[test]
fn the_checked_in_parity_file_matches_this_crate() {
    let file: ParityFile =
        serde_json::from_str(include_str!("vectors/quip_hd_parity.json")).expect("parse");
    assert_eq!(file, generated());
}

/// Equivalences the design note states, read back from the file.
#[test]
fn the_parity_file_encodes_the_design_equivalences() {
    let file = generated();
    // Seeds and public-key hashes; the first case also carries full keys.
    let by_name = |name: &str| -> BTreeMap<String, (String, String)> {
        file.positive
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("{name}"))
            .keys
            .iter()
            .map(|(id, k)| (id.clone(), (k.seed.clone(), k.public_sha256.clone())))
            .collect()
    };
    let bare = by_name("bare phrase");
    for same in [
        "surrounding and doubled spaces",
        "empty password",
        "junction //0",
        "junctions //0//0",
        "tab, newline and no-break space (library only: not in the ASCII SURI phrase class)",
    ] {
        assert_eq!(by_name(same), bare, "{same}");
    }
    assert_eq!(
        by_name("NFKD password, precomposed"),
        by_name("NFKD password, decomposed")
    );
    assert_ne!(
        by_name("named junction //Alice"),
        by_name("dev phrase //Alice")
    );
    assert_ne!(by_name("junction //1"), bare);
    // The raw seed's keys are keypair_from_seed of the seed itself.
    for (id, (seed, _)) in by_name("raw seed") {
        assert_eq!(seed, RAW, "{id}");
    }
    // Each library-only positive is a negative for the SDK and the signers.
    for case in file.positive.iter().filter(|c| c.scope == ["quip-hd"]) {
        let negative = file.negative.iter().find(|n| n.suri == case.suri);
        assert_eq!(
            negative.map(|n| n.rejected_by.clone()),
            Some(vec![s("sdk"), s("signer")]),
            "{}",
            case.name
        );
    }
    // A negative the library layer rejects is a phrase hybrid_leaf refuses.
    for case in file
        .negative
        .iter()
        .filter(|n| n.rejected_by.iter().any(|l| l == "quip-hd"))
    {
        for (_, _, suite) in SUITES {
            assert!(
                hybrid_leaf(suite, &case.suri, "", 0, 0).is_err(),
                "{}",
                case.name
            );
        }
    }
    assert_eq!(
        by_name("raw seed in uppercase hex digits"),
        by_name("raw seed"),
        "0x2A.. and 0x2a.. are one seed"
    );
    assert_ne!(
        by_name("dev phrase with ///pw"),
        by_name("dev phrase (empty SURI)")
    );
    // Every negative is rejected by at least one layer.
    for case in &file.negative {
        assert!(!case.rejected_by.is_empty(), "{}", case.name);
    }
    // The signers' positives carry no junction.
    for case in file
        .positive
        .iter()
        .filter(|c| c.scope.iter().any(|l| l == "signer"))
    {
        let body = case.suri.split("///").next().unwrap();
        assert!(!body.contains('/'), "{}", case.name);
    }
}
