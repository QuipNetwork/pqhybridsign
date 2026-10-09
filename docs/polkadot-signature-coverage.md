# Polkadot signature coverage

`pqhybridsign` provides the `ed25519` and `sr25519` signature primitives used throughout the SDK.
It provides part of the `sr25519` Verifiable Random Function (VRF) and key-derivation requirements.
It does not provide `ECDSA`, `BLS`, `Bandersnatch` ring proofs, signature aggregation, or encryption.

This scan answers `QUI-1247`.

It examines `paritytech/polkadot-sdk` commit `05ddbee5c062d49c8a2a072c529a2fc80aad243e` on 2026-10-09 using Coordinated Universal Time (UTC).
The upstream commit date is 2026-10-09 at 14:14:41 UTC.
The table contains 92 subsystem and primitive pairs.
It marks 40 Covered and 10 Partial.
It marks 42 Not covered.

## What pqhybridsign covers

The library provides these constructions:

- Signatures pair `ed25519` or `sr25519` with `ML-DSA-44`, `FN-DSA-512`, or `SHRINCS`.
  The six suite types are `ED-ML-44`, `ED-FN-512`, `SR-ML-44`, `SR-FN-512`, `ED-SH`, and `SR-SH`.
- The `vrf` feature provides schnorrkel's `sr25519` VRF and the `RFC 9381` `ECVRF-EDWARDS25519-SHA512-TAI`.
  Each construction verifies a post-quantum binding.
  Output bytes derive only from the classical pre-output.
- The `mnemonic` feature derives a master seed from English `BIP39` entropy and an optional password.
  Hard junctions derive a child master seed.
  `HKDF` derives separate component seeds for each suite.
  The library does not support soft junctions.

The library does not provide Substrate `Pair` types, host functions, keystore storage, session keys, `SCALE` envelopes, or account identifier rules.
The separate Substrate integration supplies those interfaces.
The library also uses its suite label where upstream `sr25519` signing uses `b"substrate"`.
Existing classical signatures and hybrid signatures require different verification paths.

`SHRINCS` VRFs spend a few-time budget through a dedicated stateless binding key.
They suit low-frequency randomness use.
The lattice suites suit per-slot VRF evaluation.
A stateful signing integration must persist leaf state and protect the rotation reserve.

The [library README](../README.md#relationship-to-substrate) describes the Substrate relationship.
The [VRF module](../crates/pqhybridsign/src/vrf.rs) lists the suites and binding limits.
The [sr25519 transcript caveat](../crates/pqhybridsign/src/classical/sr25519.rs) explains the `BABE` input limits.
The [hard derivation module](../crates/pqhybridsign/src/derive.rs) defines child master seeds.

## Coverage table

Covered means that the library provides the required signing primitive or master seed operation.
It does not mean that existing upstream keys, signatures, transcripts, or interfaces accept the hybrid construction.
Partial means that a primitive exists but a required cryptographic operation or key interface needs more work.
Not covered means that the library does not provide the listed operation.

Paths refer to the recorded upstream commit, relative to the clone root.
Each row groups one consumer or API role with one primitive.
An enum consumer permits each listed variant, regardless of which variant a deployment selects.
Experimental and example code appears with an explicit note.

| Subsystem | Primitive | Where | Purpose | Coverage | Notes |
|---|---|---|---|---|---|
| Host and keystore signatures | `ed25519` | `substrate/primitives/io/src/relay_chain.rs:844` | Sign and verify runtime messages. | Covered | `ed25519_verify` appears at line 860. |
| Host and keystore signatures | `sr25519` | `substrate/primitives/io/src/relay_chain.rs:1023` | Sign and verify runtime messages. | Covered | Version 2 verification appears at line 918. Legacy verification also exists. |
| Host and keystore signatures | `ECDSA` over `secp256k1` | `substrate/primitives/io/src/relay_chain.rs:1118`, `substrate/primitives/io/src/relay_chain.rs:1150`, `substrate/primitives/io/src/relay_chain.rs:1199` | Sign, verify, and recover public keys. | Not covered | Includes prehashed signatures and compressed recovery at line 1258. |
| Host and keystore keys | `ed25519` | `substrate/primitives/io/src/relay_chain.rs:813`, `substrate/primitives/io/src/relay_chain.rs:828` | List, generate, and store app keys. | Partial | Hybrid key generation needs a keystore and host interface. |
| Host and keystore keys | `sr25519` | `substrate/primitives/io/src/relay_chain.rs:992`, `substrate/primitives/io/src/relay_chain.rs:1007` | List, generate, and store app keys. | Partial | Hybrid key generation exists. Secret URI parsing and keystore storage need integration. |
| Host and keystore keys | `ECDSA` over `secp256k1` | `substrate/primitives/io/src/relay_chain.rs:1049`, `substrate/primitives/io/src/relay_chain.rs:1064` | List, generate, and store `ECDSA` keys. | Not covered | The library has no `ECDSA` component. |
| Host and keystore keys | `BLS12-381` | `substrate/primitives/io/src/relay_chain.rs:1309`, `substrate/primitives/io/src/relay_chain.rs:1326`, `substrate/primitives/keystore/src/lib.rs:318` | Generate keys, sign, and prove possession. | Not covered | Requires `bls-experimental`. No `BLS` component or `BLS` proof of possession exists here. |
| Host and keystore keys | `ecdsa_bls381` | `substrate/primitives/io/src/relay_chain.rs:1346`, `substrate/primitives/keystore/src/lib.rs:350` | Generate paired keys and sign messages. | Not covered | Requires `bls-experimental`. Both components are classical. |
| Host and keystore keys | `Bandersnatch` | `substrate/primitives/io/src/relay_chain.rs:1365`, `substrate/primitives/io/src/relay_chain.rs:1382` | Generate keys and sign runtime messages. | Not covered | Requires `bandersnatch-experimental`. |
| Keystore VRFs | `sr25519` VRF | `substrate/primitives/keystore/src/lib.rs:102`, `substrate/primitives/keystore/src/lib.rs:116` | Produce proofs and pre-outputs. | Partial | The classical VRF exists. Structured transcripts and extra transcript data need integration. |
| Keystore VRFs | `Bandersnatch` VRF | `substrate/primitives/keystore/src/lib.rs:233` | Produce ordinary VRF proofs. | Not covered | An `ed25519` `ECVRF` uses a different curve and proof format. |
| Keystore VRFs | `Bandersnatch` ring VRF | `substrate/primitives/keystore/src/lib.rs:271` | Produce anonymous VRF proofs. | Not covered | The library has no ring prover or verifier. |
| Legacy batch host APIs | `ed25519` | `substrate/primitives/io/src/relay_chain.rs:899` | Accumulate verification results for old runtimes. | Not covered | The API now verifies each signature immediately and needs a result accumulator. |
| Legacy batch host APIs | `sr25519` | `substrate/primitives/io/src/relay_chain.rs:940` | Accumulate verification results for old runtimes. | Not covered | The API now verifies each signature immediately. This is not a current batch verification engine. |
| Legacy batch host APIs | `ECDSA` over `secp256k1` | `substrate/primitives/io/src/relay_chain.rs:1172` | Accumulate `ECDSA` verification results. | Not covered | The library provides neither `ECDSA` nor this legacy interface. |
| Runtime signature enums | `ed25519` | `substrate/primitives/runtime/src/lib.rs:272`, `substrate/primitives/runtime/src/lib.rs:339` | Represent signatures and account signers. | Covered | `MultiSignature` and `MultiSigner` need new hybrid variants and account rules. |
| Runtime signature enums | `sr25519` | `substrate/primitives/runtime/src/lib.rs:274`, `substrate/primitives/runtime/src/lib.rs:341` | Represent signatures and account signers. | Covered | The current enums contain classical keys and signatures. |
| Runtime signature enums | `ECDSA` over `secp256k1` | `substrate/primitives/runtime/src/lib.rs:276`, `substrate/primitives/runtime/src/lib.rs:278`, `substrate/primitives/runtime/src/lib.rs:350` | Represent Substrate and Ethereum account signatures. | Not covered | Both `Ecdsa` and `Eth` exist. `Eth` uses Keccak signatures and different account derivation. |
| Runtime `AnySignature` | `ed25519` | `substrate/primitives/runtime/src/lib.rs:528` | Verify an untagged signature. | Covered | The verifier tries `ed25519` and `sr25519`. Hybrid signatures need an explicit format. |
| Runtime `AnySignature` | `sr25519` | `substrate/primitives/runtime/src/lib.rs:522` | Verify an untagged signature. | Covered | The current 64-byte envelope cannot hold a hybrid signature. |
| `BABE` | `sr25519` signatures | `substrate/primitives/consensus/babe/src/lib.rs:47` | Authenticate block authors. | Covered | App key type: `babe`. |
| `BABE` | `sr25519` VRF | `substrate/client/consensus/babe/src/authorship.rs:152`, `substrate/primitives/consensus/babe/src/lib.rs:103` | Select leaders and contribute randomness. | Partial | The proof format matches schnorrkel. `BABE` and the library build different input transcripts. |
| `GRANDPA` | `ed25519` | `substrate/primitives/consensus/grandpa/src/lib.rs:47` | Sign finality votes and justifications. | Covered | App key type: `gran`. |
| `AURA` | `sr25519` | `substrate/primitives/consensus/aura/src/lib.rs:34` | Authenticate slot authors. | Covered | App key type: `aura`. |
| `AURA` | `ed25519` | `substrate/primitives/consensus/aura/src/lib.rs:52` | Authenticate slot authors. | Covered | This is a separate supported `AURA` key configuration. |
| `BEEFY` | `ECDSA` over `secp256k1` | `substrate/primitives/consensus/beefy/src/lib.rs:120` | Sign bridge finality commitments. | Not covered | App key type: `beef`. `BEEFY` uses its own message hashing rules. |
| `BEEFY` | `BLS12-381` | `substrate/primitives/consensus/beefy/src/lib.rs:190` | Sign experimental finality commitments. | Not covered | Requires `bls-experimental`. The observed `BEEFY` variant uses `BLS381`, not `BLS377`. |
| `BEEFY` | `ecdsa_bls381` | `substrate/primitives/consensus/beefy/src/lib.rs:251` | Sign paired experimental finality commitments. | Not covered | Requires `bls-experimental`. Verification uses the `BEEFY` Keccak path. |
| `BEEFY` witnesses | `BLS12-381` aggregation | `substrate/primitives/consensus/beefy/src/witness.rs:46`, `substrate/primitives/consensus/beefy/src/witness.rs:201` | Represent and exercise signature accumulators. | Not covered | The generic witness accepts an aggregator. The concrete `BLS` aggregation hit belongs to a test. |
| `Sassafras` authority keys | `Bandersnatch` signatures | `substrate/primitives/consensus/sassafras/src/lib.rs:48` | Authenticate consensus authorities. | Not covered | App key type: `sass`. |
| `Sassafras` randomness | `Bandersnatch` VRF | `substrate/frame/sassafras/src/lib.rs:315` | Derive slot randomness. | Not covered | The runtime derives bytes from a `Bandersnatch` pre-output. |
| `Sassafras` tickets | `Bandersnatch` ring VRF | `substrate/frame/sassafras/src/lib.rs:422` | Verify anonymous authoring tickets. | Not covered | Requires ring membership proofs and ring verifier state. |
| `Sassafras` ephemeral keys | `ed25519` | `substrate/primitives/consensus/sassafras/src/ticket.rs:24`, `substrate/primitives/consensus/sassafras/src/ticket.rs:66` | Carry ephemeral ticket keys and signatures. | Covered | These keys differ from `Bandersnatch` authority keys. |
| `FRAME` personhood | Ring VRF | `substrate/frame/people/src/lib.rs:207`, `substrate/frame/people/src/lib.rs:607` | Prove membership without revealing the member. | Not covered | The `Crypto` configuration selects a `verifiable` proof system. The scan does not establish a deployed proof system. |
| `im-online` | `sr25519` | `substrate/frame/im-online/src/lib.rs:119` | Sign validator heartbeats. | Covered | App key type: `imon`. |
| `im-online` | `ed25519` | `substrate/frame/im-online/src/lib.rs:137` | Sign validator heartbeats. | Covered | The pallet also exposes this key configuration. |
| Authority discovery | `sr25519` | `substrate/primitives/authority-discovery/src/lib.rs:28`, `substrate/client/authority-discovery/src/worker.rs:1178` | Sign authority address records. | Covered | App key type: `audi`. Peer identity signatures use the separate network key. |
| Network identity | `ed25519` | `substrate/client/network/src/service/signature.rs:58`, `substrate/client/network/types/src/peer_id.rs:117` | Sign peer messages and derive peer identifiers. | Partial | The primitive exists. `Libp2p` and `Litep2p` require their existing key formats and peer identifier rules. |
| `WebRTC` certificates | `ECDSA` over `P-256` | `substrate/client/network/src/webrtc.rs:108`, `substrate/client/network/src/webrtc.rs:131` | Derive certificate keys and sign `DTLS` certificates. | Not covered | The node derives a `P-256` key from its `ed25519` secret with `HMAC-SHA256`. |
| `Mixnet` authentication | `sr25519` | `substrate/primitives/mixnet/src/types.rs:26` | Provide mixnet app keys. | Covered | App key type: `mixn`. |
| `Mixnet` key exchange | `X25519` | `substrate/primitives/mixnet/src/types.rs:62` | Exchange encryption keys with mixnodes. | Not covered | Signature suites do not provide key exchange or encryption. |
| Statement-store signatures | `sr25519` | `substrate/primitives/statement-store/src/lib.rs:257`, `substrate/primitives/statement-store/src/lib.rs:582` | Authenticate stored statements. | Covered | App key type: `stmt`. The statement proof needs a hybrid envelope. |
| Statement-store signatures | `ed25519` | `substrate/primitives/statement-store/src/lib.rs:266`, `substrate/primitives/statement-store/src/lib.rs:592` | Authenticate stored statements. | Covered | The private signing path also exists outside the keystore. |
| Statement-store signatures | `ECDSA` over `secp256k1` | `substrate/primitives/statement-store/src/lib.rs:278`, `substrate/primitives/statement-store/src/lib.rs:602` | Authenticate stored statements. | Not covered | The signer carries a compressed `ECDSA` public key. |
| Statement-store encryption | `Ed25519-to-X25519` `ECIES` | `substrate/primitives/statement-store/src/ecies.rs:95`, `substrate/primitives/statement-store/src/ecies.rs:125` | Encrypt and decrypt statement payloads. | Not covered | The code converts an `ed25519` key to `X25519`. Ed25519 signature coverage does not cover this use. |
| Parachain collators | `sr25519` | `polkadot/primitives/src/v9/mod.rs:96`, `polkadot/node/network/protocol/src/lib.rs:521` | Authenticate collator declarations and candidate data. | Covered | App key type: `coll`. |
| Parachain validators | `sr25519` | `polkadot/primitives/src/v9/mod.rs:114`, `polkadot/primitives/src/v9/mod.rs:1280`, `polkadot/primitives/src/v9/mod.rs:1345` | Sign backing statements, disputes, and approvals. | Covered | App key type: `para`. Consumers share `ValidatorSignature`. |
| Approval assignments | `sr25519` VRF | `polkadot/primitives/src/v9/mod.rs:492`, `polkadot/node/core/approval-voting/src/criteria.rs:318`, `polkadot/node/core/approval-voting/src/criteria.rs:387` | Select approval checkers and delay tranches. | Partial | App key type: `asgn`. The protocol uses custom input and extra transcripts. |
| Approval relay story | `sr25519` VRF | `polkadot/node/primitives/src/approval/mod.rs:132` | Derive assignment randomness from `BABE` pre-outputs. | Partial | Output contexts and transcript reconstruction need parity checks. |
| `Cumulus` authoring | `sr25519` | `cumulus/parachains/common/types/src/lib.rs:49` | Provide parachain `AURA` authority keys. | Covered | The common `AuraId` selects `sr25519`. |
| `Cumulus` authoring | `ed25519` | `cumulus/parachains/common/types/src/lib.rs:56` | Provide Asset Hub Polkadot `AURA` keys. | Covered | The type retains `ed25519` after the Shell transition. |
| Substrate bridge finality | `ed25519` | `bridges/primitives/header-chain/src/justification/verification/mod.rs:302`, `substrate/primitives/consensus/grandpa/src/lib.rs:47` | Verify remote `GRANDPA` justifications. | Covered | The bridge calls the `GRANDPA` signature verifier. |
| Substrate bridge accounts | `ed25519` | `bridges/primitives/polkadot-core/src/lib.rs:210`, `substrate/primitives/runtime/src/lib.rs:272` | Authenticate bridge transactions. | Covered | The shared account signature type is `MultiSignature`. |
| Substrate bridge accounts | `sr25519` | `bridges/primitives/polkadot-core/src/lib.rs:210`, `substrate/primitives/runtime/src/lib.rs:274` | Authenticate bridge transactions. | Covered | The relay signing trait selects its concrete `Pair`. |
| Substrate bridge accounts | `ECDSA` over `secp256k1` | `bridges/primitives/polkadot-core/src/lib.rs:210`, `substrate/primitives/runtime/src/lib.rs:276` | Authenticate bridge transactions. | Not covered | The shared enum permits `ECDSA`. This does not establish an active `ECDSA` relay key. |
| `Snowbridge` Ethereum client | `BLS12-381` aggregation | `bridges/snowbridge/primitives/beacon/src/bls.rs:26`, `bridges/snowbridge/primitives/beacon/src/bls.rs:79` | Verify Ethereum sync committee signatures. | Not covered | Uses Ethereum `BLS` signatures through `milagro_bls`. Its format differs from the SDK `BLS381` scheme. |
| Ethereum claims | `ECDSA` over `secp256k1` | `polkadot/runtime/common/src/claims/mod.rs:185`, `polkadot/runtime/common/src/claims/mod.rs:585` | Recover Ethereum claim signers. | Not covered | The 65-byte signature follows Ethereum message rules. |
| Crowdloan authorization | `ed25519` | `polkadot/runtime/common/src/crowdloan/mod.rs:450`, `substrate/primitives/runtime/src/lib.rs:272` | Verify contribution authorization. | Covered | The authorization uses `MultiSignature`. |
| Crowdloan authorization | `sr25519` | `polkadot/runtime/common/src/crowdloan/mod.rs:450`, `substrate/primitives/runtime/src/lib.rs:274` | Verify contribution authorization. | Covered | The authorization uses `MultiSignature`. |
| Crowdloan authorization | `ECDSA` over `secp256k1` | `polkadot/runtime/common/src/crowdloan/mod.rs:450`, `substrate/primitives/runtime/src/lib.rs:276` | Verify contribution authorization. | Not covered | The enum permits `ECDSA`. Runtime configuration determines actual use. |
| `purchase` statements | `ed25519` | `polkadot/runtime/common/src/purchase/mod.rs:429`, `substrate/primitives/runtime/src/lib.rs:528` | Verify signed statements for token sales. | Covered | `AnySignature` tries both supported primitives. |
| `purchase` statements | `sr25519` | `polkadot/runtime/common/src/purchase/mod.rs:429`, `substrate/primitives/runtime/src/lib.rs:522` | Verify signed statements for token sales. | Covered | The 64-byte classical envelope needs replacement for hybrid signatures. |
| `FRAME` contracts | `sr25519` | `substrate/frame/contracts/src/exec.rs:1561` | Verify signatures within contracts. | Covered | The contract interface accepts fixed classical key and signature lengths. |
| `FRAME` contracts | `ECDSA` over `secp256k1` | `substrate/frame/contracts/src/exec.rs:1557` | Recover contract signers and Ethereum addresses. | Not covered | The library has no recoverable `ECDSA` signature. |
| `FRAME` `Revive` | `sr25519` | `substrate/frame/revive/src/exec.rs:2607` | Verify signatures within contracts. | Covered | The current contract interface needs a hybrid signature operation. |
| `FRAME` `Revive` | `ECDSA` over `secp256k1` | `substrate/frame/revive/src/exec.rs:2603`, `substrate/frame/revive/src/evm/api/signature.rs:41`, `substrate/frame/revive/src/precompiles/builtin/ecrecover.rs:58` | Recover Ethereum transaction and contract signers. | Not covered | Includes Ethereum transaction signatures, `EIP-7702` paths, and `ecrecover`. |
| `FRAME` `Revive` | `ECDSA` over `P-256` | `substrate/frame/revive/src/precompiles/builtin/p256_verify.rs:56` | Verify `RIP-7212` signatures. | Not covered | `P-256` differs from `secp256k1` and both library classical components. |
| Asset permits | `ECDSA` over `secp256k1` | `substrate/frame/assets/precompiles/src/permit.rs:291` | Verify Ethereum permit authorization. | Not covered | The permit verifier recovers an Ethereum address. |
| `FRAME` `nfts` authorization | `ed25519` | `substrate/frame/nfts/src/common_functions.rs:46`, `cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs:1376`, `cumulus/parachains/common/types/src/lib.rs:26` | Verify signed mint and attribute requests. | Covered | The inspected Asset Hub configuration uses `MultiSignature`. |
| `FRAME` `nfts` authorization | `sr25519` | `substrate/frame/nfts/src/common_functions.rs:46`, `cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs:1376`, `cumulus/parachains/common/types/src/lib.rs:26` | Verify signed mint and attribute requests. | Covered | The pallet accepts the runtime signature type. |
| `FRAME` `nfts` authorization | `ECDSA` over `secp256k1` | `substrate/frame/nfts/src/common_functions.rs:46`, `cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs:1376`, `substrate/primitives/runtime/src/lib.rs:276` | Verify signed mint and attribute requests. | Not covered | The runtime enum permits `ECDSA`. |
| `FRAME` identity usernames | `ed25519` | `substrate/frame/identity/src/lib.rs:1558`, `cumulus/parachains/runtimes/people/people-westend/src/people.rs:51`, `cumulus/parachains/common/types/src/lib.rs:26` | Verify username authorization. | Covered | The inspected People runtime uses the shared account signature type. |
| `FRAME` identity usernames | `sr25519` | `substrate/frame/identity/src/lib.rs:1558`, `cumulus/parachains/runtimes/people/people-westend/src/people.rs:51`, `cumulus/parachains/common/types/src/lib.rs:26` | Verify username authorization. | Covered | The verifier also checks wrapped message bytes. |
| `FRAME` identity usernames | `ECDSA` over `secp256k1` | `substrate/frame/identity/src/lib.rs:1558`, `cumulus/parachains/runtimes/people/people-westend/src/people.rs:51`, `substrate/primitives/runtime/src/lib.rs:276` | Verify username authorization. | Not covered | The runtime enum permits `ECDSA`. |
| `FRAME` transaction signature extension | `ed25519` | `substrate/frame/verify-signature/src/extension.rs:152`, `cumulus/parachains/runtimes/people/people-westend/src/lib.rs:643`, `substrate/primitives/runtime/src/lib.rs:272` | Check signatures that set transaction origins. | Covered | The inspected configuration uses `MultiSignature`. |
| `FRAME` transaction signature extension | `sr25519` | `substrate/frame/verify-signature/src/extension.rs:152`, `cumulus/parachains/runtimes/people/people-westend/src/lib.rs:643`, `substrate/primitives/runtime/src/lib.rs:274` | Check signatures that set transaction origins. | Covered | The runtime supplies the signature verifier. |
| `FRAME` transaction signature extension | `ECDSA` over `secp256k1` | `substrate/frame/verify-signature/src/extension.rs:152`, `cumulus/parachains/runtimes/people/people-westend/src/lib.rs:643`, `substrate/primitives/runtime/src/lib.rs:276` | Check signatures that set transaction origins. | Not covered | The runtime enum permits both `ECDSA` account variants. |
| `HOP` message authorization | `ed25519` | `substrate/client/hop/src/rpc.rs:256`, `substrate/client/hop/src/types.rs:81`, `substrate/primitives/runtime/src/lib.rs:272` | Authenticate message submission and consent. | Covered | The API carries `MultiSignature` and an ephemeral `MultiSigner`. |
| `HOP` message authorization | `sr25519` | `substrate/client/hop/src/rpc.rs:256`, `substrate/client/hop/src/types.rs:81`, `substrate/primitives/runtime/src/lib.rs:274` | Authenticate message submission and consent. | Covered | The runtime must also verify the signed consent payload. |
| `HOP` message authorization | `ECDSA` over `secp256k1` | `substrate/client/hop/src/rpc.rs:256`, `substrate/client/hop/src/types.rs:81`, `substrate/primitives/runtime/src/lib.rs:276` | Authenticate message submission and consent. | Not covered | The API accepts the shared `ECDSA` signature variants. |
| Offchain worker example | `sr25519` | `substrate/frame/examples/offchain-worker/src/lib.rs:107` | Sign offchain transaction payloads. | Covered | This is example code. App key type: `btc!`. |
| Experimental core schemes | `BLS12-377` | `substrate/primitives/core/src/bls.rs:51` | Provide signatures, key derivation, and possession proofs. | Not covered | The primitive exists in `sp_core`. No `BEEFY` app binding to `BLS377` appeared. |
| Experimental core schemes | `BLS12-381` | `substrate/primitives/core/src/bls.rs:79` | Provide signatures, key derivation, and possession proofs. | Not covered | The SDK scheme includes a Chaum-Pedersen proof. |
| Experimental core schemes | `ecdsa_bls377` | `substrate/primitives/core/src/paired_crypto.rs:33` | Provide paired signatures and derived keys. | Not covered | Both paired schemes are classical. |
| Experimental core schemes | `ecdsa_bls381` | `substrate/primitives/core/src/paired_crypto.rs:149` | Provide paired signatures and derived keys. | Not covered | The library ships neither component. |
| Mnemonic seed recovery | `BIP39` entropy derivation | `substrate/primitives/core/src/crypto.rs:873`, `substrate/primitives/core/src/crypto.rs:881` | Recover key seeds from an English mnemonic. | Covered | The `mnemonic` feature matches the master seed derivation. Hybrid component keys still differ. |
| Hard key paths | `ed25519` hard junctions | `substrate/primitives/core/src/ed25519.rs:66`, `substrate/primitives/core/src/ed25519.rs:98` | Derive child keys from a seed and chain code. | Partial | Hybrid hard junctions exist. Upstream uses `Ed25519HDKD` and Blake2, while the library derives a master seed with `HKDF`. |
| Hard key paths | `sr25519` hard junctions | `substrate/primitives/core/src/sr25519.rs:199`, `substrate/primitives/core/src/sr25519.rs:251` | Derive child keys from a secret and chain code. | Partial | The library re-derives both hybrid components. It does not reproduce the native `sr25519` derivation operation. |
| Hard key paths | `ECDSA` over `secp256k1` | `substrate/primitives/core/src/ecdsa.rs:217`, `substrate/primitives/core/src/ecdsa.rs:378` | Derive child `ECDSA` keys. | Not covered | Native derivation uses `Secp256k1HDKD` and Blake2. The library has no `ECDSA` component. |
| Hard key paths | `Bandersnatch` | `substrate/primitives/core/src/bandersnatch.rs:114`, `substrate/primitives/core/src/bandersnatch.rs:125` | Derive child `Bandersnatch` keys. | Not covered | Native derivation uses `bandersnatch-vrf-HDKD` and Blake2. Soft junctions fail. |
| Soft key paths | `sr25519` soft junctions | `substrate/primitives/core/src/sr25519.rs:79`, `substrate/primitives/core/src/sr25519.rs:250` | Derive public and private child keys. | Not covered | The library rejects soft junctions by design. |
| Secret URI handling | Mnemonic and junction parsing | `substrate/primitives/core/src/crypto.rs:949` | Parse phrases, passwords, seeds, and junction strings. | Partial | Seed recovery and hard derivation exist. String parsing and chain code encoding stay in the integration. |

## Gaps

**Now / Directional — host and keystore key interfaces.**
The library generates hybrid keys, but upstream stores app keys through scheme-specific methods.
A keystore integration could call the existing key generation functions.
It must also define session keys and `SCALE` envelopes.
Account identifier rules remain unknown, along with deployment choices.

**Next / Directional — `BABE` and generic `sr25519` VRFs.**
`BABE` constructs a `Merlin` transcript from the slot and epoch, plus chain randomness.
The library accepts input bytes under its suite signing context.
An integration must supply the protocol data through `input` and verify the resulting transcript mapping.
Matching `DLEQ` proof formats does not establish matching transcripts or leadership scores.
This scan does not establish those equivalences.
The post-quantum binding must never enter the randomness derivation.

**Next / Directional — approval assignment VRFs and relay stories.**
Approval voting uses custom transcripts and output contexts through `vrf_sign_extra_after_check`.
Its verifier also checks an extra transcript that binds the assigned cores.
The library provides the `sr25519` VRF primitive but no corresponding extra-transcript API.
A hybrid assignment protocol could use that primitive after defining the transcript and binding rules.
The required mapping and selection scores remain unknown, along with the certificate format.

**Now / Directional — network identity.**
Network signing and peer identifiers use `Libp2p` or `Litep2p` `ed25519` types outside the app keystore.
Hybrid `ed25519` keys and signatures do not fit these existing network formats.
Hybrid peer authentication would need new key encoding and peer identifier rules.
It would also need a new verifier.
This scan does not establish peer compatibility or a protocol for those changes.

**Later / Exploratory — `ECDSA` and Ethereum recovery.**
Host functions, `BEEFY`, statement storage, account enums, contracts, permits, and claims require `ECDSA` over `secp256k1`.
The library provides neither that component nor public key recovery.
It also lacks native `ECDSA` hard key derivation.
A future `ECDSA` hybrid suite could serve protocols that accept new key and signature formats.
Existing Ethereum signature formats cannot carry its post-quantum component.
The required recovery API and hashing rules remain unknown, along with external protocol changes.

**Later / Exploratory — `P-256` signatures and certificate keys.**
`WebRTC` derives a `P-256` key from the node secret and signs a `DTLS` certificate.
`Revive` verifies `P-256` signatures through `RIP-7212`.
Neither operation uses `secp256k1`, `ed25519`, or `sr25519`.
A future `P-256` hybrid suite would still need certificate and precompile changes.
This scan does not establish client acceptance or signature format rules.
Execution costs also remain unknown.

**Later / Exploratory — `BLS` and paired classical schemes.**
The SDK supplies `BLS377` and `BLS381`, along with `ECDSA-BLS` pairs.
Those schemes also supply key derivation and proofs of possession.
`BEEFY` app bindings use `BLS381` and `ECDSA-BLS381` behind `bls-experimental`.
The library supplies none of these components.
Adding a `BLS` hybrid component would also require compatible proofs of possession and message hashing.
The required scheme variants and deployment configurations remain unknown.

**Later / Exploratory — signature aggregation.**
`Snowbridge` verifies Ethereum `BLS` signatures after aggregation.
`BEEFY` witnesses accept an accumulator, and an experimental test combines `BLS` signatures.
The library verifies individual hybrid signatures and provides no signature aggregation construction.
Pairing `BLS` with an ordinary post-quantum signature would not prove signature aggregation for both components.
A suitable post-quantum signature aggregation construction and its proof costs remain unknown.

**Later / Exploratory — `Bandersnatch` signatures, VRFs, and ring proofs.**
`Sassafras` needs `Bandersnatch` authority signatures and slot VRFs, plus anonymous ring VRF tickets.
Keystore methods expose the same VRF operations.
The native hard key path also needs a `Bandersnatch` key component.
`FRAME` personhood also expects a membership proof system, normally a ring VRF.
The library's VRFs do not provide `Bandersnatch` or anonymous membership proofs.
An ordinary post-quantum signature binding does not preserve ring anonymity.
A private hybrid construction and its proof size remain unknown, along with the selected personhood proof system.

**Now / Directional — legacy batch verification interfaces.**
The SDK retains batch host functions for old runtimes.
Those functions now verify individual signatures and accumulate a boolean result.
The scan found no `BatchVerifier` type.
An adapter could call the library's individual verifier for each `ed25519` or `sr25519` signature.
The library does not provide this interface or an efficient hybrid batch algorithm.
Runtime requirements and batch verification costs remain unknown.

**Next / Directional — hard junctions and secret URI parsing.**
The library derives hybrid child master seeds with `HKDF` and re-derives both components.
Upstream `ed25519` and `sr25519` use their native hard derivation operations.
Matching mnemonic master seeds does not imply matching component keys or derived child keys.
An integration can use hybrid hard junctions, but it must parse junction strings and encode chain codes.
Existing key compatibility and the required parsing rules remain unknown.
`SHRINCS` child keys also need persistent state after their first derivation.

**Later / Exploratory — soft junctions.**
Upstream `sr25519` derives public and private child keys through soft junctions.
The library supports hard junctions only.
An adapter cannot add a missing hybrid soft derivation construction.
A design would need compatible child keys for both signature components.
The required public derivation behavior and post-quantum construction remain unknown.

**Later / Exploratory — encryption and key exchange.**
Statement storage converts `ed25519` keys to `X25519` for `ECIES`.
`Mixnet` uses `X25519` keys for message encryption.
The library's `ed25519` signature component does not supply these operations or post-quantum confidentiality.
A separate encryption or key exchange construction would need protocol-specific integration.
The required encryption key rules and post-quantum key exchange choice remain unknown.

## Method

The scan follows the Task 5 searches in `docs/superpowers/plans/2026-10-09-audit-fixes-and-stable-release.md`.
The task brief supplies the commands in this worktree.
The scan uses a depth-one clone of the default upstream branch.
It treats source files as untrusted data and runs no upstream builds, scripts, or tests.

The original searches use these commands from the workspace root.
Each command saves stdout in `target/polkadot-scan/`.
Counts include comments, tests, and repeated hits.
The `-l` search counts matching files.
The key-type command names `crypto.rs` twice through overlapping search roots.

```sh
mkdir -p target/polkadot-scan
P=target/polkadot-sdk
# host-functions.txt: 0 lines
rg -n "fn (ed25519|sr25519|ecdsa|bls|bandersnatch)[a-z0-9_]*(verify|sign|recover|generate|public_keys)[a-z0-9_]*" $P/substrate/primitives/io/src/lib.rs > target/polkadot-scan/host-functions.txt

# app-crypto.txt: 30 lines
rg -n "app_crypto!\(" $P --type rust > target/polkadot-scan/app-crypto.txt

# key-types.txt: 53 lines
rg -n "KeyTypeId\(\*b\"" $P/substrate/primitives/core/src/crypto.rs $P --type rust > target/polkadot-scan/key-types.txt

# multisignature.txt: 37 lines
rg -n "enum MultiSignature|enum MultiSigner|Ed25519\(|Sr25519\(|Ecdsa\(" $P/substrate/primitives/runtime/src/lib.rs > target/polkadot-scan/multisignature.txt

# vrf.txt: 263 lines
rg -n "vrf_sign|VrfSignature|VrfPreOutput|vrf_pre_output|RingVrfSignature|ring_vrf|make_bytes" $P/substrate/primitives $P/substrate/client/consensus $P/substrate/frame --type rust > target/polkadot-scan/vrf.txt

# uncovered-primitives.txt: 55 lines
rg -n "ecdsa::|secp256k1|bls377|bls381|ecdsa_bls|bandersnatch|ed448|paired_crypto" $P/substrate/primitives $P/substrate/frame $P/polkadot $P/cumulus $P/bridges --type rust -l > target/polkadot-scan/uncovered-primitives.txt

# batch.txt: 100 lines
rg -n "verify_batch|BatchVerifier|batch_verify|aggregate" $P/substrate/primitives $P/substrate/client --type rust > target/polkadot-scan/batch.txt

# node-keys.txt: 27 lines
rg -n "identity::Keypair|ed25519::Keypair|sign\(" $P/substrate/client/network/src $P/substrate/client/authority-discovery/src $P/substrate/client/statement-store --type rust > target/polkadot-scan/node-keys.txt
```

The original host search returned zero lines because the functions moved from `io/src/lib.rs` to `io/src/relay_chain.rs`.
The scan widened that search to `io/src/` and found 27 lines.
The host pattern also omits names that start with `secp256k1`.
A separate recovery search found six lines.

```sh
rg -n "fn (ed25519|sr25519|ecdsa|bls|bandersnatch)[a-z0-9_]*(verify|sign|recover|generate|public_keys)[a-z0-9_]*" $P/substrate/primitives/io/src > target/polkadot-scan/host-functions-wide.txt
rg -n "fn secp256k1_ecdsa_recover" $P/substrate/primitives/io/src > target/polkadot-scan/host-recovery.txt
```

Other searches examine the whole Rust tree and follow consumers, key derivation, enum variants, certificates, personhood, and bridge verification.
Those searches found the `Eth` enum variant, approval VRFs, `P-256` uses, and `Sassafras` ephemeral `ed25519` keys.
They also found `BLS377` core primitives and `Snowbridge` signature aggregation outside the original primitive patterns.
All search output files received a full read before drafting.
Source reads resolve ambiguous hits in deprecated batch operations and aggregation tests.

The scan does not infer cryptographic use from a key type identifier alone.
Documentation macros and test key identifiers do not create separate consumer rows.
Repeated app wrappers also share rows.
Generic consumers inherit variants only when inspected type bindings establish their signature enum.
The scan excludes unrelated transaction stream aggregation and Merkle proof batch hits.
Text searches do not prove that all runtime configurations or external dependency internals use the same primitives.

Raw output remains in the ignored clone and scan directories.
No raw output enters the documentation commit.
Upstream citations can also use this fixed source root:
`https://github.com/paritytech/polkadot-sdk/blob/05ddbee5c062d49c8a2a072c529a2fc80aad243e/`.

## blocked / needs-decision

No blocker prevents this report.

The report makes these assumptions and records these limits:

- Covered measures primitive support.
  Existing wire formats, suite contexts, and Substrate interfaces still need integration.
- Subsystem and primitive pairs group related consumers and API roles.
  Shared account enums permit variants without proving that every deployment uses every variant.
- The default branch snapshot represents upstream on the scan date.
  The clone contains one commit and does not establish historical coverage.
- Now, Next, and Later state an assessment of follow-up order.
  Directional and Exploratory express confidence, not a delivery commitment.
- Experimental definitions count as source coverage.
  The report does not claim that a deployed network enables them.
- The initial host pattern returned zero matches.
  Widening the path recovered the current host definitions.
- The whole-tree `\bed448\b` pattern returned zero matches.
  The table contains no ed448 row.
- The whole-tree `BatchVerifier` pattern returned zero matches.
  Legacy batch host functions still appear and need separate interpretation.
- Supplemental searches named four absent paths: bridge `signing.rs`, `client-polkadot/src/lib.rs`, `FRAME` `hop/src/lib.rs`, and people `impls.rs`.
  Wider searches found bridge signing traits and `HOP` primitives.
  They also found personhood types.
  Missing paths supplied no table evidence.
- The supplemental VRF exclusion globs did not exclude the intended prefixed paths.
  That search included the original roots again.
  The scan retained and read the repeated hits.
- The scan reads external cryptographic call sites without fetching dependency implementations.
  It does not prove compatibility with external cryptographic code or runtime costs.
