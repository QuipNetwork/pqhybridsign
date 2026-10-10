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

### Host functions and keystore methods

The original host search returned zero lines because the functions moved from `io/src/lib.rs` to `io/src/relay_chain.rs`.
The file list identified the current source path.

```sh
# Initial file discovery: 3 lines
rg --files target/polkadot-sdk/substrate/primitives/io/src
```

The scan widened the original host path to `io/src/` and found 27 lines.
The original pattern omits names that start with `secp256k1`.
The separate recovery pattern found six lines.

```sh
# host-functions-wide.txt: 27 lines, exit 0
rg -n "fn (ed25519|sr25519|ecdsa|bls|bandersnatch)[a-z0-9_]*(verify|sign|recover|generate|public_keys)[a-z0-9_]*" $P/substrate/primitives/io/src > target/polkadot-scan/host-functions-wide.txt 2> target/polkadot-scan/host-functions-wide.err

# host-recovery.txt: 6 lines, exit 0
rg -n "fn secp256k1_ecdsa_recover" $P/substrate/primitives/io/src > target/polkadot-scan/host-recovery.txt 2> target/polkadot-scan/host-recovery.err
```

The keystore search applies scheme-specific patterns to the keystore interface.
The primitive search adds module definitions and proof-of-possession operations.

```sh
# keystore-apis.txt: 52 lines, exit 0
rg -n "^\s*fn (ed25519|sr25519|ecdsa|bls381|ecdsa_bls381|bandersnatch)_(public_keys|generate_new|sign|vrf|ring|generate_proof)" $P/substrate/primitives/keystore/src/lib.rs > target/polkadot-scan/keystore-apis.txt 2> target/polkadot-scan/keystore-apis.err

# primitive-definitions.txt: 78 lines, exit 0
rg -n "^pub mod (bls377|bls381|ecdsa_bls377|ecdsa_bls381)|^pub type (Signature|Public)|^pub struct .*Signature|proof_of_possession|fn bls381" $P/substrate/primitives/core/src/{bls,paired_crypto,proof_of_possession}.rs $P/substrate/primitives/io/src/relay_chain.rs > target/polkadot-scan/primitive-definitions.txt 2> target/polkadot-scan/primitive-definitions.err
```

### Primitive inventory

The `crypto-inventory` search expands `uncovered-primitives` to the whole Rust tree and adds supported schemes and signature types.
Its globs exclude test files and test directories.
The file list identifies the current core, network, and bridge client sources.
The final patterns use word boundaries for candidate primitive names and then isolate `ed448`.

```sh
# crypto-inventory.txt: 182 lines, exit 0
rg -l "ed25519::|sr25519::|ecdsa::|secp256k1|bls377|bls381|ecdsa_bls|bandersnatch|ed448|paired_crypto|MultiSignature|VrfSignature|RingProof|ring_vrf" $P --type rust -g "!**/tests/**" -g "!**/tests.rs" -g "!**/mock.rs" -g "!**/benchmarking.rs" -g "!**/benches/**" -g "!**/test_utils.rs" -g "!**/test-utils/**" > target/polkadot-scan/crypto-inventory.txt 2> target/polkadot-scan/crypto-inventory.err

# crypto-tree.txt: 89 lines, exit 0
rg --files $P/substrate/primitives/core/src $P/substrate/client/network/src $P/bridges/relays/client-substrate/src > target/polkadot-scan/crypto-tree.txt 2> target/polkadot-scan/crypto-tree.err

# absent-primitives.txt: 25 lines, exit 0
rg -n "\b(ed448|bls377|ecdsa_bls377)\b" $P --type rust > target/polkadot-scan/absent-primitives.txt 2> target/polkadot-scan/absent-primitives.err

# no-ed448.txt: 0 lines, exit 1
rg -n "\bed448\b" $P --type rust > target/polkadot-scan/no-ed448.txt 2> target/polkadot-scan/no-ed448.err
```

### Key derivation and signing contexts

The derivation search adds hard and soft junctions to the original signature and key patterns.
The context search then checks native derivation labels and signing functions.
It also reads `bridges/snowbridge/primitives/beacon/Cargo.toml`.

```sh
# derivation.txt: 68 lines, exit 0
rg -n "fn (derive|from_phrase|from_string|from_seed_slice)|DeriveJunction::(Soft|Hard)|DeriveError::SoftKeyInPath|mini_secret_from_entropy" $P/substrate/primitives/core/src/{crypto,ed25519,sr25519,ecdsa,bandersnatch,bls,paired_crypto}.rs > target/polkadot-scan/derivation.txt 2> target/polkadot-scan/derivation.err

# seed-and-context.txt: 79 lines, exit 0
rg -n "seed_from_entropy|SIGNING_CTX|Ed25519HDKD|substrate-bip39|verifiable|BLS12|BlsEngine|fn sign|fn verify" $P/substrate/primitives/core/src/{ed25519,sr25519,bls}.rs $P/substrate/primitives/core/src/crypto.rs $P/bridges/snowbridge/primitives/beacon/Cargo.toml > target/polkadot-scan/seed-and-context.txt 2> target/polkadot-scan/seed-and-context.err
```

### Transcripts and signature enums

The `vrf-extra` search widens the original VRF search to the whole Rust tree.
Its exclusion globs did not match the prefixed paths, so the output retains repeated hits.
The enum search adds `Eth` and `AnySignature` to the original enum patterns.
It also checks `BABE` input construction and approval extra transcripts.

```sh
# vrf-extra.txt: 363 lines, exit 0
rg -n "vrf_sign|VrfSignature|VrfPreOutput|vrf_pre_output|RingVrfSignature|ring_vrf|make_bytes" $P --type rust -g "!substrate/primitives/**" -g "!substrate/client/consensus/**" -g "!substrate/frame/**" > target/polkadot-scan/vrf-extra.txt 2> target/polkadot-scan/vrf-extra.err

# enum-and-transcripts.txt: 59 lines, exit 0
rg -n "Eth\(|AnySignature|make_vrf_transcript|BABE_ENGINE_ID|vrf_sign_extra_after_check|VrfInput::new|Transcript::new|extra" $P/substrate/primitives/runtime/src/lib.rs $P/substrate/primitives/consensus/babe/src/lib.rs $P/polkadot/node/core/approval-voting/src/criteria.rs $P/substrate/primitives/core/src/sr25519.rs > target/polkadot-scan/enum-and-transcripts.txt 2> target/polkadot-scan/enum-and-transcripts.err
```

### Batch verification and signature aggregation

The first command widens the original batch search to the whole Rust tree and targets definitions.
The next patterns isolate `BatchVerifier` and `verify_batch`, then `BatchVerifier` alone.
The `BEEFY` search adds feature conditions and commitment verification to the aggregation patterns.

```sh
# verification-extra.txt: 26 lines, exit 0
rg -n "fn (verify_batch|batch_verify)|struct BatchVerifier|fn.*aggregate|SignatureAggregator" $P --type rust > target/polkadot-scan/verification-extra.txt 2> target/polkadot-scan/verification-extra.err

# no-batch-verifier.txt: 7 lines, exit 0
rg -n "BatchVerifier|verify_batch" $P --type rust > target/polkadot-scan/no-batch-verifier.txt 2> target/polkadot-scan/no-batch-verifier.err

# batch-verifier-only.txt: 0 lines, exit 1
rg -n "BatchVerifier" $P --type rust > target/polkadot-scan/batch-verifier-only.txt 2> target/polkadot-scan/batch-verifier-only.err

# beefy-crypto.txt: 215 lines, exit 0
rg -n "app_crypto!|cfg\(|Signature|ProofOfPossession|verify|commitment|aggregate|public_key_to|bls381|BLS381" $P/substrate/primitives/consensus/beefy/src/{lib,witness}.rs $P/substrate/frame/beefy-mmr/src/lib.rs > target/polkadot-scan/beefy-crypto.txt 2> target/polkadot-scan/beefy-crypto.err
```

### Consensus and runtime consumers

These commands follow app key bindings into concrete consumers.
The runtime and contract patterns add verification call sites beyond the original app macros and signature enum.
The node search adds primitive and network type paths to `node-keys`.
The ticket search isolates `Sassafras` ephemeral keys from authority keys.

```sh
# polkadot-signatures.txt: 64 lines, exit 0
rg -n "app_crypto!|type (Collator|Validator|Assignment)|Signature|sign_payload|check_signature|fn sign" $P/polkadot/primitives/src/v9/mod.rs $P/polkadot/node/primitives/src/{lib,disputes/mod}.rs $P/polkadot/node/network/protocol/src/lib.rs > target/polkadot-scan/polkadot-signatures.txt 2> target/polkadot-scan/polkadot-signatures.err

# runtime-crypto.txt: 170 lines, exit 0
rg -n "MultiSignature|sr25519|ed25519|verify\(|Signature|signing" $P/polkadot/runtime/common/src/{claims/mod,crowdloan/mod,purchase/mod}.rs $P/substrate/frame/{identity,nfts}/src/lib.rs $P/substrate/frame/system/src/offchain.rs $P/substrate/frame/verify-signature/src/extension.rs > target/polkadot-scan/runtime-crypto.txt 2> target/polkadot-scan/runtime-crypto.err

# contract-crypto.txt: 32 lines, exit 0
rg -n "fn.*(ed25519|sr25519|ecdsa|secp256k1)|secp256k1_ecdsa|ecdsa_recover|Signature::|verify\(|recover\(" $P/substrate/frame/{contracts,revive}/src/exec.rs $P/substrate/frame/revive/src/{precompiles/builtin/ecrecover,evm/api/signature,evm/eip7702}.rs $P/substrate/frame/assets/precompiles/src/permit.rs > target/polkadot-scan/contract-crypto.txt 2> target/polkadot-scan/contract-crypto.err

# node-extra.txt: 324 lines, exit 0
rg -n "sr25519|ed25519|ecdsa|sign\(|verify\(|PeerId|from_public|Proof|Bandersnatch|verifiable" $P/substrate/primitives/statement-store/src/lib.rs $P/substrate/client/network/src/service/signature.rs $P/substrate/client/network/types/src/{peer_id,ed25519}.rs $P/substrate/primitives/mixnet/src/types.rs $P/substrate/client/authority-discovery/src/worker.rs > target/polkadot-scan/node-extra.txt 2> target/polkadot-scan/node-extra.err

# sassafras-ephemeral.txt: 5 lines, exit 0
rg -n "EphemeralPublic|EphemeralSignature|EphemeralPair|bandersnatch|ed25519|sr25519|verify" $P/substrate/primitives/consensus/sassafras/src/ticket.rs $P/substrate/frame/sassafras/src/lib.rs > target/polkadot-scan/sassafras-ephemeral.txt 2> target/polkadot-scan/sassafras-ephemeral.err
```

### Certificates and other primitives

The original `uncovered-primitives` pattern omitted `P-256`.
The whole-tree pattern adds `secp256r1` and `p256::`, along with other candidate schemes.
The certificate search then isolates the network certificate operations.

```sh
# other-primitives.txt: 43 lines, exit 0
rg -n "secp256r1|p256::|P256|rsa::|RS256|ed448|blst::|milagro_bls|BandersnatchVrfVerifiable" $P --type rust > target/polkadot-scan/other-primitives.txt 2> target/polkadot-scan/other-primitives.err

# network-certificates.txt: 62 lines, exit 0
rg -n "p256|ecdsa|SigningKey|sign_prehash|Certificate|certificate|fn derive|fn generate|seed" $P/substrate/client/network/src/webrtc.rs > target/polkadot-scan/network-certificates.txt 2> target/polkadot-scan/network-certificates.err
```

### Encryption and key exchange

This pattern adds encryption and key exchange operations to the original node signing search.
It examines statement encryption and mixnet public keys, along with network transport.

```sh
# key-exchange.txt: 30 lines, exit 0
rg -n "fn (encrypt|decrypt)|x25519|X25519|NoiseConfig|noise::|SecretKey|fn derive_shared" $P/substrate/primitives/statement-store/src/ecies.rs $P/substrate/client/network/src/transport.rs $P/substrate/primitives/mixnet/src/types.rs > target/polkadot-scan/key-exchange.txt 2> target/polkadot-scan/key-exchange.err
```

### Consumer account bindings

The first command checks concrete runtime signature and authority types.
It names the absent path `substrate/frame/hop/src/lib.rs`.

```sh
# runtime-bindings.txt: 20 lines, exit 2
rg -n "type (OffchainSignature|OffchainPublic|SigningPublicKey|Signature|AccountKeyPair)|pub type Signature|type Crypto =|Crypto = verifiable|type AuthorityId" $P/cumulus/parachains/runtimes/{people,assets}/ $P/polkadot/core-primitives/src/lib.rs $P/templates/{parachain,solochain}/runtime/src/{lib,configs/mod}.rs $P/substrate/frame/{verify-signature,hop}/src/lib.rs > target/polkadot-scan/runtime-bindings.txt 2> target/polkadot-scan/runtime-bindings.err
```

The `HOP` search uses the current client and primitive directories instead of that absent pallet path.
Its pattern follows signatures and verification call sites.

```sh
# hop-crypto.txt: 43 lines, exit 0
rg -n "sr25519|ed25519|Signature|verify|sign\(" $P/substrate/primitives/hop/src/lib.rs $P/substrate/client/hop/src/{promotion,types,rpc}.rs > target/polkadot-scan/hop-crypto.txt 2> target/polkadot-scan/hop-crypto.err
```

The next command names the absent bridge client path `bridges/relays/client-polkadot/src/lib.rs`.

```sh
# configured-consumers.txt: 4 lines, exit 2
rg -n "type AccountKeyPair|OffchainSignature|pub type Signature|signature.verify|\.verify\(|sr25519|ed25519" $P/bridges/relays/client-polkadot/src/lib.rs $P/substrate/frame/nfts/src/features/{create_delete_item,attributes}.rs $P/cumulus/parachains/common/types/src/lib.rs > target/polkadot-scan/configured-consumers.txt 2> target/polkadot-scan/configured-consumers.err
```

The binding search widens that path to `bridges/relays` and checks account key aliases.
It also checks proof system configuration and ephemeral key types in current runtime and primitive paths.

```sh
# binding-closure.txt: 11 lines, exit 0
rg -n "type AccountKeyPair =|BandersnatchVrfVerifiable|type (Crypto|Verifier) =|impl pallet_hop|type Signature =|PublicKey =|EphemeralPublic|EphemeralSignature" $P/bridges/relays $P/cumulus/parachains/runtimes/people $P/substrate/primitives/consensus/sassafras/src/lib.rs $P/substrate/frame/people > target/polkadot-scan/binding-closure.txt 2> target/polkadot-scan/binding-closure.err
```

### Personhood and asset authorization

The first pattern adds membership proof terms to the original VRF and primitive searches.
The runtime search checks the inspected `People` configuration.

```sh
# people-crypto.txt: 278 lines, exit 0
rg -n "Bandersnatch|ring_vrf|verifiable|Proof|signature|key" $P/substrate/frame/people/src/lib.rs $P/substrate/primitives/statement-store/Cargo.toml $P/Cargo.toml > target/polkadot-scan/people-crypto.txt 2> target/polkadot-scan/people-crypto.err

# people-bindings.txt: 2 lines, exit 0
rg -n "Bandersnatch|GenerateVerifiable|Crypto|OffchainSignature|Signature|verify|Proof" $P/cumulus/parachains/runtimes/people/people-westend/src/people.rs > target/polkadot-scan/people-bindings.txt 2> target/polkadot-scan/people-bindings.err
```

The next command names the absent path `substrate/frame/people/src/impls.rs`.

```sh
# consumer-closure.txt: 8 lines, exit 2
rg -n "OffchainSignature|verify|fn.*sign|Signature|Crypto|Verifier" $P/substrate/frame/nfts/src/features/{create_delete_item,attributes}.rs $P/substrate/frame/people/src/{types,impls}.rs > target/polkadot-scan/consumer-closure.txt 2> target/polkadot-scan/consumer-closure.err
```

The replacement search widens `NFT` paths to `nfts/src` and reads personhood configuration from `people/src/lib.rs`.
It adds `bridges/snowbridge/primitives/beacon/Cargo.toml` and excludes test files.

```sh
# current-consumers.txt: 57 lines, exit 0
rg -n "OffchainSignature|fn validate_signature|\.verify\(|type Crypto|impl.*Config|BLS12-381|milagro" $P/substrate/frame/nfts/src $P/substrate/frame/people/src/lib.rs $P/bridges/snowbridge/primitives/beacon/Cargo.toml -g "!**/tests.rs" -g "!**/tests/**" -g "!**/mock.rs" -g "!**/benchmarking.rs" > target/polkadot-scan/current-consumers.txt 2> target/polkadot-scan/current-consumers.err
```

### Bridge verification

The first command adds bridge authority types and `BLS` verification to the original unsupported primitive search.
It names the absent path `bridges/relays/client-substrate/src/signing.rs`.

```sh
# bridge-crypto.txt: 94 lines, exit 2
rg -n "AuthorityId|AuthoritySignature|Grandpa|Pair|Signature|ecdsa|bls|Bls|BLST|PublicKey|fast_aggregate" $P/bridges/primitives/{header-chain,polkadot-core}/src/lib.rs $P/bridges/relays/client-substrate/src/{chain,signing}.rs $P/bridges/snowbridge/primitives/beacon/src/bls.rs > target/polkadot-scan/bridge-crypto.txt 2> target/polkadot-scan/bridge-crypto.err
```

The replacement widens the relay path to `bridges/relays/client-substrate/src`.
It also searches the header verifier directory.
Its changed pattern targets signing methods and verification call sites.

```sh
# bridge-signing-wide.txt: 6 lines, exit 0
rg -n "type AccountKeyPair|fn sign_transaction|fn sign\(|check_message_signature|AuthoritySignature::|signature.verify" $P/bridges/relays/client-substrate/src $P/bridges/primitives/header-chain/src > target/polkadot-scan/bridge-signing-wide.txt 2> target/polkadot-scan/bridge-signing-wide.err
```

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

### Limits

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
