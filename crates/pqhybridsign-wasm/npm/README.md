# @quip.network/pqhybridsign

Hybrid classical/post-quantum signing (ED-ML-44, ED-FN-512, SR-ML-44,
SR-FN-512, ED-SH, SR-SH), compiled to WebAssembly, with one Promise-based
TypeScript API for both Node.js and browsers.

```sh
npm install @quip.network/pqhybridsign
```

## Usage

Every function is async. Each resolves after the wasm module loads. The
loader caches the load, so the first call pays for it and every later call
reuses it. The one exception is a module trap. If a call rejects with
`PqHybridSignPanic`, the loader discards the cached instance and the next
call loads a new one.

```ts
import { keygenFromSeed, sign, verify } from "@quip.network/pqhybridsign";

const seed = crypto.getRandomValues(new Uint8Array(32));
const { publicKey, secretKey } = await keygenFromSeed("ED-ML-44", seed);

const msg = new TextEncoder().encode("the message to sign");
const ctx = new TextEncoder().encode("example-context");
const sig = await sign("ED-ML-44", secretKey, msg, ctx);

const ok = await verify("ED-ML-44", publicKey, msg, ctx, sig);
// ok === true
```

`Suite` names ED-ML-44 through SR-FN-512 are stateless: `keygenFromSeed`,
`sign` and `signDeterministic` sign and verify with them, and reject ED-SH
and SR-SH. ED-SH and SR-SH are stateful: each signature spends a one-time
leaf. `keygenStatefulFromSeed`, `openStatefulKey`, `signStateful`,
`signStateless` and `adoptKey` handle them instead. Each call takes a
caller-supplied durable leaf journal, which
records a leaf before its signature returns. That durability stops a
JavaScript secret key handle from forking its counter. A bare
`structuredClone` or a second reference would otherwise fork it and destroy
the key's post-quantum security. `verify`, `verifyWithStoredPublicKey` and
the length accessors work as documented for every suite.

`masterSeedFromMnemonic`, `deriveHardJunction` and `deriveHardJunctionPath`
derive a 32-byte master seed from an English recovery phrase or from an
existing master seed, using Substrate's key derivation rather than standard
BIP39.

`vrfProofLen`, `vrfProve`, `vrfProveDeterministic`, `vrfVerify` and
`vrfMakeBytes` cover the hybrid verifiable random function for ED-ML-44
through SR-FN-512. ED-SH and SR-SH use it through `deriveVrfStatelessKey`
and the returned key's `prove`, which spend a caller-tracked few-time
stateless budget instead of a signing leaf.

## Publishing this package

`package.json` here declares the package's name, exports and files, but
`web/`, `node/` and `dist/` are build output, not checked into git. To
produce a publishable package:

```sh
../scripts/build-npm.sh   # writes npm/web/, npm/node/ and npm/dist/
npm publish               # run from this directory
```

`scripts/check-types.sh` (run from the crate root, and wired into
continuous integration) regenerates the wasm-bindgen TypeScript definitions
and fails if they differ from the checked-in copies under `types/`. Run
`scripts/regenerate-types.sh` and commit the result whenever
`src/lib.rs`'s public surface changes.
