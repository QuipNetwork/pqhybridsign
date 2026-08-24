# @quip.network/pqhybridsign

Hybrid classical/post-quantum signing (H1-H6), compiled to WebAssembly, with
one Promise-based TypeScript API for both Node.js and browsers.

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
const { publicKey, secretKey } = await keygenFromSeed("H1", seed);

const msg = new TextEncoder().encode("the message to sign");
const ctx = new TextEncoder().encode("example-context");
const sig = await sign("H1", secretKey, msg, ctx);

const ok = await verify("H1", publicKey, msg, ctx, sig);
// ok === true
```

`Suite` names H1 through H4 sign and verify from this package. H5 and H6 are
stateful suites: this package does not offer signing for them, because a
JavaScript secret key object cannot stop `structuredClone` or a second
reference from forking its one-time leaf counter, which destroys the key's
post-quantum security. `keygenFromSeed`, `sign` and `signDeterministic`
reject for H5 and H6. `verify`, `verifyWithStoredPublicKey` and the length
accessors work as documented for every suite.

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
