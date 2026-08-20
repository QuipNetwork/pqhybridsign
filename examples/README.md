# Sample sign/verify roundtrips

One roundtrip program per language, exercising every stateless suite
(H1 through H4) this release ships. Each one runs against a published
artifact, never against this source tree, so a file missing from a
package fails a smoke job before that package reaches a registry.

Every program runs the same check for H1, then H2, then H3, then H4. It
derives a keypair from a fixed 32-byte seed and signs a fixed message
with it. That signature must verify. A copy of the message with one
byte flipped must not verify under the same signature. No program uses
a random number generator. Every seed and nonce is a fixed constant, so
a run is byte-for-byte repeatable. Each program prints one line per
suite as it passes and exits 0. On the first failure it prints one
message to stderr and exits nonzero.

| Language | File | What it proves | How the smoke job runs it |
| -- | -- | -- | -- |
| Rust | `rust/src/main.rs` | The `pqhybridsign` and `pqhybridsign-core` crates round-trip H1-H4 as published to crates.io. | Builds `examples/rust` against the unpacked `.crate` tarballs via a temporary `[patch.crates-io]` block, then runs the release binary. |
| C++ | `cpp/roundtrip.cpp` | The C ABI header (`pqhybridsign.h`) matches the shipped `libpqhybridsign_cffi` library byte for byte. | Compiles against the released clib tarball's header and library, then runs the binary. |
| Python | `python/roundtrip.py` | The `pqhybridsign` wheel imports and round-trips H1-H4 from a clean virtual environment. | Installs the built wheel into a fresh venv, then runs the script under that interpreter. |
| TypeScript | `typescript/src/roundtrip.ts` | The `@quip.network/pqhybridsign` npm package's async wasm API round-trips H1-H4. | Installs the packed npm tarball into a clean project, compiles with `tsc`, then runs the emitted JavaScript under Node. |

## Two ways to build a signer

**Rust and C++ call the same compiled code two ways.** The Rust example
calls `pqhybridsign_core::composite` and `composite_delta` directly. The
C++ example calls the identical operations through `pqhybridsign-cffi`'s
`pqhs_*` entry points, which wrap that same Rust code behind a stable C
interface. Neither example reimplements signing or verification.

**Python and TypeScript both load the same primitives through a
different boundary.** Python reaches them through PyO3
(`pqhybridsign-py`). TypeScript reaches them through WebAssembly
(`pqhybridsign-wasm`). Loading a wasm module takes time, so the
TypeScript functions return a promise, and the example code awaits
each one. Both languages run the same compiled Rust that the crates.io
and PyPI releases run.

## Build each example

### Rust

```sh
cd examples/rust && cargo run --release
```

### C++

Requires `libpqhybridsign_cffi` and `pqhybridsign.h` from a built or
released artifact. Point `PQHS_LIB_DIR`/`PQHS_INCLUDE_DIR` at them, or
build the library locally from this repository:

```sh
cargo build --release -p pqhybridsign-cffi
g++ -std=c++17 -O2 -Wall -Wextra \
  -I crates/pqhybridsign-cffi/include \
  examples/cpp/roundtrip.cpp -o /tmp/pqhs_roundtrip_cpp \
  -L target/release -Wl,-rpath,"$PWD/target/release" \
  -lpqhybridsign_cffi -lpthread -ldl -lm
/tmp/pqhs_roundtrip_cpp
```

### Python

```sh
pip install pqhybridsign
python examples/python/roundtrip.py
```

### TypeScript

```sh
cd examples/typescript && npm install && npm run build
npm run start
```

## Suite coverage

Only H1 through H4 appear here. H5 and H6 (the stateful SHRINCS suites)
spend a one-time leaf per signature. Every binding signs them through a
separate, journal-bound path instead. A roundtrip that reused a fixed
seed across repeated runs would double-spend a leaf. A stateful example
also needs a durable journal, which sits outside the scope of a
stateless sign/verify smoke check. The TypeScript wasm API reflects
this directly: `keygenFromSeed`, `sign`, and `signDeterministic` all
reject for H5 and H6, while `verify` and the length accessors work for
every suite.
