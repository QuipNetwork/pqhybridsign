# QPA-03: secret storage cleanup (work in progress)

QPA-03 must remain open. These changes reduce the reported copies; they do
not establish erasure of every secret-bearing value in dependencies or all
supported builds.

## Changes

Hard-junction derivation has an output-buffer API. Path derivation uses two
drop-wiped buffers, overwrites the old parent and wipes the next buffer after
copying. The existing return-value API remains available and wipes its local
output after returning a copy. The caller owns the returned seed. As before,
the HKDF/HMAC implementation retains internal keyed state that this crate
cannot erase.

Secret SHA-512 inputs in the deterministic RNG, sr25519 nonce derivation,
Falcon nonce derivation and Ed25519 VRF expansion and nonce generation use an
explicitly wiped buffer and state. The adapter uses the existing sha2
compression function and preserves the SHA-512 byte stream. Ed25519 VRF
response arithmetic borrows the nonce and uses a wiped in-place multiplication
operand. These measures do not guarantee erasure of compiler- or
dependency-created temporaries.

The SDK wrapper holds parent and child seeds in drop-wiped buffers. Until its
pinned library exposes the output-buffer API, an SDK-local implementation of
the identical HKDF junction writes into the guarded child buffer. SDK tests
compare it with the pinned library. The SDK's key-generation and key-import
adapters also write into drop-wiped secret-key objects and guard generated
seeds. Its ML-DSA public-key recovery still calls fips204's by-value secret
key deserializer, which may create another copy outside the caller's guard.

Replacing the SDK's temporary junction implementation with the library API
requires a library revision that contains these changes, the QPA-02 fixes,
and the SDK's QUIP HD API, followed by an SDK dependency and lockfile update.

## Remaining work before closure

* The sha2 0.10.9 software compression backend copies a complete input block
  and the hash state into local working arrays without zeroization. Secret
  inputs may remain in those arrays. Review or replace the relevant SHA-512
  backends with implementations that erase secret-bearing working storage;
  examine hardware-specific backends as well.
* The linked x86-64 `curve25519-dalek` scalar multiplication implementation
  uses stack storage for unpacked scalar limbs without an explicit wipe. A
  wipe of the caller's scalar cannot cover the callee's stack frame. Review
  or replace the relevant arithmetic implementation and verify its generated
  code on each supported target.
* Integrate the SDK with the fixed library, replace its temporary junction
  implementation with the output-buffer API, and inspect all reported paths in
  the final linked native and Wasm artifacts with supported release toolchains.
  The CertiK report
  used rustc 1.99.1; the local inspection used rustc 1.97.1 and LLVM 22.1.6.
  Functional tests do not measure memory residue.

## Validation performed

The SHA-512 adapter was compared to `sha2` on empty input, around the SHA-512
padding and block boundaries, and over multiple input chunk sizes. The
allocation-free configuration and 202 library tests with `alloc,std,vrf`
passed. The library workspace tests and workspace clippy passed in a temporary
integration copy. The SDK's 44 wrapper tests passed against a temporary copy
combining QUIP HD and the library changes; its junction tests also passed
against the actual pinned dependency. QPA-02 regression tests passed in both
contexts. These are compatibility checks, not proof of memory erasure.

On 2026-11-27 the SDK's crypto-core tests and 46 wrapper tests passed against
its existing pin; the junction tests also passed in release mode. A native
release test executable was built and its junction code inspected. The
crypto-core crate compiled for `wasm32-unknown-unknown`; the full SDK Wasm
check did not complete because `clang` was unavailable. Workspace clippy
for both SDK crates was blocked by existing warnings in the runtime-interface
procedural macro; the crypto-core clippy check passed separately.
