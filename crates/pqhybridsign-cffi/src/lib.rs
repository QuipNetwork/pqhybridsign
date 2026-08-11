// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![doc = "The C ABI binding over `pqhybridsign-abi`.

Every function here is `extern \"C\"`, `#[no_mangle]`, and prefixed `pqhs_`.
`cbindgen.toml` in this crate's root drives the generated header,
`include/pqhybridsign.h`; regenerate it with
`cargo run --example gen_header -p pqhybridsign-cffi` after changing any
public signature or doc comment here, and commit the result --
`cargo test -p pqhybridsign-cffi` fails the build if the checked-in header
has drifted from what this crate's source now generates.

# Every entry point returns an error code

`0` (`PQHS_OK`) is success. A nonzero return is one of the `PQHS_ERR_*`
constants: `1..=16` mirror [`pqhybridsign_abi::AbiError`] one for one, and
`100`/`101` are this crate's own codes for a null pointer and a caught
panic, situations the ABI crate -- which never sees a raw pointer and never
panics -- has no code for. [`pqhs_error_message`] turns any of them into a
human-readable string. [`pqhs_verify`] is the one exception: an invalid
signature is reported through its `bool` out-parameter, not the return
code, because rejecting a signature is not a call failure.

# The caller owns every buffer

Every buffer parameter is a pointer plus a length; this crate never
allocates a buffer it hands back to the caller, and never retains one after
a call returns. A length is always checked against what the call needs
before anything is written -- a caller-supplied length is never trusted
past that check -- and a buffer that is too small comes back as an error
code, never a partial write past its bound. A null pointer is likewise
always an error code and never a dereference -- a null pointer paired with
a length of `0` is read as an empty buffer, not an error. Because
this crate holds no secret key material of its own between calls -- keys
live only in the caller's buffers, passed in and read back out -- there is
nothing here for this crate to zeroize on drop; zeroizing a secret key
buffer once the caller is done with it is the caller's own responsibility.

# H5 and H6 keep their guardrails

H5 and H6 spend a one-time leaf per signature; reusing one is a total loss
of the key's post-quantum security. This crate offers no call shaped like
an ordinary stateless sign that can reach either suite: [`pqhs_sign`] and
[`pqhs_sign_deterministic`] reject them with
`PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE`, and the only way to spend a leaf is
[`pqhs_sign_stateful`], which requires a [`PqhsLeafJournal`] -- a durable,
caller-owned log of spent leaves -- as an argument, not an optional one.

# No panics cross this boundary

Every entry point is wrapped in an internal panic guard, which
catches an unwinding panic from anywhere underneath -- this crate,
`pqhybridsign-abi`, or one of its dependencies -- and turns it into
`PQHS_ERR_PANIC` instead of letting it cross into C, which is undefined
behaviour. `pqhybridsign-abi` is written not to panic; this is a backstop,
not the primary contract. No function in this crate itself calls `unwrap`
or `expect` outside `#[cfg(test)]`, indexes with a caller-controlled index,
or does arithmetic that can panic on caller-controlled input.
"]

mod error;
mod ffi;
mod keygen;
mod profile;
mod sign;
mod sizes;
mod stateful;
mod suite;

pub use error::{
    pqhs_error_message, PQHS_ERR_BAD_LENGTH, PQHS_ERR_BAD_PATH_SELECTOR,
    PQHS_ERR_BAD_ROTATION_KIND, PQHS_ERR_COMPONENT_FAILURE, PQHS_ERR_CONTEXT_TOO_LONG,
    PQHS_ERR_DELTA_LENGTH_OUT_OF_RANGE, PQHS_ERR_GRIND_ABORT, PQHS_ERR_INVALID_SUITE,
    PQHS_ERR_JOURNAL_FAILED, PQHS_ERR_LEAF_COUNT_OUT_OF_RANGE, PQHS_ERR_LEAVES_EXHAUSTED,
    PQHS_ERR_NULL_POINTER, PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL, PQHS_ERR_PANIC,
    PQHS_ERR_SIGNING_FAILED, PQHS_ERR_SOFT_JUNCTION_REJECTED, PQHS_ERR_TRAILING_BYTES,
    PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE, PQHS_OK,
};
pub use keygen::{pqhs_keygen_from_seed, pqhs_keygen_stateful_from_seed};
pub use profile::pqhs_profile_name;
pub use sign::{pqhs_sign, pqhs_sign_deterministic, pqhs_verify};
pub use sizes::{pqhs_public_key_len, pqhs_secret_key_len, pqhs_signature_len};
pub use stateful::{pqhs_sign_stateful, pqhs_sign_stateless, PqhsLeafJournal};
