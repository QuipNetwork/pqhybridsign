// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![doc = "The C ABI binding over `pqhybridsign-abi`.

Every function here is `extern \"C\"`, `#[no_mangle]`, and prefixed `pqhs_`.

# The boundary contract lives in the generated header

`cbindgen.toml` in this crate's root drives `include/pqhybridsign.h`, and
its `header` block carries the whole contract this boundary keeps: what an
error code means, who owns each buffer, which pointers may not overlap,
whose job it is to wipe secret key material, why H5 and H6 have their own
entry points, what is and is not thread-safe, and why no panic crosses into
C. That text is in the header rather than here because the header is the
only artifact a C integrator reads -- they have no rustdoc build -- and
keeping one copy is what stops the two from drifting apart.

Regenerate the header with
`cargo run --example gen_header -p pqhybridsign-cffi` after changing any
public signature, doc comment, or the `header` block, and commit the
result: `cargo test -p pqhybridsign-cffi` fails the build if the checked-in
header has drifted from what this crate's source now generates.

# What this crate guarantees about itself

No function in this crate calls `unwrap` or `expect` outside
`#[cfg(test)]`, indexes with a caller-controlled index, or does arithmetic
that can panic on caller-controlled input. Every entry point is wrapped in
an internal panic guard as a backstop, and nothing outside this crate's
internal `ffi` module dereferences a caller-supplied pointer.
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
    pqhs_error_message, PQHS_ERR_ALIASED_BUFFERS, PQHS_ERR_BAD_LENGTH, PQHS_ERR_BAD_PATH_SELECTOR,
    PQHS_ERR_BAD_ROTATION_KIND, PQHS_ERR_BUDGET_STORE_FAILED, PQHS_ERR_COMPONENT_FAILURE,
    PQHS_ERR_CONTEXT_TOO_LONG, PQHS_ERR_COUNTERS_DIVERGED, PQHS_ERR_DELTA_LENGTH_OUT_OF_RANGE,
    PQHS_ERR_GRIND_ABORT, PQHS_ERR_INVALID_SUITE, PQHS_ERR_JOURNAL_FAILED,
    PQHS_ERR_JOURNAL_KEY_MISMATCH, PQHS_ERR_LEAF_COUNT_OUT_OF_RANGE, PQHS_ERR_LEAVES_EXHAUSTED,
    PQHS_ERR_NULL_POINTER, PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL, PQHS_ERR_PANIC,
    PQHS_ERR_SIGNING_FAILED, PQHS_ERR_STATELESS_BUDGET_EXHAUSTED, PQHS_ERR_TRAILING_BYTES,
    PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE, PQHS_OK,
};
pub use keygen::{pqhs_keygen_from_seed, pqhs_keygen_stateful_from_seed};
pub use profile::pqhs_profile_name;
pub use sign::{pqhs_sign, pqhs_sign_deterministic, pqhs_verify};
pub use sizes::{pqhs_public_key_len, pqhs_secret_key_len, pqhs_signature_len};
pub use stateful::{
    pqhs_adopt_key, pqhs_key_identity, pqhs_key_identity_from_secret_key, pqhs_sign_stateful,
    pqhs_sign_stateless, PqhsLeafJournal, PqhsStatelessBudget, PQHS_BUDGET_KEY_LEN,
    PQHS_KEY_IDENTITY_LEN,
};
