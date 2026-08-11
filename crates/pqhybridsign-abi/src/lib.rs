// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![doc = "Type-erased, runtime-dispatched API over the pqhybridsign suites.

Every suite this workspace ships -- H1, H2, H3, H4, H5, H6 -- is a
compile-time type in `pqhybridsign`/`pqhybridsign-shrincs`; callers write
`sign::<H1>(...)`. No C header, JavaScript function or Python module can
name a type parameter, so no binding can be built directly over that
generic API. This crate is the runtime stand-in every binding wraps: the
[`Suite`] enum replaces the type parameter, and every function here takes
a [`Suite`] value and dispatches to the right generic implementation
internally.

# Two paths, kept apart

H1 through H4 are stateless: signing them costs nothing but CPU time, and
[`sign`]/[`sign_deterministic`]/[`keygen_from_seed`] handle all four. H5
and H6 are stateful: their post-quantum half spends a one-time leaf per
signature, and reusing a leaf is a total loss of the key's post-quantum
security. A stateless-looking call that silently spent a leaf would be the
worst failure mode this crate could offer, so H5 and H6 have their own
entry points -- [`sign_stateful`], [`sign_stateless`] and
[`keygen_stateful_from_seed`] -- and the stateless functions reject them
with [`AbiError::WrongEntryPointForSuite`] rather than doing anything with
them. [`verify`] is the one function that covers all six suites, because
verifying never spends anything.

# Sizes first

[`public_key_len`], [`secret_key_len`] and [`signature_len`] exist because
every binding needs to allocate before it can call anything else that
writes into a buffer. [`signature_len`] is a maximum, not an exact figure,
for H2, H4, H5 and H6: see its documentation for why each is
variable-length.

# Out of scope

Key rotation and the leaf-tracking policy machine
([`pqhybridsign_core::rotation`], [`pqhybridsign_core::policy`]) are not
part of this crate's surface. Both need registry state -- which leaves a
key has already offered, which rotation epoch is current -- that has to
live in the integrator's own system, not behind a stateless FFI call.
Exposing half of that machinery through a C ABI would invite an
integrator to reimplement the rest incorrectly. A later crate may add a
rotation-aware surface once that state boundary has an owner; this crate
does not attempt it.

# The SHRINCS profile is a build-time choice

[`profile_name`] reports the SHRINCS profile this crate was compiled
with (for example `\"shrincs-256s\"`). Exactly one profile feature of
`pqhybridsign-shrincs` is active per build, so a binding built against one
profile cannot interoperate with keys or signatures from a build against
another; [`profile_name`] lets an integrator confirm the two sides of an
integration agree before trusting anything the wire carries.

# No panics

No function in this crate calls `unwrap` or `expect` outside `#[cfg(test)]`,
and no function indexes or does arithmetic that can panic on attacker- or
caller-controlled input. A panic across a language boundary is undefined
behaviour, and every function here is written to be called from one.
"]

mod error;
mod sizes;
mod stateful_suites;
mod stateless_suites;
mod suite;
mod verify;

pub use error::AbiError;
pub use sizes::{public_key_len, secret_key_len, signature_len};
pub use stateful_suites::{keygen_stateful_from_seed, sign_stateful, sign_stateless};
pub use stateless_suites::{keygen_from_seed, sign, sign_deterministic};
pub use suite::Suite;
pub use verify::verify;

/// Re-exported so a caller can implement [`LeafJournal`] for
/// [`sign_stateful`] without depending on `pqhybridsign-core` directly.
pub use pqhybridsign_core::stateful::LeafJournal;

/// The SHRINCS profile this build links against, for example
/// `"shrincs-256s"`.
///
/// Exactly one `pqhybridsign-shrincs` profile feature is active in any one
/// build (enforced at compile time in that crate). Two builds of this
/// crate linked against different profiles are not interchangeable: a
/// key, signature or verify key produced under one profile is meaningless
/// -- and in general the wrong length -- under another. A binding reports
/// this string so an integrator can confirm both sides of an integration
/// were built against the same profile before trusting anything on the
/// wire.
#[must_use]
pub fn profile_name() -> &'static str {
    <<pqhybridsign_shrincs::H5 as pqhybridsign_core::StatefulSuite>::Pq as pqhybridsign_core::PqStatefulScheme>::NAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_is_the_active_shrincs_profile() {
        // Exactly one of `pqhybridsign-shrincs`'s `profile-*` features is
        // active per build; this crate's `Cargo.toml` pulls in the
        // default (`profile-256s`) unless a workspace-level override
        // changes it, so the string names that profile.
        assert!(profile_name().starts_with("shrincs-"));
    }
}
