// SPDX-License-Identifier: AGPL-3.0-or-later
//! Suite traits: the classical and post-quantum components, and the
//! registry-checked label, that together identify one hybrid construction.

use crate::component::{ClassicalScheme, PqScheme, PqStatefulScheme};

/// One hybrid construction: a classical component, a post-quantum
/// component, and the label that separates it from every other suite.
///
/// Modelled on the Noise Protocol Framework, where the protocol name is
/// composed from its primitives and then bound cryptographically. Here the
/// composed name is the label prepended into `M'`.
pub trait Suite {
    /// The classical component.
    type Classical: ClassicalScheme;
    /// The post-quantum component.
    type Pq: PqScheme;

    /// Null-terminated registry label from specification section 7.
    const LABEL: &'static [u8];

    /// Length in bytes of the composite public key: the classical public
    /// key followed by the post-quantum public key.
    const PUBLIC_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
        + <Self::Pq as PqScheme>::PUBLIC_KEY_LEN;
    /// Length in bytes of the composite secret key: the classical secret
    /// key followed by the post-quantum secret key.
    const SECRET_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::SECRET_KEY_LEN
        + <Self::Pq as PqScheme>::SECRET_KEY_LEN;
    /// Length in bytes of the composite signature: the classical signature
    /// followed by the post-quantum signature. Fixed, since both halves are
    /// fixed-length for every [`Suite`] (H1, H3); H2 and H4's variable-length
    /// post-quantum half is why they implement [`DeltaSuite`] instead.
    const SIGNATURE_LEN: usize =
        <Self::Classical as ClassicalScheme>::SIGNATURE_LEN + <Self::Pq as PqScheme>::SIGNATURE_LEN;
    /// Byte offset where the post-quantum half begins.
    const SPLIT: usize = <Self::Classical as ClassicalScheme>::SIGNATURE_LEN;
}

/// Declare a hybrid suite.
///
/// Composes the label as `"hybrid-" classical "-" pq "-v1"` plus a null
/// byte, then checks the result against the registry literal and its byte
/// count at compile time. A typo becomes a build failure, not a silently
/// incompatible signature.
#[macro_export]
macro_rules! hybrid_suite {
    (
        $(#[$meta:meta])*
        $name:ident,
        classical = $classical:ty as $ctok:literal,
        pq = $pq:ty as $ptok:literal,
        label = $label:literal,
        label_len = $len:literal $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl $crate::suite::Suite for $name {
            type Classical = $classical;
            type Pq = $pq;
            const LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1", "\0").as_bytes();
        }

        const _: () = {
            // The composed name must equal the registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1"),
                    $label,
                ),
                "composed suite label does not match the registry literal",
            );
            // The byte count must equal the registry byte count, which
            // includes the trailing null byte.
            assert!(
                $label.len() + 1 == $len,
                "label length does not match the registry byte count",
            );
            // Each name token must equal its component's NAME constant.
            assert!(
                $crate::suite::const_str_eq(
                    <$classical as $crate::component::ClassicalScheme>::NAME, $ctok,
                ),
                "classical name token does not match ClassicalScheme::NAME",
            );
            assert!(
                $crate::suite::const_str_eq(
                    <$pq as $crate::component::PqScheme>::NAME, $ptok,
                ),
                "post-quantum name token does not match PqScheme::NAME",
            );
        };
    };
}

/// One stateful hybrid construction: a classical component, a stateful
/// post-quantum component, and the label that separates it from every other
/// suite.
///
/// Mirrors [`Suite`], but its post-quantum half is [`PqStatefulScheme`]
/// rather than [`PqScheme`]: a stateful signature spends a one-time leaf and
/// its encoded length varies with the leaf index, neither of which
/// [`PqScheme`]'s fixed-length, stateless shape can express.
///
/// `STORED_PUBLIC_KEY_LEN` is the small on-storage form (a classical public
/// key plus a commitment); `VERIFY_PUBLIC_KEY_LEN` is the larger form a
/// verifier needs at verification time (a classical public key plus the
/// full verify key). There is no single `SIGNATURE_LEN`: see
/// [`PqStatefulScheme::FIXED_STATEFUL_SIG_LEN`] and
/// [`PqStatefulScheme::STATELESS_SIG_LEN`].
pub trait StatefulSuite {
    /// The classical component.
    type Classical: ClassicalScheme;
    /// The stateful post-quantum component.
    type Pq: PqStatefulScheme;

    /// Null-terminated registry label from specification section 7.
    const LABEL: &'static [u8];

    /// Null-terminated registry label for the rotation domain, specification
    /// section 19.2. Distinct from [`LABEL`](Self::LABEL) so an ordinary
    /// classical signature can never be spliced in as a rotation
    /// co-signature.
    const ROTATE_LABEL: &'static [u8];

    /// Length in bytes of the small, on-storage composite public key: the
    /// classical public key followed by the post-quantum component's
    /// commitment ([`PqStatefulScheme::PUBLIC_KEY_LEN`]). Not enough on its
    /// own to verify against; see [`VERIFY_PUBLIC_KEY_LEN`](Self::VERIFY_PUBLIC_KEY_LEN).
    const STORED_PUBLIC_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
        + <Self::Pq as PqStatefulScheme>::PUBLIC_KEY_LEN;
    /// Length in bytes of the larger composite public key a verifier needs:
    /// the classical public key followed by the post-quantum component's
    /// full verify key ([`PqStatefulScheme::VERIFY_KEY_LEN`]).
    const VERIFY_PUBLIC_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
        + <Self::Pq as PqStatefulScheme>::VERIFY_KEY_LEN;
    /// Length in bytes of the composite secret key: the classical secret
    /// key followed by the post-quantum secret key's exported form
    /// ([`PqStatefulScheme::SECRET_KEY_LEN`]).
    const SECRET_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::SECRET_KEY_LEN
        + <Self::Pq as PqStatefulScheme>::SECRET_KEY_LEN;
    /// Byte offset where the post-quantum half begins in the composite wire
    /// encoding (`pqhybridsign_core::encoding_path`).
    const SPLIT: usize = <Self::Classical as ClassicalScheme>::SIGNATURE_LEN;
}

/// Declare a stateful hybrid suite.
///
/// Same compile-time discipline as [`hybrid_suite!`]: composes the label as
/// `"hybrid-" classical "-" pq "-v1"` plus a null byte, then checks the
/// result against the registry literal and its byte count, and each name
/// token against its component's `NAME`, all at compile time. The rotation
/// label (specification section 19.2) gets the same treatment: composed as
/// `"hybrid-" classical "-" pq "-rotate-v1"` plus a null byte, checked
/// against its own registry literal and byte count.
#[macro_export]
macro_rules! hybrid_stateful_suite {
    (
        $(#[$meta:meta])*
        $name:ident,
        classical = $classical:ty as $ctok:literal,
        pq = $pq:ty as $ptok:literal,
        label = $label:literal,
        label_len = $len:literal,
        rotate_label = $rotate_label:literal,
        rotate_label_len = $rotate_len:literal $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl $crate::suite::StatefulSuite for $name {
            type Classical = $classical;
            type Pq = $pq;
            const LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1", "\0").as_bytes();
            const ROTATE_LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-rotate-v1", "\0").as_bytes();
        }

        const _: () = {
            // The composed name must equal the registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1"),
                    $label,
                ),
                "composed suite label does not match the registry literal",
            );
            // The byte count must equal the registry byte count, which
            // includes the trailing null byte.
            assert!(
                $label.len() + 1 == $len,
                "label length does not match the registry byte count",
            );
            // The composed rotation name must equal its own registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-rotate-v1"),
                    $rotate_label,
                ),
                "composed rotate label does not match the registry literal",
            );
            // Same byte-count discipline as the label above.
            assert!(
                $rotate_label.len() + 1 == $rotate_len,
                "rotate label length does not match the registry byte count",
            );
            // Each name token must equal its component's NAME constant.
            assert!(
                $crate::suite::const_str_eq(
                    <$classical as $crate::component::ClassicalScheme>::NAME, $ctok,
                ),
                "classical name token does not match ClassicalScheme::NAME",
            );
            assert!(
                $crate::suite::const_str_eq(
                    <$pq as $crate::component::PqStatefulScheme>::NAME, $ptok,
                ),
                "post-quantum name token does not match PqStatefulScheme::NAME",
            );
        };
    };
}

/// One hybrid construction whose post-quantum half is delta-length encoded
/// on the wire (specification section 6): a classical component, a
/// post-quantum component, the label that separates it from every other
/// suite, and the smallest signature length its 1-byte length field can
/// represent.
///
/// [`Suite`] bakes a fixed-offset split into [`Suite::SIGNATURE_LEN`] and
/// [`Suite::SPLIT`], which FN-DSA-512 does not fit: its wire form carries a
/// length field between the classical and post-quantum halves
/// (`crate::encoding_delta`). This trait exists so H2 and H4 can share
/// [`hybrid_delta_suite!`](crate::hybrid_delta_suite) and `crate::composite_delta` without perturbing
/// [`Suite`] or the fixed-offset composite functions H1 and H3 already use,
/// mirroring how [`StatefulSuite`] sits beside [`Suite`] for the same
/// reason.
pub trait DeltaSuite {
    /// The classical component.
    type Classical: ClassicalScheme;
    /// The post-quantum component.
    type Pq: PqScheme;

    /// Null-terminated registry label from specification section 7.
    const LABEL: &'static [u8];

    /// Smallest post-quantum signature length the wire `DeltaLen` field can
    /// represent (specification section 6). `MIN_FALCON512_SIG_LEN` for H2
    /// and H4.
    const MIN_PQ_SIG_LEN: usize;

    /// Length in bytes of the composite public key: the classical public
    /// key followed by the post-quantum public key.
    const PUBLIC_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
        + <Self::Pq as PqScheme>::PUBLIC_KEY_LEN;
    /// Length in bytes of the composite secret key: the classical secret
    /// key followed by the post-quantum secret key.
    const SECRET_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::SECRET_KEY_LEN
        + <Self::Pq as PqScheme>::SECRET_KEY_LEN;
    /// Largest wire-encoded signature this suite can produce: the classical
    /// signature, the 1-byte `DeltaLen` field, and the post-quantum
    /// component's largest signature. Callers size `sig_out` for
    /// `crate::composite_delta::sign`/`sign_deterministic` with this.
    const MAX_SIGNATURE_LEN: usize = <Self::Classical as ClassicalScheme>::SIGNATURE_LEN
        + 1
        + <Self::Pq as PqScheme>::SIGNATURE_LEN;
}

/// Declare a delta-length-encoded hybrid suite.
///
/// Same compile-time discipline as [`hybrid_suite!`]: composes the label as
/// `"hybrid-" classical "-" pq "-v1"` plus a null byte, then checks the
/// result against the registry literal and its byte count, and each name
/// token against its component's `NAME`, all at compile time.
///
/// It additionally checks that `min_pq_sig_len` and the post-quantum
/// component's [`PqScheme::SIGNATURE_LEN`] agree with the 1-byte `DeltaLen`
/// field: the component's signature must be at least `min_pq_sig_len` and
/// no more than 255 bytes above it, or no `DeltaLen` value could ever
/// encode it.
#[macro_export]
macro_rules! hybrid_delta_suite {
    (
        $(#[$meta:meta])*
        $name:ident,
        classical = $classical:ty as $ctok:literal,
        pq = $pq:ty as $ptok:literal,
        label = $label:literal,
        label_len = $len:literal,
        min_pq_sig_len = $min_len:expr $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl $crate::suite::DeltaSuite for $name {
            type Classical = $classical;
            type Pq = $pq;
            const LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1", "\0").as_bytes();
            const MIN_PQ_SIG_LEN: usize = $min_len;
        }

        const _: () = {
            // The composed name must equal the registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1"),
                    $label,
                ),
                "composed suite label does not match the registry literal",
            );
            // The byte count must equal the registry byte count, which
            // includes the trailing null byte.
            assert!(
                $label.len() + 1 == $len,
                "label length does not match the registry byte count",
            );
            // Each name token must equal its component's NAME constant.
            assert!(
                $crate::suite::const_str_eq(
                    <$classical as $crate::component::ClassicalScheme>::NAME, $ctok,
                ),
                "classical name token does not match ClassicalScheme::NAME",
            );
            assert!(
                $crate::suite::const_str_eq(
                    <$pq as $crate::component::PqScheme>::NAME, $ptok,
                ),
                "post-quantum name token does not match PqScheme::NAME",
            );
            // The delta-length field is one byte: the post-quantum
            // component's signature must be at least `min_pq_sig_len` and
            // no more than 255 bytes above it, or `DeltaLen` cannot encode
            // it.
            assert!(
                <$pq as $crate::component::PqScheme>::SIGNATURE_LEN >= $min_len,
                "min_pq_sig_len exceeds the post-quantum component's signature length",
            );
            assert!(
                <$pq as $crate::component::PqScheme>::SIGNATURE_LEN - $min_len <= 255,
                "the post-quantum component's signature length does not fit the 1-byte delta field",
            );
        };
    };
}

/// Compare two string literals in a const context.
#[doc(hidden)]
pub const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
